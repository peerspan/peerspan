//! Bounded in-memory reuse of verified results. Reading a catalog, loading a
//! snapshot and building a projection are pure functions of their exact
//! inputs, and one command repeats each of them many times on the same
//! inputs; a memo keyed by a hash of every input returns the earlier result
//! instead. Loading a join request is the same, and background workers
//! reload every request on each pass; so are reading a statement, a prior,
//! a stored frame and the untimed checks of opening one, which every
//! catalog read, projection and request pass repeats on the same bytes.
//! Only successes are kept, nothing is persisted, and a full memo starts
//! over.
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Mutex};

/// Entries kept per memo, unless it is sized otherwise.
const ENTRIES: usize = 32;
/// Total weight (about the catalog bytes behind the entries) kept per memo.
const BUDGET: usize = 32 << 20;
/// Heavier results are not kept.
const LARGEST: usize = 8 << 20;

pub(crate) type Key = [u8; 32];

pub(crate) struct Memo<V>(Mutex<Option<(HashMap<Key, V>, usize)>>, usize);
impl<V: Clone> Memo<V> {
    pub(crate) const fn new() -> Self {
        Self::sized(ENTRIES)
    }
    /// A memo of up to `entries` results, for callers that cycle through
    /// more distinct inputs than the default holds.
    pub(crate) const fn sized(entries: usize) -> Self {
        Self(Mutex::new(None), entries)
    }
    pub(crate) fn get(&self, key: &Key) -> Option<V> {
        let guard = self.0.lock().ok()?;
        guard.as_ref()?.0.get(key).cloned()
    }
    /// Keeps `value` under `key`; `weight` is about the bytes it holds.
    pub(crate) fn put(&self, key: Key, value: &V, weight: usize) {
        if weight > LARGEST {
            return;
        }
        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        let (map, total) = guard.get_or_insert_with(Default::default);
        if map.len() >= self.1 || *total + weight > BUDGET {
            map.clear();
            *total = 0;
        }
        if map.insert(key, value.clone()).is_none() {
            *total += weight;
        }
    }
}

/// A key over length-prefixed parts, so no two different input lists share
/// one.
pub(crate) fn key<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Key {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// Adds every row of `query` with `params` to `hash`, each value tagged with
/// its type and length-prefixed, so different row sets give different keys.
pub(crate) fn hash_rows(
    hash: &mut Sha256,
    query: &mut rusqlite::CachedStatement<'_>,
    params: impl rusqlite::Params,
) -> rusqlite::Result<()> {
    use rusqlite::types::ValueRef;
    let columns = query.column_count();
    let mut rows = query.query(params)?;
    while let Some(row) = rows.next()? {
        hash.update([0xff]);
        for i in 0..columns {
            match row.get_ref(i)? {
                ValueRef::Null => hash.update([0]),
                ValueRef::Integer(v) => {
                    hash.update([1]);
                    hash.update(v.to_be_bytes());
                }
                ValueRef::Real(v) => {
                    hash.update([2]);
                    hash.update(v.to_bits().to_be_bytes());
                }
                ValueRef::Text(v) => {
                    hash.update([3]);
                    hash.update((v.len() as u64).to_be_bytes());
                    hash.update(v);
                }
                ValueRef::Blob(v) => {
                    hash.update([4]);
                    hash.update((v.len() as u64).to_be_bytes());
                    hash.update(v);
                }
            }
        }
    }
    hash.update([0xfe]);
    Ok(())
}

/// Adds `value` to `hash`, each node tagged with its type and every string,
/// key and array length-prefixed, so different values give different keys.
/// Unlike hashing its JSON text, strings are hashed as their bytes, without
/// escaping, which matters for a projection's megabyte catalog field.
pub(crate) fn hash_value(hash: &mut Sha256, value: &serde_json::Value) {
    use serde_json::Value;
    fn bytes(hash: &mut Sha256, tag: u8, bytes: &[u8]) {
        hash.update([tag]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    match value {
        Value::Null => hash.update([0]),
        Value::Bool(b) => hash.update([1, u8::from(*b)]),
        Value::Number(n) => bytes(hash, 2, n.to_string().as_bytes()),
        Value::String(s) => bytes(hash, 3, s.as_bytes()),
        Value::Array(items) => {
            hash.update([4]);
            hash.update((items.len() as u64).to_be_bytes());
            for item in items {
                hash_value(hash, item);
            }
        }
        Value::Object(map) => {
            hash.update([5]);
            hash.update((map.len() as u64).to_be_bytes());
            for (k, v) in map {
                bytes(hash, 6, k.as_bytes());
                hash_value(hash, v);
            }
        }
    }
}

/// A key over `value` and length-prefixed `parts`.
pub(crate) fn value_key<'a>(
    value: &serde_json::Value,
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> Key {
    let mut hash = Sha256::new();
    hash_value(&mut hash, value);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
