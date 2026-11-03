//! Bounded in-memory reuse of verified results. Reading a catalog, loading a
//! snapshot and building a projection are pure functions of their exact
//! inputs, and one command repeats each of them many times on the same
//! inputs; a memo keyed by a hash of every input returns the earlier result
//! instead. Only successes are kept, nothing is persisted, and a full memo
//! starts over.
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Mutex};

/// Entries kept per memo.
const ENTRIES: usize = 32;
/// Total weight (about the catalog bytes behind the entries) kept per memo.
const BUDGET: usize = 32 << 20;
/// Heavier results are not kept.
const LARGEST: usize = 8 << 20;

pub(crate) type Key = [u8; 32];

pub(crate) struct Memo<V>(Mutex<Option<(HashMap<Key, V>, usize)>>);
impl<V: Clone> Memo<V> {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(None))
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
        if map.len() >= ENTRIES || *total + weight > BUDGET {
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
