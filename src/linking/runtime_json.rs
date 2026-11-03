//! Fixed runtime JSON budgets. Parsing alone never establishes authority.
use super::*;
use serde::de::DeserializeOwned;

fn decode_runtime<T: DeserializeOwned>(raw: &[u8], required: &str, limit: usize) -> Result<T> {
    let value = parse_limit(raw, limit)?;
    fields(object(&value)?, required, &[])?;
    Ok(serde_json::from_slice(raw)?)
}

/// Strict mutation parsing under the fixed 1 MiB route bound.
pub fn decode_mutation<T: DeserializeOwned>(raw: &[u8], required: &str) -> Result<T> {
    decode_runtime(raw, required, MAX_OBJECT)
}

/// Strict private-row parsing; network responses retain their smaller bounds.
pub fn decode_stored_json<T: DeserializeOwned>(raw: &[u8], required: &str) -> Result<T> {
    decode_runtime(raw, required, 32 << 20)
}
