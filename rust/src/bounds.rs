//! Resource bounds (capabilities contract, slice 3): a capability may limit
//! the values of named top-level arguments of its tool operations to a list
//! of combinations. The serving host checks each call's input against them
//! at submission and again before start.
use crate::{canonical, model::Error};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// One combination: argument names, in byte order, to one value each.
pub type Combination = BTreeMap<String, String>;

const MAX_COMBINATIONS: usize = 16;
const MAX_ENTRIES: usize = 4;

fn name_shape(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
/// A bound value: 1 to 256 bytes, with no control character.
fn value_shape(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
}

/// Reads `bounds` from a create request: absent or `{}` is no bound (an
/// empty list); otherwise `{"arguments": [COMBINATION, ...]}`.
pub fn parse(value: Option<&Value>) -> Result<Vec<Combination>, Error> {
    let invalid = |m: &str| Err(Error::Invalid(format!("bounds: {m}")));
    let object = match value {
        None => return Ok(Vec::new()),
        Some(Value::Object(o)) => o,
        Some(_) => return invalid("bounds is an object"),
    };
    if object.is_empty() {
        return Ok(Vec::new());
    }
    if object.len() != 1 {
        return invalid("bounds has only arguments");
    }
    let Some(Value::Array(list)) = object.get("arguments") else {
        return invalid("arguments is a list of combinations");
    };
    if list.is_empty() || list.len() > MAX_COMBINATIONS {
        return invalid("arguments holds 1 to 16 combinations");
    }
    let mut out = Vec::new();
    for item in list {
        let Value::Object(entries) = item else {
            return invalid("a combination is an object");
        };
        if entries.is_empty() || entries.len() > MAX_ENTRIES {
            return invalid("a combination names 1 to 4 arguments");
        }
        let mut c = Combination::new();
        for (name, value) in entries {
            let Some(value) = value.as_str() else {
                return invalid("a bound value is a string");
            };
            if !name_shape(name) {
                return invalid("an argument name matches [A-Za-z_][A-Za-z0-9_]{0,63}");
            }
            if !value_shape(value) {
                return invalid(
                    "a bound value is 1 to 256 bytes of UTF-8 without control characters",
                );
            }
            c.insert(name.clone(), value.to_owned());
        }
        out.push(c);
    }
    Ok(out)
}

/// The stored form: `{}`, or `{"arguments": [...]}`.
pub fn to_value(combinations: &[Combination]) -> Value {
    if combinations.is_empty() {
        json!({})
    } else {
        json!({"arguments": combinations})
    }
}
/// A record's bounds, read leniently; anything else is no bound.
pub fn of_record(value: &Value) -> Vec<Combination> {
    value["arguments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let o = c.as_object()?;
            Some(
                o.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect(),
            )
        })
        .collect()
}

/// Every name in order of first appearance: the first combination's, then
/// each later combination's new ones.
pub fn names(combinations: &[Combination]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in combinations {
        for k in c.keys() {
            if !out.contains(k) {
                out.push(k.clone());
            }
        }
    }
    out
}

/// `KEY is VALUE and ...` for each combination, joined by ` or `.
pub fn allowed(combinations: &[Combination]) -> String {
    combinations
        .iter()
        .map(|c| {
            c.iter()
                .map(|(k, v)| format!("{k} is {v}"))
                .collect::<Vec<_>>()
                .join(" and ")
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

/// A valid `repo` argument of the gh source: `OWNER/REPO`.
pub fn repo_shape(value: &str) -> bool {
    let Some((owner, repo)) = value.split_once('/') else {
        return false;
    };
    owner_shape(owner)
        && !repo.is_empty()
        && repo.len() <= 100
        && repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && repo != "."
        && repo != ".."
}
/// A GitHub owner: `[A-Za-z0-9][A-Za-z0-9-]{0,38}`.
pub fn owner_shape(owner: &str) -> bool {
    let mut chars = owner.chars();
    owner.len() <= 39
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}
/// `OWNER` of a gh bound value `OWNER/*`.
pub fn owner_wildcard(value: &str) -> Option<&str> {
    value.strip_suffix("/*").filter(|o| owner_shape(o))
}
/// Whether a gh `repo` bound value is acceptable: `OWNER/REPO` or `OWNER/*`.
pub fn gh_repo_bound(value: &str) -> bool {
    repo_shape(value) || owner_wildcard(value).is_some()
}

/// Whether one input value matches one bound value. `gh` marks the gh
/// source's `repo` matcher: case-insensitive, with `OWNER/*`.
fn value_matches(bound: &str, got: &str, gh_repo: bool) -> bool {
    if !gh_repo {
        return bound == got;
    }
    if let Some(owner) = owner_wildcard(bound) {
        return got
            .split_once('/')
            .is_some_and(|(o, rest)| !rest.is_empty() && o.eq_ignore_ascii_case(owner));
    }
    bound.eq_ignore_ascii_case(got)
}

/// Whether a call's input passes the bound. `gh` is true for a gh source.
pub fn passes(combinations: &[Combination], input: &Value, gh: bool) -> bool {
    combinations.iter().any(|c| {
        c.iter().all(|(k, v)| {
            input
                .get(k)
                .and_then(Value::as_str)
                .is_some_and(|got| value_matches(v, got, gh && k == "repo"))
        })
    })
}

/// What the call has, for each bound name: `KEY "VALUE"`, `no KEY`, or `a
/// non-string KEY`, joined by ` and `.
pub fn got(combinations: &[Combination], input: &Value) -> String {
    names(combinations)
        .iter()
        .map(|k| match input.get(k) {
            None => format!("no {k}"),
            Some(Value::String(s)) => {
                format!("{k} {}", canonical::value_text(&Value::String(s.clone())))
            }
            Some(_) => format!("a non-string {k}"),
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The 403 `out_of_bounds` refusal.
pub fn refusal(combinations: &[Combination], input: &Value) -> Error {
    let mut extra = Map::new();
    extra.insert("bounds".into(), to_value(combinations));
    Error::Coded {
        status: 403,
        code: "out_of_bounds",
        message: format!(
            "This capability is limited to calls where {}. The call has {}. Nothing was run.",
            allowed(combinations),
            got(combinations, input)
        ),
        extra,
    }
}

/// The 400 `bound_unenforceable` refusal for the first operation whose
/// schema lacks a bound name as a string property, if any.
pub fn unenforceable<'a>(
    combinations: &[Combination],
    operations: impl Iterator<Item = (&'a str, Option<&'a Value>)>,
) -> Option<Error> {
    let names = names(combinations);
    for (op, schema) in operations {
        for k in &names {
            let declared = schema
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.get(k))
                .and_then(|p| p.get("type"))
                == Some(&json!("string"));
            if !declared {
                return Some(Error::Coded {
                    status: 400,
                    code: "bound_unenforceable",
                    message: format!(
                        "Operation {op} has no string argument {k}, so Peerspan cannot check this bound for it. Leave the operation out, or narrow the credential instead (--env-file)."
                    ),
                    extra: Map::new(),
                });
            }
        }
    }
    None
}

/// A tool operation's input schema as recipients see it under the bound:
/// an `enum` for a single argument with exact values, otherwise each bound
/// property's description extended. The snapshot is unchanged.
pub fn narrow(schema: &Value, combinations: &[Combination], gh: bool) -> Value {
    if combinations.is_empty() {
        return schema.clone();
    }
    let mut out = schema.clone();
    let Some(properties) = out.get_mut("properties").and_then(Value::as_object_mut) else {
        return out;
    };
    let names = names(combinations);
    let single = combinations.iter().all(|c| c.len() == 1)
        && names.len() == 1
        && !combinations
            .iter()
            .flat_map(|c| c.iter())
            .any(|(k, v)| gh && k == "repo" && owner_wildcard(v).is_some());
    if single {
        let k = &names[0];
        if properties.contains_key(k) {
            let mut values: Vec<String> = Vec::new();
            for c in combinations {
                if let Some(v) = c.get(k)
                    && !values.contains(v)
                {
                    values.push(v.clone());
                }
            }
            properties.insert(k.clone(), json!({"type": "string", "enum": values}));
        }
        return out;
    }
    let sentence = format!("Limited by the owner: {}.", allowed(combinations));
    for k in &names {
        if let Some(Value::Object(p)) = properties.get_mut(k) {
            let description = match p.get("description").and_then(Value::as_str) {
                Some(d) => format!("{d} {sentence}"),
                None => sentence.clone(),
            };
            p.insert("description".into(), json!(description));
        }
    }
    out
}
