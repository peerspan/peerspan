//! The canonical encoding of a call result (capabilities contract, the call
//! view's result text): no whitespace outside strings, object keys sorted
//! by their UTF-8 bytes, numbers exactly as received, and strings as raw
//! UTF-8 with only the listed escapes. It works on the received JSON text,
//! because a parsed `serde_json::Value` re-formats numbers.
use serde_json::Value;

/// A JSON value that keeps each number's text.
enum Raw {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Raw>),
    Object(Vec<(String, Raw)>),
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
}
impl Parser<'_> {
    fn space(&mut self) {
        while self
            .text
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }
    fn eat(&mut self, b: u8) -> Option<()> {
        self.space();
        (self.text.get(self.at) == Some(&b)).then(|| self.at += 1)
    }
    fn literal(&mut self, word: &str) -> Option<()> {
        self.text[self.at..]
            .starts_with(word.as_bytes())
            .then(|| self.at += word.len())
    }
    fn value(&mut self, depth: usize) -> Option<Raw> {
        if depth > 256 {
            return None;
        }
        self.space();
        match *self.text.get(self.at)? {
            b'n' => self.literal("null").map(|_| Raw::Null),
            b't' => self.literal("true").map(|_| Raw::Bool(true)),
            b'f' => self.literal("false").map(|_| Raw::Bool(false)),
            b'"' => self.string().map(Raw::String),
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                if self.eat(b']').is_some() {
                    return Some(Raw::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    if self.eat(b',').is_some() {
                        continue;
                    }
                    self.eat(b']')?;
                    return Some(Raw::Array(items));
                }
            }
            b'{' => {
                self.at += 1;
                let mut members: Vec<(String, Raw)> = Vec::new();
                if self.eat(b'}').is_some() {
                    return Some(Raw::Object(members));
                }
                loop {
                    self.space();
                    let key = self.string()?;
                    self.eat(b':')?;
                    let value = self.value(depth + 1)?;
                    // A repeated key keeps its last value, as serde_json does.
                    members.retain(|(k, _)| *k != key);
                    members.push((key, value));
                    if self.eat(b',').is_some() {
                        continue;
                    }
                    self.eat(b'}')?;
                    return Some(Raw::Object(members));
                }
            }
            _ => self.number().map(Raw::Number),
        }
    }
    fn number(&mut self) -> Option<String> {
        let start = self.at;
        while self
            .text
            .get(self.at)
            .is_some_and(|b| matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.at += 1;
        }
        let token = std::str::from_utf8(&self.text[start..self.at]).ok()?;
        // Only valid JSON numbers.
        serde_json::from_str::<serde_json::Number>(token).ok()?;
        Some(token.to_owned())
    }
    fn hex4(&mut self) -> Option<u32> {
        let digits = std::str::from_utf8(self.text.get(self.at..self.at + 4)?).ok()?;
        self.at += 4;
        u32::from_str_radix(digits, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        if self.text.get(self.at) != Some(&b'"') {
            return None;
        }
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = *self.text.get(self.at)?;
            self.at += 1;
            match b {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.text.get(self.at)?;
                    self.at += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first) {
                                if self.text.get(self.at..self.at + 2)? != b"\\u" {
                                    return None;
                                }
                                self.at += 2;
                                let second = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&second) {
                                    return None;
                                }
                                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                            } else {
                                first
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0..0x20 => return None,
                _ => out.push(b),
            }
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(value: &Raw, out: &mut String) {
    match value {
        Raw::Null => out.push_str("null"),
        Raw::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Raw::Number(n) => out.push_str(n),
        Raw::String(s) => write_string(s, out),
        Raw::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Raw::Object(members) => {
            let mut sorted: Vec<&(String, Raw)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write(v, out);
            }
            out.push('}');
        }
    }
}

fn from_value(value: &Value) -> Raw {
    match value {
        Value::Null => Raw::Null,
        Value::Bool(b) => Raw::Bool(*b),
        Value::Number(n) => Raw::Number(n.to_string()),
        Value::String(s) => Raw::String(s.clone()),
        Value::Array(items) => Raw::Array(items.iter().map(from_value).collect()),
        Value::Object(map) => Raw::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), from_value(v)))
                .collect(),
        ),
    }
}

/// The canonical text of the member `key` of the JSON object `body`, keeping
/// its numbers as written; `None` when the body does not parse or the member
/// is absent or null.
pub fn member_text(body: &[u8], key: &str) -> Option<String> {
    let mut parser = Parser { text: body, at: 0 };
    let Raw::Object(members) = parser.value(0)? else {
        return None;
    };
    parser.space();
    if parser.at != body.len() {
        return None;
    }
    let (_, value) = members.into_iter().find(|(k, _)| k == key)?;
    if matches!(value, Raw::Null) {
        return None;
    }
    let mut out = String::new();
    write(&value, &mut out);
    Some(out)
}

/// The canonical text of a parsed value, for a result stored without its
/// received text.
pub fn value_text(value: &Value) -> String {
    let mut out = String::new();
    write(&from_value(value), &mut out);
    out
}
