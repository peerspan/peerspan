//! Existing Go coordinator-address grammar, independent of DNS or pin trust.
pub(super) fn valid(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    let Ok(number) = port.parse::<u16>() else {
        return false;
    };
    if number == 0 || number.to_string() != port {
        return false;
    }
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        let Some(inner) = bracketed.strip_suffix(']') else {
            return false;
        };
        if inner.contains(['[', ']']) {
            return false;
        }
        inner
    } else {
        if host.contains([':', '[', ']']) {
            return false;
        }
        host
    };
    !host.is_empty()
        && !host
            .chars()
            .any(|ch| ch <= '\u{20}' || ch == '\u{7f}' || "/\\@?#%".contains(ch))
}
