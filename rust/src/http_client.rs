//! A small HTTP/1.1 client for the public web (capabilities slice 3, remote
//! MCP servers and OAuth): `http` and `https` with the system's trust
//! store, a 10-second connect bound, no proxies, and no redirects. One
//! connection per request.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Incoming, header::HeaderMap};
use hyper_util::rt::TokioIo;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

/// Connecting, TLS included, must finish within this long.
pub const CONNECT_BOUND: Duration = Duration::from_secs(10);

/// A parsed absolute `http` or `https` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// `http` or `https`, lowercased.
    pub scheme: String,
    /// The host as written, lowercased; an IPv6 host keeps its brackets.
    pub host: String,
    pub port: u16,
    /// Whether the port was written.
    pub explicit_port: bool,
    /// The path, `""` or starting with `/`.
    pub path: String,
    /// The query, without `?`, when present.
    pub query: Option<String>,
}
impl Url {
    /// The path and query, as sent in the request line.
    pub fn target(&self) -> String {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        match &self.query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_owned(),
        }
    }
    /// `scheme://host[:port]`.
    pub fn origin(&self) -> String {
        if self.explicit_port {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        } else {
            format!("{}://{}", self.scheme, self.host)
        }
    }
    /// The host without IPv6 brackets, for connecting.
    pub fn bare_host(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&self.host)
    }
    /// Whether the host is `localhost`, `127.0.0.1`, or `[::1]`.
    pub fn loopback(&self) -> bool {
        matches!(self.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }
    /// `https`, or `http` on a loopback host.
    pub fn secure_enough(&self) -> bool {
        self.scheme == "https" || (self.scheme == "http" && self.loopback())
    }
    fn host_header(&self) -> String {
        if self.explicit_port {
            format!("{}:{}", self.host, self.port)
        } else {
            self.host.clone()
        }
    }
}

/// Parses an absolute `http` or `https` URL with a host. The fragment is
/// dropped.
pub fn parse_url(text: &str) -> Option<Url> {
    let (scheme, rest) = text.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let close = after.find(']')?;
        let host = format!("[{}]", &after[..close]);
        let port = after[close + 1..].strip_prefix(':');
        if !after[close + 1..].is_empty() && port.is_none() {
            return None;
        }
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (authority.to_owned(), None),
        }
    };
    if host.is_empty() || host == "[]" || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let (port, explicit) = match port {
        Some(p) => (p.parse::<u16>().ok().filter(|p| *p != 0)?, true),
        None => (default, false),
    };
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (tail.to_owned(), None),
    };
    Some(Url {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        explicit_port: explicit,
        path,
        query,
    })
}

/// The canonical form of a URL: scheme and host lowercased, no fragment,
/// and trailing `/` characters removed from the path.
pub fn canonical(text: &str) -> Option<String> {
    let url = parse_url(text)?;
    let mut out = url.origin();
    out.push_str(url.path.trim_end_matches('/'));
    if let Some(q) = &url.query {
        out.push('?');
        out.push_str(q);
    }
    Some(out)
}

/// The host of a URL for texts: lowercased, without port.
pub fn display_host(text: &str) -> String {
    parse_url(text).map(|u| u.host).unwrap_or_default()
}

/// Why a request failed without an HTTP answer.
#[derive(Debug)]
pub enum Failure {
    /// The connection could not be made (DNS, TCP, or TLS): nothing sent.
    Connect(String),
    /// The connection ended after the request may have been sent.
    Lost(String),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "could not connect: {e}"),
            Self::Lost(e) => write!(f, "the connection was lost: {e}"),
        }
    }
}

/// An HTTP answer, its body still to read.
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Incoming,
}
impl Response {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map(|b| b.with_root_certificates(roots).with_no_client_auth());
            Arc::new(config.unwrap_or_else(|_| {
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("default protocol versions")
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
            }))
        })
        .clone()
}

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

async fn connect(url: &Url) -> Result<Sender, String> {
    let tcp = tokio::net::TcpStream::connect((url.bare_host(), url.port))
        .await
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    if url.scheme == "https" {
        let name = rustls::pki_types::ServerName::try_from(url.bare_host().to_owned())
            .map_err(|e| e.to_string())?;
        let tls = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }
}

/// Sends one request on a new connection and returns its answer, whatever
/// the status. Redirects are not followed.
pub async fn send(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> Result<Response, Failure> {
    let mut sender = match tokio::time::timeout(CONNECT_BOUND, connect(url)).await {
        Ok(Ok(sender)) => sender,
        Ok(Err(e)) => return Err(Failure::Connect(e)),
        Err(_) => {
            return Err(Failure::Connect(
                "the connection did not open within 10 seconds".into(),
            ));
        }
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(url.target())
        .header("Host", url.host_header())
        .header(
            "User-Agent",
            concat!("peerspan/", env!("CARGO_PKG_VERSION")),
        );
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| Failure::Connect(e.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| Failure::Lost(e.to_string()))?;
    let (parts, body) = response.into_parts();
    Ok(Response {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    })
}

/// Why a body could not be read whole.
#[derive(Debug)]
pub enum BodyError {
    /// More than the limit.
    TooLarge,
    Lost(String),
}

/// Reads a body up to `limit` bytes.
pub async fn read_body(body: &mut Incoming, limit: usize) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| BodyError::Lost(e.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if out.len() + data.len() > limit {
                return Err(BodyError::TooLarge);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Reads the next chunk of a body; `None` at its end.
pub async fn next_chunk(body: &mut Incoming) -> Result<Option<Bytes>, BodyError> {
    loop {
        match body.frame().await {
            None => return Ok(None),
            Some(Err(e)) => return Err(BodyError::Lost(e.to_string())),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    return Ok(Some(data));
                }
            }
        }
    }
}

/// `application/x-www-form-urlencoded` encoding of one component.
pub fn form_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
/// Encodes pairs as a form body or query.
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
/// Decodes one form or query component.
pub fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or(())
                {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
/// The parameters of a query string, in order.
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(p), String::new()),
        })
        .collect()
}

/// The parameters of a `WWW-Authenticate` challenge with the `Bearer`
/// scheme, or `None` for another scheme.
pub fn bearer_challenge(header: &str) -> Option<Vec<(String, String)>> {
    let trimmed = header.trim_start();
    let (scheme, rest) = match trimmed.find(char::is_whitespace) {
        Some(i) => (&trimmed[..i], &trimmed[i..]),
        None => (trimmed, ""),
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut params = Vec::new();
    let mut rest = rest.trim_start();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else {
            break;
        };
        let name = rest[..eq]
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        rest = rest[eq + 1..].trim_start();
        let value;
        if let Some(after) = rest.strip_prefix('"') {
            let mut v = String::new();
            let mut chars = after.char_indices();
            let mut end = after.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, n)) = chars.next() {
                            v.push(n);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    c => v.push(c),
                }
            }
            value = v;
            rest = after[end.min(after.len())..].trim_start();
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            value = rest[..end].trim().to_owned();
            rest = &rest[end..];
        }
        rest = rest.trim_start().trim_start_matches(',').trim_start();
        params.push((name, value));
    }
    Some(params)
}
