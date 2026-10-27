//! Bounded direct bootstrap transport. Every resource client pins its reviewed
//! endpoint key before sending a capability; transport results confer no power.
use super::{
    bootstrap::{self, Contact, Frame},
    codec::*,
    mailbox::ParticipantMailbox,
};
use crate::store::Store;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rusqlite::OptionalExtension;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};

#[derive(Clone, Default)]
pub struct Settings {
    pub bootstrap: Vec<String>,
    pub quic: Vec<String>,
    pub rendezvous: Vec<Value>,
    pub relays: Vec<Value>,
    pub publish_contacts: bool,
}
pub(crate) struct RelayResource {
    pub address: String,
    pub public_key: Vec<u8>,
    pub credential: Vec<u8>,
}
/// Only explicitly selected current transport settings start a helper client;
/// retained SQL rows or legacy network coordinators cannot select an endpoint.
pub(crate) fn relay_resources(store: &Store) -> Result<Vec<RelayResource>> {
    let hints = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .relays
        .clone();
    require(hints.len() <= 4, "quota_exceeded")?;
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut output = Vec::new();
    for hint in hints {
        let hint = object(&hint)?;
        fields(hint, "address public_key")?;
        let address = text(hint, "address")?;
        bootstrap::endpoint(address)?;
        let public_key = b64(text(hint, "public_key")?, 32)?;
        let row:Option<(String,Option<Vec<u8>>)>=c.query_row("SELECT record,credential FROM dec_helpers WHERE kind='relay' AND address=?1 AND public_key=?2",rusqlite::params![address,text(hint,"public_key")?],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
        let Some((raw, credential)) = row else {
            continue;
        };
        let value = parse(raw.as_bytes(), 32 << 10)?;
        let row = object(&value)?;
        fields(row, "format enabled")?;
        version(row)?;
        let enabled = row["enabled"]
            .as_bool()
            .ok_or_else(|| Error::new("state_conflict"))?;
        if !enabled {
            continue;
        }
        let credential = credential.unwrap_or_default();
        check(
            credential.len() <= 1024
                && std::str::from_utf8(&credential).is_ok()
                && !credential.iter().any(|b| matches!(b, 0 | 10 | 13)),
        )?;
        output.push(RelayResource {
            address: address.into(),
            public_key,
            credential,
        });
    }
    Ok(output)
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn wire(_: impl std::fmt::Display) -> Error {
    let mut error = Error::new("recovery_required");
    error.stage = Some("transport");
    error
}
fn protected(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(wire)?;
    let meta = file.metadata().map_err(wire)?;
    // SAFETY: geteuid has no pointer arguments and never mutates process state.
    check(meta.is_file() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0)?;
    require(meta.len() <= max as u64, "quota_exceeded")?;
    let mut out = Vec::new();
    file.by_ref()
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(wire)?;
    require(out.len() <= max, "quota_exceeded")?;
    Ok(out)
}
fn addresses(value: &Value, name: &str) -> Result<Vec<String>> {
    let list = array(object(value)?, name)?;
    require(list.len() <= 8, "quota_exceeded")?;
    let out = list
        .iter()
        .map(|a| {
            let a = a.as_str().ok_or_else(|| Error::new("invalid"))?;
            bootstrap::endpoint(a)?;
            Ok(a.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    check(out.windows(2).all(|w| w[0] < w[1]))?;
    Ok(out)
}
pub fn configure(store: &Store, config: Option<&Path>, bound: SocketAddr) -> Result<()> {
    let mut s = Settings::default();
    if let Some(path) = config {
        let v = parse(&protected(path, 32 << 10)?, 32 << 10)?;
        let o = object(&v)?;
        fields(
            o,
            "format advertise_bootstrap advertise_quic rendezvous relays publish_contacts",
        )?;
        version(o)?;
        s.bootstrap = addresses(&v, "advertise_bootstrap")?;
        s.quic = addresses(&v, "advertise_quic")?;
        s.publish_contacts = o["publish_contacts"]
            .as_bool()
            .ok_or_else(|| Error::new("invalid"))?;
        let mut helpers = Vec::new();
        for (kind, name) in [("rendezvous", "rendezvous"), ("relay", "relays")] {
            let list = array(o, name)?;
            require(list.len() <= 4, "quota_exceeded")?;
            let mut previous = None;
            for h in list {
                let h = object(h)?;
                fields(h, "address public_key token_file")?;
                let pair = (text(h, "address")?, text(h, "public_key")?);
                bootstrap::endpoint(pair.0)?;
                check(key(pair.1) && previous.is_none_or(|p| p < pair))?;
                previous = Some(pair);
                let credential = if text(h, "token_file")? == "-" {
                    None
                } else {
                    let raw = protected(Path::new(text(h, "token_file")?), 1024)?;
                    check(
                        std::str::from_utf8(&raw).is_ok()
                            && !raw.iter().any(|b| matches!(b, 0 | 10 | 13)),
                    )?;
                    Some(raw)
                };
                let hint = json!({"address":pair.0,"public_key":pair.1});
                if kind == "rendezvous" {
                    s.rendezvous.push(hint)
                } else {
                    s.relays.push(hint)
                };
                helpers.push((
                    kind.to_owned(),
                    pair.0.to_owned(),
                    pair.1.to_owned(),
                    credential,
                ));
            }
        }
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        tx.execute(
            "UPDATE dec_helpers SET record=?1",
            [json!({"format":1,"enabled":false}).to_string()],
        )
        .map_err(db)?;
        for (kind, address, key, credential) in helpers {
            tx.execute("INSERT INTO dec_helpers(kind,address,public_key,record,credential) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(kind,address,public_key) DO UPDATE SET record=excluded.record,credential=excluded.credential",rusqlite::params![kind,address,key,json!({"format":1,"enabled":true}).to_string(),credential]).map_err(db)?;
        }
        tx.commit().map_err(db)?;
    }
    if s.bootstrap.is_empty() {
        let mut ips = if bound.ip().is_unspecified() {
            crate::network::interface_addresses()
        } else {
            vec![bound.ip()]
        };
        ips.retain(|ip| {
            !ip.is_unspecified() && !ip.is_multicast() && (bound.is_ipv6() || ip.is_ipv4())
        });
        s.bootstrap = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, bound.port()).to_string())
            .collect();
        s.bootstrap.sort();
        s.bootstrap.dedup();
        require(s.bootstrap.len() <= 8, "quota_exceeded")?;
    }
    if s.quic.is_empty()
        && let Some(bound) = *store
            .peer_bound
            .read()
            .map_err(|_| Error::new("internal"))?
    {
        let ips = if bound.ip().is_unspecified() {
            crate::network::interface_addresses()
        } else {
            vec![bound.ip()]
        };
        s.quic = ips
            .into_iter()
            .filter(|ip| {
                !ip.is_unspecified() && !ip.is_multicast() && (bound.is_ipv6() || ip.is_ipv4())
            })
            .map(|ip| SocketAddr::new(ip, bound.port()).to_string())
            .collect();
        s.quic.sort();
        s.quic.dedup();
        require(s.quic.len() <= 8, "quota_exceeded")?;
    }
    require(
        s.bootstrap.len() + s.quic.len() + s.relays.len() <= 16,
        "quota_exceeded",
    )?;
    for a in s.bootstrap.iter().chain(&s.quic) {
        bootstrap::endpoint(a)?;
    }
    *store
        .bootstrap_settings
        .write()
        .map_err(|_| Error::new("internal"))? = s;
    Ok(())
}
pub(crate) fn own_contact(
    c: &rusqlite::Connection,
    store: &Store,
    now: &str,
    network: &str,
    context: &str,
) -> Result<Contact> {
    let settings = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .clone();
    let previous:Option<(rusqlite::types::Value,String)>=c.query_row("SELECT sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 AND host_key=?3",rusqlite::params![network,context,store.identity().public_key],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
    if let Some((number, raw)) = &previous {
        let sequence = super::storage::decode_u64(number, true)?;
        let v = parse(raw.as_bytes(), 32 << 10)?;
        let o = object(&v)?;
        fields(o, "format message_hashes conflicted contacts_base64")?;
        version(o)?;
        let hashes = array(o, "message_hashes")?;
        check(
            matches!(hashes.len(), 1 | 2)
                && hashes.iter().all(|v| v.as_str().is_some_and(digest))
                && hashes.windows(2).all(|w| w[0].as_str() < w[1].as_str()),
        )?;
        check(o["conflicted"].as_bool() == Some(hashes.len() == 2))?;
        let bodies = array(o, "contacts_base64")?;
        check(bodies.len() <= 2)?;
        let mut previous_body = None;
        for body in bodies {
            let body = b64(
                body.as_str().ok_or_else(|| Error::new("state_conflict"))?,
                8 << 10,
            )?;
            let contact = Contact::read(&body)?;
            let body_hash = hash(&body);
            check(
                contact.context_id == context
                    && contact.host_public_key == store.identity().public_key
                    && contact.sequence == sequence
                    && previous_body.as_ref().is_none_or(|h| h < &body_hash),
            )?;
            require(now >= contact.issued_at.as_str(), "clock_rollback")?;
            check(hashes.iter().any(|h| {
                h.as_str() == Some(contact_message_hash(&contact).ok().as_deref().unwrap_or(""))
            }))?;
            previous_body = Some(body_hash);
        }
    }
    let seq = previous
        .as_ref()
        .map(|(v, _)| super::storage::decode_u64(v, true))
        .transpose()?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let contact = Contact::create(
        &store.signing_key,
        context,
        seq,
        now,
        &json!({"bootstrap_addresses":settings.bootstrap,"quic_addresses":settings.quic,"relays":settings.relays}),
    )?;
    let o = object(&parse(&contact.body, 8 << 10)?)?.clone();
    let msg = lines(&[
        "peerspan-decentralized-contact-v1",
        context,
        &contact.host_public_key,
        &seq.to_string(),
        &contact.issued_at,
        &contact.expires_at,
        &hash(&b64(text(&o, "payload_base64")?, 8 << 10)?),
    ]);
    c.execute("INSERT INTO dec_contacts(network_id,context_id,host_key,sequence,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(network_id,context_id,host_key) DO UPDATE SET sequence=excluded.sequence,record=excluded.record",rusqlite::params![network,context,contact.host_public_key,super::storage::encode_u64(seq,true)?,json!({"format":1,"message_hashes":[hash(&msg)],"conflicted":false,"contacts_base64":[encode(&contact.body)]}).to_string()]).map_err(db)?;
    Ok(contact)
}
fn contact_message_hash(contact: &Contact) -> Result<String> {
    let value = parse(&contact.body, 8 << 10)?;
    let o = object(&value)?;
    Ok(hash(&lines(&[
        "peerspan-decentralized-contact-v1",
        &contact.context_id,
        &contact.host_public_key,
        &contact.sequence.to_string(),
        &contact.issued_at,
        &contact.expires_at,
        &hash(&b64(text(o, "payload_base64")?, 8 << 10)?),
    ])))
}

pub struct Listener {
    socket: TcpListener,
    store: Arc<Store>,
    mailboxes: Arc<ParticipantMailbox>,
    acceptor: tokio_rustls::TlsAcceptor,
}
impl Listener {
    pub async fn bind(
        store: Arc<Store>,
        address: SocketAddr,
        config: Option<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        let socket = TcpListener::bind(address).await?;
        let actual = socket.local_addr()?;
        let setup = store.clone();
        let (mailboxes, tls) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            configure(&setup, config.as_deref(), actual)
                .map_err(|e| anyhow::anyhow!("{}", e.code))?;
            let m = ParticipantMailbox::open_with_completion(
                setup.state_directory(),
                Some(super::completion::handler(setup.clone())),
            )?;
            Ok((m, crate::peer::bootstrap_server_config(setup)?))
        })
        .await??;
        *store
            .bootstrap_mailboxes
            .write()
            .map_err(|_| anyhow::anyhow!("bootstrap resources lock"))? = Arc::downgrade(&mailboxes);
        Ok(Self {
            socket,
            store,
            mailboxes,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
        })
    }
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let tasks_limit = Arc::new(Semaphore::new(256));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=shutdown.changed()=>break,
                Some(_)=tasks.join_next()=>{},
                accepted=self.socket.accept()=>{
                let (stream,remote)=accepted?;let source=match remote.ip(){IpAddr::V6(v)=>v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or_else(||{let mut segments=v.segments();segments[4..].fill(0);IpAddr::V6(std::net::Ipv6Addr::from(segments))}),v=>v};
                    let Some(pending)=self.store.dec_bootstrap_admission.acquire(vec![super::bootstrap_admission::source(source)]) else {continue};
                    let Ok(task_permit)=tasks_limit.clone().try_acquire_owned()else{continue};
                    let Some(transport_buffers)=self.mailboxes.transport_buffers()else{continue};
                    let acceptor=self.acceptor.clone();let mailboxes=self.mailboxes.clone();let store=self.store.clone();
                    tasks.spawn(async move{let _task=task_permit;let _pending=pending;let _transport_buffers=transport_buffers;let accepted=timeout(Duration::from_secs(5),acceptor.accept(stream)).await;if let Ok(Ok(tls))=accepted{if tls.get_ref().1.alpn_protocol()==Some(super::peer::REPAIR_ALPN){let _=super::peer::serve_repair(store,tls).await;}else{let _=mailboxes.serve_connection(tls).await;}}});
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(self.store);
        Ok(())
    }
}

struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort()
    }
}
fn receive_budget() -> &'static Arc<Semaphore> {
    static B: OnceLock<Arc<Semaphore>> = OnceLock::new();
    B.get_or_init(|| Arc::new(Semaphore::new(64 << 20)))
}
pub(crate) struct Response {
    pub status: u16,
    pub body: ResponseBody,
    retry_after: Option<u64>,
}
pub(crate) struct ResponseBody {
    bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}
impl std::ops::Deref for ResponseBody {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
/// The task that drives HTTP is aborted on every cancellation/error path.
pub(crate) async fn exchange(
    store: Arc<Store>,
    endpoint: &Value,
    method: Method,
    path: String,
    cap: &str,
    body: Vec<u8>,
) -> Result<Response> {
    exchange_inner(store, endpoint, method, path, Some(cap), body.into()).await
}
pub(crate) async fn complete(store: Arc<Store>, endpoint: &Value, body: Bytes) -> Result<Response> {
    exchange_inner(
        store,
        endpoint,
        Method::POST,
        "/bootstrap/v1/activations".into(),
        None,
        body,
    )
    .await
}
async fn exchange_inner(
    store: Arc<Store>,
    endpoint: &Value,
    method: Method,
    path: String,
    cap: Option<&str>,
    body: Bytes,
) -> Result<Response> {
    let max = if cap.is_none() {
        20 << 20
    } else if method == Method::GET {
        48 << 20
    } else {
        1 << 20
    };
    let e = object(endpoint)?;
    let address = text(e, "address")?.to_owned();
    let expected = text(e, "public_key")?.to_owned();
    bootstrap::endpoint(&address)?;
    check(key(&expected))?;
    if let Some(cap) = cap {
        check(digest(cap) && path.starts_with("/bootstrap/v1/mailboxes"))?;
        require(body.len() <= bootstrap::MAX_FRAME_POST, "quota_exceeded")?;
    } else {
        check(text(e, "kind")? == "participant" && path == "/bootstrap/v1/activations")?;
        require(body.len() <= 20 << 20, "quota_exceeded")?;
    }
    let lookup = store.clone();
    let address2 = address.clone();
    let key2 = expected.clone();
    let resource = cap.is_some();
    let (config, credential) = tokio::task::spawn_blocking(move || -> Result<_> {
        let credential = if resource {
            let c = lookup.connection().map_err(|_| Error::new("internal"))?;
            c.query_row("SELECT credential FROM dec_helpers WHERE kind='rendezvous' AND address=?1 AND public_key=?2 AND json_extract(record,'$.enabled')=1",rusqlite::params![address2,key2],|r|r.get::<_,Option<Vec<u8>>>(0)).optional().map_err(db)?.flatten()
        } else {
            None
        };
        let config = crate::peer::pinned_client_config(lookup, b64(&key2, 32)?, bootstrap::ALPN).map_err(wire)?;
        Ok((config, credential))
    }).await.map_err(wire)??;
    let tcp = timeout(Duration::from_secs(5), TcpStream::connect(&address))
        .await
        .map_err(wire)?
        .map_err(wire)?;
    let server = rustls::pki_types::ServerName::try_from("peerspan-bootstrap").map_err(wire)?;
    let tls = timeout(
        Duration::from_secs(5),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server, tcp),
    )
    .await
    .map_err(wire)?
    .map_err(wire)?;
    check(tls.get_ref().1.alpn_protocol() == Some(bootstrap::ALPN))?;
    exchange_stream(tls, address, method, path, cap, body, credential, max).await
}
pub(crate) async fn completion_exchange<S>(
    stream: S,
    method: Method,
    path: String,
    body: Bytes,
) -> Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    check(
        (method == Method::POST && path == "/bootstrap/v1/activations")
            || (method == Method::GET
                && path
                    .strip_prefix("/bootstrap/v1/operations/")
                    .is_some_and(|id| ident(id, "link_"))
                && body.is_empty()),
    )?;
    require(body.len() <= 20 << 20, "quota_exceeded")?;
    exchange_stream(
        stream,
        "peerspan-bootstrap".into(),
        method,
        path,
        None,
        body,
        None,
        20 << 20,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn exchange_stream<S>(
    stream: S,
    address: String,
    method: Method,
    path: String,
    cap: Option<&str>,
    body: Bytes,
    credential: Option<Vec<u8>>,
    max: u32,
) -> Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_headers(64).max_buf_size(16 << 10);
    let (mut sender, connection) = builder
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(wire)?;
    let _driver = ConnectionTask(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", address)
        .header("Connection", "close");
    if let Some(cap) = cap {
        request = request.header("Authorization", format!("Bearer {cap}"));
    }
    if !body.is_empty() {
        request = request.header("Content-Type", "application/json");
    }
    if let Some(token) = credential {
        check(
            token.len() <= 1024
                && std::str::from_utf8(&token).is_ok()
                && !token.iter().any(|b| matches!(b, 0 | 10 | 13)),
        )?;
        request = request.header("X-Peerspan-Resource-Token", encode(&token));
    }
    let request = request.body(Full::new(body)).map_err(wire)?;
    let response = timeout(Duration::from_secs(10), sender.send_request(request))
        .await
        .map_err(wire)?
        .map_err(wire)?;
    let status = response.status().as_u16();
    let retry_after = if status == 429 {
        let mut values = response
            .headers()
            .get_all(hyper::header::RETRY_AFTER)
            .iter();
        let text = values
            .next()
            .ok_or_else(|| Error::new("recovery_required"))?
            .to_str()
            .map_err(wire)?;
        require(
            values.next().is_none() && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
            "recovery_required",
        )?;
        Some(text.parse::<u64>().map_err(wire)?)
    } else {
        None
    };
    let budget = receive_budget()
        .clone()
        .try_acquire_many_owned(max)
        .map_err(|_| Error::new("quota_exceeded"))?;
    let body = timeout(Duration::from_secs(10), async {
        // One bounded allocation avoids collecting then copying a maximum-size
        // response while both copies remain in the receive queue.
        let mut bytes = Vec::with_capacity(max as usize);
        let mut incoming = response.into_body();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(wire)?;
            if let Some(data) = frame.data_ref() {
                require(data.len() <= max as usize - bytes.len(), "quota_exceeded")?;
                bytes.extend_from_slice(data);
            }
        }
        Ok::<_, Error>(bytes)
    })
    .await
    .map_err(wire)??;
    Ok(Response {
        status,
        retry_after,
        body: ResponseBody {
            bytes: body,
            _budget: budget,
        },
    })
}
pub(crate) fn creation_body(first: &Frame, cap: &str) -> Result<Vec<u8>> {
    let mut object = BTreeMap::<&str, Box<RawValue>>::new();
    let data = json!({"format":1,"request_id":first.request_id,"locator":first.locator,"read_cap_hash":hash(cap.as_bytes()),"created_at":first.created_at,"expires_at":first.expires_at});
    for (key, value) in data.as_object().ok_or_else(|| Error::new("internal"))? {
        object.insert(key, RawValue::from_string(value.to_string()).map_err(wire)?);
    }
    object.insert(
        "frame",
        RawValue::from_string(String::from_utf8(first.body.clone()).map_err(wire)?)
            .map_err(wire)?,
    );
    serde_json::to_vec(&object).map_err(wire)
}
pub(crate) fn append_body(frame: &Frame) -> Result<Vec<u8>> {
    let raw: Box<RawValue> = serde_json::from_slice(&frame.body).map_err(wire)?;
    serde_json::to_vec(&BTreeMap::from([("frame", raw)])).map_err(wire)
}
pub(crate) fn success(response: Response) -> Result<ResponseBody> {
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    let v = parse(&response.body, 1 << 20).ok();
    let code = v
        .as_ref()
        .and_then(|v| v.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("recovery_required");
    let mut error = Error::new(match code {
        "rate_limited" => "rate_limited",
        "quota_exceeded" => "quota_exceeded",
        "forbidden" => "forbidden",
        "invalid" => "invalid",
        "not_found" => "not_found",
        "expired" => "expired",
        "operation_conflict" => "operation_conflict",
        "state_conflict" => "state_conflict",
        _ => "recovery_required",
    });
    error.retry_after = response.retry_after;
    error.stage = Some("transport");
    Err(error)
}
