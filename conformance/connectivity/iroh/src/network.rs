//! Test-only endpoints and self-hosted TLS relay, controlled over a private socket.
use crate::driver;
#[path = "../../net_driver.rs"]
mod net_driver;
use anyhow::Result;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, Connection, EndpointHooks, PortmapperConfig, QuicTransportConfig,
        Side, presets,
    },
};
use iroh_relay::{
    RelayConfig, RelayQuicConfig,
    server::{Access, AccessControl, ClientRequest},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
const ALPN: &[u8] = b"peerspan-bench/1";

#[derive(Clone, Debug)]
struct Admission(Arc<RwLock<HashSet<EndpointId>>>);
impl EndpointHooks for Admission {
    async fn after_handshake(&self, connection: &Connection) -> AfterHandshakeOutcome {
        if connection.side() == Side::Server
            && !self.0.read().unwrap().contains(&connection.remote_id())
        {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"unknown peer".to_vec(),
            }
        } else {
            AfterHandshakeOutcome::Accept
        }
    }
}

#[derive(Clone)]
struct Node {
    endpoint: Endpoint,
    peers: Arc<RwLock<HashMap<String, EndpointAddr>>>,
    admission: Admission,
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    relay: Option<iroh::RelayUrl>,
}

// A cancelled bounded request must not keep returning to a dead cached
// connection. This belongs to our test adapter, not to the iroh library.
struct CacheGuard {
    cache: Arc<Mutex<HashMap<String, Connection>>>,
    id: String,
    connection: Connection,
    verified: bool,
}
impl Drop for CacheGuard {
    fn drop(&mut self) {
        if !self.verified {
            let mut cache = self.cache.lock().unwrap();
            if cache
                .get(&self.id)
                .is_some_and(|c| c.stable_id() == self.connection.stable_id())
            {
                cache.remove(&self.id);
            }
            self.connection
                .close(0u32.into(), b"failed or cancelled fixture request");
        }
    }
}
impl Node {
    fn address(&self, value: &Value) -> Result<EndpointAddr> {
        let id: EndpointId = value["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing peer id"))?
            .parse()?;
        let mut address = EndpointAddr::new(id);
        if let Some(relay) = &self.relay {
            address = address.with_relay_url(relay.clone());
        }
        if let Some(ip) = value["address"].as_str().filter(|s| !s.is_empty()) {
            address = address.with_ip_addr(ip.parse()?);
        }
        Ok(address)
    }
    async fn exchange(
        &self,
        address: EndpointAddr,
        payload: Vec<u8>,
        path: String,
        raw_head: Option<String>,
    ) -> Result<()> {
        let id = address.id.to_string();
        let cached = self
            .connections
            .lock()
            .unwrap()
            .get(&id)
            .filter(|c| c.close_reason().is_none())
            .cloned();
        let connection = match cached.clone() {
            Some(c) => c,
            None => {
                let c = self.endpoint.connect(address.clone(), ALPN).await?;
                self.connections
                    .lock()
                    .unwrap()
                    .insert(id.clone(), c.clone());
                c
            }
        };
        let mut guard = CacheGuard {
            cache: self.connections.clone(),
            id: id.clone(),
            connection: connection.clone(),
            verified: false,
        };
        let (send, recv) = connection.open_bi().await?;
        if let Some(head) = raw_head {
            let result = net_driver::malformed(send, recv, &head).await;
            guard.verified = result.is_ok();
            return result;
        }
        let result = net_driver::exchange(send, recv, &payload, &path).await;
        if result.is_err() {
            self.connections.lock().unwrap().remove(&id);
            if cached.is_some() && connection.close_reason().is_some() {
                // A single retry on a stale closed cached connection, as in Peerspan.
                let c = self.endpoint.connect(address, ALPN).await?;
                let (send, recv) = c.open_bi().await?;
                self.connections.lock().unwrap().insert(id, c.clone());
                guard.connection = c;
                let retried = net_driver::exchange(send, recv, &payload, &path).await;
                guard.verified = retried.is_ok();
                return retried;
            }
        }
        guard.verified = result.is_ok();
        result
    }
    async fn command(&self, cmd: Value) -> Result<Value> {
        let id = cmd["peer_id"].as_str().unwrap_or("").to_owned();
        match cmd["op"].as_str().unwrap_or("") {
            "info" => Ok(
                json!({"id":self.endpoint.id().to_string(),"public_key":self.endpoint.id().to_string(),"addresses":format!("{:?}",self.endpoint.addr())}),
            ),
            "pin" => {
                let address = self.address(&cmd["target"])?;
                self.admission.0.write().unwrap().insert(address.id);
                let previous = self
                    .peers
                    .write()
                    .unwrap()
                    .insert(address.id.to_string(), address.clone());
                if previous.is_some_and(|old| old != address)
                    && let Some(c) = self
                        .connections
                        .lock()
                        .unwrap()
                        .remove(&address.id.to_string())
                {
                    c.close(0u32.into(), b"configured peer address changed");
                }
                Ok(json!({"ok":true}))
            }
            "forget" => {
                self.admission
                    .0
                    .write()
                    .unwrap()
                    .remove(&id.parse::<EndpointId>()?);
                self.peers.write().unwrap().remove(&id);
                Ok(json!({"ok":true}))
            }
            "drop" => {
                if let Some(c) = self.connections.lock().unwrap().remove(&id) {
                    c.close(0u32.into(), b"fixture drop");
                }
                Ok(json!({"ok":true}))
            }
            "path" => {
                let connections = self.connections.lock().unwrap();
                if let Some(c) = connections.get(&id) {
                    let paths = c.paths();
                    let details=paths.iter().map(|p|json!({"selected":p.is_selected(),"kind":if p.is_ip(){"direct"}else{"relay"},
                        "endpoint":format!("{:?}",p.remote_addr()),"rtt_ms":p.rtt().as_secs_f64()*1000.0,
                        "tx_bytes":p.stats().udp_tx.bytes,"rx_bytes":p.stats().udp_rx.bytes})).collect::<Vec<_>>();
                    let selected = details.iter().find(|p| p["selected"] == true);
                    Ok(
                        json!({"path":selected.map(|p|p["kind"].clone()).unwrap_or(json!("none")),"paths":details,"closed":c.close_reason().is_some()}),
                    )
                } else {
                    Ok(json!({"path":"none"}))
                }
            }
            "run" => {
                let address = if cmd["target"].is_object() {
                    self.address(&cmd["target"])?
                } else {
                    self.peers
                        .read()
                        .unwrap()
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("unknown peer"))?
                };
                let path = cmd["path"].as_str().unwrap_or("/bench/echo").to_owned();
                let raw_head = cmd["raw_head"].as_str().map(str::to_owned);
                let node = self.clone();
                net_driver::measure(&cmd, move |payload| {
                    let node = node.clone();
                    let address = address.clone();
                    let path = path.clone();
                    let raw_head = raw_head.clone();
                    async move { node.exchange(address, payload, path, raw_head).await }
                })
                .await
            }
            _ => anyhow::bail!("unknown operation"),
        }
    }
}

pub async fn node() -> Result<()> {
    let directory = PathBuf::from(std::env::var("PEERSPAN_NET_STATE")?);
    std::fs::create_dir_all(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let key_path = directory.join("key.bin");
    let key = if key_path.exists() {
        SecretKey::from_bytes(
            &std::fs::read(&key_path)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad saved key"))?,
        )
    } else {
        let key = SecretKey::generate();
        std::fs::write(&key_path, key.to_bytes())?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        key
    };
    let admission = Admission(Arc::new(RwLock::new(HashSet::new())));
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(std::env::var("PEERSPAN_NET_BIND").unwrap_or_else(|_| "0.0.0.0:7401".into()))?
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .max_tls_tickets(0)
        .portmapper_config(PortmapperConfig::Disabled)
        .hooks(admission.clone());
    if std::env::var("PEERSPAN_IROH_MATCHED").is_ok() {
        builder = builder.transport_config(
            QuicTransportConfig::builder()
                .enable_segmentation_offload(false)
                .max_concurrent_bidi_streams(16u32.into())
                .max_concurrent_uni_streams(0u32.into())
                .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?))
                .build(),
        );
    }
    let relay = std::env::var("PEERSPAN_NET_RELAY")
        .ok()
        .map(|s| s.parse::<iroh::RelayUrl>())
        .transpose()?;
    if let Some(url) = &relay {
        let certificate = rustls::pki_types::CertificateDer::from(std::fs::read(std::env::var(
            "PEERSPAN_NET_CA",
        )?)?);
        builder = builder
            .ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([certificate]))
            .relay_mode(RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(
                url.clone(),
                Some(RelayQuicConfig::new(7842)),
            )])));
    }
    let endpoint = builder.bind().await?;
    let node = Node {
        endpoint: endpoint.clone(),
        peers: Arc::new(RwLock::new(HashMap::new())),
        admission: admission.clone(),
        connections: Arc::new(Mutex::new(HashMap::new())),
        relay,
    };
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let known = admission.clone();
            tokio::spawn(async move {
                let c = incoming.await?;
                let id = c.remote_id();
                while let Ok((send, recv)) = c.accept_bi().await {
                    let known = known.clone();
                    tokio::spawn(net_driver::echo(send, recv, move || {
                        known.0.read().unwrap().contains(&id)
                    }));
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    let router = axum::Router::new().route(
        "/bench",
        axum::routing::post(move |axum::Json(cmd): axum::Json<Value>| {
            let node = node.clone();
            async move {
                axum::Json(match node.command(cmd).await {
                    Ok(v) => v,
                    Err(e) => json!({"succeeded":0,"failed":1,"error":format!("{e:#}")}),
                })
            }
        }),
    );
    let socket = directory.join("admin.sock");
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper_util::service::TowerToHyperService::new(router),
                )
                .await;
        });
    }
}

#[derive(Debug)]
struct RelayAdmission(PathBuf);
impl AccessControl for RelayAdmission {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let peers = std::fs::read(&self.0)
            .ok()
            .and_then(|v| serde_json::from_slice::<Vec<String>>(&v).ok())
            .unwrap_or_default();
        if peers.contains(&request.endpoint_id().to_string()) {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("fixture membership".into()),
            }
        }
    }
}
pub async fn relay() -> Result<()> {
    use iroh_relay::server::{
        CertConfig, QuicConfig, RelayConfig as ServerRelay, Server, ServerConfig, TlsConfig,
    };
    let directory = PathBuf::from(std::env::var("PEERSPAN_NET_STATE")?);
    std::fs::create_dir_all(&directory)?;
    let cert_path = directory.join("relay-cert.der");
    let key_path = directory.join("relay-key.der");
    if !cert_path.exists() {
        let key = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(vec!["203.0.113.1".into()])?.self_signed(&key)?;
        std::fs::write(&cert_path, cert.der())?;
        std::fs::write(&key_path, key.serialize_der())?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let cert = rustls::pki_types::CertificateDer::from(std::fs::read(cert_path)?);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(std::fs::read(key_path)?);
    let crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())?;
    let mut config = ServerConfig::default();
    let mut relay = ServerRelay::new("203.0.113.1:7404".parse::<std::net::SocketAddr>()?);
    relay.tls = Some(TlsConfig::new(
        "203.0.113.1:7400".parse::<std::net::SocketAddr>()?,
        CertConfig::Manual {
            server_config: crypto.clone(),
        },
    ));
    relay.access = Arc::new(RelayAdmission(directory.join("allow.json")));
    config.relay = Some(relay);
    let mut quic = QuicConfig::new("203.0.113.1:7842".parse::<std::net::SocketAddr>()?);
    quic.server_config = Some(crypto);
    config.quic = Some(quic);
    let mut server = Server::spawn(config).await?;
    println!("READY");
    server.join().await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_request_evicts_and_closes_its_cached_connection() -> Result<()> {
        let server = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")?
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")?
            .bind()
            .await?;
        let accept = server.clone();
        let accepted = tokio::spawn(async move { accept.accept().await.unwrap().await.unwrap() });
        let address = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
        let connection = client.connect(address, ALPN).await?;
        let peer_connection = accepted.await?;
        let id = server.id().to_string();
        let cache = Arc::new(Mutex::new(HashMap::from([(
            id.clone(),
            connection.clone(),
        )])));
        let future = async {
            let _guard = CacheGuard {
                cache: cache.clone(),
                id,
                connection: connection.clone(),
                verified: false,
            };
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), future)
                .await
                .is_err()
        );
        assert!(cache.lock().unwrap().is_empty());
        assert!(connection.close_reason().is_some());
        peer_connection.close(0u32.into(), b"test done");
        client.close().await;
        server.close().await;
        Ok(())
    }
}
