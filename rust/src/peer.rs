//! Authenticated host messaging. The owner-local router is never exposed here.
use crate::{
    api::{blocking, decode},
    model::Error,
    peer_store::*,
    store::Store,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    routing::{get, post},
};
use bytes::Bytes as BodyBytes;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring::default_provider, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::{fmt, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::*;

fn tls_error(message: &str) -> rustls::Error {
    rustls::Error::General(message.into())
}
fn certificate_key(cert: &CertificateDer<'_>, at: UnixTime) -> Result<Vec<u8>, rustls::Error> {
    let (rest, cert) = X509Certificate::from_der(cert.as_ref())
        .map_err(|_| tls_error("invalid peer certificate"))?;
    if !rest.is_empty()
        || cert.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112"
        || cert.public_key().subject_public_key.data.len() != 32
        || cert.public_key().subject_public_key.unused_bits != 0
    {
        return Err(tls_error("invalid peer certificate"));
    }
    let now =
        ASN1Time::from_timestamp(at.as_secs() as i64).map_err(|_| tls_error("invalid clock"))?;
    if now < cert.validity().not_before || now >= cert.validity().not_after {
        return Err(tls_error("expired or not-yet-valid peer certificate"));
    }
    for extension in cert.extensions() {
        if extension.critical
            && matches!(
                extension.parsed_extension(),
                ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::ParseError { .. }
            )
        {
            return Err(tls_error("unknown critical certificate extension"));
        }
    }
    Ok(cert.public_key().subject_public_key.data.to_vec())
}
struct Pins {
    store: Arc<Store>,
    expected: Option<Vec<u8>>,
}
impl fmt::Debug for Pins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostIdentityPins")
    }
}
impl Pins {
    fn verify(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        at: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(tls_error("one peer certificate required"));
        }
        let key = certificate_key(cert, at)?;
        if let Some(expected) = &self.expected {
            if expected != &key {
                return Err(tls_error("peer identity pin mismatch"));
            }
        } else if self
            .store
            .peer_pins
            .read()
            .map_err(|_| tls_error("peer pins lock poisoned"))?
            .get(&key_id(&key))
            != Some(&key)
        {
            return Err(tls_error("unknown peer"));
        }
        Ok(())
    }
}
impl ServerCertVerifier for Pins {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        at: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify(cert, intermediates, at)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error("TLS 1.2 is disabled"))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for Pins {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        at: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify(cert, intermediates, at)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error("TLS 1.2 is disabled"))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
fn certificate(
    store: &Store,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let der = store.signing_key.to_pkcs8_der()?;
    let key_der = PrivatePkcs8KeyDer::from(der.as_bytes().to_vec());
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)?;
    let mut params = rcgen::CertificateParams::default();
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::minutes(5);
    params.not_after = now + ::time::Duration::days(30);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, store.identity().id);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    Ok((
        vec![params.self_signed(&key)?.der().clone()],
        key_der.into(),
    ))
}
pub fn server_config(store: Arc<Store>) -> anyhow::Result<ServerConfig> {
    let (certs, key) = certificate(&store)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Pins {
            store,
            expected: None,
        }))
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    Ok(config)
}
fn client_config(store: Arc<Store>, peer: &Peer) -> anyhow::Result<ClientConfig> {
    let (certs, key) = certificate(&store)?;
    let expected = peer_key(peer).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pins {
            store,
            expected: Some(expected),
        }))
        .with_client_auth_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}
fn peer_router(store: Arc<Store>, sender: String) -> Router {
    Router::new()
        .route("/peer/v1/messages", post(accept))
        .route("/peer/v1/receipts/{id}", get(receipt))
        .layer(Extension(sender))
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(store)
}
async fn accept(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Receipt>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_message(&sender, request)).await?,
    ))
}
async fn receipt(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<Receipt>, Error> {
    Ok(Json(
        blocking(store, move |s| s.message_receipt(&sender, &id)).await?,
    ))
}
pub async fn serve(
    listener: TcpListener,
    store: Arc<Store>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(store.clone())?));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
         _=shutdown.changed()=>break,
         Some(_)=connections.join_next(),if !connections.is_empty()=>{},
         incoming=listener.accept(),if connections.len()<64=>{
          let(stream,_)=incoming?;let acceptor=acceptor.clone();let store=store.clone();
          connections.spawn(async move {
           let Ok(Ok(tls))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream)).await else{return;};
           let Some(cert)=tls.get_ref().1.peer_certificates().and_then(|c|c.first()) else{return;};
           let Ok(key)=certificate_key(cert,UnixTime::now()) else{return;};let sender=key_id(&key);
           let router=peer_router(store,sender);
           let connection=hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(tls),TowerToHyperService::new(router));
           let _=tokio::time::timeout(Duration::from_secs(15),connection).await;
          });
         }
        }
    }
    // Requests which outlive the bounded drain remain unknown to their senders.
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
// Dropping a timed-out or cancelled call closes its separately polled transport.
struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn call(
    store: Arc<Store>,
    peer: Peer,
    out: &OutboundMessage,
    receipt_only: bool,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let config = client_config(store, &peer)?;
    let stream = TcpStream::connect(&peer.address).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("capsule-peer")?, stream)
        .await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let _connection_task = ConnectionTask(tokio::spawn(async move {
        let _ = connection.await;
    }));
    async {
        let (method, path, body) = if receipt_only {
            (
                Method::GET,
                format!("/peer/v1/receipts/{}", out.request.request_id),
                Vec::new(),
            )
        } else {
            (
                Method::POST,
                "/peer/v1/messages".into(),
                serde_json::to_vec(&out.request)?,
            )
        };
        let request = Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", peer.address))
            .header("Host", &peer.address)
            .header("Content-Type", "application/json")
            .header("Connection", "close")
            .body(Full::new(BodyBytes::from(body)))?;
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        let bytes = http_body_util::Limited::new(response.into_body(), 1 << 20)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("read peer response: {e}"))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
    .await
}
async fn exchange(
    store: Arc<Store>,
    mut out: OutboundMessage,
    receipt_only: bool,
) -> Result<OutboundMessage, Error> {
    if out.state == "accepted" {
        return Ok(out);
    }
    let peer_id = out.peer_host_id.clone();
    let peer = blocking(store.clone(), move |s| s.peer(&peer_id)).await?;
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        call(store.clone(), peer, &out, receipt_only),
    )
    .await;
    out.state = "unknown".into();
    out.error = None;
    let result: anyhow::Result<()> = match response {
        Ok(Ok((200, body))) => match serde_json::from_slice::<Receipt>(&body) {
            Ok(receipt)
                if receipt.sender_host_id == store.identity().id
                    && receipt.receiver_host_id == out.peer_host_id
                    && receipt.request_id == out.request.request_id
                    && receipt.target_agent_id == out.request.target_agent_id
                    && chrono::DateTime::parse_from_rfc3339(&receipt.accepted_at).is_ok() =>
            {
                out.state = "accepted".into();
                out.receipt = Some(receipt);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("invalid peer receipt")),
        },
        Ok(Ok((status, _))) => {
            if !receipt_only && matches!(status, 400 | 403 | 404 | 409) {
                out.state = "rejected".into();
            }
            Err(anyhow::anyhow!("peer returned HTTP {status}"))
        }
        Ok(Err(error)) => Err(error),
        Err(error) => Err(error.into()),
    };
    if let Err(error) = result {
        out.error = Some(format!("{error:#}"));
    }
    blocking(store, move |s| s.finish_outbound(out)).await
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/peers", get(peers).post(add_peer))
        .route("/v1/grants", get(grants).post(create_grant))
        .route("/v1/grants/{id}/revoke", post(revoke))
        .route("/v1/messages", get(messages))
        .route("/v1/outbound", post(send))
        .route("/v1/outbound/{peer}/{id}", get(outbound))
        .route("/v1/outbound/{peer}/{id}/retry", post(retry))
        .route("/v1/outbound/{peer}/{id}/refresh", post(refresh))
}
async fn peers(State(store): State<Arc<Store>>) -> Result<Json<Vec<Peer>>, Error> {
    Ok(Json(blocking(store, Store::peers).await?))
}
async fn add_peer(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Peer>, Error> {
    let request = decode(body)?;
    Ok(Json(blocking(store, move |s| s.add_peer(request)).await?))
}
async fn grants(State(store): State<Arc<Store>>) -> Result<Json<Vec<Grant>>, Error> {
    Ok(Json(blocking(store, Store::grants).await?))
}
async fn create_grant(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(axum::http::StatusCode, Json<Grant>), Error> {
    let request = decode(body)?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(blocking(store, move |s| s.create_grant(request)).await?),
    ))
}
async fn revoke(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Grant>, Error> {
    Ok(Json(blocking(store, move |s| s.revoke_grant(&id)).await?))
}
#[derive(serde::Deserialize)]
struct MessagePage {
    after: Option<i64>,
    limit: Option<i64>,
}
async fn messages(
    State(store): State<Arc<Store>>,
    query: Result<Query<MessagePage>, QueryRejection>,
) -> Result<Json<Vec<ReceivedMessage>>, Error> {
    let Query(page) = query.map_err(|_| Error::Invalid("invalid message page".into()))?;
    Ok(Json(
        blocking(store, move |s| {
            s.messages(page.after.unwrap_or(0), page.limit.unwrap_or(100))
        })
        .await?,
    ))
}
async fn send(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<OutboundMessage>, Error> {
    let request = decode(body)?;
    let out = blocking(store.clone(), move |s| s.prepare_outbound(request)).await?;
    Ok(Json(exchange(store, out, false).await?))
}
async fn outbound(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundMessage>, Error> {
    Ok(Json(
        blocking(store, move |s| s.outbound(&peer, &id)).await?,
    ))
}
async fn retry(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundMessage>, Error> {
    let out = blocking(store.clone(), move |s| s.outbound(&peer, &id)).await?;
    Ok(Json(exchange(store, out, false).await?))
}
async fn refresh(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundMessage>, Error> {
    let out = blocking(store.clone(), move |s| s.outbound(&peer, &id)).await?;
    Ok(Json(exchange(store, out, true).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_validity_and_identity_pins() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&temporary.path().join("host")).unwrap());
        let (certs, _) = certificate(&store).unwrap();
        let key = certificate_key(&certs[0], UnixTime::now()).unwrap();
        assert_eq!(key_id(&key), store.identity().id);
        let later = UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                + Duration::from_secs(31 * 24 * 3600),
        );
        assert!(certificate_key(&certs[0], later).is_err());
        assert!(certificate_key(&certs[0], UnixTime::since_unix_epoch(Duration::ZERO)).is_err());
        assert!(certificate_key(&CertificateDer::from(vec![0]), UnixTime::now()).is_err());
        let correct = Pins {
            store: store.clone(),
            expected: Some(key),
        };
        assert!(correct.verify(&certs[0], &[], UnixTime::now()).is_ok());
        let wrong = Pins {
            store,
            expected: Some(vec![0; 32]),
        };
        assert!(wrong.verify(&certs[0], &[], UnixTime::now()).is_err());
        assert!(correct.verify(&certs[0], &certs, UnixTime::now()).is_err());
    }
}
