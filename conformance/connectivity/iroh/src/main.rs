#[path = "../../driver.rs"]
mod driver;
mod network;

use anyhow::{Result, ensure};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, PortmapperConfig, QuicTransportConfig, presets},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const ALPN: &[u8] = b"peerspan-bench/1";

#[derive(Clone)]
struct Iroh {
    client: Endpoint,
    address: EndpointAddr,
    connection: Arc<Mutex<Option<Connection>>>,
}
impl driver::Backend for Iroh {
    async fn connect(&self) -> Result<()> {
        let connection = self.client.connect(self.address.clone(), ALPN).await?;
        ensure!(
            connection.remote_id() == self.address.id,
            "unexpected peer identity"
        );
        *self.connection.lock().unwrap() = Some(connection);
        Ok(())
    }
    async fn disconnect(&self) -> Result<()> {
        if let Some(connection) = self.connection.lock().unwrap().take() {
            connection.close(0u32.into(), b"benchmark cold connection");
        }
        Ok(())
    }
    async fn exchange(&self, payload: Arc<Vec<u8>>) -> Result<()> {
        let connection = self.connection.lock().unwrap().clone().unwrap();
        let (send, recv) = connection.open_bi().await?;
        driver::http_exchange(send, recv, &payload).await
    }
}

async fn endpoint() -> Result<Endpoint> {
    // Explicit addresses, no public relays or address lookup. Default crate
    // features remain enabled; TLS tickets are disabled to match Peerspan.
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .alpns(vec![ALPN.to_vec()])
        .portmapper_config(PortmapperConfig::Disabled)
        .max_tls_tickets(0);
    if std::env::var("PEERSPAN_IROH_GSO_OFF").is_ok() {
        builder = builder.transport_config(
            QuicTransportConfig::builder()
                .enable_segmentation_offload(false)
                .build(),
        );
    }
    Ok(builder.bind().await?)
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    if let Ok(filter) = std::env::var("PEERSPAN_NET_TRACE") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
    match std::env::var("PEERSPAN_NET_MODE").as_deref() {
        Ok("node") => return network::node().await,
        Ok("relay") => return network::relay().await,
        _ => {}
    }
    let client = endpoint().await?;
    let server = endpoint().await?;
    let address = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    let accept_endpoint = server.clone();
    let client_id = client.id();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            tokio::spawn(async move {
                let connection = incoming.await?;
                ensure!(connection.remote_id() == client_id, "unknown client");
                while let Ok((send, recv)) = connection.accept_bi().await {
                    tokio::spawn(driver::serve_http(send, recv));
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(240),
        driver::run(
            Iroh {
                client: client.clone(),
                address,
                connection: Arc::new(Mutex::new(None)),
            },
            "iroh-rust-1.3.0",
        ),
    )
    .await?;
    client.close().await;
    server.close().await;
    accept.abort();
    result
}
