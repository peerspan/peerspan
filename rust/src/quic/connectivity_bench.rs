//! Benchmark-only echo over the actual Capsule endpoint, identity and stream code.
use super::*;
use anyhow::{Result, ensure};
#[path = "../../../conformance/connectivity/driver.rs"]
pub(super) mod driver;

#[derive(Clone)]
struct Capsule {
    sender: Arc<Store>,
    transport: Arc<Transport>,
    target: Peer,
    connection: Arc<Mutex<Option<Connection>>>,
}
impl driver::Backend for Capsule {
    async fn connect(&self) -> Result<()> {
        let key = peer_key(&self.target).map_err(|e| anyhow::anyhow!("{e}"))?;
        let connection = self
            .transport
            .connection(
                &self.sender,
                &self.target,
                &key,
                &Paths {
                    direct: Some(self.target.address.parse()?),
                    relay: None,
                },
                tokio::time::Instant::now() + REQUEST_BOUND,
            )
            .await?;
        *self.connection.lock().unwrap() = Some(connection);
        Ok(())
    }
    async fn disconnect(&self) -> Result<()> {
        if let Some(connection) = self.connection.lock().unwrap().take() {
            self.transport.evict(&self.target.id, &connection);
            connection.close(0u32.into(), b"benchmark cold connection");
        }
        Ok(())
    }
    async fn exchange(&self, payload: Arc<Vec<u8>>) -> Result<()> {
        let connection = self.connection.lock().unwrap().clone().unwrap();
        let (status, response) = super::exchange(&connection, "POST", "/bench/echo", &payload)
            .await
            .map_err(|failure| failure.error)?;
        ensure!(
            status == 200 && response == *payload,
            "echo payload mismatch"
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in connectivity benchmark, driven by conformance/connectivity_bench.py"]
async fn connectivity_benchmark() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sender = Arc::new(Store::open(&directory.path().join("sender"))?);
    let receiver = Arc::new(Store::open(&directory.path().join("receiver"))?);
    let sender_address = listen(&sender, "127.0.0.1:0".parse()?)?;
    let receiver_address = listen(&receiver, "127.0.0.1:0".parse()?)?;
    let peer = |store: &Arc<Store>, address: SocketAddr| {
        let id = store.identity();
        Peer {
            id: id.id,
            public_key: id.public_key,
            address: address.to_string(),
        }
    };
    receiver
        .add_peer(peer(&sender, sender_address))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let target = sender
        .add_peer(peer(&receiver, receiver_address))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let server = transport(&receiver)?;
    let server_endpoint = server.endpoint.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            tokio::spawn(async move {
                let connection = incoming.await?;
                ensure!(
                    negotiated(&connection).as_deref() == Some(ALPN),
                    "unexpected ALPN"
                );
                while let Ok((send, recv)) = connection.accept_bi().await {
                    tokio::spawn(driver::serve_http(send, recv));
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    let client = transport(&sender)?;
    let result = tokio::time::timeout(
        Duration::from_secs(240),
        driver::run(
            Capsule {
                sender,
                transport: client.clone(),
                target,
                connection: Arc::new(Mutex::new(None)),
            },
            "capsule-rust",
        ),
    )
    .await?;
    client.endpoint.close(0u32.into(), b"done");
    server.endpoint.close(0u32.into(), b"done");
    accept.abort();
    result
}
