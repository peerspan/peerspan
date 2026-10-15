//! Separate-process network fixture. Compiled only into the Rust test binary.
use super::connectivity_bench::driver;
use super::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
#[path = "../../../conformance/connectivity/net_driver.rs"]
mod net_driver;

async fn command(store: Arc<Store>, cmd: Value) -> Result<Value> {
    let id = cmd["peer_id"].as_str().unwrap_or("").to_owned();
    match cmd["op"].as_str().unwrap_or("") {
        "info" => Ok(serde_json::to_value(store.identity())?),
        "path" => {
            let status = path_status(&store, &id).map_err(|e| anyhow::anyhow!("{e}"))?;
            if status.path == "none"
                && let Some(cached) = transport(&store)?.cache.lock().unwrap().get(&id)
            {
                return Ok(
                    json!({"path":"direct", "endpoint":cached.connection.remote_address().to_string()}),
                );
            }
            Ok(serde_json::to_value(status)?)
        }
        "drop" => {
            if let Some(cached) = transport(&store)?.cache.lock().unwrap().remove(&id) {
                cached.connection.close(0u32.into(), b"fixture drop");
            }
            Ok(json!({"ok":true}))
        }
        "forget" => {
            store.peer_pins.write().unwrap().remove(&id);
            store
                .connection()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .execute("DELETE FROM peers WHERE id = ?1", [&id])?;
            Ok(json!({"ok":true}))
        }
        "run" => {
            let peer: Peer = if cmd["target"].is_object() {
                serde_json::from_value(cmd["target"].clone())?
            } else {
                store.dial_target(&id).map_err(|e| anyhow::anyhow!("{e}"))?
            };
            let path = cmd["path"].as_str().unwrap_or("/bench/echo").to_owned();
            let raw_head = cmd["raw_head"].as_str().map(str::to_owned);
            net_driver::measure(&cmd, move |payload| {
                let store = store.clone();
                let peer = peer.clone();
                let path = path.clone();
                let raw_head = raw_head.clone();
                async move {
                    if let Some(head) = raw_head {
                        let target = transport(&store)?;
                        let routes = paths(&store, &target, &peer).await?;
                        let key = peer_key(&peer).map_err(|e| anyhow::anyhow!("{e}"))?;
                        let connection = target
                            .connection(
                                &store,
                                &peer,
                                &key,
                                &routes,
                                tokio::time::Instant::now() + REQUEST_BOUND,
                            )
                            .await?;
                        let (send, recv) = connection.open_bi().await?;
                        return net_driver::malformed(send, recv, &head).await;
                    }
                    let (status, response) = request(store, &peer, "POST", &path, &payload).await?;
                    ensure!(
                        status == 200 && response == payload,
                        "HTTP {status} or echo mismatch"
                    );
                    Ok(())
                }
            })
            .await
        }
        _ => anyhow::bail!("unknown operation"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in separate-process network helper"]
async fn connectivity_network_helper() -> Result<()> {
    let directory = std::env::var("PEERSPAN_NET_STATE")?;
    let store = Arc::new(Store::open(std::path::Path::new(&directory))?);
    store.set_coordination_interval(1);
    listen(
        &store,
        std::env::var("PEERSPAN_NET_BIND")
            .unwrap_or_else(|_| "0.0.0.0:7401".into())
            .parse()?,
    )?;
    let client = transport(&store)?;
    let (_shutdown, rx) = watch::channel(false);
    tokio::spawn(crate::network::coordinate(store.clone(), rx));
    tokio::spawn(keep_relays(store.clone(), client.clone()));
    let server = store.clone();
    let endpoint = client.endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let store = server.clone();
            tokio::spawn(async move {
                let connection = incoming.await?;
                let key = connection
                    .peer_identity()
                    .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
                    .and_then(|certs| certificate_key(certs.first()?, UnixTime::now()).ok())
                    .ok_or_else(|| anyhow::anyhow!("identity"))?;
                ensure!(negotiated(&connection).as_deref() == Some(ALPN), "ALPN");
                while let Ok((send, recv)) = connection.accept_bi().await {
                    let store = store.clone();
                    let key = key.clone();
                    tokio::spawn(net_driver::echo(send, recv, move || {
                        store.knows(&key).unwrap_or(false)
                    }));
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    let handler = store.clone();
    let router = crate::api::router(store.clone()).route(
        "/bench",
        axum::routing::post(move |axum::Json(cmd): axum::Json<Value>| {
            let store = handler.clone();
            async move {
                axum::Json(match command(store, cmd).await {
                    Ok(value) => value,
                    Err(e) => json!({"succeeded":0,"failed":1,"error":format!("{e:#}")}),
                })
            }
        }),
    );
    let socket = store.socket_path();
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
                .await;
        });
    }
}
