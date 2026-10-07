//! Test-only network workload, shared by the two Rust helpers.
use super::driver::Duplex;

pub async fn malformed<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    mut send: S,
    recv: R,
    head: &str,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    send.write_all(head.as_bytes()).await?;
    send.shutdown().await?;
    let mut data = Vec::new();
    recv.take(65537).read_to_end(&mut data).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    ensure!(
        response.parse(&data)?.is_complete(),
        "incomplete malformed-request response"
    );
    ensure!(response.code == Some(200), "HTTP {:?}", response.code);
    Ok(())
}

#[allow(dead_code)] // Capsule exercises its production stream client.
pub async fn exchange<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    mut send: S,
    recv: R,
    payload: &[u8],
    path: &str,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ensure!(
        path.starts_with('/') && !path.contains(['\r', '\n']),
        "invalid path"
    );
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: capsule-peer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    send.write_all(head.as_bytes()).await?;
    send.write_all(payload).await?;
    send.shutdown().await?;
    let mut data = Vec::new();
    recv.take(131073).read_to_end(&mut data).await?;
    ensure!(data.len() <= 131072, "oversize response");
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(start) = response.parse(&data)? else {
        anyhow::bail!("incomplete response")
    };
    ensure!(response.code == Some(200), "HTTP {:?}", response.code);
    ensure!(&data[start..] == payload, "echo mismatch");
    Ok(())
}
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn echo<S, R, F>(send: S, recv: R, known: F) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    F: Fn() -> bool + Send + Sync + 'static,
{
    let known = Arc::new(known);
    let service = service_fn(move |request: Request<Incoming>| {
        let known = known.clone();
        async move {
            let (status, bytes) = if !known() {
                (403, Bytes::new())
            } else if request.uri().path() != "/bench/echo" {
                (404, Bytes::new())
            } else if request.method() != "POST" {
                (400, Bytes::new())
            } else {
                let bytes = request.into_body().collect().await?.to_bytes();
                if bytes.len() > 65536 {
                    (413, Bytes::new())
                } else {
                    (200, bytes)
                }
            };
            Ok::<_, anyhow::Error>(
                Response::builder()
                    .status(status)
                    .header("Connection", "close")
                    .body(Full::new(bytes))?,
            )
        }
    });
    tokio::time::timeout(
        Duration::from_secs(8),
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .half_close(true)
            .serve_connection(TokioIo::new(Duplex(send, recv)), service),
    )
    .await??;
    Ok(())
}

pub async fn measure<F, Fut>(command: &Value, exchange: F) -> Result<Value>
where
    F: Fn(Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    let count = command["count"].as_u64().unwrap_or(1) as usize;
    let concurrency = command["concurrency"].as_u64().unwrap_or(1) as usize;
    let size = command["size"].as_u64().unwrap_or(16) as usize;
    ensure!(
        (1..=10000).contains(&count)
            && (1..=64).contains(&concurrency)
            && (16..=65536).contains(&size),
        "invalid workload"
    );
    let token = command["token"]
        .as_str()
        .unwrap_or("fixture")
        .as_bytes()
        .to_vec();
    let start = Instant::now();
    let mut workers = tokio::task::JoinSet::new();
    for worker in 0..concurrency {
        let exchange = exchange.clone();
        let token = token.clone();
        workers.spawn(async move {
            let mut samples = Vec::new();
            for index in (worker..count).step_by(concurrency) {
                let mut payload = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
                // Fresh checked application data on every exchange, including after outages.
                for (dst, src) in payload.iter_mut().zip(&token) { *dst = *src; }
                payload[size - 8..].copy_from_slice(&(index as u64).to_be_bytes());
                let before = Instant::now();
                let result = tokio::time::timeout(Duration::from_secs(8), exchange(payload)).await;
                let error = match result { Ok(Ok(())) => None, Ok(Err(e)) => Some(format!("{e:#}")), Err(e) => Some(e.to_string()) };
                samples.push(json!({"index": index, "seconds": before.elapsed().as_secs_f64(), "verified": error.is_none(), "error": error}));
            }
            samples
        });
    }
    let mut attempts = Vec::new();
    while let Some(samples) = workers.join_next().await {
        attempts.extend(samples?);
    }
    attempts.sort_by_key(|v| v["index"].as_u64());
    let succeeded = attempts.iter().filter(|v| v["verified"] == true).count();
    Ok(
        json!({"attempts": attempts, "succeeded": succeeded, "failed": count - succeeded,
        "count": count, "concurrency": concurrency, "content_bytes": size, "wall_seconds": start.elapsed().as_secs_f64()}),
    )
}
