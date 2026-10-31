//! Shared workload for Peerspan Rust and iroh. Only explicit benchmark runs use it.
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait Backend: Clone + Send + Sync + 'static {
    fn connect(&self) -> impl Future<Output = Result<()>> + Send;
    fn disconnect(&self) -> impl Future<Output = Result<()>> + Send;
    fn exchange(&self, payload: Arc<Vec<u8>>) -> impl Future<Output = Result<()>> + Send;
}

pub struct Duplex<S, R>(pub S, pub R);
impl<S: Unpin, R: AsyncRead + Unpin> AsyncRead for Duplex<S, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.1).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin, R: Unpin> AsyncWrite for Duplex<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub async fn serve_http<
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
>(
    send: S,
    recv: R,
) -> Result<()> {
    let echo = service_fn(|request: Request<Incoming>| async move {
        ensure!(
            request.method() == "POST" && request.uri().path() == "/bench/echo",
            "unexpected request"
        );
        let data = request.into_body().collect().await?.to_bytes();
        ensure!(data.len() <= 65536, "oversize payload");
        Ok::<_, anyhow::Error>(
            Response::builder()
                .header("Connection", "close")
                .body(Full::<Bytes>::new(data))?,
        )
    });
    tokio::time::timeout(
        Duration::from_secs(8),
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .half_close(true)
            .serve_connection(TokioIo::new(Duplex(send, recv)), echo),
    )
    .await??;
    Ok(())
}

#[allow(dead_code)] // Peerspan uses its production client; iroh uses this one.
pub async fn http_exchange<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    mut send: S,
    recv: R,
    payload: &[u8],
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let header = format!(
        "POST /bench/echo HTTP/1.1\r\nHost: peerspan-peer\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    send.write_all(header.as_bytes()).await?;
    send.write_all(payload).await?;
    send.shutdown().await?;
    let mut response = Vec::new();
    recv.take(65536 + 65536 + 1)
        .read_to_end(&mut response)
        .await?;
    ensure!(response.len() <= 65536 + 65536, "oversize response");
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(start) = parsed.parse(&response)? else {
        anyhow::bail!("incomplete response")
    };
    ensure!(parsed.code == Some(200), "unexpected response status");
    let length = parsed
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| anyhow::anyhow!("missing content length"))?;
    ensure!(
        std::str::from_utf8(length.value)?.trim().parse::<usize>()? == payload.len(),
        "wrong content length"
    );
    ensure!(&response[start..] == payload, "echo payload mismatch");
    Ok(())
}

fn parameter(name: &str, default: usize) -> Result<usize> {
    Ok(std::env::var(name)
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(default))
}

pub async fn run<B: Backend>(backend: B, name: &str) -> Result<()> {
    let count = parameter("PEERSPAN_BENCH_COUNT", 200)?;
    let cold = parameter("PEERSPAN_BENCH_COLD", 20)?;
    let warmup = parameter("PEERSPAN_BENCH_WARMUP", 20)?;
    let concurrency = parameter("PEERSPAN_BENCH_CONCURRENCY", 8)?;
    ensure!(
        count > 0 && cold > 0 && (1..=16).contains(&concurrency),
        "invalid workload parameters"
    );
    let tiny = Arc::new(vec![42; 16]);
    let mut cold_seconds = Vec::new();
    for _ in 0..cold {
        backend.disconnect().await?;
        let start = Instant::now();
        tokio::time::timeout(Duration::from_secs(8), async {
            backend.connect().await?;
            // Prove both ends completed authentication before closing it.
            backend.exchange(tiny.clone()).await
        })
        .await??;
        cold_seconds.push(start.elapsed().as_secs_f64());
    }
    let mut workloads = Vec::new();
    for size in [16, 65536] {
        let payload = Arc::new((0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        for _ in 0..warmup {
            tokio::time::timeout(Duration::from_secs(8), backend.exchange(payload.clone()))
                .await??;
        }
        let mut sequential_seconds = Vec::new();
        for _ in 0..count {
            let start = Instant::now();
            tokio::time::timeout(Duration::from_secs(8), backend.exchange(payload.clone()))
                .await??;
            sequential_seconds.push(start.elapsed().as_secs_f64());
        }
        let start = Instant::now();
        let mut workers = tokio::task::JoinSet::new();
        for worker in 0..concurrency {
            let backend = backend.clone();
            let payload = payload.clone();
            workers.spawn(async move {
                let mut samples = Vec::new();
                for _ in (worker..count).step_by(concurrency) {
                    let start = Instant::now();
                    tokio::time::timeout(Duration::from_secs(8), backend.exchange(payload.clone()))
                        .await??;
                    samples.push(start.elapsed().as_secs_f64());
                }
                Ok::<_, anyhow::Error>(samples)
            });
        }
        let mut concurrent_seconds = Vec::new();
        while let Some(samples) = workers.join_next().await {
            concurrent_seconds.extend(samples??);
        }
        workloads.push(json!({"content_bytes": size, "sequential_seconds": sequential_seconds,
            "concurrent_seconds": concurrent_seconds, "concurrent_wall_seconds": start.elapsed().as_secs_f64()}));
    }
    backend.disconnect().await?;
    let output = std::env::var("PEERSPAN_BENCH_OUTPUT")?;
    std::fs::write(
        output,
        serde_json::to_vec_pretty(
            &json!({"backend": name, "cold_first_echo_seconds": cold_seconds,
        "workloads": workloads, "count": count, "cold": cold, "warmup": warmup, "concurrency": concurrency}),
        )?,
    )?;
    Ok(())
}
