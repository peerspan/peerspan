//! A debug-only timing log for latency work. With `PEERSPAN_TIMING=1` in a
//! debug build, each CLI request to the daemon and each whole command, each
//! request the daemon serves (local and peer) and sends to a peer, and the
//! daemon's costly steps (snapshot loads, projection builds, catalog reads,
//! waits for the store lock) print one `timing #N KIND WHAT MS` line to
//! standard error, where `#N` numbers the served request a line belongs to
//! (`#0`: none, as for background work). Release builds never print it.
use std::time::Instant;

/// Whether the timing log is on: debug builds with `PEERSPAN_TIMING` set.
pub fn enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| std::env::var_os("PEERSPAN_TIMING").is_some_and(|v| !v.is_empty()))
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

tokio::task_local! {
    static REQUEST: u64;
}
thread_local! {
    static BLOCKING: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
/// The served request this task or blocking closure works for, if any.
pub fn current() -> Option<u64> {
    REQUEST
        .try_with(|r| *r)
        .ok()
        .or_else(|| BLOCKING.with(|b| b.get()))
}
/// Marks this (blocking) thread as working for `request` until dropped.
pub struct Within(Option<u64>);
/// Attributes this thread's timing lines to `request` until the guard drops.
pub fn within(request: Option<u64>) -> Within {
    Within(BLOCKING.with(|b| b.replace(request)))
}
impl Drop for Within {
    fn drop(&mut self) {
        BLOCKING.with(|b| b.set(self.0));
    }
}

/// Prints one timing line for something that started at `began`, with the
/// number of the served request it belongs to (`#0` for background work).
pub fn log(kind: &str, what: &str, began: Instant) {
    if enabled() {
        eprintln!(
            "timing #{} {kind} {what} {:.1}ms",
            current().unwrap_or(0),
            began.elapsed().as_secs_f64() * 1000.0
        );
    }
}

/// Middleware: one line per request a router serves.
pub async fn layer(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !enabled() {
        return next.run(request).await;
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let what = format!("{} {}", request.method(), request.uri().path());
    let began = Instant::now();
    REQUEST
        .scope(id, async move {
            let response = next.run(request).await;
            log(
                "serve",
                &format!("{what} {}", response.status().as_u16()),
                began,
            );
            response
        })
        .await
}
