//! Runtime tasks (runtime task contract): the local switch, the client of
//! the runtime's local API (`peerspan-runtime serve`), and `/v1/runtime`.
//! The switch lives only on this host, in `runtime.json` in the state
//! directory, never in policy.
use crate::{
    api::{blocking, decode},
    model::Error,
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::get,
};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const SWITCH_FILE: &str = "runtime.json";
/// Long enough for an events request waiting 25 seconds.
const CALL_TIMEOUT: Duration = Duration::from_secs(35);
const RESPONSE_LIMIT: usize = 1 << 20;

/// The stored switch: the runtime's socket while enabled.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Switch {
    pub socket: PathBuf,
}

impl Store {
    /// The runtime's socket, or None while the switch is off.
    pub(crate) fn runtime_switch(&self) -> Result<Option<Switch>, Error> {
        match std::fs::read(self.state_directory().join(SWITCH_FILE)) {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Internal(e.into())),
        }
    }
    /// Turns the switch on with `socket`, or off with None.
    pub fn set_runtime_switch(&self, socket: Option<&Path>) -> Result<(), Error> {
        let path = self.state_directory().join(SWITCH_FILE);
        let Some(socket) = socket else {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(Error::Internal(e.into()))
                }
                _ => Ok(()),
            };
        };
        let raw = serde_json::to_vec(&Switch {
            socket: socket.to_owned(),
        })?;
        let partial = path.with_extension("json.partial");
        {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&partial)
                .map_err(|e| Error::Internal(e.into()))?;
            file.write_all(&raw)
                .and_then(|()| file.sync_all())
                .map_err(|e| Error::Internal(e.into()))?;
        }
        std::fs::rename(&partial, &path).map_err(|e| Error::Internal(e.into()))
    }
}

/// A runtime answer: its status and JSON body.
pub(crate) struct Answer {
    pub status: u16,
    pub body: Value,
}

/// One request to the runtime's local API. An error means no answer: the
/// socket was unreachable, the connection failed, or the call timed out.
pub(crate) async fn call(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> anyhow::Result<Answer> {
    tokio::time::timeout(CALL_TIMEOUT, async {
        let stream = tokio::net::UnixStream::connect(socket).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let encoded = match body {
            Some(body) => serde_json::to_vec(body)?,
            None => Vec::new(),
        };
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(encoded)))?;
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        let bytes = http_body_util::Limited::new(response.into_body(), RESPONSE_LIMIT)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("read runtime response: {e}"))?
            .to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok(Answer { status, body })
    })
    .await
    .map_err(|_| anyhow::anyhow!("the runtime did not answer in time"))?
}

/// The runtime's own report (`GET /v1/runtime`), or why there is none.
pub async fn report(socket: &Path) -> Result<Value, String> {
    let answer = call(socket, Method::GET, "/v1/runtime", None)
        .await
        .map_err(|e| format!("cannot reach the runtime at {}: {e}", socket.display()))?;
    let fields = [
        "version",
        "image",
        "max_cpus",
        "max_memory_mib",
        "max_seconds",
        "max_concurrent_runs",
        "running",
    ];
    match answer.body.as_object() {
        Some(o) if answer.status == 200 && fields.iter().all(|f| o.contains_key(*f)) => {
            Ok(answer.body)
        }
        _ => Err(format!(
            "the runtime at {} answered {} without a runtime report",
            socket.display(),
            answer.status
        )),
    }
}

/// This host's runtime rule in its person's current policy, with the
/// network it is in: the first such network by ID.
fn own_rule(store: &Store) -> Result<Option<Value>, Error> {
    let c = store.connection()?;
    let own = store.identity().id;
    for (network, member) in store.decentralized_own_members(&c)? {
        let Some(person) = member.person_id else {
            continue;
        };
        let Some(key) = store.product_person_key(&c, &network, &person)? else {
            continue;
        };
        let Some(policy) = store.product_policy(&c, &network, &key)? else {
            continue;
        };
        if let Some(rule) = policy.runtime_rules().iter().find(|r| r.host == own) {
            let mut value = serde_json::to_value(rule)?;
            value["network_id"] = network.into();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/runtime", get(show).put(enable).delete(disable))
}

/// `GET /v1/runtime`, with its keys in the contract's order.
#[derive(Serialize)]
struct Show {
    enabled: bool,
    socket: Option<PathBuf>,
    runtime: Value,
    rule: Option<Value>,
}
async fn show(State(store): State<Arc<Store>>) -> Result<Json<Show>, Error> {
    let (switch, rule) = blocking(store, |s| Ok((s.runtime_switch()?, own_rule(s)?))).await?;
    let runtime = match &switch {
        Some(s) => report(&s.socket)
            .await
            .unwrap_or_else(|error| json!({ "error": error })),
        None => Value::Null,
    };
    Ok(Json(Show {
        enabled: switch.is_some(),
        socket: switch.map(|s| s.socket),
        runtime,
        rule,
    }))
}

async fn enable(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: Switch = decode(body)?;
    if !request.socket.is_absolute() {
        return Err(Error::Invalid("socket must be an absolute path".into()));
    }
    let runtime = report(&request.socket).await.map_err(Error::Unavailable)?;
    blocking(store, move |s| {
        s.set_runtime_switch(Some(&request.socket))?;
        let mut c = s.connection()?;
        let tx = c.transaction()?;
        append_event(&tx, "runtime.enabled", &s.identity().id, &now())?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(Json(runtime))
}

async fn disable(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    blocking(store, |s| {
        let was = s.runtime_switch()?.is_some();
        s.set_runtime_switch(None)?;
        if was {
            let mut c = s.connection()?;
            let tx = c.transaction()?;
            append_event(&tx, "runtime.disabled", &s.identity().id, &now())?;
            tx.commit()?;
        }
        Ok(())
    })
    .await?;
    Ok(Json(json!({ "enabled": false })))
}
