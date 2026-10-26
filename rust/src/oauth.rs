//! OAuth sign-in for remote MCP servers (capabilities slice 3): Peerspan is
//! its own OAuth client. It finds the authorization server through protected
//! resource metadata, registers itself (dynamic client registration, or a
//! client the owner gives), signs in with PKCE through the owner's browser,
//! and keeps the tokens in host state, refreshing them one at a time.
//! Tokens never leave this host.
use crate::{
    api::{blocking, decode},
    capabilities::{capability_record, capability_records},
    http_client,
    mcp::{LoginRequired, TokenFuture, TokenMode, Tokens},
    model::Error,
    sources::{Instance, server_record},
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::post,
};
use base64::Engine;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Database version 22: OAuth client registrations and credentials.
pub(crate) const SCHEMA: &str = "
CREATE TABLE oauth_clients (issuer TEXT NOT NULL, redirect_uri TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(issuer, redirect_uri));
CREATE TABLE oauth_credentials (agent_id TEXT NOT NULL, server TEXT NOT NULL, capability TEXT NOT NULL DEFAULT '', record TEXT NOT NULL, PRIMARY KEY(agent_id, server, capability));
PRAGMA user_version = 22;
";

/// A sign-in link is valid this long.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Tokens expiring within this long are refreshed before use.
const REFRESH_EARLY: i64 = 60;
/// Metadata, registration, token, and revocation answers are read up to
/// this many bytes.
const ANSWER_LIMIT: usize = 1 << 20;

/// `(agent_id, server, capability)`, with `""` for the source's own.
pub type Key = (String, String, String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientRef {
    pub issuer: String,
    pub redirect_uri: String,
}
/// `oauth_credentials.record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: String,
    pub resource: String,
    pub registration: String,
    pub client: ClientRef,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: Option<String>,
    pub scope: Option<String>,
    pub account: Option<String>,
    pub obtained_at: String,
    pub refreshed_at: Option<String>,
    pub state: String,
    #[serde(default)]
    pub refresh_failed_at: Option<String>,
}
impl Credential {
    /// The auth view's fields from this credential.
    pub fn view(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "scope": self.scope,
            "account": self.account,
            "registration": self.registration,
            "obtained_at": self.obtained_at,
            "expires_at": self.expires_at,
        })
    }
}
/// `oauth_clients.record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub issuer: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub registration_access_token: Option<String>,
    pub method: String,
    pub registration: String,
    pub created_at: String,
}

/// In-memory OAuth state: logins waiting for their redirect, refresh locks,
/// and credentials marked by a 401 to a call.
#[derive(Default)]
pub struct OAuthState {
    logins: Mutex<HashMap<String, Pending>>,
    locks: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
    /// Tokens refused by a call, by credential.
    marked: Mutex<HashMap<Key, Option<String>>>,
}
#[derive(Clone)]
struct Pending {
    state: String,
    verifier: String,
    client: Registration,
    issuer: String,
    redirect_uri: String,
    scopes: Option<String>,
    account: Option<String>,
    agent_id: String,
    agent_name: String,
    server: String,
    capability: Option<String>,
    resource: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    expires: Instant,
}

pub(crate) fn credential(conn: &Connection, key: &Key) -> Result<Option<Credential>, Error> {
    conn.query_row(
        "SELECT record FROM oauth_credentials WHERE agent_id = ?1 AND server = ?2 AND capability = ?3",
        params![key.0, key.1, key.2],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|t| serde_json::from_str(&t).map_err(Error::from))
    .transpose()
}
fn save_credential(conn: &Connection, key: &Key, c: &Credential) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO oauth_credentials VALUES (?1, ?2, ?3, ?4)",
        params![key.0, key.1, key.2, serde_json::to_string(c)?],
    )?;
    Ok(())
}
fn delete_credential(conn: &Connection, key: &Key) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM oauth_credentials WHERE agent_id = ?1 AND server = ?2 AND capability = ?3",
        params![key.0, key.1, key.2],
    )?;
    Ok(())
}
/// Every credential of a source, the source's and its capabilities'.
pub(crate) fn credentials_of(
    conn: &Connection,
    agent: &str,
    server: &str,
) -> Result<Vec<(Key, Credential)>, Error> {
    let mut statement = conn.prepare(
        "SELECT capability, record FROM oauth_credentials WHERE agent_id = ?1 AND server = ?2",
    )?;
    let rows: Vec<(String, String)> = statement
        .query_map(params![agent, server], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(c, t)| {
            Ok((
                (agent.to_owned(), server.to_owned(), c),
                serde_json::from_str(&t)?,
            ))
        })
        .collect()
}
/// Deletes credentials, returning them for revocation.
pub(crate) fn take_credentials(
    conn: &Connection,
    keys: &[Key],
) -> Result<Vec<(Credential, Option<Registration>)>, Error> {
    let mut out = Vec::new();
    for key in keys {
        if let Some(c) = credential(conn, key)? {
            let r = registration(conn, &c.client.issuer, &c.client.redirect_uri)?;
            delete_credential(conn, key)?;
            out.push((c, r));
        }
    }
    Ok(out)
}
fn registration(
    conn: &Connection,
    issuer: &str,
    redirect_uri: &str,
) -> Result<Option<Registration>, Error> {
    conn.query_row(
        "SELECT record FROM oauth_clients WHERE issuer = ?1 AND redirect_uri = ?2",
        params![issuer, redirect_uri],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|t| serde_json::from_str(&t).map_err(Error::from))
    .transpose()
}
fn latest_registration(conn: &Connection, issuer: &str) -> Result<Option<Registration>, Error> {
    let mut statement = conn.prepare("SELECT record FROM oauth_clients WHERE issuer = ?1")?;
    let rows: Vec<String> = statement
        .query_map([issuer], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut all: Vec<Registration> = rows
        .iter()
        .filter_map(|t| serde_json::from_str(t).ok())
        .collect();
    all.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(all.pop())
}
fn save_registration(conn: &Connection, r: &Registration) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO oauth_clients VALUES (?1, ?2, ?3)",
        params![r.issuer, r.redirect_uri, serde_json::to_string(r)?],
    )?;
    Ok(())
}
/// Whether a credential is usable for a server whose canonical URL is
/// `resource`: present, `ok` or `refresh_failed`, and for that resource.
pub(crate) fn usable(conn: &Connection, key: &Key, resource: Option<&str>) -> Result<bool, Error> {
    Ok(credential(conn, key)?.is_some_and(|c| {
        (c.state == "ok" || c.state == "refresh_failed") && Some(c.resource.as_str()) == resource
    }))
}

fn coded(status: u16, code: &'static str, message: impl Into<String>) -> Error {
    Error::Coded {
        status,
        code,
        message: message.into(),
        extra: Map::new(),
    }
}
fn random_bytes() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(bytes)
}
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
/// This machine's host name up to its first `.`, at most 64 bytes.
pub fn host_label() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for its length, and gethostname writes
    // at most that many bytes.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    let name = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut label = name.split('.').next().unwrap_or_default().to_owned();
    while label.len() > 64 {
        label.pop();
    }
    label
}
/// The client name registered with providers.
pub fn client_name() -> String {
    match host_label() {
        l if l.is_empty() => "Peerspan".into(),
        l => format!("Peerspan ({l})"),
    }
}

/// A JSON object from a `GET`, when the answer is 200.
/// The whole exchange with an OAuth endpoint, sending and reading
/// included, is bounded by 30 seconds.
const OAUTH_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(30);
async fn get_json(text: &str) -> Result<Map<String, Value>, String> {
    tokio::time::timeout(OAUTH_EXCHANGE, get_json_unbounded(text))
        .await
        .unwrap_or_else(|_| Err(format!("{text} did not answer within 30 seconds")))
}
async fn get_json_unbounded(text: &str) -> Result<Map<String, Value>, String> {
    let url = http_client::parse_url(text).ok_or_else(|| format!("{text} is not a usable URL"))?;
    if !url.secure_enough() {
        return Err(format!("{text} is neither https nor loopback http"));
    }
    let mut response = http_client::send(
        "GET",
        &url,
        &[("Accept".into(), "application/json".into())],
        None,
    )
    .await
    .map_err(|e| format!("{text}: {e}"))?;
    if response.status != 200 {
        return Err(format!("{text} answered HTTP {}", response.status));
    }
    let body = http_client::read_body(&mut response.body, ANSWER_LIMIT)
        .await
        .map_err(|e| format!("{text}: {e:?}"))?;
    match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Object(o)) => Ok(o),
        _ => Err(format!("{text} did not answer with a JSON object")),
    }
}
/// A `POST` of a body, and the answer's status and JSON (null when not
/// JSON).
async fn post_to(
    text: &str,
    content_type: &str,
    body: String,
    extra: Vec<(String, String)>,
) -> Result<(u16, Value), String> {
    tokio::time::timeout(
        OAUTH_EXCHANGE,
        post_to_unbounded(text, content_type, body, extra),
    )
    .await
    .unwrap_or_else(|_| Err(format!("{text} did not answer within 30 seconds")))
}
async fn post_to_unbounded(
    text: &str,
    content_type: &str,
    body: String,
    extra: Vec<(String, String)>,
) -> Result<(u16, Value), String> {
    let url = http_client::parse_url(text).ok_or_else(|| format!("{text} is not a usable URL"))?;
    let mut headers = vec![
        ("Content-Type".to_owned(), content_type.to_owned()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ];
    headers.extend(extra);
    let mut response = http_client::send("POST", &url, &headers, Some(body.into_bytes()))
        .await
        .map_err(|e| e.to_string())?;
    let body = http_client::read_body(&mut response.body, ANSWER_LIMIT)
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok((
        response.status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    ))
}
/// The client's authentication for a token or revocation request: form
/// fields and headers.
fn client_auth(r: &Registration, form: &mut Vec<(String, String)>) -> Vec<(String, String)> {
    form.push(("client_id".into(), r.client_id.clone()));
    match (r.method.as_str(), &r.client_secret) {
        ("client_secret_post", Some(secret)) => {
            form.push(("client_secret".into(), secret.clone()));
            Vec::new()
        }
        ("client_secret_basic", Some(secret)) => {
            let pair = format!(
                "{}:{}",
                http_client::form_encode(&r.client_id),
                http_client::form_encode(secret)
            );
            vec![(
                "Authorization".into(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair)
                ),
            )]
        }
        _ => Vec::new(),
    }
}
fn form_body(pairs: &[(String, String)]) -> String {
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    http_client::form(&refs)
}
/// `ERROR (DESCRIPTION)`, or `ERROR`, from an OAuth error answer.
fn error_text(status: u16, answer: &Value) -> String {
    let error = answer["error"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("HTTP {status}"));
    match answer["error_description"].as_str() {
        Some(d) => format!("{error} ({d})"),
        None => error,
    }
}
fn expiry(answer: &Value) -> Option<String> {
    let seconds = answer["expires_in"].as_f64()?;
    let at = chrono::Utc::now() + chrono::TimeDelta::milliseconds((seconds * 1000.0) as i64);
    Some(crate::store::rfc3339(at))
}

/// Posts each token to the revocation endpoint. True when every one got
/// a 200; false without an endpoint.
async fn revoke(c: &Credential, r: Option<&Registration>) -> bool {
    let Some(endpoint) = &c.revocation_endpoint else {
        return false;
    };
    let mut tokens = Vec::new();
    if let Some(refresh) = &c.refresh_token {
        tokens.push((refresh.clone(), "refresh_token"));
    }
    tokens.push((c.access_token.clone(), "access_token"));
    let mut all = true;
    for (token, hint) in tokens {
        let mut form = vec![
            ("token".to_owned(), token),
            ("token_type_hint".to_owned(), hint.to_owned()),
        ];
        let headers = match r {
            Some(r) => client_auth(r, &mut form),
            None => Vec::new(),
        };
        let ok = matches!(
            tokio::time::timeout(
                Duration::from_secs(15),
                post_to(
                    endpoint,
                    "application/x-www-form-urlencoded",
                    form_body(&form),
                    headers
                ),
            )
            .await,
            Ok(Ok((200, _)))
        );
        all &= ok;
    }
    all
}
/// Revokes deleted credentials in the background, best effort.
pub(crate) fn revoke_later(taken: Vec<(Credential, Option<Registration>)>) {
    if taken.is_empty() {
        return;
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            for (c, r) in taken {
                revoke(&c, r.as_ref()).await;
            }
        });
    }
}

/// The token provider for a remote instance's credential.
pub(crate) fn tokens(store: &Arc<Store>, key: Key, url: &str) -> Tokens {
    let weak = Arc::downgrade(store);
    // A session only ever uses a credential for its own resource, so a new
    // sign-in to a changed URL never reaches an older session.
    let resource = crate::http_client::canonical(url).unwrap_or_else(|| url.to_owned());
    Arc::new(move |mode: TokenMode| -> TokenFuture {
        let weak = weak.clone();
        let key = key.clone();
        let resource = resource.clone();
        Box::pin(async move {
            let Some(store) = weak.upgrade() else {
                return Err(LoginRequired);
            };
            provide(store, key, mode, resource).await
        })
    })
}
/// Arms a launch's remote part with its credential's token provider.
pub(crate) fn arm(store: &Arc<Store>, launch: &mut crate::mcp::Launch) {
    if let Some(remote) = launch.remote.as_mut()
        && let Some(key) = remote.credential.clone()
    {
        remote.tokens = Some(tokens(store, key, &remote.url));
    }
}

async fn provide(
    store: Arc<Store>,
    key: Key,
    mode: TokenMode,
    resource: String,
) -> Result<Option<String>, LoginRequired> {
    match &mode {
        TokenMode::Mark(token) => {
            if let Ok(mut marked) = store.oauth.marked.lock() {
                marked.insert(key, token.clone());
            }
            return Ok(None);
        }
        TokenMode::Lapse(token) => {
            let (k, t) = (key.clone(), token.clone());
            let _ = blocking(store.clone(), move |s| s.lapse(&k, t.as_deref())).await;
            return Ok(None);
        }
        _ => {}
    }
    let lock = {
        let mut locks = store.oauth.locks.lock().map_err(|_| LoginRequired)?;
        locks.entry(key.clone()).or_default().clone()
    };
    let _guard = lock.lock().await;
    let k = key.clone();
    let Ok(Some(c)) = blocking(store.clone(), move |s| credential(&*s.connection()?, &k)).await
    else {
        return Err(LoginRequired);
    };
    if c.state == "login_required" || c.resource != resource {
        return Err(LoginRequired);
    }
    let marked = store
        .oauth
        .marked
        .lock()
        .map(|m| {
            m.get(&key)
                .is_some_and(|t| t.as_deref().is_none_or(|t| t == c.access_token))
        })
        .unwrap_or(false);
    // A forced refresh whose refused token another request already
    // replaced uses the new one.
    let forced = match &mode {
        TokenMode::Force(stale) => stale.as_deref().is_none_or(|t| t == c.access_token),
        _ => false,
    };
    let expiring = c.expires_at.as_deref().is_some_and(|at| {
        crate::membership::time(at)
            .is_ok_and(|t| t <= chrono::Utc::now() + chrono::TimeDelta::seconds(REFRESH_EARLY))
    });
    if forced || marked || expiring {
        return refresh(&store, &key, c).await;
    }
    Ok(Some(c.access_token))
}

/// Refreshes a credential (its lock held). A refused refresh makes it
/// `login_required`; another failure `refresh_failed`, and the current
/// token is used.
async fn refresh(
    store: &Arc<Store>,
    key: &Key,
    c: Credential,
) -> Result<Option<String>, LoginRequired> {
    if let Ok(mut marked) = store.oauth.marked.lock() {
        marked.remove(key);
    }
    let log = store.tool_log(&Instance {
        agent_id: key.0.clone(),
        server: key.1.clone(),
        capability: (!key.2.is_empty()).then(|| key.2.clone()),
    });
    let Some(refresh_token) = c.refresh_token.clone() else {
        crate::mcp::note(
            &log,
            "the token cannot be refreshed: there is no refresh token",
        );
        let (k, t) = (key.clone(), c.access_token.clone());
        let _ = blocking(store.clone(), move |s| s.lapse(&k, Some(&t))).await;
        return Err(LoginRequired);
    };
    let (i, ru) = (c.client.issuer.clone(), c.client.redirect_uri.clone());
    let client = blocking(store.clone(), move |s| {
        registration(&*s.connection()?, &i, &ru)
    })
    .await
    .ok()
    .flatten();
    let mut form = vec![
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("refresh_token".to_owned(), refresh_token),
    ];
    let headers = match &client {
        Some(r) => client_auth(r, &mut form),
        None => Vec::new(),
    };
    form.push(("resource".into(), c.resource.clone()));
    let answer = post_to(
        &c.token_endpoint,
        "application/x-www-form-urlencoded",
        form_body(&form),
        headers,
    )
    .await;
    match answer {
        Ok((200, answer)) if answer["access_token"].is_string() => {
            crate::mcp::note(&log, "refreshed the token");
            let read_token = c.access_token.clone();
            let mut c = c;
            c.access_token = answer["access_token"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if let Some(r) = answer["refresh_token"].as_str() {
                c.refresh_token = Some(r.to_owned());
            }
            c.expires_at = expiry(&answer);
            if let Some(scope) = answer["scope"].as_str() {
                c.scope = Some(scope.to_owned());
            }
            c.refreshed_at = Some(now());
            c.state = "ok".into();
            c.refresh_failed_at = None;
            let token = c.access_token.clone();
            let (k, fresh) = (key.clone(), c.clone());
            // Stored only while the credential is still the one refreshed: a
            // sign-out, a dropped source, or a new sign-in in the meantime
            // wins, and the new tokens are revoked.
            let stored = blocking(store.clone(), move |s| {
                let mut conn = s.connection()?;
                let tx = conn.transaction()?;
                let current = credential(&tx, &k)?;
                if current.is_none_or(|cur| cur.access_token != read_token) {
                    return Ok(false);
                }
                save_credential(&tx, &k, &fresh)?;
                s.refresh_login_reason(&tx, &k.0, &k.1)?;
                tx.commit()?;
                Ok(true)
            })
            .await;
            if !matches!(stored, Ok(true)) {
                revoke_later(vec![(c, client)]);
                return Err(LoginRequired);
            }
            Ok(Some(token))
        }
        Ok((status, answer))
            if (status == 400 || status == 401)
                && matches!(
                    answer["error"].as_str(),
                    Some("invalid_grant" | "invalid_client")
                ) =>
        {
            crate::mcp::note(
                &log,
                &format!("the provider refused to refresh the token (HTTP {status})"),
            );
            let (k, t) = (key.clone(), c.access_token.clone());
            let _ = blocking(store.clone(), move |s| s.lapse(&k, Some(&t))).await;
            Err(LoginRequired)
        }
        other => {
            let detail = match &other {
                Ok((status, _)) => format!("HTTP {status}"),
                Err(e) => e.clone(),
            };
            crate::mcp::note(&log, &format!("refreshing the token failed: {detail}"));
            let k = key.clone();
            let token = c.access_token.clone();
            let _ = blocking(store.clone(), move |s| {
                let mut conn = s.connection()?;
                let tx = conn.transaction()?;
                if credential(&tx, &k)?.is_none_or(|cur| cur.access_token != c.access_token) {
                    return Ok(());
                }
                let mut c = c;
                c.state = "refresh_failed".into();
                if c.refresh_failed_at.is_none() {
                    c.refresh_failed_at = Some(now());
                }
                save_credential(&tx, &k, &c)?;
                append_event(&tx, "sources.token_refresh_failed", &subject(&k), &now())?;
                tx.commit()?;
                Ok(())
            })
            .await;
            Ok(Some(token))
        }
    }
}

/// `AGENT_ID/SERVER`, or `AGENT_ID/SERVER@CAPABILITY`.
fn subject(key: &Key) -> String {
    if key.2.is_empty() {
        format!("{}/{}", key.0, key.1)
    } else {
        format!("{}/{}@{}", key.0, key.1, key.2)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    redirect_port: Option<u16>,
    #[serde(default)]
    account: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    callback_url: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutBody {
    #[serde(default)]
    capability: Option<String>,
}

/// What the start of a sign-in needs from the database.
struct Target {
    agent_id: String,
    agent_name: String,
    server: String,
    url: String,
    challenge_needed: crate::mcp::Launch,
    oauth: Value,
    authorization_header: bool,
}

impl Store {
    /// Makes a credential `login_required`, records the failed refresh, and
    /// recomputes its source's reason.
    fn lapse(&self, key: &Key, token: Option<&str>) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // Only the credential that was refused: one replaced since stays.
        if let Some(mut c) = credential(&tx, key)?
            && token.is_none_or(|t| t == c.access_token)
        {
            if c.state != "login_required" {
                c.state = "login_required".into();
                save_credential(&tx, key, &c)?;
                append_event(&tx, "sources.token_refresh_failed", &subject(key), &now())?;
            }
            self.refresh_login_reason(&tx, &key.0, &key.1)?;
        }
        tx.commit()?;
        Ok(())
    }
    /// The agent ID and name of a local agent named or identified `agent`.
    fn agent_of(&self, conn: &Connection, agent: &str) -> Result<Option<(String, String)>, Error> {
        Ok(conn
            .query_row(
                "SELECT id, name FROM agents WHERE name = ?1 OR id = ?1 ORDER BY id = ?1 DESC LIMIT 1",
                [agent],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
    /// Checks a sign-in's source and capability, in the contract's order.
    fn login_target(
        &self,
        agent: &str,
        server: &str,
        capability: Option<&str>,
    ) -> Result<Target, Error> {
        let conn = self.connection()?;
        let shown = format!("{agent}/{server}");
        let missing = || {
            coded(
                404,
                "not_found",
                format!("No source {shown} on this host. Run peerspan sources."),
            )
        };
        let Some((agent_id, agent_name)) = self.agent_of(&conn, agent)? else {
            return Err(missing());
        };
        let source = format!("{agent_name}/{server}");
        let Some(record) = server_record(&conn, &agent_id, server)? else {
            return Err(coded(
                404,
                "not_found",
                format!("No source {source} on this host. Run peerspan sources."),
            ));
        };
        if let Some(name) = capability {
            let Some(c) = capability_record(&conn, name)? else {
                return Err(coded(
                    404,
                    "not_found",
                    format!("No capability {name} on this host. Run peerspan capability list."),
                ));
            };
            if c.agent_id != agent_id || c.source.server != server {
                return Err(coded(
                    400,
                    "invalid",
                    format!("{name} is not built on {source}."),
                ));
            }
        }
        let no_challenge = || {
            coded(
                409,
                "no_challenge",
                format!("{source} did not ask for a sign-in, so there is nothing to sign in to."),
            )
        };
        let d = &record.definition;
        if d.transport != "remote" {
            return Err(no_challenge());
        }
        let remote = d.remote_spec();
        if remote["oauth"].is_null() {
            return Err(coded(
                409,
                "oauth_disabled",
                format!("{source} has OAuth turned off in its harness configuration."),
            ));
        }
        if let Some(reason) = record.reason.as_deref().filter(|r| *r != "login") {
            return Err(coded(
                409,
                "not_usable",
                format!("{source} is not usable ({reason}), so Peerspan cannot sign in to it."),
            ));
        }
        let instance = Instance {
            agent_id: agent_id.clone(),
            server: server.to_owned(),
            capability: None,
        };
        let mut launch = self.launch_with(&conn, &instance, None)?;
        let authorization_header = launch.remote.as_ref().is_some_and(|r| {
            r.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        }) || d
            .header_names()
            .iter()
            .any(|n| n.eq_ignore_ascii_case("authorization"));
        let url = launch
            .remote
            .as_ref()
            .map(|r| r.url.clone())
            .unwrap_or_default();
        if let Some(r) = launch.remote.as_mut() {
            r.credential = None;
            r.tokens = None;
        }
        Ok(Target {
            agent_id,
            agent_name,
            server: server.to_owned(),
            url,
            challenge_needed: launch,
            oauth: remote["oauth"].clone(),
            authorization_header,
        })
    }
    /// Stores a probe's challenge with the source.
    fn store_challenge(
        &self,
        agent: &str,
        server: &str,
        resource_metadata: Option<String>,
        scope: Option<String>,
    ) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if let Some(mut r) = server_record(&tx, agent, server)? {
            r.auth_mode = Some("oauth".into());
            r.challenge = Some(crate::sources::Challenge {
                resource_metadata,
                scope,
            });
            crate::sources::save_record(&tx, &r)?;
            self.refresh_login_reason(&tx, agent, server)?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Starts a sign-in: steps 1 to 10 of the contract.
async fn start(
    store: Arc<Store>,
    agent: String,
    server: String,
    body: LoginBody,
) -> Result<Value, Error> {
    if body.client_secret.is_some() && body.client_id.is_none() {
        return Err(Error::Invalid("client_secret needs client_id".into()));
    }
    if body.redirect_port == Some(0) {
        return Err(Error::Invalid("redirect_port is from 1 to 65535".into()));
    }
    if let Some(a) = &body.account
        && (a.len() > 256 || a.chars().any(|c| c < ' ' || c == '\u{7f}'))
    {
        return Err(Error::Invalid(
            "account is at most 256 bytes without control characters".into(),
        ));
    }
    let (a, s, c) = (agent.clone(), server.clone(), body.capability.clone());
    let target = blocking(store.clone(), move |st| {
        st.login_target(&a, &s, c.as_deref())
    })
    .await?;
    let source = format!("{}/{}", target.agent_name, target.server);
    // 2. The probe.
    let client = crate::mcp::Client::remote(&target.challenge_needed).map_err(|e| {
        coded(
            502,
            "unreachable",
            format!("Peerspan could not reach {source}: {e}"),
        )
    })?;
    let probe = tokio::time::timeout(crate::mcp::START_BOUND, client.initialize()).await;
    client.kill();
    let no_challenge = || {
        coded(
            409,
            "no_challenge",
            format!("{source} did not ask for a sign-in, so there is nothing to sign in to."),
        )
    };
    let challenge = match probe {
        Err(_) => {
            return Err(coded(
                502,
                "unreachable",
                format!("Peerspan could not reach {source}: no answer within 30 seconds"),
            ));
        }
        Ok(Ok(_)) => return Err(no_challenge()),
        Ok(Err(e)) => match e.downcast_ref::<crate::mcp::HttpFail>() {
            Some(f)
                if matches!(
                    f.kind,
                    crate::mcp::HttpKind::Connect | crate::mcp::HttpKind::Lost
                ) =>
            {
                return Err(coded(
                    502,
                    "unreachable",
                    format!("Peerspan could not reach {source}: {}", f.detail),
                ));
            }
            Some(f)
                if f.kind == crate::mcp::HttpKind::Unauthorized && !target.authorization_header =>
            {
                match f
                    .authenticate
                    .as_deref()
                    .and_then(http_client::bearer_challenge)
                {
                    Some(params) => params,
                    None => return Err(no_challenge()),
                }
            }
            _ => return Err(no_challenge()),
        },
    };
    let param = |name: &str| {
        challenge
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let (resource_metadata, challenge_scope) = (param("resource_metadata"), param("scope"));
    {
        let (a, s, rm, sc) = (
            target.agent_id.clone(),
            target.server.clone(),
            resource_metadata.clone(),
            challenge_scope.clone(),
        );
        blocking(store.clone(), move |st| st.store_challenge(&a, &s, rm, sc)).await?;
    }
    // 3. The authorization server.
    let metadata_error = |detail: String| {
        coded(
            502,
            "oauth_metadata",
            format!(
                "Peerspan could not read the authorization server metadata for {source}: {detail}"
            ),
        )
    };
    let mcp_url = http_client::parse_url(&target.url)
        .ok_or_else(|| metadata_error("the server's URL is not usable".into()))?;
    let mut prm_urls = Vec::new();
    if let Some(rm) = &resource_metadata {
        prm_urls.push(rm.clone());
    }
    let canonical_path = mcp_url.path.trim_end_matches('/');
    if !canonical_path.is_empty() {
        prm_urls.push(format!(
            "{}/.well-known/oauth-protected-resource{canonical_path}",
            mcp_url.origin()
        ));
    }
    prm_urls.push(format!(
        "{}/.well-known/oauth-protected-resource",
        mcp_url.origin()
    ));
    let mut prm = None;
    let mut last = String::from("no protected resource metadata");
    for u in &prm_urls {
        match get_json(u).await {
            Ok(o) => {
                let servers: Vec<String> = o
                    .get("authorization_servers")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                if servers.is_empty() {
                    last = format!("{u} lists no authorization_servers");
                    continue;
                }
                prm = Some((o, servers[0].clone()));
                break;
            }
            Err(e) => last = e,
        }
    }
    let Some((prm, issuer)) = prm else {
        return Err(metadata_error(last));
    };
    let issuer_url = http_client::parse_url(&issuer)
        .ok_or_else(|| metadata_error(format!("the issuer {issuer} is not a usable URL")))?;
    let mut as_urls = Vec::new();
    let path = issuer_url.path.trim_end_matches('/');
    if !path.is_empty() {
        as_urls.push(format!(
            "{}/.well-known/oauth-authorization-server{path}",
            issuer_url.origin()
        ));
        as_urls.push(format!(
            "{}/.well-known/openid-configuration{path}",
            issuer_url.origin()
        ));
        as_urls.push(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ));
    } else {
        as_urls.push(format!(
            "{}/.well-known/oauth-authorization-server",
            issuer_url.origin()
        ));
        as_urls.push(format!(
            "{}/.well-known/openid-configuration",
            issuer_url.origin()
        ));
    }
    let mut meta = None;
    let mut last = String::from("no authorization server metadata");
    for u in &as_urls {
        match get_json(u).await {
            Ok(o) => {
                meta = Some(o);
                break;
            }
            Err(e) => last = e,
        }
    }
    let Some(meta) = meta else {
        return Err(metadata_error(last));
    };
    if meta.get("issuer").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(metadata_error(format!(
            "the metadata's issuer does not match {issuer}"
        )));
    }
    let endpoint = |name: &str, required: bool| -> Result<Option<String>, Error> {
        match meta.get(name) {
            Some(Value::String(e)) => {
                if !http_client::parse_url(e).is_some_and(|u| u.secure_enough()) {
                    return Err(metadata_error(format!(
                        "{name} {e} is neither https nor loopback http"
                    )));
                }
                Ok(Some(e.clone()))
            }
            None | Some(Value::Null) if !required => Ok(None),
            _ if required => Err(metadata_error(format!("the metadata has no {name}"))),
            _ => Ok(None),
        }
    };
    let authorization_endpoint = endpoint("authorization_endpoint", true)?.unwrap_or_default();
    let token_endpoint = endpoint("token_endpoint", true)?.unwrap_or_default();
    let registration_endpoint = endpoint("registration_endpoint", false)?;
    let revocation_endpoint = endpoint("revocation_endpoint", false)?;
    // 4. PKCE.
    let s256 = meta
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|m| m == "S256"));
    if !s256 {
        return Err(coded(
            409,
            "no_pkce",
            format!(
                "The authorization server for {source} ({issuer}) does not advertise PKCE, so Peerspan will not sign in to it."
            ),
        ));
    }
    // 5. The redirect URI.
    let hint_port = target.oauth["callback_port"].as_u64().map(|p| p as u16);
    let i = issuer.clone();
    let latest = blocking(store.clone(), move |s| {
        latest_registration(&*s.connection()?, &i)
    })
    .await?;
    let latest_port = latest
        .as_ref()
        .and_then(|r| http_client::parse_url(&r.redirect_uri))
        .map(|u| u.port);
    let port = match body.redirect_port.or(hint_port).or(latest_port) {
        Some(p) => p,
        None => std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .map_err(|e| Error::Internal(anyhow::anyhow!("no free port: {e}")))?,
    };
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    // 6. The client.
    let (i, ru) = (issuer.clone(), redirect_uri.clone());
    let stored = blocking(store.clone(), move |s| {
        registration(&*s.connection()?, &i, &ru)
    })
    .await?;
    let methods: Vec<String> = meta
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let client = if let Some(id) = &body.client_id {
        let method = match &body.client_secret {
            None => "none",
            Some(_)
                if methods.iter().any(|m| m == "client_secret_basic")
                    && !methods.iter().any(|m| m == "client_secret_post") =>
            {
                "client_secret_basic"
            }
            Some(_) => "client_secret_post",
        };
        let r = Registration {
            issuer: issuer.clone(),
            redirect_uri: redirect_uri.clone(),
            client_id: id.clone(),
            client_secret: body.client_secret.clone(),
            registration_access_token: None,
            method: method.into(),
            registration: "manual".into(),
            created_at: now(),
        };
        let saved = r.clone();
        blocking(store.clone(), move |s| {
            save_registration(&*s.connection()?, &saved)
        })
        .await?;
        r
    } else if let Some(r) = stored {
        r
    } else if let Some(id) = target.oauth["client_id"].as_str() {
        let r = Registration {
            issuer: issuer.clone(),
            redirect_uri: redirect_uri.clone(),
            client_id: id.to_owned(),
            client_secret: None,
            registration_access_token: None,
            method: "none".into(),
            registration: "harness".into(),
            created_at: now(),
        };
        let saved = r.clone();
        blocking(store.clone(), move |s| {
            save_registration(&*s.connection()?, &saved)
        })
        .await?;
        r
    } else if let Some(endpoint) = &registration_endpoint {
        let request = json!({
            "client_name": client_name(),
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "native",
        });
        let refused = |detail: String| {
            coded(
                502,
                "registration_failed",
                format!(
                    "The authorization server for {source} ({issuer}) refused to register Peerspan: {detail}"
                ),
            )
        };
        let (status, answer) = post_to(
            endpoint,
            "application/json",
            request.to_string(),
            Vec::new(),
        )
        .await
        .map_err(refused)?;
        if !(status == 200 || status == 201) {
            return Err(refused(error_text(status, &answer)));
        }
        let Some(id) = answer["client_id"].as_str() else {
            return Err(refused("the answer has no client_id".into()));
        };
        let secret = answer["client_secret"].as_str().map(str::to_owned);
        let method = match (&secret, answer["token_endpoint_auth_method"].as_str()) {
            (None, _) => "none",
            (Some(_), Some("client_secret_post")) => "client_secret_post",
            (Some(_), _) => "client_secret_basic",
        };
        let r = Registration {
            issuer: issuer.clone(),
            redirect_uri: redirect_uri.clone(),
            client_id: id.to_owned(),
            client_secret: secret,
            registration_access_token: answer["registration_access_token"]
                .as_str()
                .map(str::to_owned),
            method: method.into(),
            registration: "dcr".into(),
            created_at: now(),
        };
        let saved = r.clone();
        blocking(store.clone(), move |s| {
            save_registration(&*s.connection()?, &saved)
        })
        .await?;
        r
    } else {
        return Err(coded(
            409,
            "no_registration",
            format!(
                "The authorization server for {source} ({issuer}) does not let Peerspan register itself. Register an OAuth app with the provider, with redirect URI http://127.0.0.1:{port}/callback, then run: peerspan sources login {source} --client-id ID [--client-secret-file PATH]"
            ),
        ));
    };
    // 7. Scopes.
    let supported = prm
        .get("scopes_supported")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty());
    let scopes = body
        .scopes
        .clone()
        .or_else(|| target.oauth["scopes"].as_str().map(str::to_owned))
        .or(challenge_scope)
        .or(supported)
        .filter(|s| !s.is_empty());
    // 8. The authorization URL.
    let state = hex::encode(random_bytes()?);
    let verifier = b64url(&random_bytes()?);
    let code_challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let resource = http_client::canonical(&target.url).unwrap_or_else(|| target.url.clone());
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &client.client_id),
        ("redirect_uri", &redirect_uri),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("state", &state),
        ("resource", &resource),
    ];
    if let Some(s) = &scopes {
        pairs.push(("scope", s));
    }
    let separator = if authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let authorization_url = format!(
        "{authorization_endpoint}{separator}{}",
        http_client::form(&pairs)
    );
    // 9. Keep it in memory.
    let login_id = format!("login_{}", hex::encode(&random_bytes()?[..16]));
    let expires_at = crate::store::rfc3339(
        chrono::Utc::now() + chrono::TimeDelta::seconds(LOGIN_TTL.as_secs() as i64),
    );
    let pending = Pending {
        state,
        verifier,
        client,
        issuer,
        redirect_uri: redirect_uri.clone(),
        scopes,
        account: body.account.clone().filter(|a| !a.is_empty()),
        agent_id: target.agent_id,
        agent_name: target.agent_name,
        server: target.server,
        capability: body.capability,
        resource,
        token_endpoint,
        revocation_endpoint,
        expires: Instant::now() + LOGIN_TTL,
    };
    if let Ok(mut logins) = store.oauth.logins.lock() {
        logins.retain(|_, p| p.expires > Instant::now());
        logins.insert(login_id.clone(), pending);
    }
    Ok(json!({
        "login_id": login_id,
        "authorization_url": authorization_url,
        "redirect_uri": redirect_uri,
        "expires_at": expires_at,
    }))
}

/// Finishes a sign-in with the redirect's address.
async fn complete(store: Arc<Store>, login_id: String, body: CompleteBody) -> Result<Value, Error> {
    let pending = store
        .oauth
        .logins
        .lock()
        .ok()
        .and_then(|mut l| l.remove(&login_id))
        .filter(|p| p.expires > Instant::now());
    let source = pending
        .as_ref()
        .map(|p| format!("{}/{}", p.agent_name, p.server))
        .unwrap_or_else(|| "SOURCE".into());
    let expired = || {
        coded(
            400,
            "login_expired",
            format!(
                "This sign-in link is no longer valid. Run peerspan sources login {source} again."
            ),
        )
    };
    let Some(p) = pending else {
        return Err(expired());
    };
    let query = body
        .callback_url
        .split('#')
        .next()
        .unwrap_or_default()
        .split_once('?')
        .map(|(_, q)| q.to_owned())
        .unwrap_or_default();
    let params = http_client::query_pairs(&query);
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    if param("state").as_deref() != Some(p.state.as_str()) {
        return Err(expired());
    }
    if let Some(error) = param("error") {
        let text = match param("error_description") {
            Some(d) => format!("The provider refused the sign-in: {error} ({d})."),
            None => format!("The provider refused the sign-in: {error}."),
        };
        return Err(coded(400, "provider_refused", text));
    }
    let Some(code) = param("code") else {
        return Err(coded(
            400,
            "no_code",
            format!(
                "The redirect carried no authorization code. Run peerspan sources login {source} again."
            ),
        ));
    };
    let mut form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code),
        ("redirect_uri".to_owned(), p.redirect_uri.clone()),
    ];
    let headers = client_auth(&p.client, &mut form);
    form.push(("code_verifier".into(), p.verifier.clone()));
    form.push(("resource".into(), p.resource.clone()));
    let refused = |text: String| {
        coded(
            502,
            "token_refused",
            format!("The provider refused to issue a token: {text}."),
        )
    };
    let (status, answer) = post_to(
        &p.token_endpoint,
        "application/x-www-form-urlencoded",
        form_body(&form),
        headers,
    )
    .await
    .map_err(|e| refused(format!("unreachable ({e})")))?;
    let bearer = answer["token_type"].is_null()
        || answer["token_type"]
            .as_str()
            .is_some_and(|t| t.eq_ignore_ascii_case("bearer"));
    if status != 200 || !answer["access_token"].is_string() || !bearer {
        return Err(refused(error_text(status, &answer)));
    }
    let at = now();
    let credential = Credential {
        issuer: p.issuer.clone(),
        resource: p.resource.clone(),
        registration: p.client.registration.clone(),
        client: ClientRef {
            issuer: p.client.issuer.clone(),
            redirect_uri: p.client.redirect_uri.clone(),
        },
        token_endpoint: p.token_endpoint.clone(),
        revocation_endpoint: p.revocation_endpoint.clone(),
        access_token: answer["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        refresh_token: answer["refresh_token"].as_str().map(str::to_owned),
        token_type: "Bearer".into(),
        expires_at: expiry(&answer),
        scope: answer["scope"]
            .as_str()
            .map(str::to_owned)
            .or(p.scopes.clone()),
        account: p.account.clone(),
        obtained_at: at.clone(),
        refreshed_at: None,
        state: "ok".into(),
        refresh_failed_at: None,
    };
    let key: Key = (
        p.agent_id.clone(),
        p.server.clone(),
        p.capability.clone().unwrap_or_default(),
    );
    let (k, c) = (key.clone(), credential.clone());
    // Serialized with refreshes of the same credential, so one in flight
    // cannot overwrite the new sign-in.
    let lock = {
        let mut locks = store
            .oauth
            .locks
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("the OAuth locks are poisoned")))?;
        locks.entry(key.clone()).or_default().clone()
    };
    let guard = lock.lock().await;
    let replaced = blocking(store.clone(), move |s| {
        let mut conn = s.connection()?;
        let tx = conn.transaction()?;
        // The sign-in's target must still be there, at the same resource:
        // a source dropped or changed, or a capability removed, while the
        // person approved, invalidates it.
        let live = crate::sources::source_resource(&tx, &k.0, &k.1)?.as_deref()
            == Some(c.resource.as_str())
            && (k.2.is_empty()
                || capability_record(&tx, &k.2)?
                    .is_some_and(|r| r.agent_id == k.0 && r.source.server == k.1));
        if !live {
            return Ok(None);
        }
        let replaced = take_credentials(&tx, std::slice::from_ref(&k))?;
        save_credential(&tx, &k, &c)?;
        if !k.2.is_empty()
            && let Some(mut r) = capability_record(&tx, &k.2)?
        {
            r.own_sign_in = true;
            crate::capabilities::save(&tx, &r)?;
        }
        append_event(&tx, "sources.login", &subject(&k), &now())?;
        s.refresh_login_reason(&tx, &k.0, &k.1)?;
        tx.commit()?;
        Ok(Some(replaced))
    })
    .await?;
    drop(guard);
    let Some(replaced) = replaced else {
        revoke_later(vec![(credential, Some(p.client.clone()))]);
        return Err(coded(
            400,
            "login_expired",
            format!(
                "This sign-in link is no longer valid. Run peerspan sources login {}/{} again.",
                p.agent_name, p.server
            ),
        ));
    };
    if let Ok(mut marked) = store.oauth.marked.lock() {
        marked.remove(&key);
    }
    // A provider may hand out the same token again: never revoke what the
    // new credential still holds.
    let replaced = replaced
        .into_iter()
        .filter(|(old, _)| {
            old.access_token != credential.access_token
                && (old.refresh_token.is_none() || old.refresh_token != credential.refresh_token)
        })
        .collect();
    revoke_later(replaced);
    let instance = Instance {
        agent_id: p.agent_id.clone(),
        server: p.server.clone(),
        capability: p.capability.clone(),
    };
    if let Some(c) = &p.capability {
        store
            .tool_pool
            .stop_key(&(p.agent_id.clone(), p.server.clone(), c.clone()));
    } else {
        store
            .tool_pool
            .stop_key(&(p.agent_id.clone(), p.server.clone(), String::new()));
    }
    crate::sources::snapshot_all(store.clone(), vec![instance]).await;
    Ok(json!({
        "source": source,
        "capability": p.capability,
        "issuer": credential.issuer,
        "scopes": credential.scope,
        "account": credential.account,
        "expires_at": credential.expires_at,
        "registration": credential.registration,
    }))
}

/// Revokes and deletes a credential.
async fn logout(
    store: Arc<Store>,
    agent: String,
    server: String,
    body: LogoutBody,
) -> Result<Value, Error> {
    let (a, s, cap) = (agent.clone(), server.clone(), body.capability.clone());
    let (key, source, taken) = blocking(store.clone(), move |st| {
        let conn = st.connection()?;
        let Some((agent_id, agent_name)) = st.agent_of(&conn, &a)? else {
            return Err(coded(
                404,
                "not_found",
                format!("No source {a}/{s} on this host. Run peerspan sources."),
            ));
        };
        let source = format!("{agent_name}/{s}");
        if server_record(&conn, &agent_id, &s)?.is_none() {
            return Err(coded(
                404,
                "not_found",
                format!("No source {source} on this host. Run peerspan sources."),
            ));
        }
        if let Some(name) = &cap {
            let Some(c) = capability_record(&conn, name)? else {
                return Err(coded(
                    404,
                    "not_found",
                    format!("No capability {name} on this host. Run peerspan capability list."),
                ));
            };
            if c.agent_id != agent_id || c.source.server != s {
                return Err(coded(
                    400,
                    "invalid",
                    format!("{name} is not built on {source}."),
                ));
            }
        }
        let key: Key = (agent_id, s.clone(), cap.clone().unwrap_or_default());
        let c = credential(&conn, &key)?;
        let r = match &c {
            Some(c) => registration(&conn, &c.client.issuer, &c.client.redirect_uri)?,
            None => None,
        };
        Ok((key, source, c.map(|c| (c, r))))
    })
    .await?;
    // Serialized with refreshes of the same credential, so a refresh in
    // flight cannot store a credential this sign-out already deleted.
    let lock = {
        let mut locks = store
            .oauth
            .locks
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("the OAuth locks are poisoned")))?;
        locks.entry(key.clone()).or_default().clone()
    };
    let _guard = lock.lock().await;
    let taken = if taken.is_some() {
        let k = key.clone();
        blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            let c = credential(&conn, &k)?;
            let r = match &c {
                Some(c) => registration(&conn, &c.client.issuer, &c.client.redirect_uri)?,
                None => None,
            };
            Ok(c.map(|c| (c, r)))
        })
        .await?
    } else {
        None
    };
    let Some((c, r)) = taken else {
        return Ok(
            json!({"source": source, "capability": body.capability, "revoked": false, "deleted": false}),
        );
    };
    let revoked = revoke(&c, r.as_ref()).await;
    let k = key.clone();
    blocking(store.clone(), move |s| {
        let mut conn = s.connection()?;
        let tx = conn.transaction()?;
        delete_credential(&tx, &k)?;
        append_event(&tx, "sources.logout", &subject(&k), &now())?;
        s.refresh_login_reason(&tx, &k.0, &k.1)?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    store.tool_pool.stop_key(&key);
    Ok(
        json!({"source": source, "capability": body.capability, "revoked": revoked, "deleted": true}),
    )
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/sources/{agent}/{server}/login", post(login_route))
        .route("/v1/sources/{agent}/{server}/logout", post(logout_route))
        .route("/v1/oauth/logins/{login_id}/complete", post(complete_route))
}
async fn login_route(
    State(store): State<Arc<Store>>,
    Path((agent, server)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: LoginBody = decode(body)?;
    Ok(Json(start(store, agent, server, request).await?))
}
async fn complete_route(
    State(store): State<Arc<Store>>,
    Path(login_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: CompleteBody = decode(body)?;
    Ok(Json(complete(store, login_id, request).await?))
}
async fn logout_route(
    State(store): State<Arc<Store>>,
    Path((agent, server)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: LogoutBody = decode(body)?;
    Ok(Json(logout(store, agent, server, request).await?))
}

/// The capabilities whose credential is a source's own sign-in.
pub(crate) fn source_sign_in_users(
    conn: &Connection,
    agent: &str,
    server: &str,
) -> Result<Vec<String>, Error> {
    Ok(capability_records(conn)?
        .into_iter()
        .filter(|c| c.agent_id == agent && c.source.server == server && !c.own_sign_in)
        .map(|c| c.name)
        .collect())
}
