//! Strict linking errors, UTC decisions and opt-in conformance barriers.
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Details {
    pub request_id: String,
    pub stage: String,
    pub required_ids: Vec<String>,
    pub next: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: String,
    pub error: String,
    pub details: Box<Details>,
    #[serde(skip)]
    pub retry_after: Option<u64>,
    #[serde(skip)]
    pub authenticated_response: bool,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "linking: {}", self.code)
    }
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    pub fn new(code: &str, request: &str, stage: &str) -> Self {
        Self {
            code: code.into(),
            error: code.replace('_', " "),
            details: Box::new(Details {
                request_id: if request.is_empty() { "-" } else { request }.into(),
                stage: if stage.is_empty() { "-" } else { stage }.into(),
                required_ids: Vec::new(),
                next: Vec::new(),
            }),
            retry_after: None,
            authenticated_response: false,
        }
    }
    pub fn required(request: &str, stage: &str, mut ids: Vec<String>) -> Self {
        ids.sort();
        ids.dedup();
        let mut f = Self::new("proof_required", request, stage);
        f.details.required_ids = ids;
        f
    }
    pub fn cause(e: anyhow::Error, request: &str, stage: &str) -> Self {
        if let Some(f) = e.downcast_ref::<Self>() {
            let mut f = f.clone();
            if f.details.request_id == "-" {
                f.details.request_id = request.into();
            }
            if f.details.stage == "-" {
                f.details.stage = stage.into();
            }
            return f;
        }
        if let Some(p) = e.downcast_ref::<crate::linking::PathError>() {
            let mut f = Self::new(p.code, request, stage);
            f.details.required_ids = p.required_ids.clone();
            return f;
        }
        if let Some(p) = e.downcast_ref::<crate::linking::ActionInvalidation>() {
            let mut f = Self::new("authority_would_be_invalidated", request, stage);
            f.details.required_ids = p.certificate_ids.clone();
            return f;
        }
        if let Some(p) = e.downcast_ref::<crate::model::Error>() {
            if let crate::model::Error::Coded {
                code,
                message,
                extra,
                ..
            } = p
            {
                let mut f = Self::new(code, request, stage);
                f.error = message.clone();
                if let Some(value) = extra.get("details")
                    && let Ok(details) = serde_json::from_value::<Details>(value.clone())
                {
                    f.details = Box::new(details);
                }
                return f;
            }

            let code = match p {
                crate::model::Error::Invalid(_) => "invalid",
                crate::model::Error::Forbidden => "forbidden",
                crate::model::Error::NotFound => "not_found",
                crate::model::Error::Conflict(_) => "state_conflict",
                crate::model::Error::Unavailable(_) => "unavailable",
                _ => "internal",
            };
            return Self::new(code, request, stage);
        }
        Self::new("internal", request, stage)
    }
    pub fn status(&self) -> StatusCode {
        match self.code.as_str() {
            "invalid" => StatusCode::BAD_REQUEST,
            "forbidden"
            | "authority_expired"
            | "device_revoked"
            | "authority_would_be_invalidated" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "operation_conflict" | "state_conflict" | "quota_exceeded" | "proof_required"
            | "recovery_required" => StatusCode::CONFLICT,
            "expired" | "deleted" => StatusCode::GONE,
            "upgrade_required" => StatusCode::UPGRADE_REQUIRED,
            "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
            "unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = self.status();
        let retry = self.retry_after;
        let mut response = (status, Json(self)).into_response();
        if let Some(seconds) = retry
            && let Ok(v) = seconds.to_string().parse()
        {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        response
    }
}

pub fn model_error(error: anyhow::Error) -> crate::model::Error {
    let failure = Failure::cause(error, "-", "catalog");
    let code = match failure.code.as_str() {
        "invalid" => "invalid",
        "forbidden" => "forbidden",
        "proof_required" => "proof_required",
        "state_conflict" => "state_conflict",
        "operation_conflict" => "operation_conflict",
        "authority_expired" => "authority_expired",
        "device_revoked" => "device_revoked",
        "authority_would_be_invalidated" => "authority_would_be_invalidated",
        "upgrade_required" => "upgrade_required",
        "quota_exceeded" => "quota_exceeded",
        "not_found" => "not_found",
        "expired" => "expired",
        "rate_limited" => "rate_limited",
        "unavailable" => "unavailable",
        _ => "internal",
    };
    let mut extra = serde_json::Map::new();
    extra.insert(
        "details".into(),
        serde_json::to_value(&failure.details).unwrap_or(serde_json::Value::Null),
    );
    crate::model::Error::Coded {
        status: failure.status().as_u16(),
        code,
        message: failure.error,
        extra,
    }
}

pub fn stamp(value: &str) -> anyhow::Result<DateTime<Utc>> {
    let t = DateTime::parse_from_rfc3339(value)?.to_utc();
    anyhow::ensure!(
        value.len() == 20
            && t.format("%Y-%m-%dT%H:%M:%SZ").to_string() == value
            && t.timestamp_subsec_nanos() == 0,
        "invalid linking time"
    );
    Ok(t)
}
pub fn now() -> Result<DateTime<Utc>, Failure> {
    if std::env::var("PEERSPAN_LINK_TEST_MODE").as_deref() == Ok("1")
        && let Some(path) =
            std::env::var_os("PEERSPAN_LINK_TEST_CLOCK_FILE").filter(|p| !p.is_empty())
    {
        let raw =
            std::fs::read_to_string(path).map_err(|_| Failure::new("internal", "-", "clock"))?;
        return stamp(raw.strip_suffix('\n').unwrap_or(&raw))
            .map_err(|_| Failure::new("internal", "-", "clock"));
    }
    Ok(DateTime::from_timestamp(crate::clock::now().timestamp(), 0).expect("UTC timestamp"))
}

pub async fn barrier(
    name: &str,
    request: &str,
    cancel: impl std::future::Future<Output = ()>,
) -> Result<(), Failure> {
    if std::env::var("PEERSPAN_LINK_TEST_MODE").as_deref() != Ok("1") {
        return Ok(());
    }
    let Some(dir) = std::env::var_os("PEERSPAN_LINK_TEST_BARRIER_DIR").filter(|p| !p.is_empty())
    else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    match tokio::fs::metadata(dir.join(format!("{name}.arm"))).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Failure::new("internal", request, "barrier")),
        _ => {}
    }
    tokio::fs::write(dir.join(format!("{name}.entered")), request)
        .await
        .map_err(|_| Failure::new("internal", request, "barrier"))?;
    tokio::pin!(cancel);
    loop {
        match tokio::fs::metadata(dir.join(format!("{name}.continue"))).await {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Failure::new("internal", request, "barrier")),
        }
        tokio::select! {
            _=&mut cancel=>return Err(Failure::new("unavailable",request,"barrier")),
            _=tokio::time::sleep(std::time::Duration::from_millis(10))=>{},
        }
    }
}
