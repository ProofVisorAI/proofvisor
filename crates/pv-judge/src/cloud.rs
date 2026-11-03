//! Cloud judge: a generic HTTP contract, `proofvisor.judge.v1`.
//!
//! This is a second path by which data leaves the harness (today the
//! harness forwards only the upstream call), so the harness lets each
//! tool opt in separately, applies its redaction engine to the request
//! first, and records the adapter kind in every verdict. It is not any
//! vendor's API: a vendor is integrated by putting a small translator
//! in front of it, or by the vendor speaking this contract.
//!
//! Request (`POST`, `application/json`):
//!
//! ```json
//! {"contract":"proofvisor.judge.v1",
//!  "predicate":{"id":"arg_matches_task@1","labels":["match","mismatch"]},
//!  "tool":"db_write","arguments":{"table":"orders"},
//!  "context":{"charter":"billing-agent","delegation_depth":0}}
//! ```
//!
//! Response (2xx, `application/json`, at most 64 KiB):
//!
//! ```json
//! {"model":{"name":"vendor-judge","version":"2026-10","weights_sha256":"<64 hex>"},
//!  "probs":[{"label":"match","p":0.18},{"label":"mismatch","p":0.82}]}
//! ```
//!
//! The reported model must equal the pin or the call fails as a model
//! mismatch. Redirects are not followed. Errors never include the URL.

use crate::adapter::{AdapterKind, BoxFuture, JudgeAdapter, JudgeError};
use crate::model::{JudgeRequest, ModelPin, RawScores};
use crate::predicate::PredicateDef;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Contract identifier sent with every request.
pub const CONTRACT: &str = "proofvisor.judge.v1";
/// Largest accepted response body.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Which part of a request a [`Redactor`] is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionTarget {
    /// The caller's tool arguments (or a recorded output): user data, so
    /// numbers and object keys are redacted too.
    Arguments,
    /// The operator's context: its numeric fields must stay numbers.
    Context,
}

/// A function that redacts a JSON value in place before it leaves.
pub type Redactor = Arc<dyn Fn(&mut Value, RedactionTarget) + Send + Sync>;

/// Cloud judge settings.
#[derive(Clone)]
pub struct CloudJudgeConfig {
    /// Endpoint. `https`, or `http` to a loopback address only.
    pub endpoint: url::Url,
    /// Bearer token, if the endpoint needs one.
    pub bearer: Option<Zeroizing<String>>,
    /// The model the endpoint must report.
    pub pin: ModelPin,
    /// Transport timeout (the runner's deadline applies as well).
    pub timeout: Duration,
}

/// The cloud judge.
pub struct CloudJudge {
    client: reqwest::Client,
    endpoint: url::Url,
    bearer: Option<Zeroizing<String>>,
    pin: ModelPin,
    redactor: Option<Redactor>,
}

#[derive(Deserialize)]
struct WireResponse {
    model: ModelPin,
    probs: Vec<WireProb>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProb {
    label: String,
    p: f64,
}

impl CloudJudge {
    /// Build a client for `config`.
    pub fn new(config: CloudJudgeConfig) -> Result<Self, String> {
        config.pin.validate()?;
        validate_endpoint(&config.endpoint)?;
        if config.timeout.is_zero() {
            return Err("cloud judge timeout must be above zero".to_owned());
        }
        // A token file with a second line or a label around the token
        // would fail every call with an unexplained request error.
        if config
            .bearer
            .as_ref()
            .is_some_and(|token| token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(
                "cloud judge bearer token must be one token of printable characters with no spaces or \
                 line breaks; the token file seems to hold more than the token"
                    .to_owned(),
            );
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .build()
            .map_err(|_| "cloud judge HTTP client could not be built".to_owned())?;
        Ok(Self {
            client,
            endpoint: config.endpoint,
            bearer: config.bearer,
            pin: config.pin,
            redactor: None,
        })
    }

    /// Redact every request with `redactor` before it is sent.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = Some(redactor);
        self
    }

    async fn call(&self, request: &JudgeRequest, predicate: &PredicateDef) -> Result<RawScores, JudgeError> {
        let mut body = serde_json::json!({
            "contract": CONTRACT,
            "predicate": { "id": predicate.id, "labels": predicate.labels },
            "tool": request.tool,
            "arguments": request.validated_args,
            "context": request.context,
        });
        if let Some(redact) = &self.redactor {
            if let Some(arguments) = body.get_mut("arguments") {
                redact(arguments, RedactionTarget::Arguments);
            }
            if let Some(context) = body.get_mut("context") {
                redact(context, RedactionTarget::Context);
            }
        }
        let mut builder = self.client.post(self.endpoint.clone()).json(&body);
        if let Some(token) = &self.bearer {
            builder = builder.bearer_auth(token.as_str());
        }
        let response = builder.send().await.map_err(transport_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(JudgeError::Unavailable(format!(
                "cloud judge answered HTTP {}",
                status.as_u16()
            )));
        }
        let bytes = read_limited(response).await?;
        let wire: WireResponse = serde_json::from_slice(&bytes)
            .map_err(|_| JudgeError::Malformed("cloud judge response is not the v1 contract".to_owned()))?;
        Ok(RawScores {
            probs: wire.probs.into_iter().map(|p| (p.label, p.p)).collect(),
            model: wire.model,
        })
    }
}

impl JudgeAdapter for CloudJudge {
    fn id(&self) -> &ModelPin {
        &self.pin
    }

    fn redact_text(&self, text: &mut String) {
        if let Some(redact) = &self.redactor {
            let mut value = Value::String(std::mem::take(text));
            redact(&mut value, RedactionTarget::Arguments);
            *text = match value {
                Value::String(redacted) => redacted,
                other => other.to_string(),
            };
        }
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Cloud
    }

    fn score<'a>(
        &'a self,
        request: &'a JudgeRequest,
        predicate: &'a PredicateDef,
    ) -> BoxFuture<'a, Result<RawScores, JudgeError>> {
        Box::pin(self.call(request, predicate))
    }
}

/// `https` anywhere; plain `http` only to a loopback address (a local
/// translator or a test double).
pub fn validate_endpoint(endpoint: &url::Url) -> Result<(), String> {
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("cloud judge endpoint must not embed credentials; use bearer_file".to_owned());
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(endpoint) => Ok(()),
        "http" => {
            Err("cloud judge endpoint must use https (plain http is accepted for loopback only)".to_owned())
        }
        other => Err(format!("cloud judge endpoint scheme {other:?} is not supported")),
    }
}

fn is_loopback(endpoint: &url::Url) -> bool {
    match endpoint.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn transport_error(error: reqwest::Error) -> JudgeError {
    if error.is_timeout() {
        JudgeError::Timeout
    } else if error.is_connect() {
        JudgeError::Unavailable("cloud judge connection failed".to_owned())
    } else {
        JudgeError::Unavailable("cloud judge request failed".to_owned())
    }
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, JudgeError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(JudgeError::Malformed(
                "cloud judge response is too large".to_owned(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn bearer_tokens_must_be_one_printable_token() {
        let build = |token: &str| {
            CloudJudge::new(CloudJudgeConfig {
                endpoint: url::Url::parse("https://judge.example.com/v1/score").unwrap(),
                bearer: Some(Zeroizing::new(token.to_owned())),
                pin: ModelPin::new("m", "1", "a".repeat(64)).unwrap(),
                timeout: Duration::from_secs(1),
            })
        };
        assert!(build("tok_0123456789").is_ok());
        for bad in ["", "tok\nsecond", "Bearer tok", "tok\u{2026}"] {
            assert!(build(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn endpoints_need_tls_except_on_loopback() {
        let check = |raw: &str| validate_endpoint(&url::Url::parse(raw).unwrap());
        assert!(check("https://judge.example.com/v1/score").is_ok());
        assert!(check("http://127.0.0.1:9000/score").is_ok());
        assert!(check("http://[::1]:9000/score").is_ok());
        assert!(check("http://localhost:9000/score").is_ok());
        assert!(check("http://judge.example.com/score").is_err());
        assert!(check("ftp://judge.example.com/").is_err());
        assert!(check("https://user:pass@judge.example.com/").is_err());
    }
}
