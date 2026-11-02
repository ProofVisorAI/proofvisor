//! TypeSafe's Jev model as a judge, through its System One API.
//!
//! Built from TypeSafe's published reference (`docs.typesafe.ai`, the
//! OpenAPI document at `api.typesafe.ai/openapi.json`): one
//! `POST /v1/systemone` per predicate, with a bearer key.
//!
//! * `state` is the request rendered by [`crate::render::render_request`]
//!   after redaction: the operator's context first, the validated
//!   arguments last and capped, never the prompt.
//! * `questions` holds one `choice` question whose options are the
//!   predicate's labels and whose instructions are its description.
//! * The answer's `probabilities` become the verdict, through the same
//!   validation as every other adapter: a missing, extra or duplicate
//!   label is a malformed answer, never a partial verdict.
//!
//! Model pin: TypeSafe names releases (`jev-1.14.0`) and reports in each
//! answer the versioned id that produced it, but publishes no weight
//! hash. The pin therefore covers the version name only: its
//! `weights_sha256` is derived from that name ([`derived_weights_sha256`]),
//! a moving alias (`jev-latest`, `jev-preview`) is refused, and an answer
//! from any other version fails as a model mismatch. A weight change
//! under an unchanged version name cannot be detected.
//!
//! This is a second path by which data leaves the harness, like the
//! generic cloud contract: the harness requires a per-tool opt-in and
//! redacts before sending. No request header that widens what TypeSafe
//! accepts (images, long context) is ever sent, and nothing is retried:
//! the runner's deadline bounds each call.

use crate::adapter::{AdapterKind, BoxFuture, JudgeAdapter, JudgeError};
use crate::cloud::{validate_endpoint, RedactionTarget, Redactor, MAX_RESPONSE_BYTES};
use crate::model::{sha256_hex, JudgeRequest, ModelPin, RawScores, SessionContext};
use crate::predicate::PredicateDef;
use crate::render::render_request;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

/// TypeSafe's System One endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";

/// The question id used in every request.
const QUESTION: &str = "verdict";

/// The pin's `weights_sha256` for a TypeSafe model version: the SHA-256
/// of `typesafe:<version>`. It identifies the version name, not weights.
pub fn derived_weights_sha256(version: &str) -> String {
    sha256_hex(format!("typesafe:{version}").as_bytes())
}

/// Whether `version` names one fixed release (`jev-1.14.0`) rather than
/// an alias that moves (`jev-latest`, `jev-preview`).
pub fn is_fixed_version(version: &str) -> bool {
    let Some((family, number)) = version.rsplit_once('-') else {
        return false;
    };
    let parts: Vec<&str> = number.split('.').collect();
    !family.is_empty()
        && family
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// TypeSafe judge settings.
#[derive(Clone)]
pub struct TypeSafeJudgeConfig {
    /// Endpoint (`https`, or `http` to a loopback address for a stand-in).
    pub endpoint: url::Url,
    /// API key.
    pub api_key: Zeroizing<String>,
    /// Model name recorded in the pin (for example `jev`).
    pub model_name: String,
    /// The fixed model version to request and accept (`jev-1.14.0`).
    pub model_version: String,
    /// Transport timeout (the runner's deadline applies as well).
    pub timeout: Duration,
}

/// The TypeSafe judge.
pub struct TypeSafeJudge {
    client: reqwest::Client,
    endpoint: url::Url,
    api_key: Zeroizing<String>,
    pin: ModelPin,
    redactor: Option<Redactor>,
}

#[derive(Deserialize)]
struct WireResponse {
    model: String,
    answers: BTreeMap<String, WireAnswer>,
}

#[derive(Deserialize)]
struct WireAnswer {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    probabilities: Option<BTreeMap<String, f64>>,
}

impl TypeSafeJudge {
    /// Build a client for `config`.
    ///
    /// # Errors
    ///
    /// When the version is an alias or malformed, the endpoint is not
    /// `https` (or loopback `http`), the key is empty, or the timeout is
    /// zero.
    pub fn new(config: TypeSafeJudgeConfig) -> Result<Self, String> {
        if !is_fixed_version(&config.model_version) {
            return Err(format!(
                "TypeSafe model version {:?} is not a fixed release (such as jev-1.14.0); \
                 aliases like jev-latest move without notice and cannot be pinned",
                config.model_version
            ));
        }
        validate_endpoint(&config.endpoint)?;
        if config.api_key.trim().is_empty() {
            return Err("TypeSafe API key is empty".to_owned());
        }
        // An HTTP header cannot carry a line break, and a key never holds
        // spaces: a key file with a second line or a label around the key
        // otherwise failed every call with an unexplained request error.
        if !config.api_key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(
                "TypeSafe API key must be one token of printable characters with no spaces or line \
                 breaks; the key file seems to hold more than the key"
                    .to_owned(),
            );
        }
        if config.timeout.is_zero() {
            return Err("TypeSafe judge timeout must be above zero".to_owned());
        }
        let pin = ModelPin::new(
            config.model_name,
            config.model_version.clone(),
            derived_weights_sha256(&config.model_version),
        )?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .build()
            .map_err(|_| "TypeSafe judge HTTP client could not be built".to_owned())?;
        Ok(Self {
            client,
            endpoint: config.endpoint,
            api_key: config.api_key,
            pin,
            redactor: None,
        })
    }

    /// Redact the arguments and the context of every request with
    /// `redactor` before it is rendered and sent.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = Some(redactor);
        self
    }

    /// The System One request body for `request`.
    fn body(&self, request: &JudgeRequest, predicate: &PredicateDef) -> Result<Value, JudgeError> {
        if let Some(error) = crate::render::arguments_too_long(request) {
            return Err(error);
        }
        let mut redacted = request.clone();
        if let Some(redact) = &self.redactor {
            redact(&mut redacted.validated_args, RedactionTarget::Arguments);
            let mut context = serde_json::to_value(&redacted.context)
                .map_err(|_| JudgeError::Unavailable("judge context is not serializable".to_owned()))?;
            redact(&mut context, RedactionTarget::Context);
            redacted.context = serde_json::from_value::<SessionContext>(context)
                .map_err(|_| JudgeError::Unavailable("redacted judge context is invalid".to_owned()))?;
        }
        let criteria: serde_json::Map<String, Value> = predicate
            .labels
            .iter()
            .map(|label| (label.clone(), Value::Null))
            .collect();
        Ok(serde_json::json!({
            "model": self.pin.version,
            "state": render_request(&redacted),
            "questions": {
                QUESTION: {
                    "type": "choice",
                    "instructions": format!(
                        "{} The state lists the operator's context for one tool call (predicate, \
                         tool, intent, task, missions, allowed intents, charter, delegation depth, \
                         earlier refusals) and then the call's arguments. Choose the label that \
                         answers the question for these arguments.",
                        predicate.description
                    ),
                    "criteria": criteria,
                }
            }
        }))
    }

    async fn call(&self, request: &JudgeRequest, predicate: &PredicateDef) -> Result<RawScores, JudgeError> {
        let body = self.body(request, predicate)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.api_key.as_str())
            .json(&body)
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        if !status.is_success() {
            // 401 (key), 429 (rate limit), 529 (overload), 4xx, 5xx: all
            // are an unavailable judge. The body may echo input; it is
            // not read.
            return Err(JudgeError::Unavailable(format!(
                "TypeSafe answered HTTP {}",
                status.as_u16()
            )));
        }
        let bytes = read_limited(response).await?;
        let wire: WireResponse = serde_json::from_slice(&bytes)
            .map_err(|_| JudgeError::Malformed("TypeSafe response is not a System One answer".to_owned()))?;
        let answer = wire.answers.get(QUESTION).ok_or_else(|| {
            JudgeError::Malformed("TypeSafe response has no answer to the question".to_owned())
        })?;
        if answer.kind != "choice" {
            return Err(JudgeError::Malformed(format!(
                "TypeSafe answered a {:?} question, expected choice",
                answer.kind
            )));
        }
        let probabilities = answer
            .probabilities
            .as_ref()
            .ok_or_else(|| JudgeError::Malformed("TypeSafe choice answer has no probabilities".to_owned()))?;
        // Every reported label, in the predicate's order first, so the
        // shared validation sees missing and extra labels alike.
        let mut probs: Vec<(String, f64)> = predicate
            .labels
            .iter()
            .filter_map(|label| probabilities.get(label).map(|p| (label.clone(), *p)))
            .collect();
        probs.extend(
            probabilities
                .iter()
                .filter(|(label, _)| !predicate.has_label(label))
                .map(|(label, p)| (label.clone(), *p)),
        );
        let model = ModelPin {
            name: self.pin.name.clone(),
            weights_sha256: derived_weights_sha256(&wire.model),
            version: wire.model,
        };
        Ok(RawScores { probs, model })
    }
}

impl JudgeAdapter for TypeSafeJudge {
    fn id(&self) -> &ModelPin {
        &self.pin
    }

    /// Recorded as `cloud`: TypeSafe is a cloud judge, and the record
    /// format stays readable by earlier builds. The adapter's name and
    /// the model pin identify the vendor.
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

fn transport_error(error: reqwest::Error) -> JudgeError {
    if error.is_timeout() {
        JudgeError::Timeout
    } else if error.is_connect() {
        JudgeError::Unavailable("TypeSafe connection failed".to_owned())
    } else if error.is_builder() {
        JudgeError::Unavailable("TypeSafe request could not be built".to_owned())
    } else {
        JudgeError::Unavailable("TypeSafe request failed".to_owned())
    }
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, JudgeError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(JudgeError::Malformed("TypeSafe response is too large".to_owned()));
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
    fn only_fixed_releases_can_be_pinned() {
        assert!(is_fixed_version("jev-1.14.0"));
        assert!(is_fixed_version("jev-1.13.0"));
        assert!(!is_fixed_version("jev-latest"));
        assert!(!is_fixed_version("jev-preview"));
        assert!(!is_fixed_version("jev-1.14"));
        assert!(!is_fixed_version("1.14.0"));
        assert!(!is_fixed_version("jev-1.14.0-rc"));
        assert!(!is_fixed_version("JEV-1.14.0"));
        assert_ne!(
            derived_weights_sha256("jev-1.14.0"),
            derived_weights_sha256("jev-1.13.0")
        );
        assert_eq!(derived_weights_sha256("jev-1.14.0").len(), 64);
    }
}
