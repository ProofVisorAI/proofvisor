//! Console-pushed policy, layered on top of the local sandbox config.
//!
//! The console publishes a policy bundle; `pvctl console-sync
//! --pull-policies` hands it to the daemon, which compiles it into one
//! [`PushedRules`] value and swaps it into the running [`crate::Sandbox`].
//! Pushed rules only ever add restrictions:
//!
//! * budgets are merged with [`BudgetSpec::tightened_by`], so the
//!   stricter cap wins on every dimension;
//! * allowlist rules run after the local policy chain, so a call must
//!   pass both;
//! * schema rules run after the local schema, so arguments must satisfy
//!   both;
//! * guardrail rules (deny patterns over tool arguments, chat requests
//!   or model responses) run after everything local, so they can only
//!   refuse;
//! * transform rules (redaction of tool arguments or chat requests) run
//!   before the verdict, so the rewritten text is what every local gate
//!   sees, what is journaled, and what is forwarded.
//!
//! A compromised console can therefore block calls the host allows, but
//! it can never let through a call the host's own config refuses.

use std::collections::HashSet;

use pv_state::BudgetSpec;
use serde_json::Value;

/// A tool-name pattern taken from a policy scope (`tool.*`,
/// `tool.create_payment`, `tool.payments.*`). `*` matches any run of
/// characters, including none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPattern {
    parts: Vec<String>,
}

impl ToolPattern {
    /// Parse a policy scope. Returns `None` for scopes that do not name
    /// tools (`llm.request`, `llm.egress`, …): the daemon cannot apply a
    /// tool rule to them and reports the policy as unsupported instead of
    /// guessing.
    pub fn from_scope(scope: &str) -> Option<Self> {
        let scope = scope.trim();
        let rest = if scope == "tool" {
            "*"
        } else {
            let rest = scope.strip_prefix("tool.")?;
            if rest.is_empty() {
                "*"
            } else {
                rest
            }
        };
        Some(Self {
            parts: rest.split('*').map(str::to_owned).collect(),
        })
    }

    /// True when `tool` matches the pattern.
    pub fn matches(&self, tool: &str) -> bool {
        let Some((first, rest)) = self.parts.split_first() else {
            return false;
        };
        let Some(mut remaining) = tool.strip_prefix(first.as_str()) else {
            return false;
        };
        let Some((last, middle)) = rest.split_last() else {
            // No `*` at all: the whole name must have matched.
            return remaining.is_empty();
        };
        for part in middle {
            match remaining.find(part.as_str()) {
                Some(index) => remaining = remaining.get(index + part.len()..).unwrap_or_default(),
                None => return false,
            }
        }
        remaining.ends_with(last.as_str())
    }
}

/// One pushed allowlist policy, limited to the tools its scope names.
#[derive(Debug, Clone)]
pub struct PushedAllowlist {
    /// Console policy name, recorded as the blocking policy.
    pub policy: String,
    /// Which tools the rule applies to.
    pub scope: ToolPattern,
    /// When set, only these tools may run (within the scope).
    pub allow_only: Option<HashSet<String>>,
    /// These tools never run.
    pub deny: HashSet<String>,
}

impl PushedAllowlist {
    /// The reason a call to `tool` is refused, if it is.
    pub fn refuses(&self, tool: &str) -> Option<String> {
        if !self.scope.matches(tool) {
            return None;
        }
        if self.deny.contains(tool) {
            return Some(format!("tool {tool:?} is deny-listed"));
        }
        match &self.allow_only {
            Some(allowed) if !allowed.contains(tool) => Some(format!("tool {tool:?} is not allow-listed")),
            _ => None,
        }
    }
}

/// One pushed argument schema for one tool.
pub struct PushedSchema {
    /// Console policy name, recorded as the blocking policy.
    pub policy: String,
    /// The tool whose arguments are validated.
    pub tool: String,
    validator: jsonschema::Validator,
}

impl std::fmt::Debug for PushedSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedSchema")
            .field("policy", &self.policy)
            .field("tool", &self.tool)
            .finish_non_exhaustive()
    }
}

/// Refuses every external `$ref`. A pushed schema comes from the console,
/// over the network; with jsonschema's default retriever a reference such
/// as `http://169.254.169.254/…` or `file:///etc/…` would make the daemon
/// fetch an address inside the customer's network, or read a local file,
/// and report what it found back to the console in the policy status.
/// References inside the schema itself (`#/$defs/…`) need no retrieval
/// and keep working.
struct NoExternalRefs;

impl jsonschema::Retrieve for NoExternalRefs {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!(
            "pushed schemas may not reference external documents ({})",
            uri.scheme().as_str()
        )
        .into())
    }
}

impl PushedSchema {
    /// Compile a schema the same way local tool schemas are compiled
    /// (draft 2020-12 with `format` enforced), except that external
    /// references are refused (see `NoExternalRefs`).
    pub fn compile(policy: &str, tool: &str, schema: &Value) -> Result<Self, String> {
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .with_retriever(NoExternalRefs)
            .build(schema)
            .map_err(|e| format!("json_schema does not compile: {e}"))?;
        Ok(Self {
            policy: policy.to_owned(),
            tool: tool.to_owned(),
            validator,
        })
    }

    /// Up to three validation errors for `arguments` (bounded work).
    pub fn errors(&self, arguments: &Value) -> Vec<String> {
        self.validator
            .iter_errors(arguments)
            .take(3)
            .map(|e| e.to_string())
            .collect()
    }
}

/// Where a pushed guardrail's deny patterns are matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardrailTarget {
    /// Every string value in the arguments of a tool call.
    ToolArgs,
    /// Every string value under `messages` of a chat request.
    LlmIngress,
    /// The text of a model response (every choice's content), checked as
    /// it is captured: a buffered response is refused before any byte
    /// reaches the client, a streamed one is cut at the first matching
    /// frame.
    LlmEgress,
}

impl GuardrailTarget {
    /// Parse the spec's `applies_to`.
    pub fn parse(applies_to: &str) -> Result<Self, String> {
        match applies_to {
            "tool.args" => Ok(Self::ToolArgs),
            "llm.ingress" => Ok(Self::LlmIngress),
            "llm.egress" => Ok(Self::LlmEgress),
            other => Err(format!(
                "applies_to {other:?} is not tool.args, llm.ingress or llm.egress"
            )),
        }
    }
}

/// Upper bound on patterns per guardrail (the console enforces the same).
pub const MAX_GUARDRAIL_PATTERNS: usize = 64;

/// One pushed guardrail: a set of deny patterns over the text an agent
/// sends. Patterns are compiled with the same bounds as the daemon's own
/// `redaction_patterns` ([`pv_redact::compile_pattern`]).
pub struct PushedGuardrail {
    /// Console policy name, recorded as the blocking policy.
    pub policy: String,
    /// What the patterns are matched against.
    pub target: GuardrailTarget,
    /// For [`GuardrailTarget::ToolArgs`], which tools the rule covers.
    pub scope: Option<ToolPattern>,
    patterns: Vec<regex::Regex>,
}

impl std::fmt::Debug for PushedGuardrail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedGuardrail")
            .field("policy", &self.policy)
            .field("target", &self.target)
            .field("scope", &self.scope)
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

/// Where a guardrail matched: which pattern (1-based, as the console
/// lists them) and the JSON pointer of the value. The matched text is
/// deliberately not recorded anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailHit {
    /// 1-based index of the pattern in `deny_patterns`.
    pub pattern: usize,
    /// How many patterns the policy has.
    pub of: usize,
    /// JSON pointer of the string value that matched.
    pub pointer: String,
}

impl PushedGuardrail {
    /// Compile a guardrail. `scope` is required for `tool.args` (it names
    /// the tools) and ignored otherwise.
    pub fn compile(
        policy: &str,
        target: GuardrailTarget,
        scope: Option<ToolPattern>,
        deny_patterns: &[String],
    ) -> Result<Self, String> {
        if deny_patterns.is_empty() {
            return Err("deny_patterns needs at least one pattern".to_owned());
        }
        if deny_patterns.len() > MAX_GUARDRAIL_PATTERNS {
            return Err(format!(
                "deny_patterns holds {} patterns; at most {MAX_GUARDRAIL_PATTERNS} are allowed",
                deny_patterns.len()
            ));
        }
        if target == GuardrailTarget::ToolArgs && scope.is_none() {
            return Err("a tool.args guardrail needs a tool scope".to_owned());
        }
        let patterns = deny_patterns
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                pv_redact::compile_pattern(raw)
                    .map_err(|error| format!("deny pattern {} does not compile: {error}", index + 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            policy: policy.to_owned(),
            target,
            scope,
            patterns,
        })
    }

    /// The first string value under `value` that a pattern matches.
    /// Strings are visited depth first; keys are not matched.
    pub fn first_hit(&self, value: &Value) -> Option<GuardrailHit> {
        let mut pointer = String::new();
        self.walk(value, &mut pointer)
    }

    fn walk(&self, value: &Value, pointer: &mut String) -> Option<GuardrailHit> {
        match value {
            Value::String(text) => self
                .patterns
                .iter()
                .position(|pattern| pattern.is_match(text))
                .map(|index| GuardrailHit {
                    pattern: index + 1,
                    of: self.patterns.len(),
                    pointer: pointer.clone(),
                }),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let len = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&index.to_string());
                    let hit = self.walk(item, pointer);
                    pointer.truncate(len);
                    if hit.is_some() {
                        return hit;
                    }
                }
                None
            }
            Value::Object(fields) => {
                for (key, item) in fields {
                    let len = pointer.len();
                    pointer.push('/');
                    // RFC 6901 escaping, so the pointer in a refusal is exact.
                    pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                    let hit = self.walk(item, pointer);
                    pointer.truncate(len);
                    if hit.is_some() {
                        return hit;
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// The reason a call to `tool` with `arguments` is refused, if it is.
    pub fn refuses_tool_call(&self, tool: &str, arguments: &Value) -> Option<String> {
        if self.target != GuardrailTarget::ToolArgs || !self.scope.as_ref()?.matches(tool) {
            return None;
        }
        let hit = self.first_hit(arguments)?;
        Some(format!(
            "tool arguments match deny pattern {} of {} (at {})",
            hit.pattern, hit.of, hit.pointer
        ))
    }

    /// The reason a chat request `payload` is refused, if it is. Only
    /// the `messages` array is inspected.
    pub fn refuses_chat(&self, payload: &Value) -> Option<String> {
        if self.target != GuardrailTarget::LlmIngress {
            return None;
        }
        let messages = payload.get("messages")?;
        let hit = self.first_hit(messages)?;
        Some(format!(
            "chat content matches deny pattern {} of {} (at /messages{})",
            hit.pattern, hit.of, hit.pointer
        ))
    }

    /// True for a rule over model responses.
    pub fn inspects_responses(&self) -> bool {
        self.target == GuardrailTarget::LlmEgress
    }

    /// The reason a model response whose captured text is `text` is
    /// refused, if it is. Only the pattern position is reported, never
    /// the matched text.
    pub fn refuses_response(&self, text: &str) -> Option<String> {
        self.refuses_response_part(text, "response")
    }

    /// Like [`Self::refuses_response`] for one part of a response:
    /// `what` names it in the reason (`response`, `reasoning`,
    /// `tool call`).
    pub fn refuses_response_part(&self, text: &str, what: &str) -> Option<String> {
        if self.target != GuardrailTarget::LlmEgress {
            return None;
        }
        let index = self.patterns.iter().position(|pattern| pattern.is_match(text))?;
        Some(format!(
            "model {what} matches deny pattern {} of {}",
            index + 1,
            self.patterns.len()
        ))
    }
}

/// Where a pushed transform rewrites text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformTarget {
    /// Every string value in the arguments of a tool call.
    ToolArgs,
    /// Every string value under `messages` of a chat request.
    LlmIngress,
    /// The text of a model response: every choice's content, reasoning
    /// and tool-call arguments, rewritten before the response is
    /// journaled or relayed.
    LlmEgress,
}

impl TransformTarget {
    /// Parse the spec's `applies_to`.
    pub fn parse(applies_to: &str) -> Result<Self, String> {
        match applies_to {
            "tool.args" => Ok(Self::ToolArgs),
            "llm.ingress" => Ok(Self::LlmIngress),
            "llm.egress" => Ok(Self::LlmEgress),
            other => Err(format!(
                "applies_to {other:?} is not tool.args, llm.ingress or llm.egress"
            )),
        }
    }
}

/// Upper bound on patterns per transform (the console enforces the same).
pub const MAX_TRANSFORM_PATTERNS: usize = 64;
/// Upper bound on the replacement text, in bytes.
pub const MAX_TRANSFORM_REPLACEMENT_BYTES: usize = 64;
/// What a match is replaced with when the spec names no replacement.
pub const DEFAULT_TRANSFORM_REPLACEMENT: &str = "[REDACTED]";

/// One pushed transform: every match of its patterns in the text an
/// agent sends is replaced before the verdict is taken, before anything
/// is journaled, and before the call is forwarded. Patterns are compiled
/// with the same bounds as the daemon's own `redaction_patterns`.
pub struct PushedTransform {
    /// Console policy name, recorded with every rewrite.
    pub policy: String,
    /// What the patterns are matched against.
    pub target: TransformTarget,
    /// For [`TransformTarget::ToolArgs`], which tools the rule covers.
    pub scope: Option<ToolPattern>,
    patterns: Vec<regex::Regex>,
    replacement: String,
}

impl std::fmt::Debug for PushedTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedTransform")
            .field("policy", &self.policy)
            .field("target", &self.target)
            .field("scope", &self.scope)
            .field("patterns", &self.patterns.len())
            .field("replacement", &self.replacement)
            .finish()
    }
}

impl PushedTransform {
    /// Compile a transform. `scope` is required for `tool.args` (it
    /// names the tools) and ignored otherwise; `replacement` defaults to
    /// [`DEFAULT_TRANSFORM_REPLACEMENT`].
    pub fn compile(
        policy: &str,
        target: TransformTarget,
        scope: Option<ToolPattern>,
        redact_patterns: &[String],
        replacement: Option<&str>,
    ) -> Result<Self, String> {
        if redact_patterns.is_empty() {
            return Err("redact_patterns needs at least one pattern".to_owned());
        }
        if redact_patterns.len() > MAX_TRANSFORM_PATTERNS {
            return Err(format!(
                "redact_patterns holds {} patterns; at most {MAX_TRANSFORM_PATTERNS} are allowed",
                redact_patterns.len()
            ));
        }
        if target == TransformTarget::ToolArgs && scope.is_none() {
            return Err("a tool.args transform needs a tool scope".to_owned());
        }
        let replacement = replacement.unwrap_or(DEFAULT_TRANSFORM_REPLACEMENT);
        if replacement.is_empty() || replacement.len() > MAX_TRANSFORM_REPLACEMENT_BYTES {
            return Err(format!(
                "replacement must be 1 to {MAX_TRANSFORM_REPLACEMENT_BYTES} bytes"
            ));
        }
        if replacement.chars().any(char::is_control) {
            return Err("replacement must not contain control characters".to_owned());
        }
        let patterns = redact_patterns
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                pv_redact::compile_pattern(raw)
                    .map_err(|error| format!("redact pattern {} does not compile: {error}", index + 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            policy: policy.to_owned(),
            target,
            scope,
            patterns,
            replacement: replacement.to_owned(),
        })
    }

    /// Replace every match in every string value under `value`; keys
    /// are left alone. Returns how many matches were replaced.
    fn rewrite(&self, value: &mut Value) -> usize {
        match value {
            Value::String(text) => {
                let mut replaced = 0;
                for pattern in &self.patterns {
                    let matches = pattern.find_iter(text).count();
                    if matches > 0 {
                        *text = pattern
                            .replace_all(text, regex::NoExpand(&self.replacement))
                            .into_owned();
                        replaced += matches;
                    }
                }
                replaced
            }
            Value::Array(items) => items.iter_mut().map(|item| self.rewrite(item)).sum(),
            Value::Object(fields) => fields.values_mut().map(|item| self.rewrite(item)).sum(),
            _ => 0,
        }
    }

    /// Rewrite the arguments of a call to `tool`, when the rule covers
    /// it. Returns how many matches were replaced.
    pub fn apply_to_tool_call(&self, tool: &str, arguments: &mut Value) -> usize {
        if self.target != TransformTarget::ToolArgs
            || !self.scope.as_ref().is_some_and(|scope| scope.matches(tool))
        {
            return 0;
        }
        self.rewrite(arguments)
    }

    /// Rewrite the `messages` of a chat request `payload`. Returns how
    /// many matches were replaced.
    pub fn apply_to_chat(&self, payload: &mut Value) -> usize {
        if self.target != TransformTarget::LlmIngress {
            return 0;
        }
        match payload.get_mut("messages") {
            Some(messages) => self.rewrite(messages),
            None => 0,
        }
    }

    /// True for a rule over model responses.
    pub fn rewrites_responses(&self) -> bool {
        self.target == TransformTarget::LlmEgress
    }

    /// Rewrite one piece of response text in place. Returns how many
    /// matches were replaced.
    pub fn apply_to_response_text(&self, text: &mut String) -> usize {
        if self.target != TransformTarget::LlmEgress {
            return 0;
        }
        let mut value = Value::String(std::mem::take(text));
        let replaced = self.rewrite(&mut value);
        if let Value::String(rewritten) = value {
            *text = rewritten;
        }
        replaced
    }
}

/// Everything the daemon applied from one console bundle.
#[derive(Debug, Default)]
pub struct PushedRules {
    /// The bundle etag these rules came from; `None` before any bundle.
    pub etag: Option<String>,
    /// Pushed budget caps (merged with the local budget, stricter wins).
    pub budget: BudgetSpec,
    /// Console names of the budget policies merged into `budget`.
    pub budget_policies: Vec<String>,
    /// Pushed allowlist rules.
    pub allowlists: Vec<PushedAllowlist>,
    /// Pushed argument schemas.
    pub schemas: Vec<PushedSchema>,
    /// Pushed guardrails (deny patterns).
    pub guardrails: Vec<PushedGuardrail>,
    /// Pushed transforms (redaction before forwarding).
    pub transforms: Vec<PushedTransform>,
}

impl PushedRules {
    /// True when any guardrail inspects model responses, so a relay can
    /// skip the scan entirely otherwise.
    pub fn inspects_responses(&self) -> bool {
        self.guardrails.iter().any(PushedGuardrail::inspects_responses)
    }

    /// The first egress guardrail that refuses a response whose captured
    /// text is `text`, as `(policy name, reason)`.
    pub fn refuses_response(&self, text: &str) -> Option<(String, String)> {
        self.refuses_response_part(text, "response")
    }

    /// Like [`Self::refuses_response`] for one part of a response
    /// (`response`, `reasoning`, `tool call`).
    pub fn refuses_response_part(&self, text: &str, what: &str) -> Option<(String, String)> {
        self.guardrails.iter().find_map(|rule| {
            rule.refuses_response_part(text, what)
                .map(|reason| (rule.policy.clone(), format!("policy {:?}: {reason}", rule.policy)))
        })
    }

    /// True when any transform rewrites model responses, so a relay can
    /// skip the rewrite (and keep streaming) otherwise.
    pub fn rewrites_responses(&self) -> bool {
        self.transforms.iter().any(PushedTransform::rewrites_responses)
    }

    /// Apply every `llm.egress` transform to one piece of response text,
    /// in bundle order. Returns `(policy, replacements)` for each rule
    /// that replaced something.
    pub fn rewrite_response_text(&self, text: &mut String) -> Vec<(String, usize)> {
        self.transforms
            .iter()
            .filter_map(|rule| {
                let replacements = rule.apply_to_response_text(text);
                (replacements > 0).then(|| (rule.policy.clone(), replacements))
            })
            .collect()
    }

    /// Which pushed budget policy set the cap a refusal hit, when the
    /// binding cap came from the console rather than the local config.
    /// `limit` is the refusal's limit name (`max_tokens`,
    /// `max_tool_calls.db_write`, …).
    pub fn budget_policy_for(&self, local: &BudgetSpec, limit: &str, cap: u64) -> Option<String> {
        let (pushed, local_cap) = match limit {
            "max_tokens" => (self.budget.max_tokens, local.max_tokens),
            "max_payout_usd_micros" => (self.budget.max_payout_usd_micros, local.max_payout_usd_micros),
            "max_total_tool_calls" => (self.budget.max_total_tool_calls, local.max_total_tool_calls),
            other => {
                let tool = other.strip_prefix("max_tool_calls.")?;
                (
                    self.budget.max_tool_calls.get(tool).copied(),
                    local.max_tool_calls.get(tool).copied(),
                )
            }
        };
        let from_console = pushed == Some(cap) && local_cap.is_none_or(|local_cap| local_cap > cap);
        if from_console && !self.budget_policies.is_empty() {
            Some(self.budget_policies.join(","))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use serde_json::json;

    #[test]
    fn pushed_schemas_never_fetch_external_references() {
        // A listener that would see the daemon's request if it made one.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/schema.json", listener.local_addr().unwrap());
        let err = PushedSchema::compile("p", "t", &json!({"$ref": url})).unwrap_err();
        assert!(err.contains("may not reference external documents"), "{err}");
        assert!(listener.accept().is_err(), "the daemon must not connect anywhere");

        // A custom meta-schema and `$dynamicRef` are resolved the same way.
        let meta = format!("http://{}/meta.json", listener.local_addr().unwrap());
        assert!(PushedSchema::compile("p", "t", &json!({"$schema": meta})).is_err());
        assert!(PushedSchema::compile("p", "t", &json!({"$dynamicRef": url})).is_err());
        // The standard meta-schemas are built in and need no retrieval.
        for draft in [
            "https://json-schema.org/draft/2020-12/schema",
            "https://json-schema.org/draft/2019-09/schema",
            "http://json-schema.org/draft-07/schema#",
            "http://json-schema.org/draft-07/schema",
            "http://json-schema.org/draft-06/schema#",
            "http://json-schema.org/draft-04/schema#",
        ] {
            PushedSchema::compile("p", "t", &json!({"$schema": draft, "type": "object"})).unwrap();
        }
        assert!(listener.accept().is_err(), "the daemon must not connect anywhere");

        let file = std::env::temp_dir().join(format!("pv-pushed-ref-{}.json", std::process::id()));
        std::fs::write(&file, r#"{"type":"object"}"#).unwrap();
        // A valid file URL on every platform: `file:///C:/…` on Windows.
        let path = file.display().to_string().replace('\\', "/");
        let file_ref = if path.starts_with('/') {
            format!("file://{path}")
        } else {
            format!("file:///{path}")
        };
        let err = PushedSchema::compile("p", "t", &json!({"$ref": file_ref})).unwrap_err();
        let _ = std::fs::remove_file(&file);
        assert!(err.contains("may not reference external documents"), "{err}");

        // References inside the schema need no retrieval.
        let local = PushedSchema::compile(
            "p",
            "t",
            &json!({"$defs": {"amount": {"type": "integer", "maximum": 10}}, "properties": {"n": {"$ref": "#/$defs/amount"}}}),
        )
        .unwrap();
        assert!(local.errors(&json!({"n": 5})).is_empty());
        assert!(!local.errors(&json!({"n": 50})).is_empty());
    }

    #[test]
    fn egress_guardrails_match_response_text_and_name_only_the_pattern() {
        let rule = PushedGuardrail::compile(
            "privacy.no_internal_codenames",
            GuardrailTarget::LlmEgress,
            None,
            &["(?i)project\\s+nightjar".to_owned(), "ACME-INTERNAL".to_owned()],
        )
        .unwrap();
        assert!(rule.inspects_responses());
        assert_eq!(
            rule.refuses_response("The plan for Project Nightjar is")
                .as_deref(),
            Some("model response matches deny pattern 1 of 2")
        );
        assert_eq!(
            rule.refuses_response("tag ACME-INTERNAL here").as_deref(),
            Some("model response matches deny pattern 2 of 2")
        );
        assert!(rule.refuses_response("nothing to see").is_none());
        // Ingress and tool rules never look at responses, and an egress
        // rule never looks at requests.
        let ingress =
            PushedGuardrail::compile("p", GuardrailTarget::LlmIngress, None, &["x".to_owned()]).unwrap();
        assert!(!ingress.inspects_responses());
        assert!(ingress.refuses_response("x").is_none());
        assert!(rule
            .refuses_chat(&json!({"messages": [{"content": "ACME-INTERNAL"}]}))
            .is_none());
        assert!(rule
            .refuses_tool_call("t", &json!({"a": "ACME-INTERNAL"}))
            .is_none());

        let mut rules = PushedRules::default();
        assert!(!rules.inspects_responses());
        rules.guardrails.push(rule);
        assert!(rules.inspects_responses());
        let (policy, reason) = rules.refuses_response("ACME-INTERNAL").unwrap();
        assert_eq!(policy, "privacy.no_internal_codenames");
        assert_eq!(
            reason,
            "policy \"privacy.no_internal_codenames\": model response matches deny pattern 2 of 2"
        );
    }

    #[test]
    fn transforms_rewrite_matches_inside_their_target_only() {
        let tool_rule = PushedTransform::compile(
            "privacy.redact_tickets",
            TransformTarget::ToolArgs,
            ToolPattern::from_scope("tool.create_*"),
            &["TCK-[0-9]{4}".to_owned()],
            None,
        )
        .unwrap();
        let mut arguments =
            json!({"title": "see TCK-1234 and TCK-9999", "nested": {"note": "TCK-0001"}, "count": 3});
        assert_eq!(tool_rule.apply_to_tool_call("create_ticket", &mut arguments), 3);
        assert_eq!(
            arguments,
            json!({"title": "see [REDACTED] and [REDACTED]", "nested": {"note": "[REDACTED]"}, "count": 3})
        );
        // A tool outside the scope, and a second pass, change nothing.
        let mut untouched = json!({"title": "TCK-1234"});
        assert_eq!(tool_rule.apply_to_tool_call("delete_ticket", &mut untouched), 0);
        assert_eq!(untouched, json!({"title": "TCK-1234"}));
        assert_eq!(tool_rule.apply_to_tool_call("create_ticket", &mut arguments), 0);

        let chat_rule = PushedTransform::compile(
            "privacy.redact_codenames",
            TransformTarget::LlmIngress,
            None,
            &["(?i)nightjar".to_owned()],
            Some("<codename>"),
        )
        .unwrap();
        let mut payload = json!({"model": "nightjar-1", "messages": [{"role": "user", "content": "Status of NIGHTJAR?"}, {"role": "assistant", "content": [{"type": "text", "text": "Nightjar is on track"}]}]});
        assert_eq!(chat_rule.apply_to_chat(&mut payload), 2);
        assert_eq!(payload["messages"][0]["content"], "Status of <codename>?");
        assert_eq!(
            payload["messages"][1]["content"][0]["text"],
            "<codename> is on track"
        );
        assert_eq!(payload["model"], "nightjar-1", "only messages are rewritten");
        // A replacement with `$` is literal, never a group reference.
        let dollar = PushedTransform::compile(
            "p",
            TransformTarget::LlmIngress,
            None,
            &["(x)".to_owned()],
            Some("$1$0"),
        )
        .unwrap();
        let mut payload = json!({"messages": [{"content": "x"}]});
        assert_eq!(dollar.apply_to_chat(&mut payload), 1);
        assert_eq!(payload["messages"][0]["content"], "$1$0");
    }

    #[test]
    fn transform_specs_are_bounded() {
        let scope = ToolPattern::from_scope("tool.*");
        let err =
            PushedTransform::compile("p", TransformTarget::ToolArgs, scope.clone(), &[], None).unwrap_err();
        assert!(err.contains("at least one"), "{err}");
        let err = PushedTransform::compile("p", TransformTarget::ToolArgs, None, &["x".to_owned()], None)
            .unwrap_err();
        assert!(err.contains("needs a tool scope"), "{err}");
        let err = PushedTransform::compile(
            "p",
            TransformTarget::ToolArgs,
            scope.clone(),
            &["(unclosed".to_owned()],
            None,
        )
        .unwrap_err();
        assert!(err.contains("redact pattern 1 does not compile"), "{err}");
        let err = PushedTransform::compile(
            "p",
            TransformTarget::ToolArgs,
            scope.clone(),
            &["x".to_owned()],
            Some(""),
        )
        .unwrap_err();
        assert!(err.contains("1 to 64 bytes"), "{err}");
        let long = "r".repeat(MAX_TRANSFORM_REPLACEMENT_BYTES + 1);
        assert!(PushedTransform::compile(
            "p",
            TransformTarget::ToolArgs,
            scope.clone(),
            &["x".to_owned()],
            Some(&long)
        )
        .is_err());
        let err = PushedTransform::compile(
            "p",
            TransformTarget::ToolArgs,
            scope,
            &["x".to_owned()],
            Some("a\nb"),
        )
        .unwrap_err();
        assert!(err.contains("control characters"), "{err}");
        let many: Vec<String> = (0..=MAX_TRANSFORM_PATTERNS).map(|i| format!("p{i}")).collect();
        let err = PushedTransform::compile("p", TransformTarget::LlmIngress, None, &many, None).unwrap_err();
        assert!(err.contains("at most 64"), "{err}");
        assert_eq!(
            TransformTarget::parse("llm.egress").unwrap(),
            TransformTarget::LlmEgress
        );
        assert!(TransformTarget::parse("tool.result").is_err());
        assert_eq!(
            GuardrailTarget::parse("llm.egress").unwrap(),
            GuardrailTarget::LlmEgress
        );
    }

    #[test]
    fn egress_transforms_rewrite_response_text_only() {
        let rule = PushedTransform::compile(
            "privacy.redact_answers",
            TransformTarget::LlmEgress,
            None,
            &["TCK-[0-9]{4}".to_owned()],
            Some("[ticket]"),
        )
        .unwrap();
        assert!(rule.rewrites_responses());
        let mut text = "see TCK-1234 and TCK-9999".to_owned();
        assert_eq!(rule.apply_to_response_text(&mut text), 2);
        assert_eq!(text, "see [ticket] and [ticket]");
        assert_eq!(rule.apply_to_response_text(&mut text), 0);
        // Not a request rule: chat and tool payloads are untouched.
        let mut payload = json!({"messages": [{"content": "TCK-1234"}]});
        assert_eq!(rule.apply_to_chat(&mut payload), 0);
        let mut arguments = json!({"a": "TCK-1234"});
        assert_eq!(rule.apply_to_tool_call("create_ticket", &mut arguments), 0);

        let mut rules = PushedRules::default();
        assert!(!rules.rewrites_responses());
        rules.transforms.push(rule);
        rules.transforms.push(
            PushedTransform::compile(
                "privacy.redact_codenames",
                TransformTarget::LlmEgress,
                None,
                &["(?i)nightjar".to_owned()],
                None,
            )
            .unwrap(),
        );
        assert!(rules.rewrites_responses());
        let mut answer = "TCK-0001 is part of Nightjar".to_owned();
        assert_eq!(
            rules.rewrite_response_text(&mut answer),
            vec![
                ("privacy.redact_answers".to_owned(), 1),
                ("privacy.redact_codenames".to_owned(), 1)
            ]
        );
        assert_eq!(answer, "[ticket] is part of [REDACTED]");
        assert!(rules.rewrite_response_text(&mut String::new()).is_empty());
        // Guardrail reasons name the part that matched.
        let guard =
            PushedGuardrail::compile("g", GuardrailTarget::LlmEgress, None, &["x".to_owned()]).unwrap();
        assert_eq!(
            guard.refuses_response_part("x", "reasoning").as_deref(),
            Some("model reasoning matches deny pattern 1 of 1")
        );
    }

    #[test]
    fn scopes_become_tool_patterns() {
        let all = ToolPattern::from_scope("tool.*").unwrap();
        assert!(all.matches("anything") && all.matches(""));
        assert!(ToolPattern::from_scope("tool").unwrap().matches("x"));
        let exact = ToolPattern::from_scope("tool.create_payment").unwrap();
        assert!(exact.matches("create_payment"));
        assert!(!exact.matches("create_payment_v2") && !exact.matches("create"));
        let family = ToolPattern::from_scope("tool.payments.*").unwrap();
        assert!(family.matches("payments.refund") && family.matches("payments."));
        assert!(!family.matches("payment.refund"));
        let middle = ToolPattern::from_scope("tool.db_*_write").unwrap();
        assert!(middle.matches("db_orders_write") && middle.matches("db__write"));
        assert!(!middle.matches("db_orders_read"));
        for scope in ["llm.request", "llm.egress", "*", "", "tools.x"] {
            assert!(ToolPattern::from_scope(scope).is_none(), "{scope}");
        }
    }

    #[test]
    fn allowlists_apply_only_inside_their_scope() {
        let rule = PushedAllowlist {
            policy: "runtime.tools".into(),
            scope: ToolPattern::from_scope("tool.payments.*").unwrap(),
            allow_only: Some(["payments.quote".to_owned()].into_iter().collect()),
            deny: ["payments.wire".to_owned()].into_iter().collect(),
        };
        assert!(rule.refuses("search").is_none(), "outside the scope");
        assert!(rule.refuses("payments.quote").is_none());
        assert!(rule.refuses("payments.wire").unwrap().contains("deny-listed"));
        assert!(rule
            .refuses("payments.refund")
            .unwrap()
            .contains("not allow-listed"));
    }

    #[test]
    fn guardrails_match_string_values_and_never_quote_them() {
        let scope = ToolPattern::from_scope("tool.crm.*").unwrap();
        let rule = PushedGuardrail::compile(
            "privacy.pii_egress",
            GuardrailTarget::ToolArgs,
            Some(scope),
            &[
                r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b".to_owned(),
                "(?i)secret".to_owned(),
            ],
        )
        .unwrap();
        let args =
            json!({"customer": {"name": "Ann", "ssn": "123-45-6789"}, "notes": ["fine", "TOP SECRET"]});
        let reason = rule.refuses_tool_call("crm.update", &args).unwrap();
        assert_eq!(
            reason,
            "tool arguments match deny pattern 1 of 2 (at /customer/ssn)"
        );
        assert!(!reason.contains("6789"), "the matched text is never copied");
        assert_eq!(
            rule.refuses_tool_call("crm.update", &json!({"notes": ["fine", "TOP SECRET"]}))
                .unwrap(),
            "tool arguments match deny pattern 2 of 2 (at /notes/1)"
        );
        assert!(
            rule.refuses_tool_call("search", &args).is_none(),
            "outside the scope"
        );
        assert!(
            rule.refuses_tool_call("crm.update", &json!({"ssn": 123456789}))
                .is_none(),
            "numbers are not text"
        );
        assert!(
            rule.refuses_tool_call("crm.update", &json!({"123-45-6789": "x"}))
                .is_none(),
            "keys are not matched"
        );
        assert!(
            rule.refuses_chat(&json!({"messages": [{"content": "123-45-6789"}]}))
                .is_none(),
            "a tool.args rule ignores chat"
        );
        // Pointer keys are escaped per RFC 6901.
        assert_eq!(
            rule.refuses_tool_call("crm.x", &json!({"a/b": {"c~d": "secret"}}))
                .unwrap(),
            "tool arguments match deny pattern 2 of 2 (at /a~1b/c~0d)"
        );

        let ingress = PushedGuardrail::compile(
            "llm.no_cards",
            GuardrailTarget::LlmIngress,
            None,
            &[r"\b(?:[0-9][ -]?){12,18}[0-9]\b".to_owned()],
        )
        .unwrap();
        let chat = json!({"model": "4111 1111 1111 1111", "messages": [
            {"role": "user", "content": [{"type": "text", "text": "pay with 4111 1111 1111 1111"}]}
        ]});
        assert_eq!(
            ingress.refuses_chat(&chat).unwrap(),
            "chat content matches deny pattern 1 of 1 (at /messages/0/content/0/text)"
        );
        assert!(ingress
            .refuses_chat(&json!({"messages": [{"content": "hello"}]}))
            .is_none());
        assert!(
            ingress
                .refuses_chat(&json!({"model": "4111 1111 1111 1111"}))
                .is_none(),
            "only messages are inspected"
        );
        assert!(
            ingress
                .refuses_tool_call("crm.x", &json!({"n": "4111 1111 1111 1111"}))
                .is_none(),
            "an ingress rule ignores tools"
        );
    }

    #[test]
    fn guardrails_are_bounded_at_compile_time() {
        let scope = || ToolPattern::from_scope("tool.*");
        let compile =
            |patterns: &[String]| PushedGuardrail::compile("p", GuardrailTarget::ToolArgs, scope(), patterns);
        assert!(compile(&[]).unwrap_err().contains("at least one"));
        let many: Vec<String> = (0..=MAX_GUARDRAIL_PATTERNS).map(|i| format!("p{i}")).collect();
        assert!(compile(&many).unwrap_err().contains("at most 64"));
        let err = compile(&["ok".to_owned(), "a".repeat(pv_redact::MAX_PATTERN_BYTES + 1)]).unwrap_err();
        assert!(
            err.starts_with("deny pattern 2 does not compile") && err.contains("at most 512"),
            "{err}"
        );
        let err = compile(&["(unclosed".to_owned()]).unwrap_err();
        assert!(err.starts_with("deny pattern 1 does not compile"), "{err}");
        assert!(
            PushedGuardrail::compile("p", GuardrailTarget::ToolArgs, None, &["x".to_owned()])
                .unwrap_err()
                .contains("tool scope")
        );
        assert!(PushedGuardrail::compile("p", GuardrailTarget::LlmIngress, None, &["x".to_owned()]).is_ok());
        assert_eq!(
            GuardrailTarget::parse("tool.args").unwrap(),
            GuardrailTarget::ToolArgs
        );
        assert_eq!(
            GuardrailTarget::parse("llm.ingress").unwrap(),
            GuardrailTarget::LlmIngress
        );
        assert_eq!(
            GuardrailTarget::parse("llm.egress").unwrap(),
            GuardrailTarget::LlmEgress
        );
        assert!(GuardrailTarget::parse("tool.result").is_err());
    }

    #[test]
    fn pushed_schema_reports_bounded_errors() {
        let schema = PushedSchema::compile(
            "procurement.vendors",
            "create_purchase_order",
            &json!({"type": "object", "required": ["vendor"], "properties": {"vendor": {"enum": ["Contoso"]}}}),
        )
        .unwrap();
        assert!(schema.errors(&json!({"vendor": "Contoso"})).is_empty());
        assert!(!schema.errors(&json!({"vendor": "Initech"})).is_empty());
        assert!(PushedSchema::compile("p", "t", &json!({"type": 12})).is_err());
    }

    #[test]
    fn budget_refusals_name_the_console_policy_only_when_it_set_the_cap() {
        let mut rules = PushedRules {
            budget_policies: vec!["finance.cap".into()],
            ..PushedRules::default()
        };
        rules.budget.max_total_tool_calls = Some(2);
        rules.budget.max_tool_calls.insert("db_write".into(), 1);
        let local = BudgetSpec {
            max_total_tool_calls: Some(10),
            ..BudgetSpec::default()
        };
        assert_eq!(
            rules
                .budget_policy_for(&local, "max_total_tool_calls", 2)
                .as_deref(),
            Some("finance.cap")
        );
        assert_eq!(
            rules
                .budget_policy_for(&local, "max_tool_calls.db_write", 1)
                .as_deref(),
            Some("finance.cap")
        );
        let tighter_local = BudgetSpec {
            max_total_tool_calls: Some(1),
            ..BudgetSpec::default()
        };
        assert!(rules
            .budget_policy_for(&tighter_local, "max_total_tool_calls", 1)
            .is_none());
        assert!(rules.budget_policy_for(&local, "max_tokens", 5).is_none());
    }
}
