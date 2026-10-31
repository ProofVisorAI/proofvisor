//! Console-pushed policy bundles.
//!
//! The daemon never calls the console. `pvctl console-sync --watch
//! --pull-policies`, running on the same host, pulls the org's policy
//! bundle (`GET /api/v1/ingest/policies`) and writes it atomically to the
//! file named by `policy_bundle_file`. The daemon loads that file at boot
//! and polls it for changes; each new bundle is compiled into
//! [`pv_sandbox::PushedRules`] plus token-rate rules and swapped in whole.
//! After every attempt the daemon writes its own answer next to the
//! bundle (`<policy_bundle_file>.status.json`): the etag it applied, the
//! policy ids it now enforces and the ones it could not enforce, with a
//! reason. `pvctl` reports that file to the console, so the console's
//! "Enforced by N of M daemons" reflects what daemons actually run, not
//! what was sent to them.
//!
//! Pushed rules only add restrictions (see [`pv_sandbox::pushed`]). A
//! bundle that cannot be read or parsed leaves the rules already in
//! force unchanged — at boot that means the daemon refuses to start,
//! because running without rules the operator expects to be there would
//! fail open.
//!
//! Kinds: `budget`, `allowlist`, `schema` (tool calls) and `rate`
//! (per-principal token velocity on model traffic) are enforced.
//! `guardrail` and `transform` policies document intent and attribute
//! the daemon's own guard hits; the daemon neither enforces nor reports
//! them. Anything else is reported unsupported.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use pv_sandbox::{PushedAllowlist, PushedRules, PushedSchema, Sandbox, ToolPattern};
use pv_state::{BudgetSpec, TokenVelocity};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Upper bound on a bundle file. The console caps policy bodies, and a
/// bundle far larger than this is not a bundle.
const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;

/// Upper bound on (rule, principal) rate windows held in memory. Idle
/// windows are evicted first when the bound is reached.
const MAX_RATE_WINDOWS: usize = 10_000;

/// One policy entry of the console bundle (contract: `server/src/lib/
/// policy-bundle.ts`).
#[derive(Debug, Clone, Deserialize)]
pub struct BundlePolicy {
    /// Console policy id, echoed in the status report.
    pub id: String,
    /// Console policy name, recorded as the blocking policy.
    pub name: String,
    /// `budget`, `allowlist`, `rate`, `schema`, `guardrail`, `transform`, …
    pub kind: String,
    /// `tool.*`, `tool.<name>`, `llm.request`, …
    pub scope: String,
    /// Always true in a bundle; a false entry is ignored.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Parsed JSON spec for the enforceable kinds, `null` otherwise.
    #[serde(default)]
    pub spec: Option<Value>,
}

fn default_true() -> bool {
    true
}

/// The console bundle file.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyBundle {
    /// Bundle format version; only `1` is understood.
    pub version: u32,
    /// SHA-256 hex of the canonical policies array, used as the bundle id.
    pub etag: String,
    /// Enabled policies of the org, sorted by name.
    pub policies: Vec<BundlePolicy>,
}

/// One policy the daemon could not enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unsupported {
    /// Console policy id.
    pub id: String,
    /// Why, in one short sentence.
    pub reason: String,
}

/// The daemon's own answer for the last bundle it processed; the body
/// `pvctl` posts to `POST /api/v1/ingest/policy-status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    /// Etag of the bundle now in force.
    pub etag: String,
    /// When it was applied (RFC 3339, UTC).
    pub applied_at: String,
    /// This daemon's version.
    pub daemon_version: String,
    /// Policy ids now enforced.
    pub applied: Vec<String>,
    /// Policy ids that could not be enforced.
    pub unsupported: Vec<Unsupported>,
    /// Set when the newest bundle file could not be applied; the rules of
    /// `etag` stay in force. Not sent to the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One per-principal token-rate rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateRule {
    /// Console policy name, recorded in the refusal.
    pub policy: String,
    /// Tokens a principal may push through the model per window.
    pub max_tokens: u64,
    /// Window length in milliseconds.
    pub window_ms: u64,
}

/// A compiled bundle, ready to swap in.
pub struct CompiledBundle {
    /// Tool-call rules for the sandbox.
    pub rules: PushedRules,
    /// Token-rate rules for model traffic.
    pub rates: Vec<RateRule>,
    /// Policy ids enforced.
    pub applied: Vec<String>,
    /// Policy ids not enforced, with reasons.
    pub unsupported: Vec<Unsupported>,
}

/// Compile a bundle. Never fails as a whole: a policy the daemon cannot
/// enforce is listed in `unsupported` and the rest still apply.
pub fn compile(bundle: &PolicyBundle) -> CompiledBundle {
    let mut rules = PushedRules {
        etag: Some(bundle.etag.clone()),
        ..PushedRules::default()
    };
    let mut rates = Vec::new();
    let mut applied = Vec::new();
    let mut unsupported = Vec::new();
    for policy in bundle.policies.iter().filter(|policy| policy.enabled) {
        let outcome = match policy.kind.as_str() {
            "guardrail" | "transform" => continue,
            "budget" => compile_budget(policy, &mut rules),
            "allowlist" => compile_allowlist(policy, &mut rules),
            "schema" => compile_schema(policy, &mut rules),
            "rate" => compile_rate(policy).map(|rule| rates.push(rule)),
            other => Err(format!("this daemon does not enforce {other:?} policies")),
        };
        match outcome {
            Ok(()) => applied.push(policy.id.clone()),
            Err(reason) => unsupported.push(Unsupported {
                id: policy.id.clone(),
                reason,
            }),
        }
    }
    CompiledBundle {
        rules,
        rates,
        applied,
        unsupported,
    }
}

fn spec_object(policy: &BundlePolicy) -> Result<&serde_json::Map<String, Value>, String> {
    policy
        .spec
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} policy has no JSON spec", policy.kind))
}

fn refuse_unknown_fields(spec: &serde_json::Map<String, Value>, known: &[&str]) -> Result<(), String> {
    match spec.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "unknown spec field {key:?} (this daemon may be older than the console)"
        )),
        None => Ok(()),
    }
}

fn spec_u64(spec: &serde_json::Map<String, Value>, field: &str) -> Result<Option<u64>, String> {
    match spec.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|n| *n <= pv_core::error::JCS_SAFE_MAX)
            .map(Some)
            .ok_or_else(|| format!("{field} must be a non-negative integer")),
    }
}

/// True for the scopes that name every tool.
fn covers_all_tools(scope: &str) -> bool {
    matches!(scope.trim(), "tool" | "tool.*" | "*")
}

fn compile_budget(policy: &BundlePolicy, rules: &mut PushedRules) -> Result<(), String> {
    let spec = spec_object(policy)?;
    refuse_unknown_fields(
        spec,
        &[
            "max_total_tool_calls",
            "max_payout_usd_micros",
            "max_tokens",
            "per_tool_max_calls",
        ],
    )?;
    if !covers_all_tools(&policy.scope) {
        return Err("budget policies need scope tool.* (per-tool caps already name their tools)".to_owned());
    }
    let mut pushed = BudgetSpec {
        max_tokens: spec_u64(spec, "max_tokens")?,
        max_payout_usd_micros: spec_u64(spec, "max_payout_usd_micros")?,
        max_total_tool_calls: spec_u64(spec, "max_total_tool_calls")?,
        ..BudgetSpec::default()
    };
    match spec.get("per_tool_max_calls") {
        None | Some(Value::Null) => {}
        Some(Value::Object(per_tool)) => {
            for (tool, cap) in per_tool {
                let cap = cap
                    .as_u64()
                    .ok_or_else(|| format!("per_tool_max_calls.{tool} must be a non-negative integer"))?;
                pushed.max_tool_calls.insert(tool.clone(), cap);
            }
        }
        Some(_) => return Err("per_tool_max_calls must be an object".to_owned()),
    }
    if !pushed.binds_anything() {
        return Err("budget spec sets no limit".to_owned());
    }
    rules.budget = rules.budget.tightened_by(&pushed);
    rules.budget_policies.push(policy.name.clone());
    Ok(())
}

fn tool_names(spec: &serde_json::Map<String, Value>, field: &str) -> Result<Option<HashSet<String>>, String> {
    match spec.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{field} entries must be tool names"))
            })
            .collect::<Result<HashSet<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("{field} must be a list of tool names")),
    }
}

fn compile_allowlist(policy: &BundlePolicy, rules: &mut PushedRules) -> Result<(), String> {
    let spec = spec_object(policy)?;
    refuse_unknown_fields(spec, &["allow_only", "deny_tools"])?;
    let scope = ToolPattern::from_scope(&policy.scope)
        .ok_or_else(|| format!("scope {:?} does not name tools", policy.scope))?;
    let allow_only = tool_names(spec, "allow_only")?.filter(|set| !set.is_empty());
    let deny = tool_names(spec, "deny_tools")?.unwrap_or_default();
    if allow_only.is_none() && deny.is_empty() {
        return Err("allowlist spec names no tools".to_owned());
    }
    rules.allowlists.push(PushedAllowlist {
        policy: policy.name.clone(),
        scope,
        allow_only,
        deny,
    });
    Ok(())
}

fn compile_schema(policy: &BundlePolicy, rules: &mut PushedRules) -> Result<(), String> {
    let spec = spec_object(policy)?;
    refuse_unknown_fields(spec, &["tool", "json_schema"])?;
    let tool = spec
        .get("tool")
        .and_then(Value::as_str)
        .filter(|tool| !tool.is_empty())
        .ok_or_else(|| "schema spec needs a tool name".to_owned())?;
    let scope = ToolPattern::from_scope(&policy.scope)
        .ok_or_else(|| format!("scope {:?} does not name tools", policy.scope))?;
    if !scope.matches(tool) {
        return Err(format!(
            "tool {tool:?} is outside the policy scope {:?}",
            policy.scope
        ));
    }
    let schema = spec
        .get("json_schema")
        .filter(|schema| schema.is_object())
        .ok_or_else(|| "json_schema must be a JSON Schema object".to_owned())?;
    rules
        .schemas
        .push(PushedSchema::compile(&policy.name, tool, schema)?);
    Ok(())
}

fn compile_rate(policy: &BundlePolicy) -> Result<RateRule, String> {
    let spec = spec_object(policy)?;
    refuse_unknown_fields(spec, &["max_tokens_per_window", "window_s"])?;
    let scope = policy.scope.trim();
    if !(scope == "llm" || scope.starts_with("llm.") || covers_all_tools(scope)) {
        return Err(format!(
            "rate policies limit model tokens; scope {scope:?} is not llm.request"
        ));
    }
    let max_tokens = spec_u64(spec, "max_tokens_per_window")?
        .filter(|n| *n > 0)
        .ok_or_else(|| "max_tokens_per_window must be at least 1".to_owned())?;
    let window_s = spec_u64(spec, "window_s")?
        .filter(|n| (1..=30 * 24 * 3600).contains(n))
        .ok_or_else(|| "window_s must be between 1 and 2592000".to_owned())?;
    Ok(RateRule {
        policy: policy.name.clone(),
        max_tokens,
        window_ms: window_s.saturating_mul(1000),
    })
}

/// Per-principal token-rate limits from the pushed bundle.
///
/// Prompt tokens are checked and recorded at admission; completion
/// tokens are recorded as the provider reports them. A request is
/// refused when its prompt would push the principal's window over the
/// cap, so a principal that ran over during a stream is refused on its
/// next request.
#[derive(Default)]
pub struct RateLimits {
    rules: RwLock<Arc<Vec<RateRule>>>,
    windows: Mutex<HashMap<(String, String), Arc<TokenVelocity>>>,
}

impl RateLimits {
    /// Replace the rules. Windows of rules that changed are dropped.
    pub fn set_rules(&self, rules: Vec<RateRule>) {
        let rules = Arc::new(rules);
        let keep: HashSet<String> = rules.iter().map(rule_key).collect();
        self.windows.lock().retain(|(rule, _), _| keep.contains(rule));
        *self.rules.write() = rules;
    }

    /// The rules currently in force.
    pub fn rules(&self) -> Arc<Vec<RateRule>> {
        Arc::clone(&self.rules.read())
    }

    fn window(&self, rule: &RateRule, principal: &str) -> Arc<TokenVelocity> {
        let mut windows = self.windows.lock();
        let key = (rule_key(rule), principal.to_owned());
        if let Some(window) = windows.get(&key) {
            return Arc::clone(window);
        }
        if windows.len() >= MAX_RATE_WINDOWS {
            let now = pv_core::time::now_ms();
            windows.retain(|_, window| window.current_at(now) > 0);
            if windows.len() >= MAX_RATE_WINDOWS {
                // Every window is busy: drop an arbitrary one rather
                // than grow without bound (its principal starts over).
                if let Some(evict) = windows.keys().next().cloned() {
                    windows.remove(&evict);
                }
            }
        }
        let window = Arc::new(TokenVelocity::new(rule.window_ms));
        windows.insert(key, Arc::clone(&window));
        window
    }

    /// Admit `tokens` for `principal`, or name the rule that refuses them.
    /// Admitted tokens are recorded against every rule.
    pub fn admit(&self, principal: &str, tokens: u64) -> Result<(), String> {
        let rules = self.rules();
        if rules.is_empty() {
            return Ok(());
        }
        let now = pv_core::time::now_ms();
        let windows: Vec<(RateRule, Arc<TokenVelocity>)> = rules
            .iter()
            .map(|rule| (rule.clone(), self.window(rule, principal)))
            .collect();
        for (rule, window) in &windows {
            let used = window.current_at(now);
            if used.saturating_add(tokens) > rule.max_tokens {
                return Err(format!(
                    "policy {:?}: token rate limit exceeded ({used} of {} tokens used in the last {} s)",
                    rule.policy,
                    rule.max_tokens,
                    rule.window_ms / 1000
                ));
            }
        }
        for (_, window) in &windows {
            window.record_at(now, tokens);
        }
        Ok(())
    }

    /// Record tokens that were already spent (completion tokens).
    pub fn record(&self, principal: &str, tokens: u64) {
        if tokens == 0 {
            return;
        }
        let rules = self.rules();
        let now = pv_core::time::now_ms();
        for rule in rules.iter() {
            self.window(rule, principal).record_at(now, tokens);
        }
    }
}

fn rule_key(rule: &RateRule) -> String {
    format!("{}|{}|{}", rule.policy, rule.max_tokens, rule.window_ms)
}

/// Path of the status file the daemon writes next to the bundle file.
pub fn status_path(bundle_file: &Path) -> PathBuf {
    let mut name = bundle_file.as_os_str().to_owned();
    name.push(".status.json");
    PathBuf::from(name)
}

/// Read and parse the bundle file. `Ok(None)` when it does not exist yet
/// (nothing was ever pushed).
pub fn read_bundle(path: &Path) -> Result<Option<(PolicyBundle, String)>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot stat policy bundle {}: {error}", path.display())),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "policy bundle {} is writable by group or others; it must be owner-only (chmod 600)",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let bytes = pv_core::fsutil::read_capped(path, MAX_BUNDLE_BYTES)
        .map_err(|error| format!("cannot read policy bundle {}: {error}", path.display()))?;
    let digest = pv_core::digest::sha256_hex(&bytes);
    let bundle: PolicyBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("policy bundle {} is not valid JSON: {error}", path.display()))?;
    if bundle.version != 1 {
        return Err(format!(
            "policy bundle version {} is not supported by this daemon (expected 1)",
            bundle.version
        ));
    }
    if bundle.etag.is_empty()
        || bundle.etag.len() > 128
        || !bundle.etag.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("policy bundle etag must be a hex hash".to_owned());
    }
    Ok(Some((bundle, digest)))
}

/// Applies bundle files to a running daemon.
pub struct PolicyPush {
    path: PathBuf,
    sandbox: Arc<Sandbox>,
    rates: Arc<RateLimits>,
    /// Digest of the file bytes last processed (applied or refused), so
    /// an unchanged file is not reprocessed on every poll.
    last_digest: Mutex<Option<String>>,
    /// Status of the bundle in force, re-written with an error when a
    /// newer file is refused.
    in_force: Mutex<Option<PolicyStatus>>,
}

impl PolicyPush {
    /// Bind to a bundle file and the enforcement points it feeds.
    pub fn new(path: PathBuf, sandbox: Arc<Sandbox>, rates: Arc<RateLimits>) -> Self {
        Self {
            path,
            sandbox,
            rates,
            last_digest: Mutex::new(None),
            in_force: Mutex::new(None),
        }
    }

    /// Boot-time load. A missing file is fine (nothing was pushed); a
    /// file that exists but cannot be applied is an error, so the daemon
    /// refuses to start rather than run without rules it was given.
    pub fn load_at_boot(&self) -> Result<Option<PolicyStatus>, String> {
        match self.apply_if_changed() {
            Ok(status) => Ok(status),
            Err(error) => Err(format!(
                "{error}. Fix or remove the file, or let pvctl console-sync --pull-policies rewrite it"
            )),
        }
    }

    /// Apply the file if its bytes changed since the last attempt.
    /// Returns the new status when a bundle was applied.
    pub fn apply_if_changed(&self) -> Result<Option<PolicyStatus>, String> {
        let read = read_bundle(&self.path);
        let (bundle, digest) = match read {
            Ok(None) => return Ok(None),
            Ok(Some(found)) => found,
            Err(error) => {
                self.record_refusal(&error);
                return Err(error);
            }
        };
        if self.last_digest.lock().as_deref() == Some(digest.as_str()) {
            return Ok(None);
        }
        let compiled = compile(&bundle);
        let status = PolicyStatus {
            etag: bundle.etag.to_ascii_lowercase(),
            applied_at: now_rfc3339(),
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            applied: compiled.applied,
            unsupported: compiled.unsupported,
            error: None,
        };
        self.sandbox.set_pushed(compiled.rules);
        self.rates.set_rules(compiled.rates);
        *self.last_digest.lock() = Some(digest);
        *self.in_force.lock() = Some(status.clone());
        self.write_status(&status)?;
        tracing::info!(
            etag = %status.etag,
            applied = status.applied.len(),
            unsupported = status.unsupported.len(),
            "applied console policy bundle"
        );
        Ok(Some(status))
    }

    /// Note a refused file in the status file, keeping the bundle in
    /// force (if any) as the reported etag.
    fn record_refusal(&self, error: &str) {
        tracing::warn!(%error, "console policy bundle refused; the rules in force are unchanged");
        let status = match self.in_force.lock().clone() {
            Some(mut status) => {
                status.error = Some(error.to_owned());
                status
            }
            None => return,
        };
        if let Err(write_error) = self.write_status(&status) {
            tracing::warn!(error = %write_error, "could not write the policy status file");
        }
    }

    fn write_status(&self, status: &PolicyStatus) -> Result<(), String> {
        let path = status_path(&self.path);
        let bytes =
            serde_json::to_vec_pretty(status).map_err(|error| format!("serialize policy status: {error}"))?;
        pv_core::fsutil::write_atomic(&path, &bytes)
            .map_err(|error| format!("cannot write policy status {}: {error}", path.display()))
    }

    /// Poll the file for changes forever (the task ends with the
    /// runtime at process exit).
    pub async fn watch(self: Arc<Self>, every: Duration) {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires at once; boot already applied the file.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let push = Arc::clone(&self);
            // File I/O and schema compilation are blocking work. A
            // refusal is already logged and written to the status file.
            if let Err(error) = tokio::task::spawn_blocking(move || push.apply_if_changed()).await {
                tracing::warn!(%error, "policy bundle poll task failed");
            }
        }
    }
}

fn now_rfc3339() -> String {
    pv_core::time::iso8601_ms(pv_core::time::now_ms())
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

    fn policy(id: &str, kind: &str, scope: &str, spec: Value) -> Value {
        json!({"id": id, "name": format!("p.{id}"), "kind": kind, "scope": scope, "enabled": true,
               "updatedAt": "2026-10-31T00:00:00.000Z", "spec": spec, "body": ""})
    }

    fn bundle(policies: Vec<Value>) -> PolicyBundle {
        serde_json::from_value(json!({"version": 1, "orgId": "o", "deploymentId": "d",
            "generatedAt": "2026-10-31T00:00:00.000Z", "etag": "ab12", "policies": policies}))
        .unwrap()
    }

    #[test]
    fn every_enforceable_kind_compiles_and_others_are_reported() {
        let compiled = compile(&bundle(vec![
            policy(
                "b1",
                "budget",
                "tool.*",
                json!({"max_total_tool_calls": 20, "per_tool_max_calls": {"create_payment": 2}}),
            ),
            policy(
                "b2",
                "budget",
                "tool.*",
                json!({"max_total_tool_calls": 5, "max_payout_usd_micros": 1_000_000}),
            ),
            policy(
                "a1",
                "allowlist",
                "tool.payments.*",
                json!({"deny_tools": ["payments.wire"]}),
            ),
            policy(
                "s1",
                "schema",
                "tool.create_po",
                json!({"tool": "create_po", "json_schema": {"type": "object"}}),
            ),
            policy(
                "r1",
                "rate",
                "llm.request",
                json!({"max_tokens_per_window": 1000, "window_s": 60}),
            ),
            json!({"id": "g1", "name": "p.g1", "kind": "guardrail", "scope": "llm.egress", "enabled": true, "spec": null, "body": "text"}),
            policy("x1", "budget", "tool.create_payment", json!({"max_tokens": 1})),
            policy("x2", "allowlist", "llm.request", json!({"deny_tools": ["x"]})),
            policy("x3", "schema", "tool.a", json!({"tool": "b", "json_schema": {}})),
            policy(
                "x4",
                "schema",
                "tool.*",
                json!({"tool": "b", "json_schema": {"type": 7}}),
            ),
            policy(
                "x5",
                "rate",
                "llm.request",
                json!({"max_tokens_per_window": 0, "window_s": 60}),
            ),
            policy(
                "x6",
                "budget",
                "tool.*",
                json!({"max_tokens": 1, "brand_new_field": 2}),
            ),
            policy("x7", "quota", "tool.*", json!({})),
        ]));
        assert_eq!(compiled.applied, vec!["b1", "b2", "a1", "s1", "r1"]);
        let refused: Vec<&str> = compiled.unsupported.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(
            refused,
            vec!["x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            "{:?}",
            compiled.unsupported
        );
        assert!(compiled.unsupported.iter().all(|u| !u.reason.is_empty()));
        assert!(
            !compiled.applied.contains(&"g1".to_owned()) && !refused.contains(&"g1"),
            "guardrails are neither"
        );
        // Two budgets merge, stricter wins.
        assert_eq!(compiled.rules.budget.max_total_tool_calls, Some(5));
        assert_eq!(compiled.rules.budget.max_payout_usd_micros, Some(1_000_000));
        assert_eq!(
            compiled.rules.budget.max_tool_calls.get("create_payment"),
            Some(&2)
        );
        assert_eq!(compiled.rules.budget_policies, vec!["p.b1", "p.b2"]);
        assert_eq!(compiled.rules.allowlists.len(), 1);
        assert_eq!(compiled.rules.schemas.len(), 1);
        assert_eq!(
            compiled.rates,
            vec![RateRule {
                policy: "p.r1".into(),
                max_tokens: 1000,
                window_ms: 60_000
            }]
        );
        assert_eq!(compiled.rules.etag.as_deref(), Some("ab12"));
    }

    #[test]
    fn rate_limits_refuse_over_the_window_and_count_completions() {
        let limits = RateLimits::default();
        assert!(limits.admit("alice", u64::MAX).is_ok(), "no rules, no limit");
        limits.set_rules(vec![RateRule {
            policy: "llm.velocity".into(),
            max_tokens: 100,
            window_ms: 60_000,
        }]);
        assert!(limits.admit("alice", 60).is_ok());
        limits.record("alice", 30);
        let refused = limits.admit("alice", 20).unwrap_err();
        assert!(
            refused.contains("llm.velocity") && refused.contains("90 of 100"),
            "{refused}"
        );
        assert!(limits.admit("alice", 10).is_ok(), "exactly at the cap is allowed");
        assert!(limits.admit("bob", 100).is_ok(), "windows are per principal");
        // New rules start fresh windows.
        limits.set_rules(vec![RateRule {
            policy: "llm.velocity".into(),
            max_tokens: 200,
            window_ms: 60_000,
        }]);
        assert!(limits.admit("alice", 150).is_ok());
        limits.set_rules(Vec::new());
        assert!(limits.admit("alice", u64::MAX).is_ok());
    }

    fn write_owner_only(path: &Path, value: &Value) {
        pv_core::fsutil::write_atomic(path, &serde_json::to_vec(value).unwrap()).unwrap();
    }

    #[test]
    fn bundle_files_apply_once_report_status_and_refusals_keep_the_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policies.json");
        let sandbox = Arc::new(Sandbox::new(pv_sandbox::SandboxConfig::default(), Vec::new()).unwrap());
        let rates = Arc::new(RateLimits::default());
        let push = PolicyPush::new(path.clone(), Arc::clone(&sandbox), Arc::clone(&rates));
        assert_eq!(push.load_at_boot().unwrap(), None, "no file: nothing pushed");

        write_owner_only(
            &path,
            &json!({"version": 1, "etag": "AB12", "policies": [
                policy("b1", "budget", "tool.*", json!({"max_total_tool_calls": 3})),
                policy("r1", "rate", "llm.request", json!({"max_tokens_per_window": 50, "window_s": 60})),
            ]}),
        );
        let status = push.apply_if_changed().unwrap().expect("a new bundle applies");
        assert_eq!(
            status.etag, "ab12",
            "etags are reported lowercase like the console stores them"
        );
        assert_eq!(status.applied, vec!["b1", "r1"]);
        assert_eq!(sandbox.effective_budget().max_total_tool_calls, Some(3));
        assert_eq!(rates.rules().len(), 1);
        let on_disk: PolicyStatus =
            serde_json::from_slice(&std::fs::read(status_path(&path)).unwrap()).unwrap();
        assert_eq!(on_disk, status);
        assert!(
            push.apply_if_changed().unwrap().is_none(),
            "unchanged bytes are not reapplied"
        );

        // A broken newer file keeps the rules in force and says why.
        std::fs::write(&path, b"{ not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(push.apply_if_changed().is_err());
        assert_eq!(
            sandbox.effective_budget().max_total_tool_calls,
            Some(3),
            "rules unchanged"
        );
        let refused: PolicyStatus =
            serde_json::from_slice(&std::fs::read(status_path(&path)).unwrap()).unwrap();
        assert_eq!(refused.etag, "ab12");
        assert!(refused.error.unwrap().contains("not valid JSON"));

        // A newer version and a group-writable file are refused too.
        write_owner_only(&path, &json!({"version": 2, "etag": "cd34", "policies": []}));
        assert!(push.apply_if_changed().unwrap_err().contains("version 2"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            write_owner_only(&path, &json!({"version": 1, "etag": "cd34", "policies": []}));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(push.apply_if_changed().unwrap_err().contains("owner-only"));
        }

        // An empty bundle clears every pushed rule.
        write_owner_only(&path, &json!({"version": 1, "etag": "cd34", "policies": []}));
        assert_eq!(push.apply_if_changed().unwrap().unwrap().etag, "cd34");
        assert_eq!(sandbox.effective_budget().max_total_tool_calls, None);
        assert!(rates.rules().is_empty());

        // At boot, a file that cannot be applied stops the daemon.
        std::fs::write(&path, b"garbage").unwrap();
        let fresh = PolicyPush::new(path.clone(), sandbox, rates);
        assert!(fresh
            .load_at_boot()
            .unwrap_err()
            .contains("pvctl console-sync --pull-policies"));
    }
}
