//! Semantic judge integration (`[judge]`).
//!
//! The judge runs on `/v1/mcp` tool calls whose tool is listed under
//! `[[judge.tools]]`, between the schema gate and the policy gate. It
//! sees the schema-validated arguments and operator-controlled context
//! (intent, mission task, charter, delegation depth, and refusals the
//! harness recorded for this session and for the caller's delegation
//! parents), never the raw prompt. Untagged tools never reach it, so
//! their admission path is unchanged.
//!
//! The judge never decides. Its verdicts go to the sandbox's policy
//! gate, where `[[judge.thresholds]]` (and any WASM ABI v2 policy) turn
//! them into allow, ask (`APPROVAL_REQUIRED`), or deny, and where every
//! failure denies or asks, never allows. Each verdict, with its full
//! distribution and the pinned model, is written into the tool-call
//! OCSF event (hashed into the signed event chain) and the ATIF tool
//! call (hashed into a retroactive receipt).
//!
//! State kept in this process: the prior-denial log, the drift monitor,
//! and the concurrency limit. A multi-instance deployment shares only
//! the pilot cap counters (they live in the state store).

use pv_judge::{
    AdapterKind, AdapterSlot, DenialSource, DriftConfig, DriftMonitor, FailurePolicy, JudgeAction,
    JudgeFailure, JudgeMode, JudgeOutcome, JudgeRunner, JudgeTask, PredicateDef, PredicateRegistry,
    PriorDenial, SessionContext, ThresholdPolicy, ThresholdRule,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

/// Default concurrency limit.
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;
/// Upper bound for `max_concurrency`.
pub const MAX_CONCURRENCY_CEILING: usize = 4_096;
/// Default deadline for a local adapter, milliseconds.
pub const DEFAULT_LOCAL_DEADLINE_MS: u64 = 200;
/// Default deadline for a cloud adapter, milliseconds.
pub const DEFAULT_CLOUD_DEADLINE_MS: u64 = 1_000;
/// Largest deadline accepted, milliseconds.
pub const MAX_DEADLINE_MS: u64 = 30_000;
/// Refusals kept per session and per agent instance.
pub const DENIALS_PER_KEY: usize = 16;
/// Sessions and agent instances tracked by the denial log.
pub const DENIAL_LOG_KEYS: usize = 20_000;
/// Longest mission `task` statement.
pub const MAX_TASK_CHARS: usize = 4_096;
/// Default concurrency limit for background judging.
pub const DEFAULT_BACKGROUND_CONCURRENCY: usize = 8;
/// Largest deadline for an adapter used by background judging. Session
/// close at shutdown allows 3 s, and a pending background verdict holds
/// the close, so it must finish well inside that.
pub const MAX_BACKGROUND_DEADLINE_MS: u64 = 2_500;
/// Longest standing rule text.
pub const MAX_RULE_CHARS: usize = 2_000;
/// Longest model output kept for the loop breaker's second opinion.
pub const MAX_LOOP_TEXT_CHARS: usize = 4_096;
/// Largest drift state file read at startup.
pub const MAX_DRIFT_STATE_BYTES: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `mode`: whether the judge can block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeModeConfig {
    /// Score and record; never block. Records what policy would have done.
    Shadow,
    /// Score, record, and let policy act on the verdicts.
    Enforce,
}

/// A failure behaviour: deny or ask. Allow cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureActionConfig {
    /// Refuse the call (`JUDGE_UNAVAILABLE`).
    Deny,
    /// Hold the call for approval (`APPROVAL_REQUIRED`).
    Ask,
}

impl From<FailureActionConfig> for JudgeAction {
    fn from(value: FailureActionConfig) -> Self {
        match value {
            FailureActionConfig::Deny => Self::Deny,
            FailureActionConfig::Ask => Self::Ask,
        }
    }
}

/// `[judge.on_failure]`. A model mismatch always denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeFailureConfig {
    /// Deadline expired (default deny).
    #[serde(default = "deny")]
    pub timeout: FailureActionConfig,
    /// Backend crashed or unreachable (default deny).
    #[serde(default = "deny")]
    pub unavailable: FailureActionConfig,
    /// Concurrency limit reached (default deny).
    #[serde(default = "deny")]
    pub saturated: FailureActionConfig,
    /// Output did not fit the predicate (default ask).
    #[serde(default = "ask")]
    pub malformed: FailureActionConfig,
}

fn deny() -> FailureActionConfig {
    FailureActionConfig::Deny
}

fn ask() -> FailureActionConfig {
    FailureActionConfig::Ask
}

impl Default for JudgeFailureConfig {
    fn default() -> Self {
        Self {
            timeout: deny(),
            unavailable: deny(),
            saturated: deny(),
            malformed: ask(),
        }
    }
}

/// `kind` of a `[[judge.adapters]]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeAdapterKind {
    /// ONNX classifier in this process (needs the `onnx` cargo feature).
    Local,
    /// HTTP endpoint speaking `proofvisor.judge.v1` (a second egress path).
    Cloud,
}

/// `[[judge.adapters]]`: one judge backend and its pinned model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeAdapterConfig {
    /// Name that `[[judge.tools]]` bindings refer to.
    pub name: String,
    /// `local` or `cloud`.
    pub kind: JudgeAdapterKind,
    /// Hard per-call deadline (default 200 ms local, 1000 ms cloud).
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// Pinned model name.
    pub model_name: String,
    /// Pinned model version.
    pub model_version: String,
    /// Pinned SHA-256 of the weights (local: of the `.onnx` file).
    pub weights_sha256: String,
    /// Local: path of the `.onnx` model.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Local: path of the Hugging Face `tokenizer.json`.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Local: SHA-256 of the tokenizer file.
    #[serde(default)]
    pub tokenizer_sha256: Option<String>,
    /// Local: label of each output logit, in output order.
    #[serde(default)]
    pub output_labels: Vec<String>,
    /// Local: token limit (default 512).
    #[serde(default)]
    pub max_input_tokens: Option<usize>,
    /// Cloud: endpoint URL (`https`, or `http` to loopback only).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Cloud: owner-only file holding the bearer token.
    #[serde(default)]
    pub bearer_file: Option<String>,
    /// Cloud: run the harness redaction engine over arguments and
    /// context before they leave (default true).
    #[serde(default = "default_true")]
    pub redact: bool,
}

fn default_true() -> bool {
    true
}

impl JudgeAdapterConfig {
    /// The configured or default deadline.
    pub fn deadline(&self) -> Duration {
        Duration::from_millis(self.deadline_ms.unwrap_or(match self.kind {
            JudgeAdapterKind::Local => DEFAULT_LOCAL_DEADLINE_MS,
            JudgeAdapterKind::Cloud => DEFAULT_CLOUD_DEADLINE_MS,
        }))
    }

    /// The pinned model.
    pub fn pin(&self) -> Result<pv_judge::ModelPin, String> {
        pv_judge::ModelPin::new(&self.model_name, &self.model_version, &self.weights_sha256)
            .map_err(|error| format!("judge adapter {:?}: {error}", self.name))
    }
}

/// One predicate bound to one adapter on a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgePredicateBinding {
    /// Versioned predicate id.
    pub id: String,
    /// Adapter name.
    pub adapter: String,
}

/// `[[judge.tools]]`: a tool tagged for semantic review.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeToolConfig {
    /// Tool name, exactly as in `tools/call`.
    pub tool: String,
    /// Predicates to evaluate for this tool.
    pub predicates: Vec<JudgePredicateBinding>,
    /// Required (`true`) to bind a cloud adapter: this tool's arguments
    /// may leave the harness for the judge.
    #[serde(default)]
    pub allow_cloud: bool,
}

/// `[[judge.thresholds]]`, written as probabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeThresholdConfig {
    /// Versioned predicate id.
    pub predicate: String,
    /// Label whose probability is compared.
    pub label: String,
    /// Deny above this probability.
    #[serde(default)]
    pub deny_above: Option<f64>,
    /// Ask above this probability.
    #[serde(default)]
    pub ask_above: Option<f64>,
    /// Ask when the most probable label is below this.
    #[serde(default)]
    pub min_confidence: Option<f64>,
}

/// `[judge.pilot]`: the capped-pilot rollout phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgePilotConfig {
    /// Most score-based judge blocks per tool per UTC day; later ones
    /// are recorded but let through. Failures still block.
    pub daily_block_cap: u64,
}

/// `[judge.drift]`: the runtime calibration check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeDriftConfig {
    /// File holding the band statistics and the ask-by-default switches,
    /// so a switch survives restarts until an operator resets it. It is
    /// written atomically after every review and reset.
    pub state_file: String,
    /// Sample one scored verdict in this many for human review (default 20).
    #[serde(default = "default_sample_every")]
    pub sample_every: u64,
    /// Reviews a confidence band needs before it counts (default 30).
    #[serde(default = "default_min_reviews")]
    pub min_reviews_per_band: u64,
    /// Allowed accuracy drop between bands, as a probability (default 0.02).
    #[serde(default = "default_tolerance")]
    pub tolerance: f64,
    /// Sampled verdicts kept waiting for review (default 10000).
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
}

fn default_sample_every() -> u64 {
    20
}
fn default_min_reviews() -> u64 {
    30
}
fn default_tolerance() -> f64 {
    0.02
}
fn default_max_pending() -> usize {
    10_000
}

/// Which recorded outputs trace judging reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceSource {
    /// A tool's response body, after the call completed.
    Tool,
    /// The model's answer (message, reasoning, or tool-call request).
    Model,
}

impl TraceSource {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Model => "model",
        }
    }
}

/// `[judge.trace]`: judge recorded outputs after the fact, off the request
/// path. Each verdict becomes an `agent.judge` event (and an ATIF step),
/// so the session's receipt covers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeTraceConfig {
    /// Adapter name.
    pub adapter: String,
    /// Predicate to score (default `output_safe@1`).
    #[serde(default = "default_trace_predicate")]
    pub predicate: String,
    /// Outputs to judge (default both).
    #[serde(default = "default_trace_sources")]
    pub sources: Vec<TraceSource>,
    /// A verdict whose positive label is above this is a finding
    /// (`finding: true`, higher severity). Default 0.7.
    #[serde(default = "default_finding_above")]
    pub finding_above: f64,
    /// Required (`true`) with a cloud adapter: outputs then leave the harness.
    #[serde(default)]
    pub allow_cloud: bool,
    /// Longest output sent, in characters (default 16384).
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,
}

fn default_trace_predicate() -> String {
    pv_judge::OUTPUT_SAFE.to_owned()
}
fn default_trace_sources() -> Vec<TraceSource> {
    vec![TraceSource::Tool, TraceSource::Model]
}
fn default_finding_above() -> f64 {
    0.7
}
fn default_max_output_chars() -> usize {
    16_384
}

/// `[judge.breaker]`: the loop breaker's second opinion. When a model
/// output's semantic delta falls inside `[ambiguous_low, ambiguous_high]`,
/// the judge decides whether the step counts as no progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeBreakerConfig {
    /// Adapter name.
    pub adapter: String,
    /// Predicate to score (default `loop_progress@1`).
    #[serde(default = "default_breaker_predicate")]
    pub predicate: String,
    /// Lower end of the ambiguous delta range.
    pub ambiguous_low: f64,
    /// Upper end of the ambiguous delta range.
    pub ambiguous_high: f64,
    /// The step counts as no progress when the positive label's
    /// probability is above this (default 0.5).
    #[serde(default = "default_looping_above")]
    pub looping_above: f64,
    /// Required (`true`) with a cloud adapter: model outputs then leave
    /// the harness.
    #[serde(default)]
    pub allow_cloud: bool,
}

fn default_breaker_predicate() -> String {
    pv_judge::LOOP_PROGRESS.to_owned()
}
fn default_looping_above() -> f64 {
    0.5
}

/// `[[judge.standing_rules]]`: a rule the agent must keep in view. When
/// context compression cuts the only copy of its text from a request,
/// the rule is appended back as a system message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingRuleConfig {
    /// Identifier recorded when the rule is re-pinned.
    pub id: String,
    /// The rule's exact text, as the application sends it.
    pub text: String,
}

fn default_background_concurrency() -> usize {
    DEFAULT_BACKGROUND_CONCURRENCY
}

/// `[judge]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeConfig {
    /// `shadow` or `enforce`. Required: there is no implicit default.
    pub mode: JudgeModeConfig,
    /// Judge calls in flight at once; beyond it calls are refused as
    /// saturated (default 16).
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    /// Backends.
    #[serde(default)]
    pub adapters: Vec<JudgeAdapterConfig>,
    /// Tools tagged for semantic review.
    #[serde(default)]
    pub tools: Vec<JudgeToolConfig>,
    /// Policy thresholds.
    #[serde(default)]
    pub thresholds: Vec<JudgeThresholdConfig>,
    /// Failure behaviour.
    #[serde(default)]
    pub on_failure: JudgeFailureConfig,
    /// Operator-defined predicates, in addition to the built-ins.
    #[serde(default)]
    pub predicates: Vec<PredicateDef>,
    /// Capped-pilot rollout.
    #[serde(default)]
    pub pilot: Option<JudgePilotConfig>,
    /// Runtime calibration check.
    #[serde(default)]
    pub drift: Option<JudgeDriftConfig>,
    /// Judge calls in flight for background judging (recorded outputs and
    /// the loop breaker's second opinion), kept apart from tool-call
    /// admission so background work never starves it (default 8).
    #[serde(default = "default_background_concurrency")]
    pub background_max_concurrency: usize,
    /// Trace judging.
    #[serde(default)]
    pub trace: Option<JudgeTraceConfig>,
    /// The loop breaker's second opinion.
    #[serde(default)]
    pub breaker: Option<JudgeBreakerConfig>,
    /// Standing rules re-pinned after context compression.
    #[serde(default)]
    pub standing_rules: Vec<StandingRuleConfig>,
}

fn default_max_concurrency() -> usize {
    DEFAULT_MAX_CONCURRENCY
}

impl JudgeConfig {
    /// Built-in predicates plus `predicates`.
    pub fn registry(&self) -> Result<PredicateRegistry, String> {
        PredicateRegistry::with_custom(&self.predicates).map_err(|error| format!("judge: {error}"))
    }

    /// The threshold policy the sandbox applies.
    pub fn threshold_policy(&self) -> Result<ThresholdPolicy, String> {
        let rules = self
            .thresholds
            .iter()
            .map(|threshold| {
                let ppm = |value: Option<f64>, name: &str| {
                    value
                        .map(pv_judge::threshold_to_ppm)
                        .transpose()
                        .map_err(|error| {
                            format!(
                                "judge threshold {} / {} {name}: {error}",
                                threshold.predicate, threshold.label
                            )
                        })
                };
                Ok(ThresholdRule {
                    predicate_id: threshold.predicate.clone(),
                    label: threshold.label.clone(),
                    deny_above_ppm: ppm(threshold.deny_above, "deny_above")?,
                    ask_above_ppm: ppm(threshold.ask_above, "ask_above")?,
                    min_confidence_ppm: ppm(threshold.min_confidence, "min_confidence")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let failure = FailurePolicy {
            timeout: self.on_failure.timeout.into(),
            unavailable: self.on_failure.unavailable.into(),
            saturated: self.on_failure.saturated.into(),
            malformed: self.on_failure.malformed.into(),
        };
        ThresholdPolicy::new(rules, failure).map_err(|error| format!("judge: {error}"))
    }

    /// The drift settings, converted.
    pub fn drift_config(&self) -> Result<Option<DriftConfig>, String> {
        let Some(drift) = &self.drift else {
            return Ok(None);
        };
        let config = DriftConfig {
            sample_every: drift.sample_every,
            min_reviews_per_band: drift.min_reviews_per_band,
            tolerance_ppm: pv_judge::threshold_to_ppm(drift.tolerance)
                .map_err(|error| format!("judge drift tolerance: {error}"))?,
            max_pending: drift.max_pending,
        };
        config.validate()?;
        Ok(Some(config))
    }

    /// Every structural problem (no file access).
    pub fn collect_errors(&self, errors: &mut Vec<String>) {
        if !(1..=MAX_CONCURRENCY_CEILING).contains(&self.max_concurrency) {
            errors.push(format!(
                "judge.max_concurrency must be between 1 and {MAX_CONCURRENCY_CEILING}"
            ));
        }
        let registry = match self.registry() {
            Ok(registry) => Some(registry),
            Err(error) => {
                errors.push(error);
                None
            }
        };
        let mut adapters: BTreeMap<&str, &JudgeAdapterConfig> = BTreeMap::new();
        for adapter in &self.adapters {
            if !is_name(&adapter.name) {
                errors.push(format!(
                    "judge adapter name {:?} must be 1..=64 characters of [A-Za-z0-9_.-]",
                    adapter.name
                ));
            }
            if adapters.insert(adapter.name.as_str(), adapter).is_some() {
                errors.push(format!(
                    "judge adapter {:?} is defined more than once",
                    adapter.name
                ));
            }
            collect_adapter_errors(adapter, errors);
        }
        if self.tools.is_empty()
            && self.trace.is_none()
            && self.breaker.is_none()
            && self.standing_rules.is_empty()
        {
            errors.push(
                "[judge] is set but enables nothing: tag tools under [[judge.tools]], or set \
                 [judge.trace], [judge.breaker] or [[judge.standing_rules]]"
                    .to_owned(),
            );
        }
        if !(1..=MAX_CONCURRENCY_CEILING).contains(&self.background_max_concurrency) {
            errors.push(format!(
                "judge.background_max_concurrency must be between 1 and {MAX_CONCURRENCY_CEILING}"
            ));
        }
        self.collect_background_errors(&adapters, registry.as_ref(), errors);
        let mut tools = BTreeSet::new();
        let mut bound_predicates = BTreeSet::new();
        for tool in &self.tools {
            if tool.tool.trim().is_empty() || tool.tool.len() > 256 || tool.tool.chars().any(char::is_control)
            {
                errors.push(format!(
                    "judge tool name {:?} is not a valid tool name",
                    tool.tool
                ));
            }
            if !tools.insert(tool.tool.as_str()) {
                errors.push(format!("judge tool {:?} is listed more than once", tool.tool));
            }
            if tool.predicates.is_empty() {
                errors.push(format!("judge tool {:?} binds no predicates", tool.tool));
            }
            let mut seen = BTreeSet::new();
            for binding in &tool.predicates {
                if !seen.insert(binding.id.as_str()) {
                    errors.push(format!(
                        "judge tool {:?} binds predicate {} more than once",
                        tool.tool, binding.id
                    ));
                }
                bound_predicates.insert(binding.id.as_str());
                let predicate = registry.as_ref().and_then(|registry| registry.get(&binding.id));
                if registry.is_some() && predicate.is_none() {
                    errors.push(format!(
                        "judge tool {:?} binds unknown predicate {:?} (define it under [[judge.predicates]])",
                        tool.tool, binding.id
                    ));
                }
                let Some(adapter) = adapters.get(binding.adapter.as_str()) else {
                    errors.push(format!(
                        "judge tool {:?} binds predicate {} to unknown adapter {:?}",
                        tool.tool, binding.id, binding.adapter
                    ));
                    continue;
                };
                if adapter.kind == JudgeAdapterKind::Cloud && !tool.allow_cloud {
                    errors.push(format!(
                        "judge tool {:?} uses cloud adapter {:?}: its arguments would leave the \
                         harness; set allow_cloud = true on this tool to opt in",
                        tool.tool, adapter.name
                    ));
                }
                if let (JudgeAdapterKind::Local, Some(predicate)) = (adapter.kind, predicate) {
                    let labels: BTreeSet<&str> = adapter.output_labels.iter().map(String::as_str).collect();
                    let expected: BTreeSet<&str> = predicate.labels.iter().map(String::as_str).collect();
                    if labels != expected || adapter.output_labels.len() != predicate.labels.len() {
                        errors.push(format!(
                            "judge adapter {:?} output_labels {:?} must be exactly the labels of {} ({:?})",
                            adapter.name, adapter.output_labels, predicate.id, predicate.labels
                        ));
                    }
                }
            }
        }
        let widest = self
            .tools
            .iter()
            .map(|tool| tool.predicates.len())
            .max()
            .unwrap_or(0);
        if widest > self.max_concurrency {
            errors.push(format!(
                "judge.max_concurrency ({}) is below the {widest} predicates bound to one tool; \
                 every call to that tool would be refused as saturated",
                self.max_concurrency
            ));
        }
        for threshold in &self.thresholds {
            match registry
                .as_ref()
                .map(|registry| registry.get(&threshold.predicate))
            {
                Some(None) => errors.push(format!(
                    "judge threshold names unknown predicate {:?}",
                    threshold.predicate
                )),
                Some(Some(predicate)) if !predicate.has_label(&threshold.label) => errors.push(format!(
                    "judge threshold label {:?} is not a label of {}",
                    threshold.label, threshold.predicate
                )),
                _ => {}
            }
            if !bound_predicates.contains(threshold.predicate.as_str()) {
                errors.push(format!(
                    "judge threshold for {} applies to no tool (bind the predicate under [[judge.tools]])",
                    threshold.predicate
                ));
            }
        }
        if let Err(error) = self.threshold_policy() {
            errors.push(error);
        }
        if let Some(pilot) = self.pilot {
            if pilot.daily_block_cap == 0 {
                errors.push("judge.pilot.daily_block_cap must be at least 1".to_owned());
            }
            if self.mode == JudgeModeConfig::Shadow {
                errors
                    .push("[judge.pilot] only applies in enforce mode; shadow mode never blocks".to_owned());
            }
        }
        if let Err(error) = self.drift_config() {
            errors.push(error);
        }
        if self
            .drift
            .as_ref()
            .is_some_and(|drift| drift.state_file.trim().is_empty())
        {
            errors.push("judge.drift.state_file must not be empty".to_owned());
        }
    }

    fn collect_background_errors(
        &self,
        adapters: &BTreeMap<&str, &JudgeAdapterConfig>,
        registry: Option<&PredicateRegistry>,
        errors: &mut Vec<String>,
    ) {
        let mut check = |section: &str, adapter_name: &str, predicate_id: &str, allow_cloud: bool| {
            let predicate = registry.and_then(|registry| registry.get(predicate_id));
            if registry.is_some() && predicate.is_none() {
                errors.push(format!(
                    "[judge.{section}] names unknown predicate {predicate_id:?}"
                ));
            }
            let Some(adapter) = adapters.get(adapter_name) else {
                errors.push(format!(
                    "[judge.{section}] names unknown adapter {adapter_name:?}"
                ));
                return;
            };
            if adapter.kind == JudgeAdapterKind::Cloud && !allow_cloud {
                errors.push(format!(
                    "[judge.{section}] uses cloud adapter {adapter_name:?}: recorded outputs would \
                     leave the harness; set allow_cloud = true in [judge.{section}] to opt in"
                ));
            }
            if adapter.deadline() > Duration::from_millis(MAX_BACKGROUND_DEADLINE_MS) {
                errors.push(format!(
                    "[judge.{section}] adapter {adapter_name:?} has a deadline above \
                     {MAX_BACKGROUND_DEADLINE_MS} ms; background verdicts hold session close, \
                     which has 3 s at shutdown"
                ));
            }
            if let (JudgeAdapterKind::Local, Some(predicate)) = (adapter.kind, predicate) {
                let labels: BTreeSet<&str> = adapter.output_labels.iter().map(String::as_str).collect();
                let expected: BTreeSet<&str> = predicate.labels.iter().map(String::as_str).collect();
                if labels != expected || adapter.output_labels.len() != predicate.labels.len() {
                    errors.push(format!(
                        "judge adapter {adapter_name:?} output_labels {:?} must be exactly the labels of {} ({:?})",
                        adapter.output_labels, predicate.id, predicate.labels
                    ));
                }
            }
        };
        if let Some(trace) = &self.trace {
            check("trace", &trace.adapter, &trace.predicate, trace.allow_cloud);
        }
        if let Some(breaker) = &self.breaker {
            check(
                "breaker",
                &breaker.adapter,
                &breaker.predicate,
                breaker.allow_cloud,
            );
        }
        if let Some(trace) = &self.trace {
            if trace.sources.is_empty() {
                errors.push("[judge.trace] sources must name tool, model, or both".to_owned());
            }
            if pv_judge::threshold_to_ppm(trace.finding_above).is_err() {
                errors.push("[judge.trace] finding_above must be a probability in [0, 1]".to_owned());
            }
            if !(1..=1_000_000).contains(&trace.max_output_chars) {
                errors.push("[judge.trace] max_output_chars must be between 1 and 1000000".to_owned());
            }
        }
        if let Some(breaker) = &self.breaker {
            let low = pv_judge::threshold_to_ppm(breaker.ambiguous_low);
            let high = pv_judge::threshold_to_ppm(breaker.ambiguous_high);
            match (low, high) {
                (Ok(low), Ok(high)) if low < high => {}
                _ => errors.push("[judge.breaker] needs 0 <= ambiguous_low < ambiguous_high <= 1".to_owned()),
            }
            if pv_judge::threshold_to_ppm(breaker.looping_above).is_err() {
                errors.push("[judge.breaker] looping_above must be a probability in [0, 1]".to_owned());
            }
        }
        let mut rule_ids = BTreeSet::new();
        for rule in &self.standing_rules {
            if !is_name(&rule.id) {
                errors.push(format!(
                    "standing rule id {:?} must be 1..=64 characters of [A-Za-z0-9_.-]",
                    rule.id
                ));
            }
            if !rule_ids.insert(rule.id.as_str()) {
                errors.push(format!("standing rule {:?} is defined more than once", rule.id));
            }
            if rule.text.trim().is_empty() || rule.text.chars().count() > MAX_RULE_CHARS {
                errors.push(format!(
                    "standing rule {:?} text must be 1..={MAX_RULE_CHARS} characters",
                    rule.id
                ));
            }
        }
    }

    /// The tools and predicates bound to `adapter`.
    pub fn uses_local_adapter(&self) -> bool {
        self.adapters
            .iter()
            .any(|adapter| adapter.kind == JudgeAdapterKind::Local)
    }
}

fn collect_adapter_errors(adapter: &JudgeAdapterConfig, errors: &mut Vec<String>) {
    if let Err(error) = adapter.pin() {
        errors.push(error);
    }
    if let Some(ms) = adapter.deadline_ms {
        if !(1..=MAX_DEADLINE_MS).contains(&ms) {
            errors.push(format!(
                "judge adapter {:?} deadline_ms must be between 1 and {MAX_DEADLINE_MS}",
                adapter.name
            ));
        }
    }
    let local_fields = adapter.model_path.is_some()
        || adapter.tokenizer_path.is_some()
        || adapter.tokenizer_sha256.is_some()
        || !adapter.output_labels.is_empty()
        || adapter.max_input_tokens.is_some();
    let cloud_fields = adapter.endpoint.is_some() || adapter.bearer_file.is_some();
    match adapter.kind {
        JudgeAdapterKind::Local => {
            if cloud_fields {
                errors.push(format!(
                    "judge adapter {:?} is local; endpoint and bearer_file belong to cloud adapters",
                    adapter.name
                ));
            }
            if adapter.model_path.as_deref().is_none_or(|p| p.trim().is_empty()) {
                errors.push(format!(
                    "judge adapter {:?} (local) needs model_path",
                    adapter.name
                ));
            }
            if adapter
                .tokenizer_path
                .as_deref()
                .is_none_or(|p| p.trim().is_empty())
            {
                errors.push(format!(
                    "judge adapter {:?} (local) needs tokenizer_path",
                    adapter.name
                ));
            }
            if !adapter
                .tokenizer_sha256
                .as_deref()
                .is_some_and(pv_judge::is_sha256_hex)
            {
                errors.push(format!(
                    "judge adapter {:?} (local) needs tokenizer_sha256 (64 lowercase hex characters)",
                    adapter.name
                ));
            }
            if adapter.output_labels.len() < 2 {
                errors.push(format!(
                    "judge adapter {:?} (local) needs output_labels (one per output logit)",
                    adapter.name
                ));
            }
            if adapter.max_input_tokens.is_some_and(|n| n == 0 || n > 8_192) {
                errors.push(format!(
                    "judge adapter {:?} max_input_tokens must be between 1 and 8192",
                    adapter.name
                ));
            }
        }
        JudgeAdapterKind::Cloud => {
            if local_fields {
                errors.push(format!(
                    "judge adapter {:?} is cloud; model_path, tokenizer_path, tokenizer_sha256, \
                     output_labels and max_input_tokens belong to local adapters",
                    adapter.name
                ));
            }
            match adapter.endpoint.as_deref().map(url::Url::parse) {
                None => errors.push(format!("judge adapter {:?} (cloud) needs endpoint", adapter.name)),
                Some(Err(_)) => {
                    errors.push(format!("judge adapter {:?} endpoint is not a URL", adapter.name))
                }
                Some(Ok(url)) => {
                    if let Err(error) = pv_judge::cloud::validate_endpoint(&url) {
                        errors.push(format!("judge adapter {:?}: {error}", adapter.name));
                    }
                }
            }
        }
    }
}

fn is_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Recent refusals by session and by agent instance (bounded).
#[derive(Default)]
struct DenialLog {
    by_key: HashMap<String, VecDeque<PriorDenial>>,
    order: VecDeque<String>,
}

impl DenialLog {
    fn push(&mut self, key: String, denial: PriorDenial) {
        if !self.by_key.contains_key(&key) {
            self.order.push_back(key.clone());
            while self.order.len() > DENIAL_LOG_KEYS {
                if let Some(oldest) = self.order.pop_front() {
                    self.by_key.remove(&oldest);
                }
            }
        }
        let entries = self.by_key.entry(key).or_default();
        entries.push_back(denial);
        while entries.len() > DENIALS_PER_KEY {
            entries.pop_front();
        }
    }

    fn recent(&self, key: &str) -> Vec<PriorDenial> {
        self.by_key
            .get(key)
            .map(|entries| entries.iter().rev().cloned().collect())
            .unwrap_or_default()
    }
}

/// What the pipeline needs to build a judge request's context.
pub(crate) struct ContextInputs<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) intent: String,
    pub(crate) missions: Vec<&'a crate::config::MissionConfig>,
    pub(crate) charter: &'a str,
    pub(crate) delegation_depth: usize,
    /// Instance uids of the agents above the caller, nearest first.
    pub(crate) parents: Vec<String>,
}

/// The running judge: runner, tool bindings, rollout state.
pub struct JudgeService {
    runner: JudgeRunner,
    /// Background judging (traces, the breaker) has its own concurrency
    /// limit, so it can never starve tool-call admission.
    background: JudgeRunner,
    trace: Option<JudgeTraceConfig>,
    breaker: Option<JudgeBreakerConfig>,
    standing_rules: Vec<StandingRuleConfig>,
    mode: JudgeMode,
    tools: BTreeMap<String, Vec<JudgeTask>>,
    adapter_kinds: BTreeMap<String, AdapterKind>,
    max_deadline: Duration,
    drift: Option<DriftMonitor>,
    drift_file: Option<std::path::PathBuf>,
    drift_write: parking_lot::Mutex<()>,
    pilot_cap: Option<u64>,
    denials: parking_lot::Mutex<DenialLog>,
    metrics: Arc<pv_core::metrics::Registry>,
}

impl JudgeService {
    /// Build from adapters that are already constructed (the boot path
    /// builds them with [`build_adapters`]; tests pass mocks).
    pub fn new(
        config: &JudgeConfig,
        adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>>,
        metrics: Arc<pv_core::metrics::Registry>,
    ) -> Result<Self, String> {
        let mut errors = Vec::new();
        config.collect_errors(&mut errors);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        let registry = Arc::new(config.registry()?);
        let mut slots = BTreeMap::new();
        let mut adapter_kinds = BTreeMap::new();
        let mut max_deadline = Duration::ZERO;
        for adapter_config in &config.adapters {
            let adapter = adapters
                .get(&adapter_config.name)
                .cloned()
                .ok_or_else(|| format!("judge adapter {:?} was not built", adapter_config.name))?;
            let pin = adapter_config.pin()?;
            if adapter.id() != &pin {
                return Err(format!(
                    "judge adapter {:?} loaded {} but the config pins {pin}",
                    adapter_config.name,
                    adapter.id()
                ));
            }
            let deadline = adapter_config.deadline();
            max_deadline = max_deadline.max(deadline);
            adapter_kinds.insert(adapter_config.name.clone(), adapter.kind());
            slots.insert(adapter_config.name.clone(), AdapterSlot { adapter, deadline });
        }
        let background = JudgeRunner::new(
            slots.clone(),
            Arc::clone(&registry),
            config.background_max_concurrency,
        )?;
        let runner = JudgeRunner::new(slots, registry, config.max_concurrency)?;
        let tools = config
            .tools
            .iter()
            .map(|tool| {
                let tasks = tool
                    .predicates
                    .iter()
                    .map(|binding| JudgeTask {
                        predicate_id: binding.id.clone(),
                        adapter: binding.adapter.clone(),
                    })
                    .collect();
                (tool.tool.clone(), tasks)
            })
            .collect();
        let drift = config.drift_config()?.map(DriftMonitor::new).transpose()?;
        let drift_file = config
            .drift
            .as_ref()
            .map(|drift| std::path::PathBuf::from(&drift.state_file));
        if let (Some(monitor), Some(path)) = (&drift, &drift_file) {
            match pv_core::fsutil::read_capped_string(path, MAX_DRIFT_STATE_BYTES) {
                Ok(text) => {
                    let state: pv_judge::DriftState = serde_json::from_str(&text).map_err(|error| {
                        format!(
                            "judge drift state file {} does not parse ({error}); inspect it, then \
                             delete it to start the calibration check over",
                            path.display()
                        )
                    })?;
                    monitor
                        .restore(state)
                        .map_err(|error| format!("judge drift state file {}: {error}", path.display()))?;
                    let tripped = monitor.tripped();
                    if !tripped.is_empty() {
                        tracing::warn!(
                            predicates = ?tripped,
                            "judge predicates restored in ask-by-default mode from the drift state file"
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("read judge drift state file {}: {error}", path.display()));
                }
            }
        }
        metrics.gauge(
            "pv_judge_drift_tripped",
            "Judge predicates in ask-by-default mode after a calibration drift check",
        );
        Ok(Self {
            runner,
            background,
            trace: config.trace.clone(),
            breaker: config.breaker.clone(),
            standing_rules: config.standing_rules.clone(),
            mode: match config.mode {
                JudgeModeConfig::Shadow => JudgeMode::Shadow,
                JudgeModeConfig::Enforce => JudgeMode::Enforce,
            },
            tools,
            adapter_kinds,
            max_deadline,
            drift,
            drift_file,
            drift_write: parking_lot::Mutex::new(()),
            pilot_cap: config.pilot.map(|pilot| pilot.daily_block_cap),
            denials: parking_lot::Mutex::new(DenialLog::default()),
            metrics,
        })
    }

    /// Trace judging settings, when `[judge.trace]` is set.
    pub fn trace(&self) -> Option<&JudgeTraceConfig> {
        self.trace.as_ref()
    }

    /// The loop breaker's second opinion settings, when `[judge.breaker]` is set.
    pub fn breaker(&self) -> Option<&JudgeBreakerConfig> {
        self.breaker.as_ref()
    }

    /// Standing rules re-pinned after context compression.
    pub fn standing_rules(&self) -> &[StandingRuleConfig] {
        &self.standing_rules
    }

    /// Background calls in flight.
    pub fn background_in_flight(&self) -> usize {
        self.background.in_flight()
    }

    /// Score one predicate on the background runner.
    pub(crate) async fn score_background(
        &self,
        adapter: &str,
        predicate: &str,
        tool: &str,
        arguments: &Value,
        context: &SessionContext,
    ) -> (JudgeOutcome, u64) {
        let started = std::time::Instant::now();
        let task = JudgeTask {
            predicate_id: predicate.to_owned(),
            adapter: adapter.to_owned(),
        };
        let outcome = self
            .background
            .evaluate(std::slice::from_ref(&task), tool, arguments, context)
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                JudgeOutcome::Failed(JudgeFailure {
                    predicate_id: predicate.to_owned(),
                    model: unknown_pin(adapter),
                    kind: pv_judge::FailureKind::Unavailable,
                    detail: "the background runner returned no outcome".to_owned(),
                    latency_us: 0,
                })
            });
        self.count_calls(std::slice::from_ref(&outcome));
        (outcome, micros_since(started))
    }

    /// Shadow or enforce.
    pub fn mode(&self) -> JudgeMode {
        self.mode
    }

    /// The predicates bound to `tool`, if it is tagged.
    pub fn tasks_for(&self, tool: &str) -> Option<&[JudgeTask]> {
        self.tools.get(tool).map(Vec::as_slice)
    }

    /// Every tagged tool.
    pub fn tagged_tools(&self) -> impl Iterator<Item = &str> {
        self.tools.keys().map(String::as_str)
    }

    /// Every predicate bound to some tool.
    pub fn bound_predicates(&self) -> BTreeSet<String> {
        self.tools
            .values()
            .flatten()
            .map(|task| task.predicate_id.clone())
            .collect()
    }

    /// The adapter kind behind an adapter name.
    pub fn adapter_kind(&self, adapter: &str) -> AdapterKind {
        self.adapter_kinds
            .get(adapter)
            .copied()
            .unwrap_or(AdapterKind::Mock)
    }

    /// The drift monitor, when `[judge.drift]` is set.
    pub fn drift(&self) -> Option<&DriftMonitor> {
        self.drift.as_ref()
    }

    /// Predicates in ask-by-default mode.
    pub fn drift_tripped(&self) -> Vec<String> {
        self.drift.as_ref().map(DriftMonitor::tripped).unwrap_or_default()
    }

    /// Calls in flight.
    pub fn in_flight(&self) -> usize {
        self.runner.in_flight()
    }

    /// Build the context the judge may see.
    pub(crate) fn context(&self, inputs: &ContextInputs<'_>) -> SessionContext {
        let tasks: Vec<&str> = inputs
            .missions
            .iter()
            .filter_map(|mission| mission.task.as_deref())
            .collect();
        let mut allowed: Vec<String> = inputs
            .missions
            .iter()
            .flat_map(|mission| mission.allowed_intents.iter().cloned())
            .collect();
        allowed.sort();
        allowed.dedup();
        let mut prior = Vec::new();
        {
            let log = self.denials.lock();
            prior.extend(log.recent(&session_key(inputs.session_id)).into_iter().take(8));
            for parent in &inputs.parents {
                prior.extend(
                    log.recent(&instance_key(parent))
                        .into_iter()
                        .map(|mut denial| {
                            denial.source = DenialSource::Parent;
                            denial
                        })
                        .take(8),
                );
            }
        }
        prior.truncate(pv_judge::render::MAX_RENDERED_DENIALS);
        SessionContext {
            intent: Some(inputs.intent.clone()),
            task: (!tasks.is_empty()).then(|| tasks.join("\n")),
            mission_ids: inputs.missions.iter().map(|mission| mission.id.clone()).collect(),
            allowed_intents: allowed,
            charter: inputs.charter.to_owned(),
            delegation_depth: u32::try_from(inputs.delegation_depth).unwrap_or(u32::MAX),
            prior_denials: prior,
        }
    }

    /// Record a refusal under the session and the refusing agent.
    pub(crate) fn record_denial(
        &self,
        session_id: &str,
        instance_uid: &str,
        tool: &str,
        denial_code: &str,
        predicate_id: Option<String>,
    ) {
        let denial = PriorDenial {
            tool: tool.to_owned(),
            denial_code: denial_code.to_owned(),
            predicate_id,
            at_ms: pv_core::time::now_ms(),
            source: DenialSource::Session,
            instance_uid: instance_uid.to_owned(),
        };
        let mut log = self.denials.lock();
        log.push(session_key(session_id), denial.clone());
        log.push(instance_key(instance_uid), denial);
    }

    /// Score `tool`'s predicates from synchronous code running on the
    /// blocking pool. The work runs on the async runtime; this thread
    /// waits at most the longest adapter deadline plus one second, so a
    /// misuse (calling from an async worker) degrades into timeouts —
    /// which fail closed — instead of a hang or a panic.
    pub(crate) fn evaluate_blocking(
        self: &Arc<Self>,
        tasks: &[JudgeTask],
        tool: &str,
        arguments: &Value,
        context: SessionContext,
    ) -> (Vec<JudgeOutcome>, u64) {
        let started = std::time::Instant::now();
        let fail_all = |kind: pv_judge::FailureKind, detail: &str| -> Vec<JudgeOutcome> {
            tasks
                .iter()
                .map(|task| {
                    JudgeOutcome::Failed(JudgeFailure {
                        predicate_id: task.predicate_id.clone(),
                        model: self
                            .runner
                            .adapter(&task.adapter)
                            .map(|slot| slot.adapter.id().clone())
                            .unwrap_or_else(|| unknown_pin(&task.adapter)),
                        kind,
                        detail: detail.to_owned(),
                        latency_us: micros_since(started),
                    })
                })
                .collect()
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            let outcomes = fail_all(
                pv_judge::FailureKind::Unavailable,
                "no async runtime for the judge",
            );
            return (outcomes, micros_since(started));
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let service = Arc::clone(self);
        let owned_tasks = tasks.to_vec();
        let owned_tool = tool.to_owned();
        let owned_arguments = arguments.clone();
        handle.spawn(async move {
            let outcomes = service
                .runner
                .evaluate(&owned_tasks, &owned_tool, &owned_arguments, &context)
                .await;
            let _ = sender.send(outcomes);
        });
        let outcomes = match receiver.recv_timeout(self.max_deadline + Duration::from_secs(1)) {
            Ok(outcomes) => outcomes,
            Err(_) => fail_all(pv_judge::FailureKind::Timeout, "judge did not answer in time"),
        };
        let judge_us = micros_since(started);
        self.observe(&outcomes, judge_us);
        (outcomes, judge_us)
    }

    fn observe(&self, outcomes: &[JudgeOutcome], judge_us: u64) {
        self.count_calls(outcomes);
        self.metrics
            .histogram_with_bounds(
                "pv_judge_wait_seconds",
                "Time a judged tool call waited for the semantic judge",
                pv_core::metrics::WIDE_LATENCY_BOUNDS_US,
            )
            .observe_us(judge_us);
    }

    fn count_calls(&self, outcomes: &[JudgeOutcome]) {
        for outcome in outcomes {
            self.metrics
                .counter(
                    &format!(
                        "pv_judge_calls_total{{predicate=\"{}\",status=\"{}\"}}",
                        outcome.predicate_id(),
                        outcome.status_str()
                    ),
                    "Semantic judge calls by predicate and outcome",
                )
                .inc();
        }
    }

    /// Count a judge decision.
    pub(crate) fn count_decision(&self, action: JudgeAction, enforced: bool) {
        self.metrics
            .counter(
                &format!(
                    "pv_judge_decisions_total{{mode=\"{}\",decision=\"{}\",enforced=\"{enforced}\"}}",
                    self.mode.as_str(),
                    action.as_str()
                ),
                "Semantic judge policy decisions",
            )
            .inc();
    }

    /// Sample scored verdicts for review; returns review ids by predicate.
    pub(crate) fn sample_reviews(&self, outcomes: &[JudgeOutcome]) -> BTreeMap<String, String> {
        let Some(drift) = &self.drift else {
            return BTreeMap::new();
        };
        outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                JudgeOutcome::Scored(verdict) => drift
                    .maybe_sample(verdict, pv_core::new_event_uid)
                    .map(|id| (verdict.predicate_id.clone(), id)),
                JudgeOutcome::Failed(_) => None,
            })
            .collect()
    }

    /// Save the drift statistics and switches (after a review or reset).
    /// Blocking file I/O: call it from the blocking pool.
    pub(crate) fn persist_drift(&self) -> Result<(), String> {
        let (Some(monitor), Some(path)) = (&self.drift, &self.drift_file) else {
            return Ok(());
        };
        let _serialized = self.drift_write.lock();
        let bytes = serde_json::to_vec_pretty(&monitor.export_state()).map_err(|error| error.to_string())?;
        pv_core::fsutil::write_atomic(path, &bytes).map_err(|error| {
            self.metrics
                .counter(
                    "pv_judge_drift_persist_failures_total",
                    "Judge drift state saves that failed (the switch may not survive a restart)",
                )
                .inc();
            format!("write judge drift state file {}: {error}", path.display())
        })
    }

    /// Update the drift gauge after a review.
    pub(crate) fn publish_drift(&self) {
        let tripped = self.drift_tripped().len();
        self.metrics
            .gauge(
                "pv_judge_drift_tripped",
                "Judge predicates in ask-by-default mode after a calibration drift check",
            )
            .set(u64::try_from(tripped).unwrap_or(u64::MAX));
    }

    /// Pilot cap: count one score-based judge block for `tool` today and
    /// say whether it may be enforced. `true` without a cap. A state
    /// store failure keeps the block (fail closed).
    pub(crate) fn pilot_admits_block(&self, store: &dyn pv_state::StateStore, tool: &str) -> bool {
        let Some(cap) = self.pilot_cap else {
            return true;
        };
        let day = pv_core::time::now_ms() / 86_400_000;
        let key = format!(
            "judge:pilot:{day}:{}",
            pv_core::digest::sha256_hex(tool.as_bytes())
        );
        match store.add(&key, 1) {
            Ok(count) => {
                let within = count <= cap;
                if !within {
                    self.metrics
                        .counter(
                            "pv_judge_pilot_cap_reached_total",
                            "Judge blocks let through because the pilot's daily cap was reached",
                        )
                        .inc();
                }
                within
            }
            Err(error) => {
                tracing::warn!(error = %error, "judge pilot counter unavailable; keeping the block");
                true
            }
        }
    }
}

fn session_key(session_id: &str) -> String {
    format!("s:{session_id}")
}

fn instance_key(instance_uid: &str) -> String {
    format!("i:{instance_uid}")
}

fn unknown_pin(adapter: &str) -> pv_judge::ModelPin {
    pv_judge::ModelPin {
        name: format!("unconfigured:{adapter}"),
        version: "0".to_owned(),
        weights_sha256: "0".repeat(64),
    }
}

fn micros_since(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Build the configured adapters (boot path). Reads model, tokenizer,
/// and bearer files; a pin mismatch refuses to start the harness.
pub fn build_adapters(
    judge: &JudgeConfig,
    redaction: Option<Arc<pv_redact::RedactionEngine>>,
) -> Result<BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>>, String> {
    let mut built: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
    for adapter in &judge.adapters {
        let pin = adapter.pin()?;
        let instance: Arc<dyn pv_judge::JudgeAdapter> = match adapter.kind {
            JudgeAdapterKind::Local => build_local(adapter, pin)?,
            JudgeAdapterKind::Cloud => {
                let endpoint = adapter
                    .endpoint
                    .as_deref()
                    .ok_or_else(|| format!("judge adapter {:?} needs endpoint", adapter.name))
                    .and_then(|raw| {
                        url::Url::parse(raw)
                            .map_err(|_| format!("judge adapter {:?} endpoint is not a URL", adapter.name))
                    })?;
                let bearer =
                    crate::pipeline::read_secret(None, adapter.bearer_file.as_deref(), "judge bearer token")
                        .map_err(|error| format!("judge adapter {:?}: {error}", adapter.name))?
                        .map(zeroize::Zeroizing::new);
                let mut cloud = pv_judge::cloud::CloudJudge::new(pv_judge::cloud::CloudJudgeConfig {
                    endpoint,
                    bearer,
                    pin,
                    timeout: adapter.deadline(),
                })
                .map_err(|error| format!("judge adapter {:?}: {error}", adapter.name))?;
                if adapter.redact {
                    // With no harness redaction configured, still apply the
                    // built-in patterns: `redact = true` must mean something.
                    let engine = match &redaction {
                        Some(engine) => Arc::clone(engine),
                        None => Arc::new(
                            pv_redact::RedactionEngine::new(pv_redact::RedactionConfig {
                                include_builtin_patterns: true,
                                ..pv_redact::RedactionConfig::default()
                            })
                            .map_err(|error| {
                                format!("judge adapter {:?} redaction: {error}", adapter.name)
                            })?,
                        ),
                    };
                    cloud =
                        cloud.with_redactor(Arc::new(move |value: &mut Value| engine.redact_value(value)));
                }
                Arc::new(cloud)
            }
        };
        built.insert(adapter.name.clone(), instance);
    }
    Ok(built)
}

#[cfg(feature = "onnx")]
fn build_local(
    adapter: &JudgeAdapterConfig,
    pin: pv_judge::ModelPin,
) -> Result<Arc<dyn pv_judge::JudgeAdapter>, String> {
    let config = pv_judge::local::LocalOnnxConfig {
        model_path: adapter.model_path.clone().unwrap_or_default().into(),
        tokenizer_path: adapter.tokenizer_path.clone().unwrap_or_default().into(),
        pin,
        tokenizer_sha256: adapter.tokenizer_sha256.clone().unwrap_or_default(),
        output_labels: adapter.output_labels.clone(),
        max_input_tokens: adapter.max_input_tokens.unwrap_or(512),
    };
    let judge = pv_judge::local::LocalOnnxJudge::load(&config)
        .map_err(|error| format!("judge adapter {:?}: {error}", adapter.name))?;
    Ok(Arc::new(judge))
}

#[cfg(not(feature = "onnx"))]
fn build_local(
    adapter: &JudgeAdapterConfig,
    _pin: pv_judge::ModelPin,
) -> Result<Arc<dyn pv_judge::JudgeAdapter>, String> {
    Err(format!(
        "judge adapter {:?} is local, which requires the `onnx` cargo feature; this build was \
         compiled without it (rebuild with --features onnx or full)",
        adapter.name
    ))
}

/// Score a labelled set with one configured adapter, exactly as the
/// harness would build it (same pin checks, same redaction for cloud
/// adapters, same deadline). Used by `pvctl judge-calibrate`.
pub async fn calibrate_from_config(
    config: &crate::config::HarnessConfig,
    adapter: &str,
    examples: &[pv_judge::calibration::LabelledExample],
) -> Result<pv_judge::calibration::CalibrationReport, String> {
    let judge = config
        .judge
        .as_ref()
        .ok_or_else(|| "the config has no [judge] section".to_owned())?;
    let mut errors = Vec::new();
    judge.collect_errors(&mut errors);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let adapter_config = judge
        .adapters
        .iter()
        .find(|candidate| candidate.name == adapter)
        .ok_or_else(|| format!("no judge adapter named {adapter:?}"))?;
    let redaction = if config.redaction_patterns.is_empty() && config.redaction_paths.is_empty() {
        None
    } else {
        let engine = pv_redact::RedactionEngine::new(pv_redact::RedactionConfig {
            regex_patterns: config.redaction_patterns.clone(),
            pointer_paths: config.redaction_paths.clone(),
            include_builtin_patterns: true,
            ..pv_redact::RedactionConfig::default()
        })
        .map_err(|error| format!("redaction engine: {error}"))?;
        Some(Arc::new(engine))
    };
    let only = JudgeConfig {
        adapters: vec![adapter_config.clone()],
        ..judge.clone()
    };
    let mut built = build_adapters(&only, redaction)?;
    let instance = built
        .remove(adapter)
        .ok_or_else(|| format!("judge adapter {adapter:?} was not built"))?;
    let mut slots = BTreeMap::new();
    slots.insert(
        adapter.to_owned(),
        AdapterSlot {
            adapter: instance,
            deadline: adapter_config.deadline(),
        },
    );
    let runner = JudgeRunner::new(slots, Arc::new(judge.registry()?), judge.max_concurrency)?;
    pv_judge::calibration::calibrate(&runner, adapter, examples).await
}

// ---------------------------------------------------------------------------
// Background judging: recorded outputs, the breaker's second opinion,
// and `agent.judge` events.
// ---------------------------------------------------------------------------

/// Holds a session open (its pending-job count) while a background
/// verdict is on its way, so a close waits for it and the verdict lands
/// inside what the session's receipt signs. Released on drop, whatever
/// happens to the task (completion, panic, cancellation at shutdown).
pub(crate) struct PendingGuard(Arc<crate::session::Session>);

impl PendingGuard {
    pub(crate) fn new(session: Arc<crate::session::Session>) -> Self {
        session.worker_job_started();
        Self(session)
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.worker_job_finished();
    }
}

/// A recorded output the audit worker hands over once its step is durable.
#[derive(Debug, Clone)]
pub(crate) struct CapturedOutput {
    pub(crate) source: TraceSource,
    pub(crate) tool: Option<String>,
    pub(crate) text: String,
}

/// The judge as the audit worker sees it.
pub struct JudgeHooks {
    service: Arc<JudgeService>,
    worker: crate::worker::WorkerHandle,
    pdp: Arc<crate::authz::PolicyDecisionPoint>,
    metrics: Arc<pv_core::metrics::Registry>,
}

/// The hooks slot shared by the application state and the audit worker,
/// so the judge can be attached after both exist.
pub type SharedJudgeHooks = Arc<parking_lot::RwLock<Option<Arc<JudgeHooks>>>>;

impl JudgeHooks {
    pub(crate) fn new(
        service: Arc<JudgeService>,
        worker: crate::worker::WorkerHandle,
        pdp: Arc<crate::authz::PolicyDecisionPoint>,
        metrics: Arc<pv_core::metrics::Registry>,
    ) -> Self {
        Self {
            service,
            worker,
            pdp,
            metrics,
        }
    }

    /// The judge service.
    pub fn service(&self) -> &Arc<JudgeService> {
        &self.service
    }

    fn context(&self, session: &crate::session::Session, intent: &str) -> SessionContext {
        let identity = session.current_identity();
        let facts = crate::authz::CallerFacts {
            instance_uid: &identity.instance_uid,
            charter: &identity.charter.name,
            subject: None,
        };
        self.service.context(&ContextInputs {
            session_id: &session.id,
            intent: intent.to_owned(),
            missions: self.pdp.applicable_missions(&facts),
            charter: &identity.charter.name,
            delegation_depth: 0,
            parents: Vec::new(),
        })
    }

    /// Publish an `agent.judge` event (and, for unsigned sessions, an ATIF
    /// step) for `session`. A full audit queue drops it and counts the drop.
    pub(crate) fn emit(&self, session: &Arc<crate::session::Session>, payload: Value) {
        let kind = payload
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("finding")
            .to_owned();
        match self.worker.try_reserve(&session.id) {
            Ok(permit) => permit.submit(crate::worker::WorkerJob {
                session: Arc::clone(session),
                identity: session.current_identity(),
                class: pv_events::EventClass::Judge,
                atif: Some(crate::worker::AtifCapture {
                    source: pv_atif::Source::System,
                    message: Value::String(format!("semantic judge {kind}: {payload}")),
                    reasoning_content: None,
                    model_name: None,
                    tool_calls: None,
                    observation: None,
                    llm_call_count: Some(0),
                }),
                payload,
                text: String::new(),
                analyze_loop: false,
                status: pv_events::StatusId::Success,
                stop_reason: None,
                native_stop_reason: None,
                metrics: pv_events::EventMetrics::default(),
                cost_usd_micros: 0,
                prompt_token_correction: 0,
                response_marker: None,
                response_attempt: None,
            }),
            Err(error) => {
                tracing::warn!(session = %session.id, %error, kind, "semantic judge event dropped: audit queue full");
                self.metrics
                    .counter(
                        &format!("pv_judge_events_dropped_total{{kind=\"{kind}\"}}"),
                        "Semantic judge events dropped because the audit queue was full",
                    )
                    .inc();
            }
        }
    }

    /// Judge a durable recorded output in the background, when trace
    /// judging covers its source. Never delays the request that produced it.
    pub(crate) fn after_capture(
        self: &Arc<Self>,
        session: Arc<crate::session::Session>,
        output: CapturedOutput,
    ) {
        let Some(trace) = self.service.trace() else {
            return;
        };
        if !trace.sources.contains(&output.source) || output.text.trim().is_empty() {
            return;
        }
        let guard = PendingGuard::new(Arc::clone(&session));
        let hooks = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = guard;
            hooks.judge_trace(&session, output).await;
        });
    }

    async fn judge_trace(&self, session: &Arc<crate::session::Session>, output: CapturedOutput) {
        let Some(trace) = self.service.trace() else {
            return;
        };
        let text = truncate_chars(&output.text, trace.max_output_chars);
        let tool = output.tool.clone().unwrap_or_else(|| "model".to_owned());
        let intent = match &output.tool {
            Some(tool) => self.pdp.intent_for(tool),
            None => "model.output".to_owned(),
        };
        let context = self.context(session, &intent);
        let arguments = serde_json::json!({"source": output.source.as_str(), "output": text});
        let (outcome, judge_us) = self
            .service
            .score_background(&trace.adapter, &trace.predicate, &tool, &arguments, &context)
            .await;
        let positive = self.positive_label(&trace.predicate);
        let risk_ppm = match &outcome {
            JudgeOutcome::Scored(verdict) => positive.as_deref().and_then(|label| verdict.ppm(label)),
            JudgeOutcome::Failed(_) => None,
        };
        let finding_above_ppm = pv_judge::threshold_to_ppm(trace.finding_above).unwrap_or(pv_judge::PPM_ONE);
        let finding = risk_ppm.is_some_and(|ppm| ppm > finding_above_ppm);
        if finding {
            self.metrics
                .counter(
                    &format!(
                        "pv_judge_trace_findings_total{{source=\"{}\"}}",
                        output.source.as_str()
                    ),
                    "Recorded outputs the semantic judge flagged",
                )
                .inc();
        }
        let record = pv_judge::OutcomeRecord::from_outcome(
            &outcome,
            &trace.adapter,
            self.service.adapter_kind(&trace.adapter),
        );
        self.emit(
            session,
            serde_json::json!({
                "kind": "trace",
                "source": output.source.as_str(),
                "tool": output.tool,
                "finding": finding,
                "risk_ppm": risk_ppm,
                "finding_above_ppm": finding_above_ppm,
                "output_sha256": pv_core::digest::sha256_hex(output.text.as_bytes()),
                "judge_us": judge_us,
                "verdict": record,
            }),
        );
    }

    fn positive_label(&self, predicate: &str) -> Option<String> {
        self.service
            .background
            .registry()
            .get(predicate)
            .map(|def| def.positive_label.clone())
    }

    /// The loop breaker's second opinion on an ambiguous step: `Some(true)`
    /// when the step should count as no progress, `Some(false)` when it
    /// should count as progress, `None` (keep the breaker's own decision)
    /// when the delta is outside the ambiguous range or the judge fails.
    /// Records an `agent.judge` event whenever the judge was asked.
    pub(crate) async fn second_opinion(
        &self,
        session: &Arc<crate::session::Session>,
        delta: f32,
        previous: Option<&str>,
        current: &str,
    ) -> Option<bool> {
        let breaker = self.service.breaker()?;
        let delta_ppm = delta_to_ppm(delta);
        let low = pv_judge::threshold_to_ppm(breaker.ambiguous_low).ok()?;
        let high = pv_judge::threshold_to_ppm(breaker.ambiguous_high).ok()?;
        if !(low..=high).contains(&delta_ppm) {
            return None;
        }
        let context = self.context(session, "model.output");
        let arguments = serde_json::json!({
            "previous": previous.map(|text| truncate_chars(text, MAX_LOOP_TEXT_CHARS)),
            "current": truncate_chars(current, MAX_LOOP_TEXT_CHARS),
        });
        let (outcome, judge_us) = self
            .service
            .score_background(
                &breaker.adapter,
                &breaker.predicate,
                "model",
                &arguments,
                &context,
            )
            .await;
        let looping_above = pv_judge::threshold_to_ppm(breaker.looping_above).unwrap_or(pv_judge::PPM_ONE);
        let positive = self.positive_label(&breaker.predicate);
        let opinion = match &outcome {
            JudgeOutcome::Scored(verdict) => positive
                .as_deref()
                .and_then(|label| verdict.ppm(label))
                .map(|ppm| ppm > looping_above),
            JudgeOutcome::Failed(_) => None,
        };
        self.metrics
            .counter(
                &format!(
                    "pv_judge_breaker_opinions_total{{opinion=\"{}\"}}",
                    match opinion {
                        Some(true) => "looping",
                        Some(false) => "progressing",
                        None => "unavailable",
                    }
                ),
                "Second opinions the semantic judge gave the loop breaker",
            )
            .inc();
        let record = pv_judge::OutcomeRecord::from_outcome(
            &outcome,
            &breaker.adapter,
            self.service.adapter_kind(&breaker.adapter),
        );
        self.emit(
            session,
            serde_json::json!({
                "kind": "breaker",
                "delta_ppm": delta_ppm,
                "ambiguous_low_ppm": low,
                "ambiguous_high_ppm": high,
                "looping": opinion,
                "judge_us": judge_us,
                "verdict": record,
            }),
        );
        opinion
    }
}

/// A breaker delta (0 to 2) in parts per million, saturating.
fn delta_to_ppm(delta: f32) -> u32 {
    if !delta.is_finite() || delta <= 0.0 {
        return 0;
    }
    pv_judge::prob_to_ppm(f64::from(delta).min(1.0))
}

fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((cut, _)) => text.get(..cut).unwrap_or(text).to_owned(),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use pv_state::{Spend, StateError, StateStore, TrySpendOutcome};

    /// A state store that is down.
    struct DownStore;

    impl StateStore for DownStore {
        fn add(&self, _key: &str, _delta: u64) -> Result<u64, StateError> {
            Err(StateError::Backend("down".into()))
        }
        fn get(&self, _key: &str) -> Result<u64, StateError> {
            Err(StateError::Backend("down".into()))
        }
        fn try_spend_many(&self, _spends: &[Spend]) -> Result<TrySpendOutcome, StateError> {
            Err(StateError::Backend("down".into()))
        }
        fn remove(&self, _key: &str) {}
    }

    fn service(cap: Option<u64>) -> JudgeService {
        let pin = pv_judge::ModelPin::new("m", "1", "a".repeat(64)).unwrap();
        let config: JudgeConfig = toml::from_str(&format!(
            r#"
            mode = "enforce"
            [[adapters]]
            name = "a"
            kind = "cloud"
            endpoint = "http://127.0.0.1:9/x"
            model_name = "m"
            model_version = "1"
            weights_sha256 = "{hash}"
            [[tools]]
            tool = "t"
            allow_cloud = true
            predicates = [{{ id = "arg_matches_task@1", adapter = "a" }}]
            [[thresholds]]
            predicate = "arg_matches_task@1"
            label = "mismatch"
            deny_above = 0.7
            {pilot}
            "#,
            hash = "a".repeat(64),
            pilot = cap
                .map(|cap| format!("[pilot]\ndaily_block_cap = {cap}"))
                .unwrap_or_default(),
        ))
        .unwrap();
        let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
        adapters.insert(
            "a".into(),
            Arc::new(pv_judge::mock::MockJudge::new(
                pin,
                pv_judge::mock::MockBehavior::scores(&[("match", 1.0), ("mismatch", 0.0)]),
            )),
        );
        JudgeService::new(&config, adapters, Arc::new(pv_core::metrics::Registry::new())).unwrap()
    }

    #[test]
    fn the_pilot_cap_keeps_the_block_when_the_store_is_down() {
        assert!(service(Some(1)).pilot_admits_block(&DownStore, "t"));
    }

    #[test]
    fn the_pilot_cap_counts_per_tool() {
        let judge = service(Some(2));
        let store = pv_state::InMemoryStore::new();
        assert!(judge.pilot_admits_block(&store, "t"));
        assert!(judge.pilot_admits_block(&store, "t"));
        assert!(!judge.pilot_admits_block(&store, "t"));
        assert!(
            judge.pilot_admits_block(&store, "other"),
            "another tool has its own cap"
        );
        assert!(
            service(None).pilot_admits_block(&DownStore, "t"),
            "no cap: always enforce"
        );
    }

    #[test]
    fn the_denial_log_is_bounded() {
        let mut log = DenialLog::default();
        let denial = |n: usize| PriorDenial {
            tool: format!("t{n}"),
            denial_code: "POLICY_DENIED".into(),
            predicate_id: None,
            at_ms: 0,
            source: DenialSource::Session,
            instance_uid: "i".into(),
        };
        for n in 0..(DENIALS_PER_KEY + 5) {
            log.push("k".into(), denial(n));
        }
        let recent = log.recent("k");
        assert_eq!(recent.len(), DENIALS_PER_KEY);
        assert_eq!(
            recent[0].tool,
            format!("t{}", DENIALS_PER_KEY + 4),
            "newest first"
        );
        for n in 0..(DENIAL_LOG_KEYS + 3) {
            log.push(format!("key-{n}"), denial(n));
        }
        assert!(log.by_key.len() <= DENIAL_LOG_KEYS);
        assert!(log.recent("k").is_empty(), "the oldest key was evicted");
    }
}
