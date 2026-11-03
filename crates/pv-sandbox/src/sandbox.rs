//! The sandbox pipeline: parse → schema → policy → budget, with timing.

use crate::denial_code::DenialCode;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::pushed::PushedRules;
use crate::rpc::{denial_error, judge_denial_error, parse_tool_call, RpcError, ToolCallRequest};
use pv_judge::{DecisionCause, JudgeAction, JudgeDecision, JudgeOutcome, ThresholdPolicy};
use pv_state::{ActionBudget, BudgetDecision, BudgetSpec, StateStore};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Sandbox configuration.
pub struct SandboxConfig {
    /// Per-tool JSON Schemas for argument validation.
    pub schemas: HashMap<String, Value>,
    /// Action budget spec applied per session.
    pub budget: BudgetSpec,
    /// Argument field carrying a payout amount in USD (e.g. `amount_usd`).
    /// When present on a call, it is charged against `max_payout_usd_micros`.
    pub payout_field: String,
    /// Reject tools without a configured schema.
    pub require_schema: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            schemas: HashMap::new(),
            budget: BudgetSpec::default(),
            payout_field: "amount_usd".into(),
            require_schema: false,
        }
    }
}

/// Verdict for one intercepted tool call.
#[derive(Debug)]
#[non_exhaustive]
pub enum ToolVerdict {
    /// Forward to the downstream tool server.
    Allowed {
        /// Tool name.
        tool: String,
        /// Remaining headroom under the binding budget dimension.
        budget_remaining: u64,
        /// Decision latency in microseconds (SLA surface, R23).
        elapsed_us: u64,
        /// Payout amount (USD micros) that
        /// `ActionBudget::try_tool_call` debited on this call. Threaded
        /// out so a lost `execution.claim()` race in the harness can
        /// call [`ActionBudget::refund_tool_call`] with the exact same
        /// amount, closing the concurrent-MCP budget
        /// double-spend.
        payout_micros: u64,
        /// Principal id whose ledger was ALSO debited (when a
        /// principal-scoped budget is bound). Threaded out so every
        /// harness failure path that refunds the session ledger can
        /// mirror the refund on the principal ledger — without this,
        /// each lost claim race / saturated worker permanently consumed
        /// principal quota with zero tools executed.
        principal_id: Option<String>,
    },
    /// Block; respond to the agent with `response`.
    Blocked {
        /// Tool name (`<unparsed>` when the payload never parsed).
        tool: String,
        /// Which gate blocked: `parse` | `schema` | `policy` | `budget`.
        stage: &'static str,
        /// Name of the policy engine that denied, when the block came
        /// from the named policy chain (`stage: "policy"`). Parse,
        /// schema, and budget gates are configured limits rather than
        /// named policies, so they stay `None` — the console's
        /// per-policy attribution must never invent a policy that the
        /// operator can't find in their policy inventory.
        policy: Option<String>,
        /// Structured denial code for machine consumption.
        denial_code: DenialCode,
        /// Human/machine-readable reason.
        reason: String,
        /// Ready-to-send JSON-RPC authorization error.
        response: Value,
        /// Decision latency in microseconds.
        elapsed_us: u64,
    },
}

impl ToolVerdict {
    /// True when the call may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Decision latency in microseconds.
    pub fn elapsed_us(&self) -> u64 {
        match self {
            Self::Allowed { elapsed_us, .. } | Self::Blocked { elapsed_us, .. } => *elapsed_us,
        }
    }
}

/// Policy name reported for refusals made by the semantic-judge
/// thresholds (console attribution needs a stable handle).
pub const JUDGE_POLICY_NAME: &str = "judge.thresholds";

/// A call that passed the parse and schema gates, with the
/// console-pushed rule snapshot those gates used.
#[derive(Debug, Clone)]
pub struct ValidatedCall {
    /// The parsed, schema-valid request.
    pub request: ToolCallRequest,
    pushed: Arc<PushedRules>,
    sandbox_us: u64,
}

/// What the semantic judge said about a call, for the policy gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JudgeEvidence {
    /// One outcome per evaluated predicate.
    pub outcomes: Vec<JudgeOutcome>,
    /// Predicates the runtime calibration check flipped to ask-by-default.
    pub drift_tripped: Vec<String>,
}

/// The sandbox: compiled schemas + policy chain + budget spec.
pub struct Sandbox {
    validators: HashMap<String, jsonschema::Validator>,
    policies: Vec<Box<dyn PolicyEngine>>,
    config: SandboxConfig,
    /// Thresholds and failure behaviour for judge outcomes. The default
    /// has no thresholds and the fail-closed failure behaviour.
    judge_policy: ThresholdPolicy,
    /// Console-pushed rules, swapped in whole when a new bundle is
    /// applied. Every check reads one snapshot, so a call never sees half
    /// of an old bundle and half of a new one.
    pushed: parking_lot::RwLock<Arc<PushedRules>>,
}

impl Sandbox {
    /// Build a sandbox, compiling every tool schema up front (a schema that
    /// fails to compile is a configuration error surfaced at boot, not a
    /// silently-skipped validation at request time).
    pub fn new(config: SandboxConfig, policies: Vec<Box<dyn PolicyEngine>>) -> Result<Self, String> {
        let mut validators = HashMap::new();
        for (tool, schema) in &config.schemas {
            // Enforce `format` keywords. In
            // jsonschema 0.49 / draft 2020-12, `format` is
            // annotation-only unless opted in — an operator writing
            // `"format": "uri"` into a tool-argument schema expected an
            // enforced gate, not a no-op.
            let v = jsonschema::options()
                .should_validate_formats(true)
                .build(schema)
                .map_err(|e| format!("schema for tool {tool:?} does not compile: {e}"))?;
            validators.insert(tool.clone(), v);
        }
        Ok(Self {
            validators,
            policies,
            config,
            pushed: parking_lot::RwLock::new(Arc::new(PushedRules::default())),
            judge_policy: ThresholdPolicy::default(),
        })
    }

    /// Set the semantic-judge thresholds and failure behaviour.
    #[must_use]
    pub fn with_judge_policy(mut self, policy: ThresholdPolicy) -> Self {
        self.judge_policy = policy;
        self
    }

    /// The semantic-judge thresholds in force.
    pub fn judge_policy(&self) -> &ThresholdPolicy {
        &self.judge_policy
    }

    /// True when `tool` has a local argument schema.
    pub fn has_schema(&self, tool: &str) -> bool {
        self.validators.contains_key(tool)
    }

    /// Names of policy engines that read judge outcomes (WASM ABI v2).
    pub fn judge_aware_policies(&self) -> Vec<String> {
        self.policies
            .iter()
            .filter(|policy| policy.sees_judge())
            .map(|policy| policy.name().to_owned())
            .collect()
    }

    /// Replace the console-pushed rules. They only ever add restrictions
    /// (see [`crate::pushed`]).
    pub fn set_pushed(&self, rules: PushedRules) {
        *self.pushed.write() = Arc::new(rules);
    }

    /// The console-pushed rules currently in force.
    pub fn pushed(&self) -> Arc<PushedRules> {
        Arc::clone(&self.pushed.read())
    }

    /// The local budget tightened by any pushed budget: the spec every
    /// session ledger is checked against.
    pub fn effective_budget(&self) -> BudgetSpec {
        self.config.budget.tightened_by(&self.pushed().budget)
    }

    /// Evaluate a raw MCP payload for `session`.
    pub fn check(&self, store: &dyn StateStore, session: &str, raw: &[u8]) -> ToolVerdict {
        self.check_with_principal(store, session, None, raw)
    }

    /// Same as [`Self::check`] but layers a principal-scoped budget check
    /// on top of the session-scoped one. When `principal` is `Some(spec)`,
    /// the tool call is refused unless BOTH ledgers admit the spend; the
    /// principal ledger persists across every session belonging to the
    /// same identity, which is what makes header-rotation attacks
    /// (resetting the session bucket by minting a new session id)
    /// visible.
    ///
    /// The two ledgers commit independently: if the principal check
    /// passes and the session check fails, the principal debit is
    /// refunded on the same dimensions before returning. Both budgets
    /// must use identical `BudgetSpec` shapes so the refund is exact.
    pub fn check_with_principal(
        &self,
        store: &dyn StateStore,
        session: &str,
        principal: Option<(&str, &BudgetSpec)>,
        raw: &[u8],
    ) -> ToolVerdict {
        let call = match self.precheck(raw) {
            Ok(call) => call,
            Err(verdict) => return verdict,
        };
        self.admit(store, session, principal, call, None)
    }

    /// Gates 1 and 2: parse the JSON-RPC envelope and validate the
    /// arguments against the local and console-pushed schemas. Returns
    /// the validated call, or the blocking verdict.
    ///
    /// Together with [`Self::admit`] this is [`Self::check_with_principal`]
    /// split at the point where the semantic judge runs: the judge only
    /// ever sees arguments that passed the schema gate. The validated call
    /// carries the console-pushed rule snapshot this precheck used, so
    /// both halves of one call see the same bundle.
    // `ToolVerdict` is the sandbox's ordinary by-value return type
    // (`check` returns it directly); boxing it here only for the refusal
    // path would make the two halves of `check` disagree in shape.
    #[allow(clippy::result_large_err)]
    pub fn precheck(&self, raw: &[u8]) -> Result<ValidatedCall, ToolVerdict> {
        let started = std::time::Instant::now();
        let elapsed = |s: std::time::Instant| u64::try_from(s.elapsed().as_micros()).unwrap_or(u64::MAX);
        let pushed = self.pushed();

        // Gate 1: parse.
        let req = match parse_tool_call(raw) {
            Ok(r) => r,
            Err(e) => {
                let (stage, reason, denial_code) = match &e {
                    // Passthrough refusal parsed fine as JSON-RPC — a
                    // deliberate policy choice, distinct HTTP class
                    // (403) from true protocol failures (400).
                    RpcError::NotToolCall(_) => (
                        "passthrough",
                        format!("passthrough refused: {e}"),
                        DenialCode::PassthroughRefused,
                    ),
                    _ => ("parse", e.to_string(), DenialCode::ParseError),
                };
                // Protocol-level failures
                // get the reserved JSON-RPC codes (-32700/-32600/
                // -32602), not the -32001 policy code — the request
                // never reached an authorization decision. The id is
                // echoed whenever the envelope made it detectable
                // (JSON-RPC 2.0 §5; see `detectable_error_id`).
                let id = crate::rpc::detectable_error_id(raw, &e);
                return Err(ToolVerdict::Blocked {
                    tool: "<unparsed>".into(),
                    stage,
                    policy: None,
                    denial_code,
                    reason,
                    response: crate::rpc::protocol_error(id.as_ref(), &e),
                    elapsed_us: elapsed(started),
                });
            }
        };

        // Gate 2: schema.
        if let Some(validator) = self.validators.get(&req.tool) {
            // Bounded work: a hostile client cannot force unbounded String
            // allocation by sending pathologically-invalid arguments.
            let errors: Vec<String> = validator
                .iter_errors(&req.arguments)
                .take(3)
                .map(|e| e.to_string())
                .collect();
            if !errors.is_empty() {
                let reason = format!("schema validation failed: {}", errors.join("; "));
                return Err(ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "schema",
                    policy: None,
                    denial_code: DenialCode::SchemaViolation,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::SchemaViolation, &reason),
                    elapsed_us: elapsed(started),
                });
            }
        } else if self.config.require_schema {
            let reason = format!("no argument schema configured for tool {:?}", req.tool);
            return Err(ToolVerdict::Blocked {
                tool: req.tool.clone(),
                stage: "schema",
                policy: None,
                denial_code: DenialCode::SchemaMissing,
                reason: reason.clone(),
                response: denial_error(req.id.as_ref(), DenialCode::SchemaMissing, &reason),
                elapsed_us: elapsed(started),
            });
        }

        // Gate 2b: console-pushed schemas, on top of the local one.
        for schema in pushed.schemas.iter().filter(|schema| schema.tool == req.tool) {
            let errors = schema.errors(&req.arguments);
            if !errors.is_empty() {
                let reason = format!(
                    "policy {:?}: schema validation failed: {}",
                    schema.policy,
                    errors.join("; ")
                );
                return Err(ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "schema",
                    policy: Some(schema.policy.clone()),
                    denial_code: DenialCode::SchemaViolation,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::SchemaViolation, &reason),
                    elapsed_us: elapsed(started),
                });
            }
        }

        Ok(ValidatedCall {
            request: req,
            pushed,
            sandbox_us: elapsed(started),
        })
    }

    /// Gates 3 and 4 for a call that passed [`Self::precheck`]: the
    /// policy chain (which sees `judge`'s outcomes), the judge
    /// thresholds, the console-pushed rules, and the budget. The
    /// verdict's `elapsed_us` is sandbox time only (precheck plus this);
    /// time spent waiting for the judge is recorded separately.
    pub fn admit(
        &self,
        store: &dyn StateStore,
        session: &str,
        principal: Option<(&str, &BudgetSpec)>,
        call: ValidatedCall,
        judge: Option<&JudgeEvidence>,
    ) -> ToolVerdict {
        let started = std::time::Instant::now();
        let ValidatedCall {
            request,
            pushed,
            sandbox_us,
        } = call;
        self.admit_inner(
            store, session, principal, request, &pushed, judge, sandbox_us, started,
        )
    }

    /// The policy gates alone, without spending budget: the verdict
    /// [`Self::admit`] would return before the budget gate, or `None`
    /// when every policy gate passes. Shadow mode uses it to compute what
    /// the judge WOULD have done.
    pub fn policy_verdict(&self, call: &ValidatedCall, judge: Option<&JudgeEvidence>) -> Option<ToolVerdict> {
        let started = std::time::Instant::now();
        self.policy_stage(&call.request, &call.pushed, judge, &|| micros_since(started))
    }

    /// The native threshold decision over `judge`'s outcomes (the same
    /// decision [`Self::admit`] applies).
    pub fn judge_decision(&self, judge: &JudgeEvidence) -> JudgeDecision {
        self.judge_policy.decide(&judge.outcomes, &|id| {
            judge.drift_tripped.iter().any(|tripped| tripped == id)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_inner(
        &self,
        store: &dyn StateStore,
        session: &str,
        principal: Option<(&str, &BudgetSpec)>,
        req: ToolCallRequest,
        pushed: &PushedRules,
        judge: Option<&JudgeEvidence>,
        prior_us: u64,
        started: std::time::Instant,
    ) -> ToolVerdict {
        let elapsed = |s: std::time::Instant| prior_us.saturating_add(micros_since(s));

        if let Some(blocked) = self.policy_stage(&req, pushed, judge, &|| elapsed(started)) {
            return blocked;
        }

        // Gate 4: budget (atomic check-and-spend).
        let payout_micros = match extract_payout_micros(&req.arguments, &self.config.payout_field) {
            Ok(m) => m,
            Err(reason) => {
                return ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    policy: None,
                    denial_code: DenialCode::PayoutInvalid,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::PayoutInvalid, &reason),
                    elapsed_us: elapsed(started),
                }
            }
        };
        let effective_budget = self.config.budget.tightened_by(&pushed.budget);
        let budget = ActionBudget::new(store, session, &effective_budget);
        // Principal-scoped pre-check. Debit the principal ledger
        // first — a header-rotation attack that resets the session bucket
        // still charges the same principal. If the principal ledger admits
        // the spend but the session ledger refuses, we refund the principal
        // debit before returning so the failed call consumed no quota
        // anywhere.
        if let Some((principal_id, principal_spec)) = principal {
            let principal_budget = ActionBudget::for_principal(store, principal_id, principal_spec);
            match principal_budget.try_tool_call(&req.tool, payout_micros) {
                Ok(BudgetDecision::Allowed { .. }) => {}
                Ok(BudgetDecision::Refused { limit, cap }) => {
                    let reason = format!("principal action budget exceeded: {limit} (cap {cap})");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        policy: None,
                        denial_code: DenialCode::BudgetExceeded,
                        reason: reason.clone(),
                        response: denial_error(req.id.as_ref(), DenialCode::BudgetExceeded, &reason),
                        elapsed_us: elapsed(started),
                    };
                }
                Err(e) => {
                    let reason = format!("principal budget check failed closed: {e}");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        policy: None,
                        denial_code: DenialCode::BudgetError,
                        reason: reason.clone(),
                        response: denial_error(req.id.as_ref(), DenialCode::BudgetError, &reason),
                        elapsed_us: elapsed(started),
                    };
                }
            }
            match budget.try_tool_call(&req.tool, payout_micros) {
                Ok(BudgetDecision::Allowed { remaining }) => {
                    return ToolVerdict::Allowed {
                        tool: req.tool,
                        budget_remaining: remaining,
                        elapsed_us: elapsed(started),
                        payout_micros,
                        principal_id: Some(principal_id.to_owned()),
                    };
                }
                Ok(BudgetDecision::Refused { limit, cap }) => {
                    // Session refused; unwind the principal debit so a
                    // failed call is fully non-consumptive.
                    principal_budget.refund_tool_call(&req.tool, payout_micros);
                    let policy = pushed.budget_policy_for(&self.config.budget, &limit, cap);
                    let reason = match &policy {
                        Some(name) => format!("policy {name:?}: action budget exceeded: {limit} (cap {cap})"),
                        None => format!("action budget exceeded: {limit} (cap {cap})"),
                    };
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        policy,
                        denial_code: DenialCode::BudgetExceeded,
                        reason: reason.clone(),
                        response: denial_error(req.id.as_ref(), DenialCode::BudgetExceeded, &reason),
                        elapsed_us: elapsed(started),
                    };
                }
                Err(e) => {
                    principal_budget.refund_tool_call(&req.tool, payout_micros);
                    let reason = format!("budget check failed closed: {e}");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        policy: None,
                        denial_code: DenialCode::BudgetError,
                        reason: reason.clone(),
                        response: denial_error(req.id.as_ref(), DenialCode::BudgetError, &reason),
                        elapsed_us: elapsed(started),
                    };
                }
            }
        }
        match budget.try_tool_call(&req.tool, payout_micros) {
            Ok(BudgetDecision::Allowed { remaining }) => ToolVerdict::Allowed {
                tool: req.tool,
                budget_remaining: remaining,
                elapsed_us: elapsed(started),
                // Thread the actual debited amount so the
                // harness can refund exactly this much on a lost
                // execution.claim() race.
                payout_micros,
                principal_id: None,
            },
            Ok(BudgetDecision::Refused { limit, cap }) => {
                let policy = pushed.budget_policy_for(&self.config.budget, &limit, cap);
                let reason = match &policy {
                    Some(name) => format!("policy {name:?}: action budget exceeded: {limit} (cap {cap})"),
                    None => format!("action budget exceeded: {limit} (cap {cap})"),
                };
                ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    policy,
                    denial_code: DenialCode::BudgetExceeded,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::BudgetExceeded, &reason),
                    elapsed_us: elapsed(started),
                }
            }
            Err(e) => {
                // State-store failure fails closed.
                let reason = format!("budget check failed closed: {e}");
                ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    policy: None,
                    denial_code: DenialCode::BudgetError,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::BudgetError, &reason),
                    elapsed_us: elapsed(started),
                }
            }
        }
    }

    /// Gate 3: the local policy chain, the judge thresholds, then the
    /// console-pushed allowlists and guardrails. A deny anywhere wins
    /// over an ask, so an earlier ask never hides a later refusal; the
    /// first ask is returned only when nothing denies.
    fn policy_stage(
        &self,
        req: &ToolCallRequest,
        pushed: &PushedRules,
        judge: Option<&JudgeEvidence>,
        elapsed_us: &dyn Fn() -> u64,
    ) -> Option<ToolVerdict> {
        let outcomes: &[JudgeOutcome] = judge.map_or(&[], |evidence| evidence.outcomes.as_slice());
        let mut held: Option<ToolVerdict> = None;

        // Gate 3: policy chain (first deny wins). A policy that read the
        // judge's verdicts names their predicates in its refusal.
        let judged: Vec<&str> = outcomes.iter().map(JudgeOutcome::predicate_id).collect();
        let refusal = |policy: &dyn PolicyEngine, code: DenialCode, reason: &str| {
            if policy.sees_judge() && !judged.is_empty() {
                crate::rpc::judged_policy_error(req.id.as_ref(), code, reason, &judged)
            } else {
                denial_error(req.id.as_ref(), code, reason)
            }
        };
        for policy in &self.policies {
            match policy.evaluate_with_judge(&req.tool, &req.arguments, outcomes) {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny { reason } => {
                    let reason = format!("policy {:?}: {reason}", policy.name());
                    return Some(ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "policy",
                        policy: Some(policy.name().to_owned()),
                        denial_code: DenialCode::PolicyDenied,
                        response: refusal(policy.as_ref(), DenialCode::PolicyDenied, &reason),
                        reason,
                        elapsed_us: elapsed_us(),
                    });
                }
                PolicyDecision::Ask { reason } => {
                    if held.is_none() {
                        let reason = format!("policy {:?}: {reason}", policy.name());
                        held = Some(ToolVerdict::Blocked {
                            tool: req.tool.clone(),
                            stage: "policy",
                            policy: Some(policy.name().to_owned()),
                            denial_code: DenialCode::ApprovalRequired,
                            response: refusal(policy.as_ref(), DenialCode::ApprovalRequired, &reason),
                            reason,
                            elapsed_us: elapsed_us(),
                        });
                    }
                }
            }
        }

        // Gate 3a: semantic-judge thresholds. Applied whenever the judge
        // ran, even without configured rules: the failure behaviour
        // (deny or ask, never allow) must hold whatever policy reads the
        // verdicts.
        if let Some(evidence) = judge {
            let decision = self.judge_decision(evidence);
            let code = match (&decision.action, &decision.cause) {
                (JudgeAction::Allow, _) => None,
                (JudgeAction::Ask, _) => Some(DenialCode::ApprovalRequired),
                (JudgeAction::Deny, DecisionCause::Failure { .. }) => Some(DenialCode::JudgeUnavailable),
                (JudgeAction::Deny, _) => Some(DenialCode::JudgeDenied),
            };
            if let Some(code) = code {
                let verdict = ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "policy",
                    policy: Some(JUDGE_POLICY_NAME.to_owned()),
                    denial_code: code,
                    reason: decision.reason.clone(),
                    response: judge_denial_error(
                        req.id.as_ref(),
                        code,
                        &decision.reason,
                        decision.predicate_id.as_deref(),
                    ),
                    elapsed_us: elapsed_us(),
                };
                if decision.action == JudgeAction::Deny {
                    return Some(verdict);
                }
                if held.is_none() {
                    held = Some(verdict);
                }
            }
        }

        // Gate 3b: console-pushed allowlists, after the local chain.
        for rule in &pushed.allowlists {
            if let Some(reason) = rule.refuses(&req.tool) {
                let reason = format!("policy {:?}: {reason}", rule.policy);
                return Some(ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "policy",
                    policy: Some(rule.policy.clone()),
                    denial_code: DenialCode::PolicyDenied,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::PolicyDenied, &reason),
                    elapsed_us: elapsed_us(),
                });
            }
        }

        // Gate 3c: console-pushed guardrails over the arguments, after
        // every local gate, so they can only add a refusal.
        for rule in &pushed.guardrails {
            if let Some(reason) = rule.refuses_tool_call(&req.tool, &req.arguments) {
                let reason = format!("policy {:?}: {reason}", rule.policy);
                return Some(ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "policy",
                    policy: Some(rule.policy.clone()),
                    denial_code: DenialCode::PolicyDenied,
                    reason: reason.clone(),
                    response: denial_error(req.id.as_ref(), DenialCode::PolicyDenied, &reason),
                    elapsed_us: elapsed_us(),
                });
            }
        }

        held
    }

    /// Evaluate an arbitrary operation payload against the configured native
    /// and WASM policy chain. Used for chat sanitization before compression.
    pub fn sanitize(&self, operation: &str, payload: &Value) -> Result<(), SanitizeDenial> {
        for policy in &self.policies {
            // Chat has no approval step: an ask refuses like a deny.
            if let PolicyDecision::Deny { reason } | PolicyDecision::Ask { reason } =
                policy.evaluate(operation, payload)
            {
                return Err(SanitizeDenial {
                    policy: None,
                    reason: format!("policy {:?}: {reason}", policy.name()),
                });
            }
        }
        // Console-pushed guardrails over chat content, after the local
        // chain, so they can only add a refusal. They name the console
        // policy so the refusal can be attributed to it.
        if operation == "chat/completions" {
            for rule in &self.pushed().guardrails {
                if let Some(reason) = rule.refuses_chat(payload) {
                    return Err(SanitizeDenial {
                        policy: Some(rule.policy.clone()),
                        reason: format!("policy {:?}: {reason}", rule.policy),
                    });
                }
            }
        }
        Ok(())
    }
}

impl Sandbox {
    /// Apply every console-pushed `llm.ingress` transform to a chat
    /// request, in bundle order. The rewritten payload is what every
    /// later gate sees, what is journaled, and what is forwarded.
    pub fn transform_chat(&self, payload: &mut Value) -> Vec<TransformApplied> {
        let pushed = self.pushed();
        pushed
            .transforms
            .iter()
            .filter_map(|rule| {
                let replacements = rule.apply_to_chat(payload);
                (replacements > 0).then(|| TransformApplied {
                    policy: rule.policy.clone(),
                    replacements,
                })
            })
            .collect()
    }

    /// Apply every console-pushed `tool.args` transform that covers
    /// `tool` to a call's `arguments`, in bundle order.
    pub fn transform_tool_arguments(&self, tool: &str, arguments: &mut Value) -> Vec<TransformApplied> {
        let pushed = self.pushed();
        pushed
            .transforms
            .iter()
            .filter_map(|rule| {
                let replacements = rule.apply_to_tool_call(tool, arguments);
                (replacements > 0).then(|| TransformApplied {
                    policy: rule.policy.clone(),
                    replacements,
                })
            })
            .collect()
    }

    /// The first console-pushed `llm.egress` guardrail that refuses a
    /// model response whose captured text is `text`.
    pub fn refuses_response(&self, text: &str) -> Option<SanitizeDenial> {
        self.pushed()
            .refuses_response(text)
            .map(|(policy, reason)| SanitizeDenial {
                policy: Some(policy),
                reason,
            })
    }
}

/// One console-pushed transform that rewrote a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformApplied {
    /// Console policy name.
    pub policy: String,
    /// How many matches were replaced.
    pub replacements: usize,
}

/// A non-tool payload the sandbox refused. `policy` names the console
/// policy when a pushed rule refused it (local policies are already
/// named inside `reason`, as they are for tool calls).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeDenial {
    /// Console policy name, for attribution.
    pub policy: Option<String>,
    /// The refusal as the client sees it.
    pub reason: String,
}

impl std::fmt::Display for SanitizeDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Extract a payout amount (USD float or integer) as micro-USD. Rejects
/// negatives, NaN/Inf, and absurd magnitudes rather than truncating silently.
fn extract_payout_micros(arguments: &Value, field: &str) -> Result<u64, String> {
    let Some(v) = arguments.get(field) else {
        return Ok(0);
    };
    let usd = v.as_f64().ok_or_else(|| format!("{field} must be a number"))?;
    if !usd.is_finite() || usd < 0.0 {
        return Err(format!("{field} must be a finite non-negative number, got {usd}"));
    }
    if usd > 1.0e12 {
        return Err(format!("{field} of {usd} exceeds sanity bounds"));
    }
    // Ceil, not round: a positive sub-micro amount (e.g. 0.0000004 USD)
    // rounded to ZERO micros, and a zero spend skips payout enforcement
    // entirely (`ActionBudget` only gates payout > 0) — including the
    // fail-closed "payout with NO cap configured is refused" rule. A
    // hostile tool argument could drip unaccounted positive payouts
    // forever. Any positive amount now costs at least one micro-USD,
    // so the cap (or its absence) always gets a say; exact zero stays
    // zero.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok((usd * pv_core::units::USD_MICROS_PER_DOLLAR as f64).ceil() as u64)
}

fn micros_since(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
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
    use crate::policy::NativePolicy;
    use pv_state::InMemoryStore;
    use serde_json::json;

    fn raw_call(tool: &str, args: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }))
        .unwrap()
    }

    fn sandbox() -> Sandbox {
        let mut schemas = HashMap::new();
        schemas.insert(
            "db_write".to_owned(),
            json!({
                "type": "object",
                "required": ["table", "row"],
                "properties": {
                    "table": {"type": "string", "minLength": 1},
                    "row": {"type": "object"}
                },
                "additionalProperties": false
            }),
        );
        let budget = BudgetSpec {
            max_tool_calls: [("db_write".to_owned(), 3)].into_iter().collect(),
            max_payout_usd_micros: Some(50_000_000),
            max_total_tool_calls: Some(100),
            max_tokens: None,
        };
        Sandbox::new(
            SandboxConfig {
                schemas,
                budget,
                payout_field: "amount_usd".into(),
                require_schema: false,
            },
            vec![Box::new(NativePolicy::deny_tools(&["rm_rf"]))],
        )
        .unwrap()
    }

    fn pin() -> pv_judge::ModelPin {
        pv_judge::ModelPin::new("judge", "1", "a".repeat(64)).unwrap()
    }

    fn scored(mismatch_ppm: u32) -> JudgeEvidence {
        JudgeEvidence {
            outcomes: vec![JudgeOutcome::Scored(pv_judge::Verdict {
                predicate_id: "arg_matches_task@1".into(),
                probs: vec![
                    pv_judge::LabelProb {
                        label: "match".into(),
                        ppm: 1_000_000 - mismatch_ppm,
                    },
                    pv_judge::LabelProb {
                        label: "mismatch".into(),
                        ppm: mismatch_ppm,
                    },
                ],
                model: pin(),
                latency_us: 5,
            })],
            drift_tripped: Vec::new(),
        }
    }

    fn failed(kind: pv_judge::FailureKind) -> JudgeEvidence {
        JudgeEvidence {
            outcomes: vec![JudgeOutcome::Failed(pv_judge::JudgeFailure {
                predicate_id: "arg_matches_task@1".into(),
                model: pin(),
                kind,
                detail: "detail".into(),
                latency_us: 5,
            })],
            drift_tripped: Vec::new(),
        }
    }

    fn judged_sandbox() -> Sandbox {
        sandbox().with_judge_policy(
            ThresholdPolicy::new(
                vec![pv_judge::ThresholdRule {
                    predicate_id: "arg_matches_task@1".into(),
                    label: "mismatch".into(),
                    deny_above_ppm: Some(700_000),
                    ask_above_ppm: Some(300_000),
                    min_confidence_ppm: None,
                }],
                pv_judge::FailurePolicy::default(),
            )
            .unwrap(),
        )
    }

    fn admit(
        s: &Sandbox,
        store: &InMemoryStore,
        tool: &str,
        args: Value,
        judge: Option<&JudgeEvidence>,
    ) -> ToolVerdict {
        let call = s.precheck(&raw_call(tool, args)).unwrap();
        s.admit(store, "sess-j", None, call, judge)
    }

    fn code(verdict: &ToolVerdict) -> DenialCode {
        match verdict {
            ToolVerdict::Blocked { denial_code, .. } => *denial_code,
            other => panic!("expected a block, got {other:?}"),
        }
    }

    #[test]
    fn precheck_then_admit_without_judge_matches_check() {
        let s = sandbox();
        let store = InMemoryStore::new();
        let args = json!({"table": "t", "row": {}});
        assert!(admit(&s, &store, "db_write", args.clone(), None).is_allowed());
        assert!(s
            .check(&store, "sess-j", &raw_call("db_write", args))
            .is_allowed());
        let refused = s
            .precheck(&raw_call("db_write", json!({"table": ""})))
            .unwrap_err();
        assert_eq!(code(&refused), DenialCode::SchemaViolation);
        assert_eq!(
            code(&admit(&s, &store, "rm_rf", json!({}), None)),
            DenialCode::PolicyDenied
        );
    }

    #[test]
    fn judge_thresholds_deny_ask_and_allow_without_spending_on_refusals() {
        let s = judged_sandbox();
        let store = InMemoryStore::new();
        let args = json!({"table": "t", "row": {}});
        let denied = admit(&s, &store, "db_write", args.clone(), Some(&scored(820_000)));
        assert_eq!(code(&denied), DenialCode::JudgeDenied);
        let ToolVerdict::Blocked {
            response,
            policy,
            stage,
            ..
        } = &denied
        else {
            unreachable!()
        };
        assert_eq!(*stage, "policy");
        assert_eq!(policy.as_deref(), Some(JUDGE_POLICY_NAME));
        assert_eq!(response["error"]["data"]["predicate_id"], "arg_matches_task@1");
        assert_eq!(response["error"]["data"]["code"], "JUDGE_DENIED");
        let held = admit(&s, &store, "db_write", args.clone(), Some(&scored(500_000)));
        assert_eq!(code(&held), DenialCode::ApprovalRequired);
        // Three db_write calls fit the budget: the two refusals spent nothing.
        for _ in 0..3 {
            assert!(admit(&s, &store, "db_write", args.clone(), Some(&scored(100_000))).is_allowed());
        }
        assert_eq!(
            code(&admit(&s, &store, "db_write", args, Some(&scored(100_000)))),
            DenialCode::BudgetExceeded
        );
    }

    /// A policy that reads the judge's verdicts (as a WASM policy with
    /// interface version 2 does) and refuses any judged call.
    struct RefusesJudged {
        sees: bool,
    }

    impl PolicyEngine for RefusesJudged {
        fn name(&self) -> &str {
            "refuses-judged"
        }
        fn evaluate(&self, _tool: &str, _arguments: &Value) -> PolicyDecision {
            PolicyDecision::Allow
        }
        fn evaluate_with_judge(
            &self,
            _tool: &str,
            _arguments: &Value,
            judge: &[JudgeOutcome],
        ) -> PolicyDecision {
            if judge.is_empty() {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny {
                    reason: "judged".into(),
                }
            }
        }
        fn sees_judge(&self) -> bool {
            self.sees
        }
    }

    /// The specification's structured denial carries the predicate id,
    /// also when the policy, not the thresholds, makes the call.
    #[test]
    fn a_policy_that_reads_verdicts_names_their_predicate_when_it_refuses() {
        let response = |sees: bool| {
            let s = Sandbox::new(
                SandboxConfig {
                    schemas: HashMap::new(),
                    budget: BudgetSpec::default(),
                    payout_field: "amount_usd".into(),
                    require_schema: false,
                },
                vec![Box::new(RefusesJudged { sees })],
            )
            .unwrap();
            let store = InMemoryStore::new();
            match admit(&s, &store, "db_write", json!({}), Some(&scored(100_000))) {
                ToolVerdict::Blocked { response, .. } => response,
                other => panic!("expected a block, got {other:?}"),
            }
        };
        let named = response(true);
        assert_eq!(named["error"]["data"]["code"], "POLICY_DENIED");
        assert_eq!(named["error"]["data"]["predicate_id"], "arg_matches_task@1");
        assert!(response(false)["error"]["data"].get("predicate_id").is_none());
    }

    #[test]
    fn judge_failures_fail_closed_even_without_rules() {
        let s = sandbox();
        let store = InMemoryStore::new();
        let args = json!({"table": "t", "row": {}});
        for kind in [
            pv_judge::FailureKind::Timeout,
            pv_judge::FailureKind::Unavailable,
            pv_judge::FailureKind::Saturated,
            pv_judge::FailureKind::ModelMismatch,
        ] {
            let verdict = admit(&s, &store, "db_write", args.clone(), Some(&failed(kind)));
            assert_eq!(code(&verdict), DenialCode::JudgeUnavailable, "{kind:?}");
        }
        let malformed = admit(
            &s,
            &store,
            "db_write",
            args.clone(),
            Some(&failed(pv_judge::FailureKind::Malformed)),
        );
        assert_eq!(code(&malformed), DenialCode::ApprovalRequired);
        // No rules and a clean verdict: nothing to apply.
        assert!(admit(&s, &store, "db_write", args, Some(&scored(990_000))).is_allowed());
    }

    #[test]
    fn a_later_deny_wins_over_an_earlier_ask() {
        let s = judged_sandbox();
        let mut rules = PushedRules::default();
        rules.allowlists.push(crate::pushed::PushedAllowlist {
            policy: "runtime.no_db".into(),
            scope: crate::pushed::ToolPattern::from_scope("tool.*").unwrap(),
            allow_only: None,
            deny: ["db_write".to_owned()].into_iter().collect(),
        });
        s.set_pushed(rules);
        let store = InMemoryStore::new();
        let verdict = admit(
            &s,
            &store,
            "db_write",
            json!({"table": "t", "row": {}}),
            Some(&scored(500_000)),
        );
        assert_eq!(code(&verdict), DenialCode::PolicyDenied);
        assert_eq!(blocked_policy(&verdict).0.as_deref(), Some("runtime.no_db"));
    }

    #[test]
    fn a_validated_call_keeps_its_rule_snapshot() {
        let s = sandbox();
        let store = InMemoryStore::new();
        let call = s.precheck(&raw_call("send_wire", json!({}))).unwrap();
        let mut rules = PushedRules::default();
        rules.allowlists.push(crate::pushed::PushedAllowlist {
            policy: "runtime.no_wires".into(),
            scope: crate::pushed::ToolPattern::from_scope("tool.*").unwrap(),
            allow_only: None,
            deny: ["send_wire".to_owned()].into_iter().collect(),
        });
        s.set_pushed(rules);
        // Prechecked under the old bundle: decided under the old bundle.
        assert!(s.admit(&store, "sess-s", None, call, None).is_allowed());
        let fresh = s.precheck(&raw_call("send_wire", json!({}))).unwrap();
        assert!(!s.admit(&store, "sess-s", None, fresh, None).is_allowed());
    }

    #[test]
    fn drift_gate_holds_calls_policy_would_allow() {
        let s = judged_sandbox();
        let store = InMemoryStore::new();
        let mut evidence = scored(100_000);
        evidence.drift_tripped = vec!["arg_matches_task@1".into()];
        let verdict = admit(
            &s,
            &store,
            "db_write",
            json!({"table": "t", "row": {}}),
            Some(&evidence),
        );
        assert_eq!(code(&verdict), DenialCode::ApprovalRequired);
    }

    #[test]
    fn policy_verdict_reports_without_spending() {
        let s = judged_sandbox();
        let store = InMemoryStore::new();
        let call = s
            .precheck(&raw_call("db_write", json!({"table": "t", "row": {}})))
            .unwrap();
        assert_eq!(
            code(&s.policy_verdict(&call, Some(&scored(820_000))).unwrap()),
            DenialCode::JudgeDenied
        );
        assert!(s.policy_verdict(&call, Some(&scored(100_000))).is_none());
        for _ in 0..3 {
            let call = s
                .precheck(&raw_call("db_write", json!({"table": "t", "row": {}})))
                .unwrap();
            assert!(s.admit(&store, "sess-v", None, call, None).is_allowed());
        }
    }

    #[test]
    fn asks_refuse_chat_sanitization() {
        struct Asker;
        impl PolicyEngine for Asker {
            fn name(&self) -> &str {
                "asker"
            }
            fn evaluate(&self, _: &str, _: &Value) -> PolicyDecision {
                PolicyDecision::Ask {
                    reason: "approve".into(),
                }
            }
        }
        let s = Sandbox::new(SandboxConfig::default(), vec![Box::new(Asker)]).unwrap();
        assert!(s.sanitize("chat/completions", &json!({})).is_err());
        let store = InMemoryStore::new();
        assert_eq!(
            code(&s.check(&store, "sess-a", &raw_call("t", json!({})))),
            DenialCode::ApprovalRequired
        );
    }

    fn blocked_policy(verdict: &ToolVerdict) -> (Option<String>, &'static str) {
        match verdict {
            ToolVerdict::Blocked { policy, stage, .. } => (policy.clone(), *stage),
            other => panic!("expected a block, got {other:?}"),
        }
    }

    #[test]
    fn pushed_rules_add_restrictions_and_name_the_console_policy() {
        let s = sandbox();
        let store = InMemoryStore::new();
        // Before any bundle: the local config alone decides.
        assert!(s
            .check(&store, "sess-p", &raw_call("send_wire", json!({})))
            .is_allowed());
        let mut rules = PushedRules {
            etag: Some("ab12".into()),
            budget_policies: vec!["finance.calls".into()],
            ..PushedRules::default()
        };
        rules.budget.max_total_tool_calls = Some(3);
        rules.allowlists.push(crate::pushed::PushedAllowlist {
            policy: "runtime.no_wires".into(),
            scope: crate::pushed::ToolPattern::from_scope("tool.*").unwrap(),
            allow_only: None,
            deny: ["send_wire".to_owned()].into_iter().collect(),
        });
        rules.schemas.push(
            crate::pushed::PushedSchema::compile(
                "procurement.vendors",
                "create_purchase_order",
                &json!({"type": "object", "required": ["vendor"], "properties": {"vendor": {"enum": ["Contoso"]}}}),
            )
            .unwrap(),
        );
        rules.guardrails.push(
            crate::pushed::PushedGuardrail::compile(
                "privacy.pii_egress",
                crate::pushed::GuardrailTarget::ToolArgs,
                crate::pushed::ToolPattern::from_scope("tool.*"),
                &[r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b".to_owned()],
            )
            .unwrap(),
        );
        rules.guardrails.push(
            crate::pushed::PushedGuardrail::compile(
                "llm.no_secrets",
                crate::pushed::GuardrailTarget::LlmIngress,
                None,
                &["(?i)top secret".to_owned()],
            )
            .unwrap(),
        );
        s.set_pushed(rules);
        assert_eq!(s.pushed().etag.as_deref(), Some("ab12"));
        // A pushed guardrail refuses matching arguments at the policy
        // stage, naming the console policy and never the matched text.
        let pii = s.check(
            &store,
            "sess-g",
            &raw_call("create_ticket", json!({"body": "ssn 123-45-6789"})),
        );
        assert_eq!(
            blocked_policy(&pii),
            (Some("privacy.pii_egress".into()), "policy")
        );
        if let ToolVerdict::Blocked { reason, .. } = &pii {
            assert!(
                reason.contains("deny pattern 1 of 1 (at /body)") && !reason.contains("6789"),
                "{reason}"
            );
        }
        assert!(s
            .check(
                &store,
                "sess-g",
                &raw_call("create_ticket", json!({"body": "no pii"}))
            )
            .is_allowed());
        // The ingress guardrail refuses matching chat content with the
        // policy name attached; the local chain still answers first.
        let denial = s
            .sanitize(
                "chat/completions",
                &json!({"messages": [{"content": "TOP SECRET plan"}]}),
            )
            .unwrap_err();
        assert_eq!(denial.policy.as_deref(), Some("llm.no_secrets"));
        assert!(
            denial.reason.contains("llm.no_secrets") && denial.reason.contains("/messages/0/content"),
            "{denial}"
        );
        assert!(s
            .sanitize(
                "chat/completions",
                &json!({"messages": [{"content": "public plan"}]})
            )
            .is_ok());
        assert!(
            s.sanitize("other", &json!({"messages": [{"content": "TOP SECRET"}]}))
                .is_ok(),
            "only chat is inspected"
        );
        assert_eq!(
            s.effective_budget().max_total_tool_calls,
            Some(3),
            "pushed 3 beats local 100"
        );
        assert_eq!(
            s.effective_budget().max_tool_calls.get("db_write"),
            Some(&3),
            "local caps survive"
        );

        let wire = s.check(&store, "sess-q", &raw_call("send_wire", json!({})));
        assert_eq!(blocked_policy(&wire), (Some("runtime.no_wires".into()), "policy"));
        let bad_vendor = s.check(
            &store,
            "sess-q",
            &raw_call("create_purchase_order", json!({"vendor": "Initech"})),
        );
        assert_eq!(
            blocked_policy(&bad_vendor),
            (Some("procurement.vendors".into()), "schema")
        );
        assert!(s
            .check(
                &store,
                "sess-q",
                &raw_call("create_purchase_order", json!({"vendor": "Contoso"}))
            )
            .is_allowed());
        // The local schema still applies on top of nothing pushed for db_write.
        let local_schema = s.check(&store, "sess-q", &raw_call("db_write", json!({"table": ""})));
        assert_eq!(blocked_policy(&local_schema), (None, "schema"));
        assert!(s
            .check(&store, "sess-q", &raw_call("search", json!({})))
            .is_allowed());
        assert!(s
            .check(&store, "sess-q", &raw_call("search", json!({})))
            .is_allowed());
        // Third allowed call above was the cap; the fourth hits the pushed budget.
        let over = s.check(&store, "sess-q", &raw_call("search", json!({})));
        assert_eq!(blocked_policy(&over), (Some("finance.calls".into()), "budget"));

        // A new bundle replaces the old rules entirely.
        s.set_pushed(PushedRules::default());
        assert!(s
            .check(&store, "sess-r", &raw_call("send_wire", json!({})))
            .is_allowed());
        assert_eq!(s.effective_budget().max_total_tool_calls, Some(100));
    }

    #[test]
    fn valid_call_allowed_with_latency() {
        let store = InMemoryStore::new();
        let sandbox = sandbox();
        let v = sandbox.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": "t", "row": {}})),
        );
        assert!(v.is_allowed(), "{v:?}");
        // R23: block/allow decision < 5ms = 5000µs. A single debug-profile
        // sample flakes under full-suite load (scheduler preemption between
        // the two Instant reads), so take the minimum over several runs:
        // one clean time slice is enough for a genuinely fast decision,
        // while a real regression stays slow on every sample. Distinct
        // sessions keep the per-session db_write budget (3) out of play.
        // The release SLA gate and criterion bench own the authoritative
        // measurement.
        let min_elapsed_us = (0..10)
            .map(|i| {
                let verdict = sandbox.check(
                    &store,
                    &format!("s-latency-{i}"),
                    &raw_call("db_write", json!({"table": "t", "row": {}})),
                );
                assert!(verdict.is_allowed(), "{verdict:?}");
                verdict.elapsed_us()
            })
            .min()
            .unwrap_or(u64::MAX);
        assert!(min_elapsed_us < 5_000, "fastest decision took {min_elapsed_us}µs");
    }

    #[test]
    fn schema_invalid_blocked() {
        let store = InMemoryStore::new();
        let s = sandbox();
        // Missing required field.
        let v = s.check(&store, "s", &raw_call("db_write", json!({"table": "t"})));
        match &v {
            ToolVerdict::Blocked { stage, response, .. } => {
                assert_eq!(*stage, "schema");
                assert_eq!(response["error"]["code"], -32001);
            }
            other => panic!("{other:?}"),
        }
        // Type confusion.
        let v = s.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": 42, "row": {}})),
        );
        assert!(!v.is_allowed());
        // Extra field (additionalProperties: false).
        let v = s.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": "t", "row": {}, "backdoor": true})),
        );
        assert!(!v.is_allowed());
    }

    #[test]
    fn policy_denied_blocked() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", &raw_call("rm_rf", json!({})));
        match v {
            ToolVerdict::Blocked {
                stage,
                policy,
                reason,
                ..
            } => {
                assert_eq!(stage, "policy");
                assert!(reason.contains("deny-listed"), "{reason}");
                // Named-policy denials carry the engine name so the
                // console can attribute the block to a policy row.
                assert_eq!(policy.as_deref(), Some("deny_tools"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_policy_gates_carry_no_policy_attribution() {
        let store = InMemoryStore::new();
        // Parse gate: invalid JSON-RPC.
        let parse = sandbox().check(&store, "s", b"not json");
        match parse {
            ToolVerdict::Blocked { stage, policy, .. } => {
                assert_eq!(stage, "parse");
                assert!(policy.is_none(), "parse gate must not invent a policy name");
            }
            other => panic!("{other:?}"),
        }
    }

    /// JSON-RPC 2.0 §5: parse-gate refusals of a WELL-FORMED envelope
    /// must echo the request id in the error response. Pre-fix the
    /// blocked-response body always carried `id: null`, so SDK
    /// correlation tables never matched and the pending call hung.
    #[test]
    fn blocked_parse_verdict_echoes_the_request_id() {
        let store = InMemoryStore::new();
        let raw = br#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{}}"#;
        match sandbox().check(&store, "s", raw) {
            ToolVerdict::Blocked {
                response,
                stage,
                reason,
                ..
            } => {
                assert_eq!(response["id"], json!(42), "{response}");
                // Mutation-run hardening (round 8): the passthrough
                // stage label was unpinned — deleting the NotToolCall
                // match arm reclassified passthrough refusals as
                // "parse" failures, corrupting the stage-keyed metrics
                // and events operators alert on.
                assert_eq!(stage, "passthrough");
                assert!(reason.contains("passthrough refused"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        // Unparseable JSON: the id is undetectable — null stands.
        match sandbox().check(&store, "s", b"not json") {
            ToolVerdict::Blocked { response, stage, .. } => {
                assert_eq!(response["id"], serde_json::Value::Null, "{response}");
                assert_eq!(stage, "parse");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn budget_enforced_across_calls() {
        let store = InMemoryStore::new();
        let s = sandbox();
        let args = json!({"table": "t", "row": {}});
        for _ in 0..3 {
            assert!(s
                .check(&store, "sess", &raw_call("db_write", args.clone()))
                .is_allowed());
        }
        let v = s.check(&store, "sess", &raw_call("db_write", args));
        match v {
            ToolVerdict::Blocked { stage, reason, .. } => {
                assert_eq!(stage, "budget");
                assert!(reason.contains("db_write"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// An `Allowed` verdict must thread the bound principal id out so the
    /// harness's failure paths (lost claim race, saturated worker, close
    /// race) can mirror the session-ledger refund on the principal ledger.
    /// Without it, every failed claim permanently consumed principal quota
    /// with zero tools executed — and the principal ledger persists across
    /// sessions, so that leak never healed. The refund round-trip below is
    /// exactly the compensation the harness performs.
    #[test]
    fn allowed_verdict_threads_principal_id_and_refund_restores_the_ledger() {
        let store = InMemoryStore::new();
        let s = sandbox();
        let args = json!({"amount_usd": 1.0});
        let principal_spec = BudgetSpec {
            max_tool_calls: std::collections::BTreeMap::new(),
            max_payout_usd_micros: Some(50_000_000),
            max_total_tool_calls: Some(1),
            max_tokens: None,
        };
        // No principal bound: field is None.
        match s.check(&store, "sess-a", &raw_call("payout", args.clone())) {
            ToolVerdict::Allowed { principal_id, .. } => assert_eq!(principal_id, None),
            other => panic!("{other:?}"),
        }
        // Principal bound: the verdict carries the id and payout the
        // harness needs for compensation.
        let verdict = s.check_with_principal(
            &store,
            "sess-b",
            Some(("principal-1", &principal_spec)),
            &raw_call("payout", args.clone()),
        );
        let (tool, payout_micros, principal_id) = match verdict {
            ToolVerdict::Allowed {
                tool,
                payout_micros,
                principal_id,
                ..
            } => (tool, payout_micros, principal_id),
            other => panic!("{other:?}"),
        };
        assert_eq!(principal_id.as_deref(), Some("principal-1"));
        assert_eq!(payout_micros, 1_000_000);
        // Simulate the harness failure path: refund BOTH ledgers with the
        // threaded values. With max_total_tool_calls = 1, the next call
        // only admits if the principal refund actually landed.
        ActionBudget::new(&store, "sess-b", &s.config.budget).refund_tool_call(&tool, payout_micros);
        ActionBudget::for_principal(&store, "principal-1", &principal_spec)
            .refund_tool_call(&tool, payout_micros);
        let retry = s.check_with_principal(
            &store,
            "sess-b",
            Some(("principal-1", &principal_spec)),
            &raw_call("payout", args),
        );
        assert!(
            retry.is_allowed(),
            "principal ledger did not heal after the compensating refund: {retry:?}"
        );
    }

    #[test]
    fn payout_cap_enforced_and_hostile_amounts_rejected() {
        let store = InMemoryStore::new();
        let s = sandbox();
        assert!(s
            .check(&store, "p", &raw_call("payout", json!({"amount_usd": 49.5})))
            .is_allowed());
        // Would cross $50 total.
        let v = s.check(&store, "p", &raw_call("payout", json!({"amount_usd": 1.0})));
        assert!(!v.is_allowed(), "{v:?}");
        // Hostile numerics.
        for bad in [
            json!({"amount_usd": -5}),
            json!({"amount_usd": "1e9"}),
            json!({"amount_usd": 1e15}),
        ] {
            let v = s.check(&store, "p2", &raw_call("payout", bad));
            assert!(!v.is_allowed(), "hostile payout accepted: {v:?}");
        }
    }

    #[test]
    fn unparsable_payload_blocked_at_parse() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", b"\xff\xfe not json");
        match v {
            ToolVerdict::Blocked { stage, tool, .. } => {
                assert_eq!(stage, "parse");
                assert_eq!(tool, "<unparsed>");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tools_without_schema_pass_schema_gate() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", &raw_call("search", json!({"anything": [1, 2]})));
        assert!(v.is_allowed(), "{v:?}");
    }

    #[test]
    fn required_schema_mode_blocks_unknown_tools() {
        let sandbox = Sandbox::new(
            SandboxConfig {
                require_schema: true,
                ..SandboxConfig::default()
            },
            Vec::new(),
        )
        .unwrap();
        let verdict = sandbox.check(&InMemoryStore::new(), "session", &raw_call("unknown", json!({})));
        assert!(matches!(verdict, ToolVerdict::Blocked { stage: "schema", .. }));
    }

    #[test]
    fn bad_boot_schema_is_a_boot_error() {
        let mut schemas = HashMap::new();
        schemas.insert("t".to_owned(), json!({"type": "not-a-type"}));
        let err = Sandbox::new(
            SandboxConfig {
                schemas,
                ..SandboxConfig::default()
            },
            vec![],
        );
        assert!(err.is_err(), "invalid schema must fail at boot, not be skipped");
    }

    #[test]
    fn chat_payload_uses_the_same_policy_chain() {
        let sandbox = Sandbox::new(
            SandboxConfig::default(),
            vec![Box::new(NativePolicy::new("no-secret", |operation, payload| {
                if operation == "chat/completions" && payload.to_string().contains("secret") {
                    PolicyDecision::Deny {
                        reason: "secret content".into(),
                    }
                } else {
                    PolicyDecision::Allow
                }
            }))],
        )
        .unwrap();
        assert!(sandbox
            .sanitize("chat/completions", &json!({"messages": ["safe"]}))
            .is_ok());
        assert!(sandbox
            .sanitize("chat/completions", &json!({"messages": ["secret"]}))
            .is_err());
    }
}

#[cfg(test)]
mod payout_boundary_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    /// Mutation-run hardening: pin the payout parser's exact
    /// bounds. `usd < 0.0` -> `<=` would refuse a legitimate zero payout;
    /// `usd > 1.0e12` -> `>=`/`==` shift or invert the sanity ceiling.
    #[test]
    fn payout_bounds_are_exact() {
        let extract = |v: serde_json::Value| extract_payout_micros(&json!({"amount_usd": v}), "amount_usd");
        assert_eq!(extract(json!(0.0)).unwrap(), 0, "zero payout is legitimate");
        assert_eq!(
            extract(json!(1.0e12)).unwrap(),
            1_000_000_000_000_u64 * pv_core::units::USD_MICROS_PER_DOLLAR,
            "the sanity ceiling itself is accepted"
        );
        let over = extract(json!(2.0e12));
        assert!(
            matches!(over, Err(ref m) if m.contains("sanity")),
            "past the ceiling must be refused, got {over:?}"
        );
        let negative = extract(json!(-0.25));
        assert!(matches!(negative, Err(ref m) if m.contains("non-negative")));
        // Sub-micro positive amounts must CEIL to one micro, never round
        // to zero: a zero result skips payout enforcement entirely —
        // including the fail-closed no-cap refusal — so a hostile tool
        // argument of 0.0000004 USD per call could drip unaccounted
        // positive payouts forever.
        assert_eq!(
            extract(json!(0.0000004)).unwrap(),
            1,
            "positive sub-micro payouts must cost at least one micro-USD"
        );
        assert_eq!(extract(json!(0.0000019)).unwrap(), 2, "ceil, not round");
    }
}
