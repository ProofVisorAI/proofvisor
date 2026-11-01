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
//!   both.
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
    /// references are refused (see [`NoExternalRefs`]).
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
}

impl PushedRules {
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
        let file_ref = format!("file://{}", file.display());
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
