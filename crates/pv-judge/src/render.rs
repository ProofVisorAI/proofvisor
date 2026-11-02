//! The text a local classifier reads for one request.
//!
//! This rendering is part of the model contract: a model must be
//! trained (or fine-tuned) on text in exactly this layout, so the
//! layout is versioned. Keys are sorted so the same call always
//! renders the same way, and long values are cut at a character
//! boundary before tokenization.

use crate::model::{DenialSource, JudgeRequest};
use serde_json::Value;
use std::fmt::Write as _;

/// Version of the layout below. Bump it on any change.
pub const INPUT_TEMPLATE_VERSION: u32 = 1;

/// Longest rendered arguments, in characters.
pub const MAX_ARGUMENT_CHARS: usize = 8_192;

/// Most prior denials rendered.
pub const MAX_RENDERED_DENIALS: usize = 16;

/// Render a request as classifier input (template version 1):
///
/// ```text
/// predicate: arg_matches_task@1
/// tool: db_write
/// arguments: {"rows":3,"table":"orders"}
/// intent: billing.reconcile
/// task: Reconcile March invoices
/// missions: m-42
/// allowed intents: billing.reconcile, billing.read
/// charter: billing-agent
/// delegation depth: 1
/// denial: session tool=db_drop code=POLICY_DENIED
/// denial: parent tool=refund code=JUDGE_DENIED predicate=arg_matches_task@1
/// ```
///
/// Absent fields are rendered as `-`.
pub fn render_request(request: &JudgeRequest) -> String {
    let context = &request.context;
    let mut text = String::new();
    let _ = writeln!(text, "predicate: {}", one_line(&request.predicate_id));
    let _ = writeln!(text, "tool: {}", one_line(&request.tool));
    let _ = writeln!(
        text,
        "arguments: {}",
        canonical_json(&request.validated_args, MAX_ARGUMENT_CHARS)
    );
    let _ = writeln!(
        text,
        "intent: {}",
        context.intent.as_deref().map_or("-".to_owned(), one_line)
    );
    let _ = writeln!(
        text,
        "task: {}",
        context.task.as_deref().map_or("-".to_owned(), one_line)
    );
    let _ = writeln!(text, "missions: {}", list(&context.mission_ids));
    let _ = writeln!(text, "allowed intents: {}", list(&context.allowed_intents));
    let _ = writeln!(text, "charter: {}", one_line(&context.charter));
    let _ = writeln!(text, "delegation depth: {}", context.delegation_depth);
    for denial in context.prior_denials.iter().take(MAX_RENDERED_DENIALS) {
        let source = match denial.source {
            DenialSource::Session => "session",
            DenialSource::Parent => "parent",
        };
        let _ = write!(
            text,
            "denial: {source} tool={} code={}",
            one_line(&denial.tool),
            one_line(&denial.denial_code)
        );
        if let Some(predicate) = &denial.predicate_id {
            let _ = write!(text, " predicate={}", one_line(predicate));
        }
        text.push('\n');
    }
    text
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        return "-".to_owned();
    }
    items
        .iter()
        .map(|item| one_line(item))
        .collect::<Vec<_>>()
        .join(", ")
}

fn one_line(value: &str) -> String {
    let flat: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate(&flat, 1_024)
}

/// JSON with object keys sorted at every level, cut to `max_chars`.
pub fn canonical_json(value: &Value, max_chars: usize) -> String {
    truncate(&sorted(value).to_string(), max_chars)
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(inner) = map.get(key) {
                    out.insert(key.clone(), sorted(inner));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((cut, _)) => text.get(..cut).unwrap_or(text).to_owned(),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::model::{PriorDenial, SessionContext};
    use serde_json::json;

    #[test]
    fn rendering_is_canonical_and_complete() {
        let request = JudgeRequest {
            predicate_id: "arg_matches_task@1".into(),
            tool: "db_write".into(),
            validated_args: json!({"table": "orders", "rows": 3, "nested": {"b": 1, "a": 2}}),
            context: SessionContext {
                intent: Some("billing.reconcile".into()),
                task: Some("Reconcile\nMarch invoices".into()),
                mission_ids: vec!["m-42".into()],
                allowed_intents: vec!["billing.reconcile".into(), "billing.read".into()],
                charter: "billing-agent".into(),
                delegation_depth: 1,
                prior_denials: vec![PriorDenial {
                    tool: "refund".into(),
                    denial_code: "JUDGE_DENIED".into(),
                    predicate_id: Some("arg_matches_task@1".into()),
                    at_ms: 1,
                    source: DenialSource::Parent,
                    instance_uid: "parent-1".into(),
                }],
            },
        };
        let text = render_request(&request);
        assert_eq!(
            text,
            "predicate: arg_matches_task@1\n\
             tool: db_write\n\
             arguments: {\"nested\":{\"a\":2,\"b\":1},\"rows\":3,\"table\":\"orders\"}\n\
             intent: billing.reconcile\n\
             task: Reconcile March invoices\n\
             missions: m-42\n\
             allowed intents: billing.reconcile, billing.read\n\
             charter: billing-agent\n\
             delegation depth: 1\n\
             denial: parent tool=refund code=JUDGE_DENIED predicate=arg_matches_task@1\n"
        );
    }

    #[test]
    fn long_arguments_are_cut_on_a_character_boundary() {
        let value = json!({"s": "é".repeat(20_000)});
        let text = canonical_json(&value, MAX_ARGUMENT_CHARS);
        assert_eq!(text.chars().count(), MAX_ARGUMENT_CHARS);
    }
}
