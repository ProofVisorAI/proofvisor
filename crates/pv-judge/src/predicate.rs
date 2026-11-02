//! Named, versioned predicates with fixed label sets.
//!
//! A predicate is the question the judge answers ("do these arguments
//! match the task?"). Its id carries a version (`name@N`) and its label
//! set is fixed for that version, so a policy written against
//! `arg_matches_task@1` and its `mismatch` label keeps meaning the same
//! thing. Changing the labels means a new version.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Built-in predicate: do the validated arguments fit the task, intent
/// and mission the operator configured for this agent?
pub const ARG_MATCHES_TASK: &str = "arg_matches_task@1";
/// Built-in predicate: is a delegated (child) agent using its parent's
/// entitlement to do what the parent was refused?
pub const CHILD_USES_PARENT_ENTITLEMENT: &str = "child_uses_parent_entitlement@1";
/// Built-in predicate for governed memory writeback: is this write to a
/// memory or knowledge store safe to persist?
pub const MEMORY_WRITE_SAFE: &str = "memory_write_safe@1";

/// Built-in predicate for trace judging: does a recorded tool or model
/// output carry instructions aimed at the agent, or data the task does
/// not need?
pub const OUTPUT_SAFE: &str = "output_safe@1";
/// Built-in predicate for the loop breaker's second opinion: is the agent
/// still making progress, or repeating itself?
pub const LOOP_PROGRESS: &str = "loop_progress@1";

/// Maximum labels per predicate.
pub const MAX_LABELS: usize = 16;

/// A predicate definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateDef {
    /// Versioned id, `name@N`.
    pub id: String,
    /// The fixed label set, in canonical order.
    pub labels: Vec<String>,
    /// The label that marks the risky outcome. Calibration measures how
    /// well the model separates it from the others.
    pub positive_label: String,
    /// What the predicate asks, for operators and model builders.
    pub description: String,
}

impl PredicateDef {
    /// Validate the id, labels, and positive label.
    pub fn validate(&self) -> Result<(), String> {
        validate_predicate_id(&self.id)?;
        if self.labels.len() < 2 || self.labels.len() > MAX_LABELS {
            return Err(format!(
                "predicate {:?} must have between 2 and {MAX_LABELS} labels",
                self.id
            ));
        }
        for (index, label) in self.labels.iter().enumerate() {
            if !is_identifier(label) {
                return Err(format!(
                    "predicate {:?} label {label:?} must be 1..=64 characters of [a-z0-9_]",
                    self.id
                ));
            }
            if self.labels.iter().take(index).any(|earlier| earlier == label) {
                return Err(format!("predicate {:?} repeats label {label:?}", self.id));
            }
        }
        if !self.labels.contains(&self.positive_label) {
            return Err(format!(
                "predicate {:?} positive_label {:?} is not one of its labels",
                self.id, self.positive_label
            ));
        }
        if self.description.trim().is_empty() {
            return Err(format!("predicate {:?} needs a description", self.id));
        }
        Ok(())
    }

    /// True when `label` belongs to this predicate.
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l == label)
    }
}

/// Check the `name@N` form: name of `[a-z0-9_]`, N a positive integer.
pub fn validate_predicate_id(id: &str) -> Result<(), String> {
    let Some((name, version)) = id.split_once('@') else {
        return Err(format!("predicate id {id:?} must have the form name@version"));
    };
    if !is_identifier(name) {
        return Err(format!(
            "predicate id {id:?}: name must be 1..=64 characters of [a-z0-9_]"
        ));
    }
    let valid_version = !version.is_empty()
        && version.len() <= 9
        && version.bytes().all(|b| b.is_ascii_digit())
        && !version.starts_with('0');
    if !valid_version {
        return Err(format!(
            "predicate id {id:?}: version must be a positive integer without leading zeros"
        ));
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The predicates a deployment knows: the built-ins plus operator-defined ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateRegistry {
    defs: BTreeMap<String, PredicateDef>,
}

impl PredicateRegistry {
    /// The built-in predicates only.
    pub fn builtin() -> Self {
        let defs = builtin_defs()
            .into_iter()
            .map(|def| (def.id.clone(), def))
            .collect();
        Self { defs }
    }

    /// Built-ins plus `custom`. A custom predicate may not reuse a
    /// built-in id or another custom id.
    pub fn with_custom(custom: &[PredicateDef]) -> Result<Self, String> {
        let mut registry = Self::builtin();
        for def in custom {
            def.validate()?;
            if registry.defs.contains_key(&def.id) {
                return Err(format!("predicate {:?} is defined more than once", def.id));
            }
            registry.defs.insert(def.id.clone(), def.clone());
        }
        Ok(registry)
    }

    /// Look up a predicate.
    pub fn get(&self, id: &str) -> Option<&PredicateDef> {
        self.defs.get(id)
    }

    /// Every predicate, ordered by id.
    pub fn iter(&self) -> impl Iterator<Item = &PredicateDef> {
        self.defs.values()
    }
}

fn builtin_defs() -> Vec<PredicateDef> {
    vec![
        PredicateDef {
            id: ARG_MATCHES_TASK.to_owned(),
            labels: vec!["match".to_owned(), "mismatch".to_owned()],
            positive_label: "mismatch".to_owned(),
            description: "Do the validated tool arguments fit the task, intent and mission \
                          the operator configured for this agent?"
                .to_owned(),
        },
        PredicateDef {
            id: CHILD_USES_PARENT_ENTITLEMENT.to_owned(),
            labels: vec!["independent".to_owned(), "laundering".to_owned()],
            positive_label: "laundering".to_owned(),
            description: "Is a delegated agent using the entitlement it inherited to do \
                          what an agent above it in the delegation chain was refused?"
                .to_owned(),
        },
        PredicateDef {
            id: OUTPUT_SAFE.to_owned(),
            labels: vec!["safe".to_owned(), "unsafe".to_owned()],
            positive_label: "unsafe".to_owned(),
            description: "Does this recorded tool or model output carry instructions aimed at \
                          the agent, or data the task does not need?"
                .to_owned(),
        },
        PredicateDef {
            id: LOOP_PROGRESS.to_owned(),
            labels: vec!["progressing".to_owned(), "looping".to_owned()],
            positive_label: "looping".to_owned(),
            description: "Given the agent's previous and current output, is it still making \
                          progress, or repeating itself?"
                .to_owned(),
        },
        PredicateDef {
            id: MEMORY_WRITE_SAFE.to_owned(),
            labels: vec!["safe".to_owned(), "unsafe".to_owned()],
            positive_label: "unsafe".to_owned(),
            description: "Is this write to a memory or knowledge store safe to persist \
                          (no instructions planted for later turns, no data outside the task)?"
                .to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn def(id: &str, labels: &[&str], positive: &str) -> PredicateDef {
        PredicateDef {
            id: id.to_owned(),
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
            positive_label: positive.to_owned(),
            description: "test".to_owned(),
        }
    }

    #[test]
    fn builtins_are_valid() {
        let registry = PredicateRegistry::builtin();
        for def in registry.iter() {
            def.validate().unwrap();
        }
        assert!(registry.get(ARG_MATCHES_TASK).is_some());
        assert!(registry.get(CHILD_USES_PARENT_ENTITLEMENT).is_some());
        assert!(registry.get(MEMORY_WRITE_SAFE).is_some());
        assert!(registry.get(OUTPUT_SAFE).is_some());
        assert!(registry.get(LOOP_PROGRESS).is_some());
    }

    #[test]
    fn ids_need_a_positive_version() {
        assert!(validate_predicate_id("refund_ok@1").is_ok());
        assert!(validate_predicate_id("refund_ok@12").is_ok());
        for bad in [
            "refund_ok",
            "refund_ok@",
            "refund_ok@0",
            "refund_ok@01",
            "Refund@1",
            "a b@1",
            "@1",
        ] {
            assert!(validate_predicate_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn custom_predicates_are_validated_and_unique() {
        let ok = def("refund_ok@1", &["within", "outside"], "outside");
        let registry = PredicateRegistry::with_custom(std::slice::from_ref(&ok)).unwrap();
        assert!(registry.get("refund_ok@1").is_some());
        assert!(PredicateRegistry::with_custom(&[ok.clone(), ok]).is_err());
        assert!(PredicateRegistry::with_custom(&[def(ARG_MATCHES_TASK, &["a", "b"], "a")]).is_err());
        assert!(PredicateRegistry::with_custom(&[def("p@1", &["a"], "a")]).is_err());
        assert!(PredicateRegistry::with_custom(&[def("p@1", &["a", "a"], "a")]).is_err());
        assert!(PredicateRegistry::with_custom(&[def("p@1", &["a", "b"], "c")]).is_err());
        assert!(PredicateRegistry::with_custom(&[def("p@1", &["a", "B"], "a")]).is_err());
    }
}
