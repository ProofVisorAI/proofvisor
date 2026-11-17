//! Semantic judge (action-correctness layer).
//!
//! Deterministic gates (schema, policy rules, budgets) cannot answer
//! questions such as "do these arguments fit the task this agent was
//! given?". The judge answers them as probabilities over a fixed label
//! set, and never decides: policy thresholds turn the probabilities
//! into allow, ask, or deny. Recorded verdicts include the full
//! distribution and model pin so decisions can be replayed. The harness
//! records them in the event chain for signed workflows and in ATIF for
//! unsigned workflows. An unsigned trajectory needs promotion to obtain
//! a signed receipt. The pin's guarantees depend on the adapter; a cloud
//! model's version identifier is not necessarily a hash of its weights.
//!
//! Layers:
//! * [`model`], [`predicate`], [`adapter`] — the data model, the named
//!   and versioned predicates, the [`JudgeAdapter`] interface and output
//!   validation;
//! * [`thresholds`] — policy thresholds and failure behaviour;
//! * [`record`] — what goes into the audit trail;
//! * [`drift`] — the runtime calibration check;
//! * `runner` (feature `runner`) — deadlines and the concurrency limit;
//! * `mock`, `calibration` (feature `runner`) — the test double and the
//!   build-time calibration harness;
//! * `local` (feature `onnx`), `cloud` (feature `cloud`) — the backends.

pub mod adapter;
pub mod drift;
pub mod model;
pub mod predicate;
pub mod record;
pub mod render;
pub mod replay;
pub mod thresholds;

#[cfg(feature = "runner")]
pub mod calibration;
#[cfg(feature = "cloud")]
pub mod cloud;
#[cfg(feature = "onnx")]
pub mod local;
#[cfg(feature = "runner")]
pub mod mock;
#[cfg(feature = "runner")]
pub mod runner;
#[cfg(feature = "cloud")]
pub mod typesafe;

pub use adapter::{
    prob_to_ppm, threshold_to_ppm, validate_scores, AdapterKind, BoxFuture, FailureKind, JudgeAdapter,
    JudgeError, JudgeFailure, JudgeOutcome,
};
pub use drift::{DriftConfig, DriftError, DriftMonitor, DriftSnapshot, DriftState, ReviewResult};
pub use model::{
    is_sha256_hex, sha256_hex, DenialSource, JudgeRequest, LabelProb, ModelPin, PriorDenial, RawScores,
    SessionContext, Verdict, PPM_ONE,
};
pub use predicate::{
    PredicateDef, PredicateRegistry, ARG_MATCHES_TASK, CHILD_USES_PARENT_ENTITLEMENT, LOOP_PROGRESS,
    MEMORY_WRITE_SAFE, OUTPUT_SAFE,
};
pub use record::{JudgeInputs, JudgeMode, JudgeRecord, OutcomeRecord};
pub use thresholds::{
    DecisionCause, FailurePolicy, JudgeAction, JudgeDecision, ThresholdPolicy, ThresholdRule,
};

#[cfg(feature = "runner")]
pub use runner::{AdapterSlot, JudgeRunner, JudgeTask};
