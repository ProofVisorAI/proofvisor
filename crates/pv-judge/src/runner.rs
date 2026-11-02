//! Runs judge adapters under a hard deadline and a concurrency limit.
//!
//! Each scoring call runs as its own task that owns a concurrency
//! permit. When the deadline expires the caller stops waiting, but the
//! permit stays held until the backend work actually finishes, so a
//! slow model keeps counting against the limit instead of piling up
//! hidden work. When no permit is free the call is not attempted and
//! comes back as [`FailureKind::Saturated`](crate::FailureKind::Saturated):
//! backpressure turns into a deny (or ask) for judged tools only, never
//! into a silent allow.

use crate::adapter::{validate_scores, JudgeAdapter, JudgeError, JudgeFailure, JudgeOutcome};
use crate::model::{JudgeRequest, SessionContext};
use crate::predicate::{PredicateDef, PredicateRegistry};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// A configured adapter with its deadline.
#[derive(Clone)]
pub struct AdapterSlot {
    /// The adapter.
    pub adapter: Arc<dyn JudgeAdapter>,
    /// Hard per-call deadline.
    pub deadline: Duration,
}

/// One predicate to score with one named adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeTask {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// Configured adapter name.
    pub adapter: String,
}

/// The runner: adapters by name, the predicate registry, and the
/// shared concurrency limit.
pub struct JudgeRunner {
    adapters: BTreeMap<String, AdapterSlot>,
    registry: Arc<PredicateRegistry>,
    permits: Arc<Semaphore>,
    max_concurrency: usize,
}

impl JudgeRunner {
    /// Build a runner. `max_concurrency` must be at least 1.
    pub fn new(
        adapters: BTreeMap<String, AdapterSlot>,
        registry: Arc<PredicateRegistry>,
        max_concurrency: usize,
    ) -> Result<Self, String> {
        if max_concurrency == 0 {
            return Err("judge max_concurrency must be at least 1".to_owned());
        }
        if max_concurrency > Semaphore::MAX_PERMITS {
            return Err("judge max_concurrency is too large".to_owned());
        }
        for (name, slot) in &adapters {
            if slot.deadline.is_zero() {
                return Err(format!("judge adapter {name:?} needs a deadline above zero"));
            }
        }
        Ok(Self {
            adapters,
            registry,
            permits: Arc::new(Semaphore::new(max_concurrency)),
            max_concurrency,
        })
    }

    /// The predicate registry.
    pub fn registry(&self) -> &PredicateRegistry {
        &self.registry
    }

    /// An adapter slot by name.
    pub fn adapter(&self, name: &str) -> Option<&AdapterSlot> {
        self.adapters.get(name)
    }

    /// Calls in flight right now (including ones whose caller already
    /// gave up at the deadline).
    pub fn in_flight(&self) -> usize {
        self.max_concurrency
            .saturating_sub(self.permits.available_permits())
    }

    /// Score every task concurrently and return one outcome per task, in
    /// task order. Never fails: every problem becomes a failed outcome.
    pub async fn evaluate(
        &self,
        tasks: &[JudgeTask],
        tool: &str,
        validated_args: &Value,
        context: &SessionContext,
    ) -> Vec<JudgeOutcome> {
        let mut pending = Vec::with_capacity(tasks.len());
        for task in tasks {
            pending.push(self.start(task, tool, validated_args, context));
        }
        let mut outcomes = Vec::with_capacity(pending.len());
        for started in pending {
            outcomes.push(match started {
                Started::Done(outcome) => outcome,
                Started::Running {
                    handle,
                    deadline_at,
                    started,
                    predicate,
                    slot,
                } => finish(handle, deadline_at, started, &predicate, &slot).await,
            });
        }
        outcomes
    }

    fn start(
        &self,
        task: &JudgeTask,
        tool: &str,
        validated_args: &Value,
        context: &SessionContext,
    ) -> Started {
        let started = Instant::now();
        let Some(slot) = self.adapters.get(&task.adapter).cloned() else {
            return Started::Done(unconfigured(task, "adapter is not configured"));
        };
        let Some(predicate) = self.registry.get(&task.predicate_id).cloned() else {
            return Started::Done(failure(
                &task.predicate_id,
                &slot,
                JudgeError::Unavailable("predicate is not registered".to_owned()),
                started,
            ));
        };
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Started::Done(failure(&predicate.id, &slot, JudgeError::Saturated, started));
        };
        let request = JudgeRequest {
            predicate_id: predicate.id.clone(),
            tool: tool.to_owned(),
            validated_args: validated_args.clone(),
            context: context.clone(),
        };
        let adapter = Arc::clone(&slot.adapter);
        let task_predicate = predicate.clone();
        let handle = tokio::spawn(async move {
            let result = adapter.score(&request, &task_predicate).await;
            drop(permit);
            result
        });
        Started::Running {
            handle,
            deadline_at: tokio::time::Instant::from_std(started) + slot.deadline,
            started,
            predicate,
            slot,
        }
    }
}

enum Started {
    Done(JudgeOutcome),
    Running {
        handle: tokio::task::JoinHandle<Result<crate::RawScores, JudgeError>>,
        deadline_at: tokio::time::Instant,
        started: Instant,
        predicate: PredicateDef,
        slot: AdapterSlot,
    },
}

async fn finish(
    handle: tokio::task::JoinHandle<Result<crate::RawScores, JudgeError>>,
    deadline_at: tokio::time::Instant,
    started: Instant,
    predicate: &PredicateDef,
    slot: &AdapterSlot,
) -> JudgeOutcome {
    let result = match tokio::time::timeout_at(deadline_at, handle).await {
        // The task keeps running and keeps its permit until it ends.
        Err(_elapsed) => Err(JudgeError::Timeout),
        Ok(Err(join_error)) => Err(JudgeError::Unavailable(if join_error.is_panic() {
            "judge adapter panicked".to_owned()
        } else {
            "judge task was cancelled".to_owned()
        })),
        Ok(Ok(result)) => result,
    };
    let latency_us = micros_since(started);
    match result.and_then(|raw| validate_scores(predicate, slot.adapter.id(), raw, latency_us)) {
        Ok(verdict) => JudgeOutcome::Scored(verdict),
        Err(error) => failure(&predicate.id, slot, error, started),
    }
}

fn failure(predicate_id: &str, slot: &AdapterSlot, error: JudgeError, started: Instant) -> JudgeOutcome {
    if matches!(error, JudgeError::ModelMismatch { .. }) {
        // The reported model name comes from the backend: bound it, and
        // flatten line breaks, before it reaches the log.
        let shown: String = error
            .to_string()
            .chars()
            .take(512)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        tracing::error!(
            predicate = predicate_id,
            error = %shown,
            "judge answered with an unpinned model; the call is refused"
        );
    }
    JudgeOutcome::Failed(JudgeFailure {
        predicate_id: predicate_id.to_owned(),
        model: slot.adapter.id().clone(),
        kind: error.kind(),
        detail: error.to_string(),
        latency_us: micros_since(started),
    })
}

fn unconfigured(task: &JudgeTask, detail: &str) -> JudgeOutcome {
    // No pin is known for an unknown adapter; config validation makes
    // this unreachable, and the all-zero pin can never match a real one.
    JudgeOutcome::Failed(JudgeFailure {
        predicate_id: task.predicate_id.clone(),
        model: crate::ModelPin {
            name: format!("unconfigured:{}", task.adapter),
            version: "0".to_owned(),
            weights_sha256: "0".repeat(64),
        },
        kind: crate::FailureKind::Unavailable,
        detail: detail.to_owned(),
        latency_us: 0,
    })
}

fn micros_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::mock::{MockBehavior, MockJudge};
    use crate::predicate::ARG_MATCHES_TASK;
    use crate::{FailureKind, ModelPin};
    use serde_json::json;

    fn pin() -> ModelPin {
        ModelPin::new("mock", "1", "e".repeat(64)).unwrap()
    }

    fn runner(mock: Arc<MockJudge>, deadline_ms: u64, max: usize) -> JudgeRunner {
        let mut adapters = BTreeMap::new();
        adapters.insert(
            "mock".to_owned(),
            AdapterSlot {
                adapter: mock,
                deadline: Duration::from_millis(deadline_ms),
            },
        );
        JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), max).unwrap()
    }

    fn task() -> JudgeTask {
        JudgeTask {
            predicate_id: ARG_MATCHES_TASK.to_owned(),
            adapter: "mock".to_owned(),
        }
    }

    #[tokio::test]
    async fn scores_come_back_validated() {
        let mock = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::scores(&[("match", 0.25), ("mismatch", 0.75)]),
        ));
        let outcomes = runner(Arc::clone(&mock), 500, 4)
            .evaluate(
                &[task()],
                "db_write",
                &json!({"table": "t"}),
                &SessionContext::default(),
            )
            .await;
        let JudgeOutcome::Scored(verdict) = &outcomes[0] else {
            panic!("{outcomes:?}")
        };
        assert_eq!(verdict.ppm("mismatch"), Some(750_000));
        assert_eq!(mock.calls(), 1);
        let seen = mock.last_request().unwrap();
        assert_eq!(seen.tool, "db_write");
        assert_eq!(seen.validated_args, json!({"table": "t"}));
    }

    #[tokio::test]
    async fn the_deadline_yields_a_timeout_and_keeps_the_permit_until_the_work_ends() {
        let mock = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::delayed(
                Duration::from_millis(300),
                MockBehavior::scores(&[("match", 1.0), ("mismatch", 0.0)]),
            ),
        ));
        let runner = runner(mock, 30, 1);
        let started = Instant::now();
        let outcomes = runner
            .evaluate(&[task()], "t", &json!({}), &SessionContext::default())
            .await;
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(matches!(&outcomes[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::Timeout));
        // The abandoned work still holds the only permit: the next call is saturated.
        assert_eq!(runner.in_flight(), 1);
        let next = runner
            .evaluate(&[task()], "t", &json!({}), &SessionContext::default())
            .await;
        assert!(matches!(&next[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::Saturated));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(runner.in_flight(), 0);
    }

    #[tokio::test]
    async fn errors_panics_and_unknown_names_become_failures() {
        let failing = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::Fail(JudgeError::Unavailable("down".into())),
        ));
        let outcomes = runner(failing, 500, 2)
            .evaluate(
                &[
                    task(),
                    JudgeTask {
                        predicate_id: "nope@1".into(),
                        adapter: "mock".into(),
                    },
                    JudgeTask {
                        predicate_id: ARG_MATCHES_TASK.into(),
                        adapter: "missing".into(),
                    },
                ],
                "t",
                &json!({}),
                &SessionContext::default(),
            )
            .await;
        assert_eq!(outcomes.len(), 3);
        for outcome in &outcomes {
            assert!(matches!(outcome, JudgeOutcome::Failed(f) if f.kind == FailureKind::Unavailable));
        }
        let panicking = Arc::new(MockJudge::new(pin(), MockBehavior::Panic));
        let outcomes = runner(panicking, 500, 2)
            .evaluate(&[task()], "t", &json!({}), &SessionContext::default())
            .await;
        assert!(matches!(&outcomes[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::Unavailable));
    }

    #[tokio::test]
    async fn wrong_model_and_bad_distributions_are_refused() {
        let other = ModelPin::new("mock", "2", "e".repeat(64)).unwrap();
        let wrong = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::Answer {
                probs: vec![("match".into(), 0.5), ("mismatch".into(), 0.5)],
                model: Some(other),
            },
        ));
        let outcomes = runner(wrong, 500, 2)
            .evaluate(&[task()], "t", &json!({}), &SessionContext::default())
            .await;
        assert!(matches!(&outcomes[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::ModelMismatch));
        let bad = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::scores(&[("match", 0.9), ("mismatch", 0.9)]),
        ));
        let outcomes = runner(bad, 500, 2)
            .evaluate(&[task()], "t", &json!({}), &SessionContext::default())
            .await;
        assert!(matches!(&outcomes[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::Malformed));
    }

    #[tokio::test]
    async fn tasks_run_concurrently_under_one_deadline() {
        let mock = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::delayed(
                Duration::from_millis(100),
                MockBehavior::scores(&[("match", 1.0), ("mismatch", 0.0)]),
            ),
        ));
        let runner = runner(mock, 1_000, 8);
        let started = Instant::now();
        let outcomes = runner
            .evaluate(
                &[task(), task(), task(), task()],
                "t",
                &json!({}),
                &SessionContext::default(),
            )
            .await;
        assert!(outcomes.iter().all(|o| matches!(o, JudgeOutcome::Scored(_))));
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn construction_is_validated() {
        let mock = Arc::new(MockJudge::new(
            pin(),
            MockBehavior::scores(&[("match", 1.0), ("mismatch", 0.0)]),
        ));
        let mut adapters = BTreeMap::new();
        adapters.insert(
            "mock".to_owned(),
            AdapterSlot {
                adapter: mock,
                deadline: Duration::ZERO,
            },
        );
        let registry = Arc::new(PredicateRegistry::builtin());
        assert!(JudgeRunner::new(adapters.clone(), Arc::clone(&registry), 1).is_err());
        assert!(JudgeRunner::new(BTreeMap::new(), registry, 0).is_err());
    }
}
