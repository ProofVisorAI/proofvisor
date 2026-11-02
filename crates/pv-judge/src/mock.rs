//! A deterministic judge for tests, shadow replay, and calibration
//! harness checks. It is not selectable from a production config.

use crate::adapter::{AdapterKind, BoxFuture, JudgeAdapter, JudgeError};
use crate::model::{JudgeRequest, ModelPin, RawScores};
use crate::predicate::PredicateDef;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// What the mock does for a call.
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Answer with these probabilities, as `model` (the pin when `None`).
    Answer {
        /// `(label, probability)` pairs.
        probs: Vec<(String, f64)>,
        /// Model to report; `None` reports the pinned model.
        model: Option<ModelPin>,
    },
    /// Fail with this error.
    Fail(JudgeError),
    /// Wait, then behave as the inner behaviour.
    Delay(Duration, Box<MockBehavior>),
    /// Panic inside the scoring task (exercises crash handling).
    Panic,
}

impl MockBehavior {
    /// Answer with these probabilities as the pinned model.
    pub fn scores(probs: &[(&str, f64)]) -> Self {
        Self::Answer {
            probs: probs.iter().map(|(l, p)| ((*l).to_owned(), *p)).collect(),
            model: None,
        }
    }

    /// Wait `delay`, then behave as `then`.
    pub fn delayed(delay: Duration, then: Self) -> Self {
        Self::Delay(delay, Box::new(then))
    }
}

/// The mock judge. Behaviour is chosen by `(predicate, tool)`, then by
/// predicate, then the default; a scorer function can replace all of it.
pub struct MockJudge {
    pin: ModelPin,
    default: Mutex<MockBehavior>,
    by_predicate: Mutex<BTreeMap<String, MockBehavior>>,
    by_tool: Mutex<BTreeMap<(String, String), MockBehavior>>,
    #[allow(clippy::type_complexity)]
    scorer: Mutex<Option<Box<dyn Fn(&JudgeRequest) -> MockBehavior + Send + Sync>>>,
    calls: AtomicU64,
    last: Mutex<Option<JudgeRequest>>,
}

impl MockJudge {
    /// A mock that behaves as `default` for every call.
    pub fn new(pin: ModelPin, default: MockBehavior) -> Self {
        Self {
            pin,
            default: Mutex::new(default),
            by_predicate: Mutex::new(BTreeMap::new()),
            by_tool: Mutex::new(BTreeMap::new()),
            scorer: Mutex::new(None),
            calls: AtomicU64::new(0),
            last: Mutex::new(None),
        }
    }

    /// Replace the default behaviour.
    pub fn set_default(&self, behavior: MockBehavior) {
        *self.default.lock() = behavior;
    }

    /// Behaviour for one predicate.
    pub fn set_for_predicate(&self, predicate_id: &str, behavior: MockBehavior) {
        self.by_predicate.lock().insert(predicate_id.to_owned(), behavior);
    }

    /// Behaviour for one predicate on one tool.
    pub fn set_for_tool(&self, predicate_id: &str, tool: &str, behavior: MockBehavior) {
        self.by_tool
            .lock()
            .insert((predicate_id.to_owned(), tool.to_owned()), behavior);
    }

    /// Decide every call with a function of the request.
    pub fn set_scorer(&self, scorer: impl Fn(&JudgeRequest) -> MockBehavior + Send + Sync + 'static) {
        *self.scorer.lock() = Some(Box::new(scorer));
    }

    /// Calls made so far.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// The most recent request.
    pub fn last_request(&self) -> Option<JudgeRequest> {
        self.last.lock().clone()
    }

    fn behavior_for(&self, request: &JudgeRequest) -> MockBehavior {
        if let Some(scorer) = self.scorer.lock().as_ref() {
            return scorer(request);
        }
        if let Some(behavior) = self
            .by_tool
            .lock()
            .get(&(request.predicate_id.clone(), request.tool.clone()))
        {
            return behavior.clone();
        }
        if let Some(behavior) = self.by_predicate.lock().get(&request.predicate_id) {
            return behavior.clone();
        }
        self.default.lock().clone()
    }
}

impl JudgeAdapter for MockJudge {
    fn id(&self) -> &ModelPin {
        &self.pin
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Mock
    }

    fn score<'a>(
        &'a self,
        request: &'a JudgeRequest,
        _predicate: &'a PredicateDef,
    ) -> BoxFuture<'a, Result<RawScores, JudgeError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock() = Some(request.clone());
        let behavior = self.behavior_for(request);
        Box::pin(async move { run(behavior, &self.pin).await })
    }
}

async fn run(mut behavior: MockBehavior, pin: &ModelPin) -> Result<RawScores, JudgeError> {
    loop {
        match behavior {
            MockBehavior::Delay(delay, then) => {
                tokio::time::sleep(delay).await;
                behavior = *then;
            }
            MockBehavior::Answer { probs, model } => {
                return Ok(RawScores {
                    probs,
                    model: model.unwrap_or_else(|| pin.clone()),
                });
            }
            MockBehavior::Fail(error) => return Err(error),
            MockBehavior::Panic => crash(),
        }
    }
}

/// Deliberate: the runner must turn an adapter crash into a failed
/// outcome, and this is how tests prove it does.
#[allow(clippy::panic)]
fn crash() -> ! {
    panic!("mock judge configured to panic")
}
