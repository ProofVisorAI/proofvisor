//! Edge cases of two features added together: the refusal log rebuilt
//! from recorded `agent.tool_call` events at startup (`restore_denials`,
//! `recorded_tool_calls`), and the drift check shared between instances
//! through a shared state store (`record_review`, `reset_drift`,
//! `drift_snapshot`, `drift_tripped`). Each test states the behaviour it
//! expects; a failing test is a finding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity
)]

use super::*;
use pv_state::{Spend, StateError, StateStore, TrySpendOutcome};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PREDICATE: &str = "arg_matches_task@1";

// ── Helpers ─────────────────────────────────────────────────────────

fn judge_toml(drift_state: Option<&std::path::Path>) -> JudgeConfig {
    let drift = drift_state
        .map(|path| {
            format!(
                "[drift]\nstate_file = \"{}\"\nsample_every = 1\nmin_reviews_per_band = 2\n",
                path.display()
            )
        })
        .unwrap_or_default();
    toml::from_str(&format!(
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
        predicates = [{{ id = "{PREDICATE}", adapter = "a" }}]
        [[thresholds]]
        predicate = "{PREDICATE}"
        label = "mismatch"
        deny_above = 0.7
        {drift}
        "#,
        hash = "a".repeat(64),
    ))
    .unwrap()
}

fn build(drift_state: Option<&std::path::Path>) -> Arc<JudgeService> {
    let config = judge_toml(drift_state);
    let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
    adapters.insert(
        "a".into(),
        Arc::new(pv_judge::mock::MockJudge::new(
            pv_judge::ModelPin::new("m", "1", "a".repeat(64)).unwrap(),
            pv_judge::mock::MockBehavior::scores(&[("match", 1.0), ("mismatch", 0.0)]),
        )),
    );
    Arc::new(JudgeService::new(&config, adapters, Arc::new(pv_core::metrics::Registry::new())).unwrap())
}

/// A shared store (it says it shares recent lists, as Redis does) that
/// can be made to fail: entirely (`down`), or only for `add` calls whose
/// key ends with a suffix, a number of times. A one-shot hook runs just
/// before an `add` whose key ends with its suffix, so a test can put
/// another instance's work between two writes of one review. `remove`
/// does nothing while the store is down, as `RedisStore::remove` only
/// logs a failed DEL.
#[derive(Default)]
struct FlakyShared {
    inner: pv_state::InMemoryStore,
    down: AtomicBool,
    fail_add: parking_lot::Mutex<Option<(String, usize)>>,
    hook: parking_lot::Mutex<Option<(String, Box<dyn FnOnce() + Send>)>>,
    reads: AtomicUsize,
}

impl FlakyShared {
    fn check(&self) -> Result<(), StateError> {
        if self.down.load(Ordering::SeqCst) {
            Err(StateError::Backend("store down".into()))
        } else {
            Ok(())
        }
    }
    fn fail_adds_ending_with(&self, suffix: &str, times: usize) {
        *self.fail_add.lock() = Some((suffix.to_owned(), times));
    }
    fn before_add_ending_with(&self, suffix: &str, hook: impl FnOnce() + Send + 'static) {
        *self.hook.lock() = Some((suffix.to_owned(), Box::new(hook)));
    }
    /// The hook and the injected failure, for any write to `key`.
    fn before_write(&self, key: &str) -> Result<(), StateError> {
        let hook = {
            let mut slot = self.hook.lock();
            if slot
                .as_ref()
                .is_some_and(|(suffix, _)| key.ends_with(suffix.as_str()))
            {
                slot.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook();
        }
        let mut fail = self.fail_add.lock();
        if let Some((suffix, left)) = fail.as_mut() {
            if *left > 0 && key.ends_with(suffix.as_str()) {
                *left -= 1;
                return Err(StateError::Backend("write failed".into()));
            }
        }
        Ok(())
    }
}

impl StateStore for FlakyShared {
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
        self.check()?;
        self.before_write(key)?;
        self.inner.add(key, delta)
    }
    fn get(&self, key: &str) -> Result<u64, StateError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        self.inner.get(key)
    }
    fn try_spend_many(&self, spends: &[Spend]) -> Result<TrySpendOutcome, StateError> {
        self.check()?;
        for spend in spends {
            self.before_write(&spend.key)?;
        }
        self.inner.try_spend_many(spends)
    }
    fn refund(&self, key: &str, amount: u64) {
        if !self.down.load(Ordering::SeqCst) {
            self.inner.refund(key, amount);
        }
    }
    fn remove(&self, key: &str) {
        if !self.down.load(Ordering::SeqCst) {
            self.inner.remove(key);
        }
    }
    fn shares_recent_lists(&self) -> bool {
        true
    }
    fn push_recent(&self, _key: &str, _value: &str, _keep: usize) -> Result<(), StateError> {
        self.check()
    }
    fn recent(&self, _key: &str, _max: usize) -> Result<Vec<String>, StateError> {
        self.check()?;
        Ok(Vec::new())
    }
}

fn verdict(top: u32) -> JudgeOutcome {
    JudgeOutcome::Scored(pv_judge::Verdict {
        predicate_id: PREDICATE.into(),
        probs: vec![
            pv_judge::LabelProb {
                label: "match".into(),
                ppm: top,
            },
            pv_judge::LabelProb {
                label: "mismatch".into(),
                ppm: 1_000_000 - top,
            },
        ],
        model: pv_judge::ModelPin::new("m", "1", "a".repeat(64)).unwrap(),
        latency_us: 1,
    })
}

fn sample(judge: &JudgeService, top: u32) -> String {
    judge.sample_reviews(&[verdict(top)])[PREDICATE].clone()
}

/// Forget the cached shared switches, as after the 5 s refresh interval.
fn expire_cache(judge: &JudgeService) {
    judge.shared_tripped.lock().0 = None;
}

fn shared_band(store: &dyn StateStore, band: usize) -> (u64, u64) {
    (
        store
            .get(&drift_key(PREDICATE, &format!("band:{band}:reviewed")))
            .unwrap(),
        store
            .get(&drift_key(PREDICATE, &format!("band:{band}:correct")))
            .unwrap(),
    )
}

fn tool_event(at_ms: u64, session: &str, instance: &str, payload: Value) -> Value {
    serde_json::json!({
        "class_name": "agent.tool_call",
        "time": at_ms,
        "session_uid": session,
        "ai_agent": {"instance_uid": instance},
        "payload": payload,
    })
}

fn refused(tool: &str) -> Value {
    serde_json::json!({"tool": tool, "allowed": false, "stage": "policy", "denial_code": "POLICY_DENIED"})
}

fn known(tool: &str) -> bool {
    tool.starts_with("refund") || tool == "wire_funds" || tool == "t"
}

fn context_for(judge: &JudgeService, session: &str, instance: &str, parents: Vec<String>) -> SessionContext {
    judge.context(&ContextInputs {
        session_id: session,
        instance_uid: instance,
        tool: "",
        intent: String::new(),
        missions: Vec::new(),
        charter: "c",
        delegation_depth: 0,
        parents,
    })
}

fn segment_line(offset: u64, event: &Value) -> String {
    serde_json::json!({
        "partition": 0, "offset": offset, "key": "k", "value": event, "stored_at": 1
    })
    .to_string()
}

/// A recorded policy-stage refusal numbered `n` (the reader keeps only
/// refusals).
fn refusal_event(n: u64) -> Value {
    serde_json::json!({"n": n, "payload": {"allowed": false, "stage": "policy"}})
}

fn topic_dir(dir: &std::path::Path) -> std::path::PathBuf {
    let topic = dir.join("topics/agent.tool_call");
    std::fs::create_dir_all(&topic).unwrap();
    topic
}

// ── Reading the recorded segments ───────────────────────────────────

/// When the tail to read starts exactly at the start of a line, that line
/// is complete and must be read (only a line cut by the start is not).
#[test]
fn a_tail_that_starts_on_a_line_boundary_keeps_its_first_line() {
    let dir = tempfile::tempdir().unwrap();
    let topic = topic_dir(dir.path());
    let lines: Vec<String> = (0..5)
        .map(|n| segment_line(n, &refusal_event(n)) + "\n")
        .collect();
    std::fs::write(topic.join("p0.jsonl"), lines.concat()).unwrap();
    let last_two = u64::try_from(lines[3].len() + lines[4].len()).unwrap();
    let events = recorded_tool_calls(dir.path(), last_two);
    let seen: Vec<u64> = events.iter().map(|event| event["n"].as_u64().unwrap()).collect();
    assert_eq!(
        seen,
        [3, 4],
        "a tail of exactly the last two lines ({last_two} bytes) should yield both lines"
    );
}

/// CRLF line ends, an empty segment, a segment holding only a torn line,
/// a partition numbered above 9, a sidecar and a file that is not a
/// segment: complete events are read, nothing else.
#[test]
fn odd_segment_files_yield_only_complete_events() {
    let dir = tempfile::tempdir().unwrap();
    let topic = topic_dir(dir.path());
    let crlf: String = (0..3)
        .map(|n| segment_line(n, &refusal_event(n)) + "\r\n")
        .collect();
    std::fs::write(topic.join("p0.jsonl"), crlf).unwrap();
    std::fs::write(topic.join("p1.jsonl"), "").unwrap();
    std::fs::write(
        topic.join("p2.jsonl"),
        "{\"offset\": 0, \"value\": {\"n\": 99, \"payload\": {\"allowed\": false, \"stage\": \"policy\"}}",
    )
    .unwrap();
    std::fs::write(
        topic.join("p10.jsonl"),
        segment_line(0, &refusal_event(10)) + "\n",
    )
    .unwrap();
    std::fs::write(
        topic.join("p0.event-uids.jsonl"),
        "{\"event_uid\":\"u\",\"offset\":0}\n",
    )
    .unwrap();
    std::fs::write(topic.join("p0.next-offset"), "3").unwrap();
    std::fs::write(topic.join("README"), "not a segment").unwrap();
    let mut seen: Vec<u64> = recorded_tool_calls(dir.path(), RESTORE_TAIL_BYTES)
        .iter()
        .map(|event| event["n"].as_u64().unwrap())
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, [0, 1, 2, 10]);
}

// ── Rebuilding the refusal log ──────────────────────────────────────

/// Fields missing or of the wrong type, future times, and times older
/// than 24 hours are not restored; a refusal exactly 24 hours old is,
/// as the shared log's `plausible_denial` accepts it.
#[test]
fn malformed_and_out_of_window_events_are_not_restored() {
    let judge = build(None);
    let now = 10 * SHARED_DENIAL_MAX_AGE_MS;
    let mut events = vec![
        tool_event(now - SHARED_DENIAL_MAX_AGE_MS, "s", "agent", refused("refund_a")),
        tool_event(
            now - SHARED_DENIAL_MAX_AGE_MS - 1,
            "s",
            "agent",
            refused("refund_b"),
        ),
        tool_event(now + 1, "s", "agent", refused("refund_c")),
    ];
    let mut wrong = tool_event(now, "s", "agent", refused("refund_d"));
    wrong["time"] = serde_json::json!(now.to_string());
    events.push(wrong);
    let mut float_time = tool_event(now, "s", "agent", refused("refund_e"));
    float_time["time"] = serde_json::json!(1.5);
    events.push(float_time);
    let mut no_instance = tool_event(now, "s", "agent", refused("refund_f"));
    no_instance["ai_agent"] = serde_json::json!({});
    events.push(no_instance);
    let mut string_allowed = tool_event(now, "s", "agent", refused("refund_g"));
    string_allowed["payload"]["allowed"] = serde_json::json!("false");
    events.push(string_allowed);
    let mut numeric_code = tool_event(now, "s", "agent", refused("refund_h"));
    numeric_code["payload"]["denial_code"] = serde_json::json!(7);
    events.push(numeric_code);
    let mut other_class = tool_event(now, "s", "agent", refused("refund_i"));
    other_class["class_name"] = serde_json::json!("agent.judge");
    events.push(other_class);
    events.push(serde_json::json!("not an object"));
    events.push(Value::Null);
    assert_eq!(judge.restore_denials(&events, &known, now), 1);
    let context = context_for(&judge, "s", "agent", Vec::new());
    let tools: Vec<&str> = context.prior_denials.iter().map(|d| d.tool.as_str()).collect();
    assert_eq!(tools, ["refund_a"]);
}

/// The same event recorded twice gives one refusal; refusals from
/// several partitions come back newest first whatever the partition
/// order; and an agent's restored refusals reach its delegated child as
/// the parent's.
#[test]
fn duplicates_order_and_parents_after_a_restore() {
    let dir = tempfile::tempdir().unwrap();
    let topic = topic_dir(dir.path());
    let now = pv_core::time::now_ms();
    let older = tool_event(now - 30_000, "s", "parent", refused("refund_old"));
    let newer = tool_event(now - 10_000, "s", "parent", refused("refund_new"));
    let middle = tool_event(now - 20_000, "s", "parent", refused("refund_mid"));
    // Newest in p0, oldest in p1 (twice), middle in p12.
    std::fs::write(topic.join("p0.jsonl"), segment_line(0, &newer) + "\n").unwrap();
    std::fs::write(
        topic.join("p1.jsonl"),
        segment_line(0, &older) + "\n" + &segment_line(1, &older) + "\n",
    )
    .unwrap();
    std::fs::write(topic.join("p12.jsonl"), segment_line(0, &middle) + "\n").unwrap();
    let judge = build(None);
    let events = recorded_tool_calls(dir.path(), RESTORE_TAIL_BYTES);
    assert_eq!(events.len(), 4);
    judge.restore_denials(&events, &known, now);
    let own = context_for(&judge, "s", "parent", Vec::new());
    let tools: Vec<&str> = own.prior_denials.iter().map(|d| d.tool.as_str()).collect();
    assert_eq!(tools, ["refund_new", "refund_mid", "refund_old"]);
    let child = context_for(&judge, "child-session", "child", vec!["parent".into()]);
    assert_eq!(child.prior_denials.len(), 3, "{:?}", child.prior_denials);
    assert!(child
        .prior_denials
        .iter()
        .all(|d| d.source == DenialSource::Parent && d.instance_uid == "parent"));
}

/// Very long session ids and instance ids are restored under their own
/// keys and do not collide with a prefix of themselves.
#[test]
fn very_long_ids_are_restored_under_their_own_keys() {
    let judge = build(None);
    let now = pv_core::time::now_ms();
    let long_session = "s".repeat(100_000);
    let long_instance = "i".repeat(100_000);
    let events = vec![
        tool_event(now - 1_000, &long_session, &long_instance, refused("refund_long")),
        tool_event(now - 1_000, "s", "i", refused("refund_short")),
    ];
    assert_eq!(judge.restore_denials(&events, &known, now), 2);
    let long = context_for(&judge, &long_session, &long_instance, Vec::new());
    assert_eq!(long.prior_denials.len(), 1);
    assert_eq!(long.prior_denials[0].tool, "refund_long");
    let short = context_for(&judge, "s", "i", Vec::new());
    assert_eq!(short.prior_denials.len(), 1);
    assert_eq!(short.prior_denials[0].tool, "refund_short");
}

/// A restored refusal behaves like a live one: a later live refusal of
/// the same kind replaces it (one entry per kind), the judge's own
/// refusals are kept first when the list is full, and with a shared store
/// the restored refusals are merged with the shared ones.
#[test]
fn restored_refusals_merge_like_live_ones() {
    let judge = build(None);
    let now = pv_core::time::now_ms();
    let mut events = vec![tool_event(
        now - 60_000,
        "s",
        "agent",
        serde_json::json!({
            "tool": "t", "allowed": false, "stage": "policy",
            "policy": pv_sandbox::JUDGE_POLICY_NAME, "denial_code": "JUDGE_DENIED",
            "judge": {"decision_predicate": PREDICATE},
        }),
    )];
    for n in 0..20 {
        events.push(tool_event(
            now - 50_000 + n,
            "s",
            "agent",
            refused(&format!("refund_{n}")),
        ));
    }
    events.push(tool_event(now - 40_000, "s", "agent", refused("wire_funds")));
    judge.restore_denials(&events, &known, now);
    judge.record_denial("s", "agent", "wire_funds", "POLICY_DENIED", None);
    let recent = judge.denials.lock().recent(&session_key("agent", "s"));
    assert_eq!(recent.len(), DENIALS_PER_KEY);
    assert_eq!(recent[0].tool, "wire_funds");
    assert!(
        recent[0].at_ms >= now,
        "the live refusal replaced the restored one"
    );
    assert_eq!(recent.iter().filter(|d| d.tool == "wire_funds").count(), 1);
    assert!(
        recent
            .iter()
            .any(|d| d.predicate_id.as_deref() == Some(PREDICATE)),
        "the judge's own restored refusal is kept when the list is full"
    );
}

// ── The shared drift check ──────────────────────────────────────────

/// A switch kept in this instance's state file must survive a shared
/// store outage at join time: once the store is back, it is written back,
/// not reset.
#[test]
fn a_switch_from_the_state_file_survives_an_outage_at_join() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("c.json");
    std::fs::write(
        &state,
        format!("{{\"stats\":{{}},\"tripped\":[\"{PREDICATE}\"]}}"),
    )
    .unwrap();
    let judge = build(Some(&state));
    let store = Arc::new(FlakyShared::default());
    store.down.store(true, Ordering::SeqCst);
    judge.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    store.down.store(false, Ordering::SeqCst);
    expire_cache(&judge);
    assert_eq!(
        judge.drift_tripped(),
        [PREDICATE],
        "after the outage the switch is off on every instance, and the local copy was reset"
    );
}

/// The switch is sticky until an operator resets it (pv-judge's drift
/// module says so). A shared store that loses its keys (a Redis restart
/// without persistence, or a flush) is not an operator reset: the switch
/// is written back.
#[test]
fn a_switch_survives_the_shared_store_losing_its_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    for (top, correct) in [
        (550_000, true),
        (550_000, true),
        (950_000, false),
        (950_000, false),
    ] {
        a.record_review(&sample(&a, top), correct).unwrap();
    }
    assert_eq!(a.drift_tripped(), [PREDICATE]);
    store.inner.remove(&drift_key(PREDICATE, "tripped"));
    for band in 0..pv_judge::drift::BAND_LOWER_PPM.len() {
        store
            .inner
            .remove(&drift_key(PREDICATE, &format!("band:{band}:reviewed")));
        store
            .inner
            .remove(&drift_key(PREDICATE, &format!("band:{band}:correct")));
    }
    expire_cache(&a);
    assert_eq!(
        a.drift_tripped(),
        [PREDICATE],
        "the store lost its keys and ask-by-default turned off without an operator reset"
    );
}

/// A predicate in ask-by-default mode in this instance's state file must
/// stay in that mode when the shared store cannot be read at startup. The
/// first read of the shared switches fails and `shared_tripped` returns
/// the cached list, which is still empty.
#[test]
fn ask_by_default_stays_on_when_the_shared_store_is_down_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("c.json");
    std::fs::write(
        &state,
        format!("{{\"stats\":{{}},\"tripped\":[\"{PREDICATE}\"]}}"),
    )
    .unwrap();
    let judge = build(Some(&state));
    assert_eq!(judge.drift_tripped(), [PREDICATE], "tripped from the state file");
    let store = Arc::new(FlakyShared::default());
    store.down.store(true, Ordering::SeqCst);
    judge.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    assert_eq!(
        judge.drift_tripped(),
        [PREDICATE],
        "with the shared store unreachable, drift_tripped() turned ask-by-default off"
    );
}

/// While the shared store is down, the switches are read at most once
/// per refresh interval, not on every judged call.
#[test]
fn a_down_store_is_not_read_on_every_judged_call() {
    let dir = tempfile::tempdir().unwrap();
    let judge = build(Some(&dir.path().join("a.json")));
    let store = Arc::new(FlakyShared::default());
    judge.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    let _ = judge.drift_tripped();
    store.down.store(true, Ordering::SeqCst);
    expire_cache(&judge);
    let before = store.reads.load(Ordering::SeqCst);
    for _ in 0..100 {
        let _ = judge.drift_tripped();
    }
    let reads = store.reads.load(Ordering::SeqCst) - before;
    assert!(
        reads <= 2,
        "100 judged calls within the refresh interval read the down store {reads} times"
    );
}

/// A review whose statistics write fails is answered 503
/// (`DriftError::Unavailable`), which tells the reviewer to try again. The
/// retry must then count the review, once, with its answer.
#[test]
fn a_review_whose_write_failed_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let judge = build(Some(&dir.path().join("a.json")));
    let store = Arc::new(FlakyShared::default());
    judge.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    let id = sample(&judge, 950_000);
    store.fail_adds_ending_with(":correct", 1);
    let first = judge.record_review(&id, true);
    assert!(
        matches!(first, Err(pv_judge::DriftError::Unavailable(_))),
        "{first:?}"
    );
    let retry = judge.record_review(&id, true);
    let band = shared_band(store.as_ref(), 5);
    assert!(
        retry.is_ok(),
        "the retry after a 503 was refused ({retry:?}); band 5 now holds (reviewed, correct) = {band:?}"
    );
    assert_eq!(band, (1, 1));
}

/// Two instances record correct reviews at the same moment, and every
/// band stays fully accurate, so nothing may trip. `record_review`
/// writes `reviewed` and `correct` as two separate additions; an instance
/// reading the bands between another instance's two writes sees a band
/// at 2 of 3 correct and trips the switch, which then stays on until an
/// operator resets it.
#[test]
fn two_correct_reviews_at_once_do_not_trip_the_switch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    let b = build(Some(&dir.path().join("b.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    b.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    for _ in 0..2 {
        assert!(!a.record_review(&sample(&a, 550_000), true).unwrap().tripped);
        assert!(!a.record_review(&sample(&a, 950_000), true).unwrap().tripped);
    }
    let low = sample(&b, 550_000);
    let high = sample(&a, 950_000);
    let b_result = Arc::new(parking_lot::Mutex::new(None));
    {
        let (b, b_result) = (Arc::clone(&b), Arc::clone(&b_result));
        // B's review lands between A's `reviewed` and `correct` writes.
        store.before_add_ending_with(":band:5:correct", move || {
            *b_result.lock() = Some(b.record_review(&low, true));
        });
    }
    let a_result = a.record_review(&high, true).unwrap();
    let b_result = b_result.lock().take().expect("the hook ran").unwrap();
    assert_eq!(shared_band(store.as_ref(), 1), (3, 3));
    assert_eq!(shared_band(store.as_ref(), 5), (3, 3));
    expire_cache(&a);
    assert!(
        !a_result.tripped && !b_result.tripped && a.drift_tripped().is_empty(),
        "every review was correct, yet the switch tripped (A: {a_result:?}, B: {b_result:?}, \
         shared switches: {:?})",
        a.drift_tripped()
    );
}

/// An operator's reset on one instance must not be undone when another
/// instance restarts: the other instance's state file follows the reset
/// too, so it has no switch to publish again.
#[test]
fn a_reset_is_not_undone_by_another_instance_restarting() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    let b_file = dir.path().join("b.json");
    let b = build(Some(&b_file));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    b.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    // The reviews that trip the switch are handled on B, whose admin
    // route saves B's state file after each one.
    for (top, correct) in [
        (550_000, true),
        (550_000, true),
        (950_000, false),
        (950_000, false),
    ] {
        b.record_review(&sample(&a, top), correct).unwrap();
        b.persist_drift().unwrap();
    }
    assert_eq!(b.drift_tripped(), [PREDICATE]);
    // The operator resets on A; A's route saves A's file.
    assert!(a.reset_drift(PREDICATE).unwrap());
    a.persist_drift().unwrap();
    expire_cache(&b);
    assert!(b.drift_tripped().is_empty(), "B follows the reset in memory");
    // B restarts from its state file.
    drop(b);
    let b = build(Some(&b_file));
    b.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    expire_cache(&a);
    assert!(
        a.drift_tripped().is_empty(),
        "B's restart switched the predicate back to ask-by-default on every instance after the \
         operator's reset (B's state file still says {:?})",
        std::fs::read_to_string(&b_file).unwrap()
    );
}

/// A reset while the shared store is down cannot clear the shared switch,
/// so it reports the failure (the admin route answers 503) and the switch
/// stays until a reset reaches the store.
#[test]
fn a_reset_during_a_store_outage_is_not_silently_lost() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    for (top, correct) in [
        (550_000, true),
        (550_000, true),
        (950_000, false),
        (950_000, false),
    ] {
        a.record_review(&sample(&a, top), correct).unwrap();
    }
    assert_eq!(a.drift_tripped(), [PREDICATE]);
    store.down.store(true, Ordering::SeqCst);
    let reported = a.reset_drift(PREDICATE);
    store.down.store(false, Ordering::SeqCst);
    expire_cache(&a);
    let after = a.drift_tripped();
    // Either the reset reports the outage (and the operator retries), or
    // it took effect: never a silent success with the switch still on.
    assert!(
        reported.is_err() || after.is_empty(),
        "reset_drift reported {reported:?} with no error, yet once the store is back the \
         predicate is still switched: {after:?}"
    );
    assert!(reported.is_err(), "the outage is reported: {reported:?}");
    assert_eq!(
        after,
        [PREDICATE],
        "and the switch is kept until a reset reaches the store"
    );
}

/// A verdict sampled while the shared store failed could never have its
/// review recorded (its claim was not written), so no review id is handed
/// out for it; once the store is back, sampled reviews are recorded.
#[test]
fn a_review_sampled_during_a_store_outage_can_be_recorded_later() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    store.down.store(true, Ordering::SeqCst);
    assert!(
        a.sample_reviews(&[verdict(950_000)]).is_empty(),
        "no review id is handed out that could never be recorded"
    );
    assert_eq!(a.drift().unwrap().pending_ids().len(), 0);
    store.down.store(false, Ordering::SeqCst);
    let id = sample(&a, 950_000);
    let result = a.record_review(&id, true);
    assert!(result.is_ok(), "{result:?}");
}

/// With the shared store unreadable, the operator's snapshot must still
/// show a predicate this instance holds in ask-by-default mode.
#[test]
fn the_snapshot_does_not_hide_a_switch_when_the_store_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    for (top, correct) in [
        (550_000, true),
        (550_000, true),
        (950_000, false),
        (950_000, false),
    ] {
        a.record_review(&sample(&a, top), correct).unwrap();
    }
    assert_eq!(a.drift_tripped(), [PREDICATE]);
    store.down.store(true, Ordering::SeqCst);
    let snapshot = a.drift_snapshot().unwrap();
    assert!(
        snapshot
            .predicates
            .iter()
            .any(|p| p.predicate_id == PREDICATE && p.tripped),
        "the snapshot lists no tripped predicate while ask-by-default is on: {snapshot:?}"
    );
}

/// A verdict sampled on A and reviewed on B is no longer waiting for
/// review, so A's snapshot must not count it.
#[test]
fn a_review_recorded_elsewhere_is_no_longer_pending() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    let b = build(Some(&dir.path().join("b.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    b.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    let id = sample(&a, 950_000);
    assert_eq!(a.drift_snapshot().unwrap().pending_reviews, 1);
    b.record_review(&id, true).unwrap();
    assert_eq!(
        a.drift_snapshot().unwrap().pending_reviews,
        0,
        "A still counts a review that B recorded"
    );
}

/// Expected to pass: review ids at and past the band limit, ids with
/// '~' in the predicate part, ids that were never issued, and a review
/// sampled before a reset and recorded after it (the local monitor keeps
/// it too).
#[test]
fn review_id_edges() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    assert_eq!(parse_review_id("u~5~a~b@1"), Some(("a~b@1".to_owned(), 5)));
    assert_eq!(parse_review_id("u~-1~p@1"), None);
    assert_eq!(parse_review_id("u~~p@1"), None);
    assert!(
        a.record_review(&format!("u~5~{PREDICATE}"), true).is_err(),
        "never issued"
    );
    assert!(
        a.record_review(&format!("u~6~{PREDICATE}"), true).is_err(),
        "no band 6"
    );
    assert!(a.record_review(&format!("u~1~{PREDICATE}~x"), true).is_err());
    assert!(a.record_review("", true).is_err());
    // An issued id with its band changed is refused: the claim is the whole id.
    let id = sample(&a, 950_000);
    let forged = id.replacen("~5~", "~1~", 1);
    assert_ne!(forged, id);
    assert!(a.record_review(&forged, true).is_err());
    assert_eq!(
        store
            .get(&drift_key(PREDICATE, &format!("review:{forged}")))
            .unwrap(),
        0
    );
    // Sampled before a reset, reviewed after it.
    assert!(!a.reset_drift(PREDICATE).unwrap());
    a.record_review(&id, false).unwrap();
    assert_eq!(shared_band(store.as_ref(), 5), (1, 0));
    assert!(a.record_review(&id, false).is_err(), "counted once");
}

/// Expected to pass: two instances reviewing the same ids at once count
/// each review exactly once.
#[test]
fn concurrent_reviews_of_the_same_ids_count_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FlakyShared::default());
    let a = build(Some(&dir.path().join("a.json")));
    let b = build(Some(&dir.path().join("b.json")));
    a.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    b.share_denials(Arc::clone(&store) as Arc<dyn StateStore>);
    let ids: Vec<String> = (0..200).map(|_| sample(&a, 550_000)).collect();
    let accepted = AtomicUsize::new(0);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        for judge in [&a, &b] {
            let (ids, accepted, barrier) = (&ids, &accepted, &barrier);
            scope.spawn(move || {
                barrier.wait();
                for id in ids {
                    if judge.record_review(id, true).is_ok() {
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    assert_eq!(accepted.load(Ordering::SeqCst), 200);
    assert_eq!(shared_band(store.as_ref(), 1), (200, 200));
}
