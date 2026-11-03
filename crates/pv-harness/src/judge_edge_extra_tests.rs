//! Edge cases of the judge's refusal log: unusual session and instance
//! ids, the one-hour rule for writing a refusal again to the shared
//! store, and a refusal recorded while the shared store fails.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;
use pv_state::{Spend, StateError, StateStore, TrySpendOutcome};
use std::sync::atomic::{AtomicUsize, Ordering};

fn service() -> JudgeService {
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
        "#,
        hash = "a".repeat(64),
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

/// A store that shares recent lists between services, like Redis. The
/// first `fail_pushes` writes fail; every write is counted.
#[derive(Default)]
struct ListStore {
    lists: parking_lot::Mutex<HashMap<String, VecDeque<String>>>,
    fail_pushes: AtomicUsize,
    pushes: AtomicUsize,
}

impl StateStore for ListStore {
    fn add(&self, _key: &str, _delta: u64) -> Result<u64, StateError> {
        Ok(0)
    }
    fn get(&self, _key: &str) -> Result<u64, StateError> {
        Ok(0)
    }
    fn try_spend_many(&self, _spends: &[Spend]) -> Result<TrySpendOutcome, StateError> {
        Err(StateError::Backend("unused".into()))
    }
    fn remove(&self, _key: &str) {}
    fn shares_recent_lists(&self) -> bool {
        true
    }
    fn push_recent(&self, key: &str, value: &str, keep: usize) -> Result<(), StateError> {
        if self
            .fail_pushes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StateError::Backend("store briefly down".into()));
        }
        self.pushes.fetch_add(1, Ordering::SeqCst);
        let mut lists = self.lists.lock();
        let list = lists.entry(key.to_owned()).or_default();
        list.push_front(value.to_owned());
        list.truncate(keep.max(1));
        Ok(())
    }
    fn recent(&self, key: &str, max: usize) -> Result<Vec<String>, StateError> {
        Ok(self
            .lists
            .lock()
            .get(key)
            .map(|list| list.iter().take(max.max(1)).cloned().collect())
            .unwrap_or_default())
    }
}

fn pair(store: &Arc<ListStore>) -> (JudgeService, JudgeService) {
    let (a, b) = (service(), service());
    a.share_denials(Arc::clone(store) as Arc<dyn StateStore>);
    b.share_denials(Arc::clone(store) as Arc<dyn StateStore>);
    assert!(a.denials_shared() && b.denials_shared());
    (a, b)
}

fn denial(tool: &str, instance: &str, at_ms: u64) -> PriorDenial {
    PriorDenial {
        tool: tool.to_owned(),
        denial_code: "POLICY_DENIED".to_owned(),
        predicate_id: None,
        at_ms,
        source: DenialSource::Session,
        instance_uid: instance.to_owned(),
    }
}

fn tools(denials: &[PriorDenial]) -> Vec<(String, u64)> {
    denials.iter().map(|d| (d.tool.clone(), d.at_ms)).collect()
}

// ── The one-hour rule ───────────────────────────────────────────────

/// A refusal that this instance could not write to the shared store
/// (the store failed) is still kept locally. The next refusal of the
/// same kind must be written, or another instance never learns of it.
#[test]
fn a_refusal_whose_shared_write_failed_is_written_on_the_next_refusal() {
    let store = Arc::new(ListStore::default());
    store.fail_pushes.store(2, Ordering::SeqCst); // both keys of the first refusal
    let (a, b) = pair(&store);
    a.record_denial("s-1", "agent-1", "refund_order", "POLICY_DENIED", None);
    assert_eq!(store.pushes.load(Ordering::SeqCst), 0, "the first write failed");
    // The store is back; the same refusal happens again a moment later.
    a.record_denial("s-1", "agent-1", "refund_order", "POLICY_DENIED", None);
    let seen = b.recent_denials(&instance_key("agent-1"), "agent-1");
    assert!(
        seen.iter().any(|d| d.tool == "refund_order"),
        "after one failed write to the shared store, record_denial (judge.rs) skips writing the \
         same refusal for an hour, because holds_since reads this instance's local log, which \
         kept the refusal although it never reached the store. Writes after the failure: {}; \
         instance B sees {:?}",
        store.pushes.load(Ordering::SeqCst),
        tools(&seen)
    );
}

/// The rule asks "did this instance share a refusal of this kind in the
/// last hour?". A refusal repeated every 30 minutes must still be written
/// again at least once an hour: other instances drop a shared entry once
/// it is 24 hours old, while the agent is still being refused.
#[test]
fn a_refusal_repeated_every_half_hour_stays_visible_to_other_instances() {
    let store = Arc::new(ListStore::default());
    let (a, b) = pair(&store);
    let now = pv_core::time::now_ms();
    let first = now - SHARED_DENIAL_MAX_AGE_MS - 1_000;
    let last_local = now - 30 * 60_000;
    // The first refusal was written to the shared store a day ago...
    let entry = serde_json::to_string(&denial("refund_order", "agent-1", first)).unwrap();
    for key in [session_key("agent-1", "s-1"), instance_key("agent-1")] {
        store
            .push_recent(&shared_denial_key(&key, false), &entry, SHARED_DENIALS_PER_KEY)
            .unwrap();
        // ...and the repeats since (the newest 30 minutes ago) were kept
        // locally only, as the rule says.
        a.denials
            .lock()
            .push(key, denial("refund_order", "agent-1", last_local));
    }
    let writes_before = store.pushes.load(Ordering::SeqCst);
    a.record_denial("s-1", "agent-1", "refund_order", "POLICY_DENIED", None);
    let seen = b.recent_denials(&instance_key("agent-1"), "agent-1");
    assert!(
        seen.iter().any(|d| d.tool == "refund_order"),
        "the agent was refused just now, but instance B sees nothing: the shared entry is from \
         {} ms ago (older than SHARED_DENIAL_MAX_AGE_MS), and record_denial wrote nothing new \
         ({} writes) because the local entry from 30 minutes ago counts as shared within the hour",
        now - first,
        store.pushes.load(Ordering::SeqCst) - writes_before
    );
}

/// Around the boundary of the hour: a successful shared write just
/// inside the hour suppresses the next write, one just outside does not.
#[test]
fn the_one_hour_rule_at_its_boundary() {
    for (age_ms, written) in [
        (SHARED_DENIAL_REPEAT_MS - 5_000, false),
        (SHARED_DENIAL_REPEAT_MS + 5_000, true),
    ] {
        let store = Arc::new(ListStore::default());
        let (a, _) = pair(&store);
        let now = pv_core::time::now_ms();
        for key in [session_key("agent-1", "s-1"), instance_key("agent-1")] {
            let earlier = denial("refund_order", "agent-1", now - age_ms);
            a.last_shared
                .lock()
                .insert(shared_mark(&key, &earlier), now - age_ms);
        }
        a.record_denial("s-1", "agent-1", "refund_order", "POLICY_DENIED", None);
        let pushes = store.pushes.load(Ordering::SeqCst);
        assert_eq!(
            pushes > 0,
            written,
            "shared write {age_ms} ms ago: {pushes} writes"
        );
        if written {
            assert_eq!(pushes, 2, "one write per key (session and instance)");
        }
    }
    // A different kind (another tool, code, or predicate) is always written.
    let store = Arc::new(ListStore::default());
    let (a, _) = pair(&store);
    a.record_denial("s-1", "agent-1", "refund_order", "POLICY_DENIED", None);
    a.record_denial("s-1", "agent-1", "refund_order", "JUDGE_DENIED", None);
    a.record_denial(
        "s-1",
        "agent-1",
        "refund_order",
        "JUDGE_DENIED",
        Some("arg_matches_task@1".into()),
    );
    a.record_denial("s-1", "agent-1", "read_ticket", "POLICY_DENIED", None);
    assert_eq!(store.pushes.load(Ordering::SeqCst), 8);
    // The same kind again: not written.
    a.record_denial("s-1", "agent-1", "read_ticket", "POLICY_DENIED", None);
    assert_eq!(store.pushes.load(Ordering::SeqCst), 8);
    // The same kind in another session: the session key is new, so only
    // that key is written.
    a.record_denial("s-2", "agent-1", "read_ticket", "POLICY_DENIED", None);
    assert_eq!(store.pushes.load(Ordering::SeqCst), 9);
}

// ── Unusual instance and session ids ────────────────────────────────

/// The identity validator accepts any instance uid of 1 to 128
/// characters without control, bidirectional or zero-width characters.
/// A refusal of such an agent on one instance must be visible on another.
#[test]
fn refusals_of_agents_with_any_valid_instance_uid_are_shared() {
    let mut rejected = Vec::new();
    for uid in [
        "agent-1",
        "spiffe://acme.io/ns/prod/sa/billing",
        "team+eu",
        "agent #7",
        "agent#7",
        "agent=1",
        "agénte",
        "代理人",
        "a".repeat(128).as_str(),
        "anonymous",
    ] {
        let store = Arc::new(ListStore::default());
        let (a, b) = pair(&store);
        a.record_denial("s-1", uid, "refund_order", "POLICY_DENIED", None);
        let by_instance = b.recent_denials(&instance_key(uid), uid);
        let by_session = b.recent_denials(&session_key(uid, "s-1"), uid);
        if by_instance.is_empty() || by_session.is_empty() {
            rejected.push(uid.to_owned());
        }
    }
    assert!(
        rejected.is_empty(),
        "refusals of these valid instance uids are written to the shared store but dropped when \
         another instance reads them back, because plausible_denial (judge.rs) accepts only ASCII \
         letters, digits and _-.:/@ in an instance uid: {rejected:?}"
    );
}

#[test]
fn empty_and_very_long_session_ids() {
    let store = Arc::new(ListStore::default());
    let (a, b) = pair(&store);
    let long = "s".repeat(100_000);
    for session in ["", long.as_str(), ":", "::", "0:", "1:a"] {
        a.record_denial(session, "agent-1", "refund_order", "POLICY_DENIED", None);
        let key = session_key("agent-1", session);
        let local = a.recent_denials(&key, "agent-1");
        let shared = b.recent_denials(&key, "agent-1");
        assert_eq!(local.len(), 1, "{:?}", &session[..session.len().min(8)]);
        assert_eq!(shared.len(), 1, "{:?}", &session[..session.len().min(8)]);
        let store_key = shared_denial_key(&key, false);
        assert!(
            store_key.len() < 100,
            "the store key is a hash: {}",
            store_key.len()
        );
    }
    // Another session of the same agent does not see these.
    let other = a.context(&ContextInputs {
        session_id: "other",
        instance_uid: "agent-1",
        tool: "refund_order",
        intent: String::new(),
        missions: Vec::new(),
        charter: "c",
        delegation_depth: 0,
        parents: Vec::new(),
    });
    assert!(other.prior_denials.is_empty(), "{:?}", other.prior_denials);
}

/// Every pair of short ids over an alphabet of a letter, a digit and
/// ':' gives its own session key, and no session key equals an instance key.
#[test]
fn session_keys_are_unique_over_short_ids() {
    let alphabet = ['a', '1', ':'];
    let mut ids = vec![String::new()];
    let mut layer = vec![String::new()];
    for _ in 0..4 {
        layer = layer
            .iter()
            .flat_map(|id| alphabet.iter().map(move |c| format!("{id}{c}")))
            .collect();
        ids.extend(layer.iter().cloned());
    }
    let mut seen: HashMap<String, (String, String)> = HashMap::new();
    for instance in &ids {
        assert!(!instance_key(instance).starts_with("s:"));
        for session in &ids {
            let key = session_key(instance, session);
            if let Some(previous) = seen.insert(key.clone(), (instance.clone(), session.clone())) {
                panic!("{key:?} for ({instance:?}, {session:?}) and {previous:?}");
            }
        }
    }
}

/// An agent's refusal recorded under an empty session id is shown in
/// that agent's context for the empty session, and under its instance
/// key to a child agent.
#[test]
fn a_refusal_in_an_empty_session_reaches_a_child_through_the_parent() {
    let judge = service();
    judge.record_denial("", "parent-1", "refund_order", "POLICY_DENIED", None);
    let child = judge.context(&ContextInputs {
        session_id: "child-session",
        instance_uid: "child-1",
        tool: "refund_order",
        intent: String::new(),
        missions: Vec::new(),
        charter: "c",
        delegation_depth: 1,
        parents: vec!["parent-1".into()],
    });
    assert_eq!(child.prior_denials.len(), 1, "{:?}", child.prior_denials);
    assert!(matches!(child.prior_denials[0].source, DenialSource::Parent));
}
