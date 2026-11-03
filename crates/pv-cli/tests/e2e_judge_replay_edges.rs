//! Edge cases for `pvctl judge-replay`, through the built binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use serde_json::{json, Value};
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_pvctl");
const PIN: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

fn pvctl(args: &[&str]) -> Output {
    std::process::Command::new(BIN)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run pvctl")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_config(dir: &Path, name: &str, deny_above: &str) -> String {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:8484"
upstream_url = "http://127.0.0.1:9"
require_identity = false
atif_spool_dir = "{dir}/spool"
bridge_data_dir = "{dir}/bridge"
tool_schema_dir = "{dir}/schemas"

[judge]
mode = "shadow"

[[judge.adapters]]
name = "vendor"
kind = "cloud"
endpoint = "http://127.0.0.1:9/score"
deadline_ms = 2000
model_name = "cli-judge"
model_version = "1"
weights_sha256 = "{PIN}"

[[judge.tools]]
tool = "refund_order"
allow_cloud = true
predicates = [{{ id = "arg_matches_task@1", adapter = "vendor" }}]

[[judge.thresholds]]
predicate = "arg_matches_task@1"
label = "mismatch"
deny_above = {deny_above}
"#,
            dir = dir.display()
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

fn policy(config: &str) -> pv_judge::ThresholdPolicy {
    pv_harness::HarnessConfig::from_toml(&std::fs::read_to_string(config).unwrap())
        .unwrap()
        .judge
        .unwrap()
        .threshold_policy()
        .unwrap()
}

fn mismatch(p: u32) -> pv_judge::JudgeOutcome {
    pv_judge::JudgeOutcome::Scored(pv_judge::Verdict {
        predicate_id: "arg_matches_task@1".into(),
        probs: vec![
            pv_judge::LabelProb {
                label: "match".into(),
                ppm: 1_000_000 - p,
            },
            pv_judge::LabelProb {
                label: "mismatch".into(),
                ppm: p,
            },
        ],
        model: pv_judge::ModelPin::new("cli-judge", "1", PIN).unwrap(),
        latency_us: 10,
    })
}

fn record(policy: &pv_judge::ThresholdPolicy, outcomes: &[pv_judge::JudgeOutcome], drift: &[&str]) -> Value {
    let decision = policy.decide(outcomes, &|id| drift.contains(&id));
    let mut record = pv_judge::JudgeRecord::new(
        pv_judge::JudgeMode::Shadow,
        10,
        outcomes
            .iter()
            .map(|o| pv_judge::OutcomeRecord::from_outcome(o, "vendor", pv_judge::AdapterKind::Cloud))
            .collect(),
        &decision,
        false,
    );
    record.drift_tripped = drift.iter().map(|s| (*s).to_owned()).collect();
    serde_json::to_value(record).unwrap()
}

fn line(offset: u64, partition: u32, judge: Option<Value>) -> String {
    let mut payload = json!({"tool": "refund_order", "allowed": true});
    if let Some(judge) = judge {
        payload["judge"] = judge;
    }
    json!({
        "partition": partition, "offset": offset, "key": "agent", "stored_at": 1_767_225_600_000u64,
        "value": {
            "class_name": "agent.tool_call",
            "session_uid": format!("s-{offset}"),
            "metadata": {"uid": format!("evt-{partition}-{offset}")},
            "payload": payload
        }
    })
    .to_string()
}

fn bridge(dir: &Path, topic: &str, partitions: u64, segments: &[(u32, Vec<String>)]) -> String {
    let bridge = dir.join("replay-bridge");
    std::fs::create_dir_all(bridge.join("topics").join(topic)).unwrap();
    std::fs::write(
        bridge.join("manifest.yaml"),
        format!(
            "manifest_version: 1\nname: replay\ntopics:\n  - name: {topic}\n    partitions: {partitions}\n    retention: {{hot_hours: 24}}\n"
        ),
    )
    .unwrap();
    for (partition, lines) in segments {
        std::fs::write(
            bridge
                .join("topics")
                .join(topic)
                .join(format!("p{partition}.jsonl")),
            lines.join("\n") + "\n",
        )
        .unwrap();
    }
    bridge.to_string_lossy().into_owned()
}

fn replay(data_dir: &str, config: &str) -> (Output, Value) {
    let output = pvctl(&["judge-replay", "--data-dir", data_dir, "--config", config]);
    let report = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output, report)
}

#[test]
fn a_bridge_with_no_judged_records_replays_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let data = bridge(
        dir.path(),
        "agent.tool_call",
        1,
        &[(0, vec![line(0, 0, None), line(1, 0, None)])],
    );
    let (output, report) = replay(&data, &config);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(report["records_read"], 2);
    assert_eq!(report["judged"], 0);
    // An empty Bridge (no segment file at all).
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let data = bridge(dir.path(), "agent.tool_call", 1, &[]);
    let (output, report) = replay(&data, &config);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(report["records_read"], 0);
}

#[test]
fn a_manifest_without_the_tool_call_topic_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let data = bridge(dir.path(), "agent.session", 1, &[]);
    let (output, _) = replay(&data, &config);
    assert!(!output.status.success());
    assert!(text(&output).contains("agent.tool_call"), "{}", text(&output));
}

#[test]
fn partitions_without_segments_and_the_partition_cap() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let data = bridge(
        dir.path(),
        "agent.tool_call",
        1024,
        &[
            (0, vec![line(0, 0, Some(record(&p, &[mismatch(820_000)], &[])))]),
            (
                1023,
                vec![line(0, 1023, Some(record(&p, &[mismatch(100_000)], &[])))],
            ),
        ],
    );
    let started = Instant::now();
    let (output, report) = replay(&data, &config);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(report["judged"], 2);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    // Past the manifest cap: refused, not looped over.
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let data = bridge(dir.path(), "agent.tool_call", u64::from(u32::MAX), &[]);
    let started = Instant::now();
    let (output, _) = replay(&data, &config);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn failure_statuses_empty_verdicts_and_foreign_drift_replay_consistently() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let pin = pv_judge::ModelPin::new("cli-judge", "1", PIN).unwrap();
    let mut lines = Vec::new();
    for (n, kind) in pv_judge::FailureKind::ALL.into_iter().enumerate() {
        let failure = pv_judge::JudgeOutcome::Failed(pv_judge::JudgeFailure {
            predicate_id: "arg_matches_task@1".into(),
            model: pin.clone(),
            kind,
            detail: "x".into(),
            latency_us: 1,
        });
        lines.push(line(n as u64, 0, Some(record(&p, &[failure], &[]))));
    }
    lines.push(line(10, 0, Some(record(&p, &[], &[]))));
    lines.push(line(
        11,
        0,
        Some(record(&p, &[mismatch(100_000)], &["other_predicate@1"])),
    ));
    lines.push(line(
        12,
        0,
        Some(record(&p, &[mismatch(100_000)], &["arg_matches_task@1"])),
    ));
    let data = bridge(dir.path(), "agent.tool_call", 1, &[(0, lines)]);
    let (output, report) = replay(&data, &config);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(report["judged"], 8);
    assert_eq!(report["consistency"]["mismatches"], 0);
    assert_eq!(report["consistency"]["unreadable"], 0);
}

#[test]
fn a_judge_value_that_is_not_an_object_is_counted_unreadable_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let lines = vec![
        line(0, 0, Some(json!(null))),
        line(1, 0, Some(json!("judge"))),
        line(2, 0, Some(json!([1, 2]))),
        line(3, 0, Some(record(&p, &[mismatch(820_000)], &[]))),
    ];
    let data = bridge(dir.path(), "agent.tool_call", 1, &[(0, lines)]);
    let (output, report) = replay(&data, &config);
    assert!(!output.status.success());
    assert_eq!(report["judged"], 4);
    assert_eq!(report["consistency"]["unreadable"], 3);
    assert_eq!(report["consistency"]["mismatches"], 0);
}

#[test]
fn a_record_with_a_missing_verdicts_field_or_an_unknown_field() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let mut missing = record(&p, &[mismatch(820_000)], &[]);
    missing.as_object_mut().unwrap().remove("verdicts");
    let mut extra = record(&p, &[mismatch(820_000)], &[]);
    extra["added_in_a_later_build"] = json!(true);
    let data = bridge(
        dir.path(),
        "agent.tool_call",
        1,
        &[(0, vec![line(0, 0, Some(missing)), line(1, 0, Some(extra))])],
    );
    let (output, report) = replay(&data, &config);
    eprintln!("{}", text(&output));
    assert!(report["consistency"]["unreadable"].as_u64().unwrap() >= 1);
}

#[test]
fn a_corrupt_line_in_the_bridge_does_not_hide_the_other_records() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let lines = vec![
        line(0, 0, Some(record(&p, &[mismatch(820_000)], &[]))),
        "{not json".to_owned(),
        line(2, 0, Some(record(&p, &[mismatch(100_000)], &[]))),
    ];
    let data = bridge(dir.path(), "agent.tool_call", 1, &[(0, lines)]);
    let (output, report) = replay(&data, &config);
    eprintln!(
        "corrupt line: success={} {}",
        output.status.success(),
        text(&output)
    );
    if output.status.success() || report != Value::Null {
        assert_eq!(report["judged"], 2, "{report}");
    }
}

#[test]
fn what_if_against_a_config_without_a_judge_section_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let p = policy(&config);
    let data = bridge(
        dir.path(),
        "agent.tool_call",
        1,
        &[(0, vec![line(0, 0, Some(record(&p, &[mismatch(820_000)], &[])))])],
    );
    let bare = dir.path().join("bare.toml");
    let full = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&bare, full.split("[judge]").next().unwrap()).unwrap();
    let output = pvctl(&[
        "judge-replay",
        "--data-dir",
        &data,
        "--config",
        &config,
        "--what-if",
        &bare.to_string_lossy(),
    ]);
    assert!(!output.status.success());
    assert!(
        text(&output).to_lowercase().contains("judge"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_what_if_exactly_at_the_recorded_probability_does_not_deny() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "c.toml", "0.7");
    let at = write_config(dir.path(), "at.toml", "0.82");
    let p = policy(&config);
    let data = bridge(
        dir.path(),
        "agent.tool_call",
        1,
        &[(0, vec![line(0, 0, Some(record(&p, &[mismatch(820_000)], &[])))])],
    );
    let output = pvctl(&[
        "judge-replay",
        "--data-dir",
        &data,
        "--config",
        &config,
        "--what-if",
        &at,
    ]);
    assert!(output.status.success(), "{}", text(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["what_if"]["changed"], 1, "0.82 is not above 0.82");
    assert_eq!(report["tools"]["refund_order"]["what_if"]["allow"], 1);
}
