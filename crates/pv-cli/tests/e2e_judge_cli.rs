//! `pvctl` and the semantic judge, through the built binary:
//! `config-validate` accepts a sound `[judge]` section and names what is
//! wrong with an unsafe one, and `judge-calibrate` measures a configured
//! adapter against a live judge endpoint and enforces its floors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Output;

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

fn write_config(dir: &Path, judge_port: u16, tool_section: &str, adapter_kind: &str) -> String {
    let adapter = if adapter_kind == "local" {
        format!(
            r#"kind = "local"
model_path = "{dir}/judge.onnx"
tokenizer_path = "{dir}/tokenizer.json"
tokenizer_sha256 = "{PIN}"
output_labels = ["match", "mismatch"]"#,
            dir = dir.display()
        )
    } else {
        format!(
            r#"kind = "cloud"
endpoint = "http://127.0.0.1:{judge_port}/score""#
        )
    };
    let path = dir.join("proofvisor.toml");
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
{adapter}
deadline_ms = 2000
model_name = "cli-judge"
model_version = "1"
weights_sha256 = "{PIN}"

{tool_section}

[[judge.thresholds]]
predicate = "arg_matches_task@1"
label = "mismatch"
deny_above = 0.7
"#,
            dir = dir.display()
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

const TOOL_WITH_OPT_IN: &str = r#"[[judge.tools]]
tool = "refund_order"
allow_cloud = true
predicates = [{ id = "arg_matches_task@1", adapter = "vendor" }]"#;

const TOOL_WITHOUT_OPT_IN: &str = r#"[[judge.tools]]
tool = "refund_order"
predicates = [{ id = "arg_matches_task@1", adapter = "vendor" }]"#;

#[test]
fn config_validate_accepts_a_sound_judge_section_and_names_the_unsafe_ones() {
    let dir = tempfile::tempdir().unwrap();
    let sound = write_config(dir.path(), 9, TOOL_WITH_OPT_IN, "cloud");
    let output = pvctl(&["config-validate", &sound]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("valid config_version=1"));

    let no_opt_in = write_config(dir.path(), 9, TOOL_WITHOUT_OPT_IN, "cloud");
    let output = pvctl(&["config-validate", &no_opt_in]);
    assert!(!output.status.success());
    assert!(text(&output).contains("allow_cloud"), "{}", text(&output));

    // A local adapter needs the onnx feature; a build without it says so
    // unless only the structure is being checked.
    let local = write_config(dir.path(), 9, TOOL_WITH_OPT_IN, "local");
    let output = pvctl(&["config-validate", &local]);
    if cfg!(feature = "onnx") {
        assert!(output.status.success(), "{}", text(&output));
    } else {
        assert!(!output.status.success());
        assert!(text(&output).contains("onnx"), "{}", text(&output));
        let structural = pvctl(&["config-validate", &local, "--structural-only"]);
        assert!(structural.status.success(), "{}", text(&structural));
    }
}

/// A judge endpoint that answers `mismatch` 0.9 for arguments mentioning
/// "danger" and 0.1 otherwise.
async fn judge_endpoint() -> u16 {
    let router = Router::new().route(
        "/score",
        post(|Json(body): Json<Value>| async move {
            let p = if body["arguments"].to_string().contains("danger") {
                0.9
            } else {
                0.1
            };
            Json(json!({
                "model": {"name": "cli-judge", "version": "1", "weights_sha256": PIN},
                "probs": [{"label": "match", "p": 1.0 - p}, {"label": "mismatch", "p": p}]
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn judge_calibrate_measures_a_live_judge_and_enforces_floors() {
    let port = judge_endpoint().await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), port, TOOL_WITH_OPT_IN, "cloud");
    let mut set = String::new();
    for (note, label) in [
        ("refund order 1001", "match"),
        ("read the March invoice", "match"),
        ("danger: wipe the ledger", "mismatch"),
        ("danger: wire funds out", "mismatch"),
    ] {
        set.push_str(
            &json!({"predicate_id": "arg_matches_task@1", "tool": "refund_order",
                    "arguments": {"note": note}, "label": label})
            .to_string(),
        );
        set.push('\n');
    }
    let set_path = dir.path().join("labelled.jsonl");
    std::fs::write(&set_path, set).unwrap();
    let set_arg = set_path.to_string_lossy().into_owned();

    let run = |adapter: &'static str, extra: Vec<&'static str>| {
        let config = config.clone();
        let set_arg = set_arg.clone();
        tokio::task::spawn_blocking(move || {
            let mut args = vec![
                "judge-calibrate",
                "--config",
                config.as_str(),
                "--adapter",
                adapter,
                "--set",
                set_arg.as_str(),
            ];
            args.extend(extra);
            pvctl(&args)
        })
    };
    let passing = run(
        "vendor",
        vec![
            "--min-examples",
            "4",
            "--min-auroc",
            "0.9",
            "--min-separation",
            "0.5",
        ],
    )
    .await
    .unwrap();
    assert!(passing.status.success(), "{}", text(&passing));
    let report: Value = serde_json::from_slice(&passing.stdout).unwrap();
    let measured = &report["predicates"][0];
    assert_eq!(measured["examples"], 4);
    assert_eq!(measured["auroc_ppm"], 1_000_000);
    assert_eq!(measured["separation_ppm"], 800_000);
    assert_eq!(report["model"]["weights_sha256"], PIN);

    let failing = run("vendor", vec!["--min-examples", "100"]).await.unwrap();
    assert!(!failing.status.success());
    assert!(
        text(&failing).contains("calibration floor not met"),
        "{}",
        text(&failing)
    );

    std::fs::write(&set_path, "\n").unwrap();
    let empty = run("vendor", Vec::new()).await.unwrap();
    assert!(!empty.status.success(), "an empty labelled set must not pass");
    assert!(text(&empty).contains("no examples"), "{}", text(&empty));

    let unknown = run("nope", Vec::new()).await.unwrap();
    assert!(!unknown.status.success());
    assert!(
        text(&unknown).contains("no judge adapter named"),
        "{}",
        text(&unknown)
    );
}

/// A judged `agent.tool_call` record, as the harness writes it: the
/// verdict, and what `policy` decided over it.
fn judged_event(
    policy: &pv_judge::ThresholdPolicy,
    offset: u64,
    outcome: pv_judge::JudgeOutcome,
    edit: impl FnOnce(&mut pv_judge::JudgeRecord),
) -> String {
    let decision = policy.decide(std::slice::from_ref(&outcome), &|_| false);
    let mut record = pv_judge::JudgeRecord::new(
        pv_judge::JudgeMode::Shadow,
        10,
        vec![pv_judge::OutcomeRecord::from_outcome(
            &outcome,
            "vendor",
            pv_judge::AdapterKind::Cloud,
        )],
        &decision,
        false,
    );
    record.would_block = decision.action != pv_judge::JudgeAction::Allow;
    edit(&mut record);
    json!({
        "partition": 0, "offset": offset, "key": "agent", "stored_at": 1_767_225_600_000u64,
        "value": {
            "class_name": "agent.tool_call",
            "session_uid": format!("s-{offset}"),
            "metadata": {"uid": format!("evt-{offset}")},
            "payload": {"tool": "refund_order", "allowed": true, "judge": record}
        }
    })
    .to_string()
}

fn mismatch_verdict(p: u32) -> pv_judge::JudgeOutcome {
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

#[test]
fn judge_replay_checks_recorded_decisions_and_tries_other_thresholds() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), 9, TOOL_WITH_OPT_IN, "cloud");
    let policy = pv_harness::HarnessConfig::from_toml(&std::fs::read_to_string(&config).unwrap())
        .unwrap()
        .judge
        .unwrap()
        .threshold_policy()
        .unwrap();
    let bridge = dir.path().join("replay-bridge");
    std::fs::create_dir_all(bridge.join("topics/agent.tool_call")).unwrap();
    std::fs::write(
        bridge.join("manifest.yaml"),
        "manifest_version: 1\nname: replay\ntopics:\n  - name: agent.tool_call\n    partitions: 1\n    retention: {hot_hours: 24}\n",
    )
    .unwrap();
    let failure = pv_judge::JudgeOutcome::Failed(pv_judge::JudgeFailure {
        predicate_id: "arg_matches_task@1".into(),
        model: pv_judge::ModelPin::new("cli-judge", "1", PIN).unwrap(),
        kind: pv_judge::FailureKind::Unavailable,
        detail: "down".into(),
        latency_us: 10,
    });
    let mut lines = vec![
        judged_event(&policy, 0, mismatch_verdict(820_000), |_| {}),
        judged_event(&policy, 1, mismatch_verdict(500_000), |_| {}),
        judged_event(&policy, 2, mismatch_verdict(100_000), |_| {}),
        judged_event(&policy, 3, failure, |_| {}),
    ];
    let segment = bridge.join("topics/agent.tool_call/p0.jsonl");
    std::fs::write(&segment, lines.join("\n") + "\n").unwrap();
    let data_dir = bridge.to_string_lossy().into_owned();

    // Every recorded decision follows from its verdict.
    let output = pvctl(&["judge-replay", "--data-dir", &data_dir, "--config", &config]);
    assert!(output.status.success(), "{}", text(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["judged"], 4);
    assert_eq!(report["consistency"]["mismatches"], 0);
    let tool = &report["tools"]["refund_order"];
    assert_eq!(tool["recorded"]["deny"], 2, "0.82 mismatch and the outage");
    // 0.5 against 0.5 is below the default confidence floor (0.6): ask.
    assert_eq!(tool["recorded"]["ask"], 1);
    assert_eq!(tool["recorded"]["allow"], 1);
    assert_eq!(tool["would_block"], 3);

    // A stricter threshold (deny above 0.4) would also block the 0.5 call.
    let stricter = dir.path().join("stricter.toml");
    std::fs::write(
        &stricter,
        std::fs::read_to_string(&config)
            .unwrap()
            .replace("deny_above = 0.7", "deny_above = 0.4"),
    )
    .unwrap();
    let output = pvctl(&[
        "judge-replay",
        "--data-dir",
        &data_dir,
        "--config",
        &config,
        "--what-if",
        &stricter.to_string_lossy(),
    ]);
    assert!(output.status.success(), "{}", text(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["what_if"]["changed"], 1);
    assert_eq!(report["tools"]["refund_order"]["what_if"]["deny"], 3);

    // A record whose probability was edited after the decision fails.
    lines.push(judged_event(&policy, 4, mismatch_verdict(820_000), |record| {
        record.verdicts[0].probs[0].ppm = 990_000;
        record.verdicts[0].probs[1].ppm = 10_000;
    }));
    std::fs::write(&segment, lines.join("\n") + "\n").unwrap();
    let output = pvctl(&["judge-replay", "--data-dir", &data_dir, "--config", &config]);
    assert!(!output.status.success(), "an edited record must fail the replay");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["consistency"]["mismatches"], 1);
    assert_eq!(
        report["consistency"]["mismatch_examples"][0]["at"]["event_uid"],
        "evt-4"
    );
    assert!(text(&output).contains("do not follow"), "{}", text(&output));
}
