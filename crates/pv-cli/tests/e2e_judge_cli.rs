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

/// Recorded calls whose inputs were kept become a labelled set to fill
/// in: one example per predicate, label empty, the judge's answer as a
/// hint; calls recorded without inputs are counted and skipped.
#[test]
fn judge_export_turns_recorded_calls_into_a_labelled_set() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), 9, TOOL_WITH_OPT_IN, "cloud");
    let policy = pv_harness::HarnessConfig::from_toml(&std::fs::read_to_string(&config).unwrap())
        .unwrap()
        .judge
        .unwrap()
        .threshold_policy()
        .unwrap();
    let bridge = dir.path().join("export-bridge");
    std::fs::create_dir_all(bridge.join("topics/agent.tool_call")).unwrap();
    std::fs::write(
        bridge.join("manifest.yaml"),
        "manifest_version: 1\nname: export\ntopics:\n  - name: agent.tool_call\n    partitions: 1\n    retention: {hot_hours: 24}\n",
    )
    .unwrap();
    let with_inputs = |amount: f64| {
        move |record: &mut pv_judge::JudgeRecord| {
            record.inputs = Some(pv_judge::JudgeInputs {
                tool: "refund_order".into(),
                arguments_json: json!({"order": "1001", "amount": amount}).to_string(),
                context: pv_judge::SessionContext {
                    task: Some("Refund order 1001".into()),
                    charter: "billing-agent".into(),
                    ..pv_judge::SessionContext::default()
                },
            });
        }
    };
    let lines = [
        judged_event(&policy, 0, mismatch_verdict(820_000), with_inputs(9_000.5)),
        judged_event(&policy, 1, mismatch_verdict(100_000), with_inputs(12.0)),
        judged_event(&policy, 2, mismatch_verdict(900_000), |_| {}),
    ];
    std::fs::write(
        bridge.join("topics/agent.tool_call/p0.jsonl"),
        lines.join("\n") + "\n",
    )
    .unwrap();
    let data_dir = bridge.to_string_lossy().into_owned();
    let output = pvctl(&["judge-export", "--data-dir", &data_dir]);
    assert!(output.status.success(), "{}", text(&output));
    let examples: Vec<Value> = String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(examples.len(), 2, "{}", text(&output));
    assert_eq!(examples[0]["predicate_id"], "arg_matches_task@1");
    assert_eq!(examples[0]["tool"], "refund_order");
    assert_eq!(examples[0]["arguments"]["amount"], 9_000.5);
    assert_eq!(examples[0]["context"]["task"], "Refund order 1001");
    assert_eq!(examples[0]["label"], "");
    assert!(examples[0]["source"]
        .as_str()
        .unwrap()
        .contains("judge said mismatch at 0.82"));
    assert!(
        text(&output).contains("1 recorded without inputs"),
        "{}",
        text(&output)
    );
    // The file is the calibration format; it needs labels before use.
    let text_set = String::from_utf8(output.stdout).unwrap();
    assert_eq!(pv_judge::calibration::load_jsonl(&text_set).unwrap().len(), 2);
    // Only the calls the judge would have blocked.
    let blocked = pvctl(&["judge-export", "--data-dir", &data_dir, "--would-block-only"]);
    assert_eq!(String::from_utf8(blocked.stdout).unwrap().lines().count(), 1);
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

// ── judge-export edge cases ─────────────────────────────────────────

/// A Bridge directory with one `agent.tool_call` partition holding
/// `lines`, and the threshold policy of the standard test config.
fn export_bridge(dir: &Path, lines: &[String]) -> (String, pv_judge::ThresholdPolicy) {
    let config = write_config(dir, 9, TOOL_WITH_OPT_IN, "cloud");
    let policy = pv_harness::HarnessConfig::from_toml(&std::fs::read_to_string(&config).unwrap())
        .unwrap()
        .judge
        .unwrap()
        .threshold_policy()
        .unwrap();
    let bridge = dir.join("export-edges");
    std::fs::create_dir_all(bridge.join("topics/agent.tool_call")).unwrap();
    std::fs::write(
        bridge.join("manifest.yaml"),
        "manifest_version: 1\nname: export\ntopics:\n  - name: agent.tool_call\n    partitions: 1\n    retention: {hot_hours: 24}\n",
    )
    .unwrap();
    std::fs::write(
        bridge.join("topics/agent.tool_call/p0.jsonl"),
        lines.join("\n") + "\n",
    )
    .unwrap();
    (bridge.to_string_lossy().into_owned(), policy)
}

fn test_policy(dir: &Path) -> pv_judge::ThresholdPolicy {
    export_bridge(dir, &[]).1
}

fn inputs(arguments_json: String) -> impl FnOnce(&mut pv_judge::JudgeRecord) {
    move |record: &mut pv_judge::JudgeRecord| {
        record.inputs = Some(pv_judge::JudgeInputs {
            tool: "refund_order".into(),
            arguments_json,
            context: pv_judge::SessionContext {
                task: Some("Rembourser la commande 1001 — 返金".into()),
                charter: "billing-agent".into(),
                ..pv_judge::SessionContext::default()
            },
        });
    }
}

fn exported(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Expected to pass: floats, unicode and very large numbers in the
/// arguments survive the export; a record judged on two predicates gives
/// one example per predicate and `--predicate` keeps one; a failed
/// verdict is exported with its status as the hint; `--would-block-only`
/// keeps only the would-be blocks; and once labelled, the file loads with
/// `pv_judge::calibration::load_jsonl`.
#[test]
fn judge_export_keeps_odd_arguments_and_several_predicates() {
    let dir = tempfile::tempdir().unwrap();
    let policy = test_policy(dir.path());
    let arguments = json!({
        "amount": 0.1, "tiny": 5e-324, "huge": 1.7976931348623157e308, "neg_zero": -0.0,
        "big": u64::MAX, "small": i64::MIN,
        "note": "café 🚀 \u{202e}evil\u{202c} \u{2028} \"quoted\" \\ back",
        "нюанс": ["日本", {"deep": [[[1]]]}]
    });
    let failed: pv_judge::JudgeOutcome = serde_json::from_value(json!({
        "status": "failed", "predicate_id": "arg_matches_task@1", "kind": "timeout",
        "detail": "slow", "model": {"name": "cli-judge", "version": "1", "weights_sha256": PIN},
        "latency_us": 3
    }))
    .unwrap();
    let second = pv_judge::OutcomeRecord::from_outcome(
        &pv_judge::JudgeOutcome::Scored(pv_judge::Verdict {
            predicate_id: "memory_write_safe@1".into(),
            probs: vec![
                pv_judge::LabelProb {
                    label: "safe".into(),
                    ppm: 400_000,
                },
                pv_judge::LabelProb {
                    label: "unsafe".into(),
                    ppm: 600_000,
                },
            ],
            model: pv_judge::ModelPin::new("cli-judge", "1", PIN).unwrap(),
            latency_us: 10,
        }),
        "vendor",
        pv_judge::AdapterKind::Cloud,
    );
    let arguments_text = arguments.to_string();
    let lines = vec![
        judged_event(&policy, 0, mismatch_verdict(100_000), |record| {
            inputs(arguments_text.clone())(record);
            record.verdicts.push(second);
        }),
        judged_event(&policy, 1, failed, inputs("{}".into())),
        judged_event(&policy, 2, mismatch_verdict(900_000), inputs("{\"x\":1}".into())),
    ];
    let (data_dir, _) = export_bridge(dir.path(), &lines);

    let all = pvctl(&["judge-export", "--data-dir", &data_dir]);
    assert!(all.status.success(), "{}", text(&all));
    let examples = exported(&all);
    assert_eq!(examples.len(), 4, "{}", text(&all));
    assert_eq!(examples[0]["arguments"], arguments);
    assert_eq!(
        examples[0]["context"]["task"],
        "Rembourser la commande 1001 — 返金"
    );
    assert_eq!(examples[1]["predicate_id"], "memory_write_safe@1");
    assert!(examples[1]["source"]
        .as_str()
        .unwrap()
        .contains("judge said unsafe at 0.6"));
    assert!(
        examples[2]["source"].as_str().unwrap().contains("judge timeout"),
        "{}",
        examples[2]
    );

    let one = pvctl(&[
        "judge-export",
        "--data-dir",
        &data_dir,
        "--predicate",
        "memory_write_safe@1",
    ]);
    assert_eq!(exported(&one).len(), 1);
    let none = pvctl(&[
        "judge-export",
        "--data-dir",
        &data_dir,
        "--predicate",
        "no_such@1",
    ]);
    assert!(none.status.success());
    assert!(exported(&none).is_empty());

    let blocked = pvctl(&["judge-export", "--data-dir", &data_dir, "--would-block-only"]);
    let blocked = exported(&blocked);
    let sources: Vec<&str> = blocked.iter().map(|e| e["source"].as_str().unwrap()).collect();
    assert_eq!(blocked.len(), 2, "{sources:?}");
    assert!(sources.iter().any(|s| s.contains("evt-1")) && sources.iter().any(|s| s.contains("evt-2")));

    let labelled: String = examples
        .iter()
        .map(|example| {
            let mut example = example.clone();
            example["label"] = json!("match");
            format!("{example}\n")
        })
        .collect();
    let loaded = pv_judge::calibration::load_jsonl(&labelled).unwrap();
    assert_eq!(loaded.len(), 4);
    assert_eq!(loaded[0].arguments, arguments);
}

/// Recorded arguments that are no longer JSON (audit redaction replaced
/// a whole number inside the JSON text, leaving `{"card":[REDACTED]}`)
/// must not become an example whose arguments are silently `null`: the
/// example would ask a reviewer to label a call nobody can see, and
/// calibration would score the judge on empty arguments.
#[test]
fn judge_export_does_not_turn_unreadable_arguments_into_null() {
    let dir = tempfile::tempdir().unwrap();
    let policy = test_policy(dir.path());
    let lines = vec![judged_event(
        &policy,
        0,
        mismatch_verdict(900_000),
        inputs("{\"order\":\"1001\",\"card\":[REDACTED]}".into()),
    )];
    let (data_dir, _) = export_bridge(dir.path(), &lines);
    let output = pvctl(&["judge-export", "--data-dir", &data_dir]);
    assert!(output.status.success(), "{}", text(&output));
    let examples = exported(&output);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        examples.iter().all(|example| !example["arguments"].is_null()),
        "an example was exported with \"arguments\": null and the summary says only: {stderr}"
    );
}

/// A judged record the exporter cannot read (here, its `inputs.context`
/// was replaced by a string, as a `redaction_paths` entry would) is
/// skipped, and the summary accounts for it.
#[test]
fn judge_export_reports_records_it_could_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let policy = test_policy(dir.path());
    let mut event: Value = serde_json::from_str(&judged_event(
        &policy,
        0,
        mismatch_verdict(900_000),
        inputs("{}".into()),
    ))
    .unwrap();
    event["value"]["payload"]["judge"]["inputs"]["context"] = json!("[REDACTED]");
    let (data_dir, _) = export_bridge(dir.path(), &[event.to_string()]);
    let output = pvctl(&["judge-export", "--data-dir", &data_dir]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(exported(&output).is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        ["unreadable", "could not", "skipped", "malformed", "not read"]
            .iter()
            .any(|word| stderr.contains(word)),
        "the summary does not mention the record it skipped: {stderr}"
    );
}
