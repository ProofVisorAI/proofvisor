//! Edge cases of `content_text` and of the bounded tool-execution
//! folder scans.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;

fn text(content: &Value) -> Option<String> {
    content_text(content).map(std::borrow::Cow::into_owned)
}

#[test]
fn content_text_of_each_content_shape() {
    assert_eq!(text(&json!("plain")).as_deref(), Some("plain"));
    assert_eq!(text(&Value::Null), None);
    assert_eq!(text(&json!(42)), None);
    assert_eq!(text(&json!([])).as_deref(), Some(""));
    assert_eq!(
        text(
            &json!([{"type": "text", "text": "a"}, {"type": "image_url", "image_url": {}},
                     {"type": "text", "text": "b"}])
        )
        .as_deref(),
        Some("ab"),
        "text parts are joined; other parts are skipped"
    );
    // A text part whose text is missing or not a string is skipped
    // without dropping the others.
    assert_eq!(
        text(&json!([{"type": "text"}, {"type": "text", "text": 7}, {"type": "text", "text": "ok"}]))
            .as_deref(),
        Some("ok")
    );
}

/// Shapes whose text a client may show but that `content_text` drops.
/// Each is printed; the refusal part is part of the chat completions
/// format, so it is asserted.
#[test]
fn content_text_of_parts_that_carry_text_under_other_names() {
    for content in [
        json!([{"type": "output_text", "text": "x"}]),
        json!([{"text": "x"}]),
        json!(["x"]),
        json!([[{"type": "text", "text": "x"}]]),
        json!({"type": "text", "text": "x"}),
        json!([{"type": "text", "text": {"value": "x"}}]),
    ] {
        println!("{content} -> {:?}", text(&content));
    }
    assert_eq!(
        text(&json!([{"type": "refusal", "refusal": "I will not do that."}])).as_deref(),
        Some("I will not do that."),
        "an assistant refusal part (chat completions content part type \"refusal\") is dropped"
    );
}

#[test]
fn the_scan_limit_at_exactly_max_and_one_more() {
    let directory = tempfile::tempdir().unwrap();
    for n in 0..3 {
        std::fs::write(directory.path().join(format!("{n}.evidence")), b"x").unwrap();
    }
    assert!(
        ensure_tool_executions_resolved_with_limit(directory.path(), "s", &[7; 32], 3).is_ok(),
        "exactly the limit is accepted"
    );
    assert!(ensure_tool_executions_resolved_with_limit(directory.path(), "s", &[7; 32], 2).is_err());
    assert_eq!(
        crate::spool::list_tool_executions(directory.path(), 3)
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        crate::spool::list_tool_executions(directory.path(), 2)
            .unwrap()
            .len(),
        3,
        "max + 1 entries, so the caller can tell"
    );
    assert_eq!(
        crate::spool::list_tool_executions(directory.path(), 0)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::spool::list_tool_executions(directory.path(), usize::MAX)
            .unwrap()
            .len(),
        3,
        "max + 1 saturates"
    );
    // An empty folder at a limit of zero.
    let empty = tempfile::tempdir().unwrap();
    assert!(ensure_tool_executions_resolved_with_limit(empty.path(), "s", &[7; 32], 0).is_ok());
}

#[tokio::test]
async fn scans_of_a_folder_that_does_not_exist() {
    let spool = tempfile::tempdir().unwrap();
    let missing = spool.path().join(crate::spool::TOOL_EXECUTIONS);
    assert!(!missing.exists());
    assert_eq!(
        crate::spool::list_tool_executions(&missing, 10)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(ensure_tool_executions_resolved(spool.path(), "s", &[7; 32])
        .await
        .is_ok());
    assert!(unresolved_tool_sessions(spool.path(), &[7; 32])
        .await
        .unwrap()
        .is_empty());
    // A spool root that does not exist either.
    let gone = spool.path().join("no-such-spool");
    assert!(ensure_tool_executions_resolved(&gone, "s", &[7; 32])
        .await
        .is_ok());
    assert!(unresolved_tool_sessions(&gone, &[7; 32])
        .await
        .unwrap()
        .is_empty());
}

/// Listing and changing take turns: a listing that runs while another
/// thread removes other files sees every file nobody touched.
#[test]
fn listings_beside_removals_see_every_untouched_file() {
    let directory = tempfile::tempdir().unwrap();
    let keep: Vec<String> = (0..300).map(|n| format!("keep-{n}.intent.json")).collect();
    for name in &keep {
        std::fs::write(directory.path().join(name), b"k").unwrap();
    }
    let path = directory.path().to_owned();
    let remover = std::thread::spawn(move || {
        for round in 0..20 {
            let names: Vec<std::path::PathBuf> = (0..200)
                .map(|n| path.join(format!("churn-{round}-{n}.audited")))
                .collect();
            for name in &names {
                std::fs::write(name, b"c").unwrap();
            }
            for name in &names {
                crate::spool::change_tool_executions(|| std::fs::remove_file(name)).unwrap();
            }
        }
    });
    let mut short = 0;
    while !remover.is_finished() {
        let listed = crate::spool::list_tool_executions(directory.path(), usize::MAX).unwrap();
        let seen = listed
            .iter()
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("keep-"))
            .count();
        if seen != keep.len() {
            short += 1;
        }
    }
    remover.join().unwrap();
    assert_eq!(short, 0, "{short} listings missed untouched files");
}

/// The same, but the other thread writes files the way `persist` and
/// `mark_audited` do: a temporary file renamed into the folder by
/// `write_atomic`, which does not take a turn.
#[test]
fn listings_beside_atomic_writes_see_every_untouched_file() {
    let directory = tempfile::tempdir().unwrap();
    let keep: Vec<String> = (0..300).map(|n| format!("keep-{n}.intent.json")).collect();
    for name in &keep {
        std::fs::write(directory.path().join(name), b"k").unwrap();
    }
    let path = directory.path().to_owned();
    let writer = std::thread::spawn(move || {
        for n in 0..1_000 {
            pv_core::fsutil::write_atomic(&path.join(format!("w-{n}.outcome.json")), b"o").unwrap();
        }
    });
    let mut short = 0;
    let mut listings = 0;
    while !writer.is_finished() {
        let listed = crate::spool::list_tool_executions(directory.path(), usize::MAX).unwrap();
        listings += 1;
        let seen = listed
            .iter()
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("keep-"))
            .count();
        if seen != keep.len() {
            short += 1;
        }
    }
    writer.join().unwrap();
    println!("{listings} listings beside atomic writes, {short} missed untouched files");
    assert_eq!(
        short, 0,
        "{short} of {listings} listings missed files nobody touched while write_atomic renamed \
         temporary files into the folder outside change_tool_executions"
    );
}
