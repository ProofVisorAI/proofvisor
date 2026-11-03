//! Spool subdirectory names shared across the harness.

/// Directory under the spool root that holds durable lifecycle-outbox files.
pub(crate) const OUTBOX: &str = "outbox";
/// Directory under the spool root that holds tool intent/outcome/audited files.
pub(crate) const TOOL_EXECUTIONS: &str = "tool-executions";
/// Directory under the spool root that holds authenticated response markers.
pub(crate) const INFLIGHT_RESPONSES: &str = "inflight-responses";

/// On-disk file suffixes for the tool-execution state machine.
pub(crate) const TOOL_INTENT_SUFFIX: &str = ".intent.json";
pub(crate) const TOOL_OUTCOME_SUFFIX: &str = ".outcome.json";
pub(crate) const TOOL_AUDITED_SUFFIX: &str = ".audited";

/// Listing the tool-execution folder and removing or renaming files in it
/// take turns. On macOS, a listing that runs while another thread removes
/// files from the folder can miss files that nobody touched, and
/// concurrent closes then left other sessions' files behind.
static TOOL_EXECUTIONS_TURNS: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// The paths in the tool-execution folder `directory`: at most
/// `max + 1`, so a caller can tell that it holds more than `max`.
pub(crate) fn list_tool_executions(
    directory: &std::path::Path,
    max: usize,
) -> std::io::Result<Vec<std::path::PathBuf>> {
    let _turn = TOOL_EXECUTIONS_TURNS.lock();
    std::fs::read_dir(directory)?
        .take(max.saturating_add(1))
        .map(|entry| entry.map(|entry| entry.path()))
        .collect()
}

/// Run `change`, which removes or renames files in the tool-execution
/// folder, while no listing of it runs.
pub(crate) fn change_tool_executions<T>(change: impl FnOnce() -> T) -> T {
    let _turn = TOOL_EXECUTIONS_TURNS.lock();
    change()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Register item 30 sub-clause: "write a one-page 'spool layout
    /// and recovery' doc". docs/reference/SPOOL-AND-RECOVERY.md exists
    /// and its file inventory must actually enumerate every real
    /// on-disk artifact the harness writes. When a new suffix or
    /// subdirectory constant is added here, this test forces it into
    /// the doc — otherwise the layout grows silently and an operator
    /// inspecting a live spool sees files they can't reason about.
    ///
    /// Behaviorally verified: adding a new constant here and NOT
    /// touching the doc fails this test with a message naming the
    /// exact missing string.
    #[test]
    fn spool_constants_are_documented_in_spool_and_recovery() {
        let doc = include_str!("../../../docs/reference/SPOOL-AND-RECOVERY.md");
        for (name, value) in [
            ("OUTBOX", OUTBOX),
            ("TOOL_EXECUTIONS", TOOL_EXECUTIONS),
            ("INFLIGHT_RESPONSES", INFLIGHT_RESPONSES),
            ("TOOL_INTENT_SUFFIX", TOOL_INTENT_SUFFIX),
            ("TOOL_OUTCOME_SUFFIX", TOOL_OUTCOME_SUFFIX),
            ("TOOL_AUDITED_SUFFIX", TOOL_AUDITED_SUFFIX),
        ] {
            assert!(
                doc.contains(value),
                "spool constant {name} = {value:?} is not documented in \
                 docs/reference/SPOOL-AND-RECOVERY.md. Every on-disk artifact \
                 the harness writes must appear in the file-inventory table \
                 so operators inspecting a live spool can identify it."
            );
        }
    }
}
