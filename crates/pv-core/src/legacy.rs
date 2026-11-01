//! Compatibility with installations made before the ProofVisor rename.
//!
//! Releases before the rename read `AV_*` environment variables and looked
//! for `agentvisor.toml` and `~/.agentvisor/`. Existing deployments keep
//! those names in systemd units, compose files and Kubernetes manifests, so
//! an upgraded binary must still honour them. The new names always win when
//! both are present.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Prefix of the environment variables before the rename.
pub const LEGACY_ENV_PREFIX: &str = "AV_";
/// Prefix of the environment variables now.
pub const ENV_PREFIX: &str = "PV_";

/// The `PV_*` names to set from `AV_*` variables, as (new name, value)
/// pairs. A legacy variable is adopted only when its new name is unset or
/// empty, so an operator who already migrated is never overridden. Empty
/// counts as unset because compose files render `PV_X: ${PV_X:-}`, and the
/// daemon already reads an empty value as "not set".
pub fn legacy_env_adoptions<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let vars: Vec<(OsString, OsString)> = vars.into_iter().collect();
    let present = |name: &OsString| vars.iter().any(|(key, value)| key == name && !value.is_empty());
    let mut adopt = Vec::new();
    for (key, value) in &vars {
        let Some(name) = key.to_str() else { continue };
        let Some(rest) = name.strip_prefix(LEGACY_ENV_PREFIX) else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        let new_name = OsString::from(format!("{ENV_PREFIX}{rest}"));
        if !present(&new_name) && !adopt.iter().any(|(n, _): &(OsString, OsString)| *n == new_name) {
            adopt.push((new_name, value.clone()));
        }
    }
    adopt
}

/// Copy every `AV_*` variable to its `PV_*` name when that name is unset,
/// and say so on stderr (names only, never values).
///
/// Call this first thing in `main`, before any thread is started: changing
/// the environment while another thread reads it is not safe on every
/// platform.
pub fn adopt_legacy_env() {
    let adoptions = legacy_env_adoptions(std::env::vars_os());
    if adoptions.is_empty() {
        return;
    }
    let names: Vec<String> = adoptions
        .iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    for (name, value) in adoptions {
        std::env::set_var(name, value);
    }
    eprintln!(
        "warning: read {} from the pre-rename AV_* variables; rename them to PV_* (the AV_* names will be removed in a later release)",
        names.join(", ")
    );
}

/// `current` if it exists, else `legacy` if that exists, else `current`.
/// For default file locations that moved with the rename: an installation
/// that still has only the old file keeps working, and a fresh one gets
/// the new location.
pub fn existing_or_legacy(current: PathBuf, legacy: &Path) -> PathBuf {
    if !current.exists() && legacy.exists() {
        legacy.to_path_buf()
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        list.iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn adopts_only_unset_new_names() {
        let got = legacy_env_adoptions(pairs(&[
            ("AV_CONFIG", "/etc/old.toml"),
            ("AV_CONSOLE_TOKEN", "old-token"),
            ("PV_CONSOLE_TOKEN", "new-token"),
            ("AV_", "ignored"),
            ("AV_LISTEN", "0.0.0.0:8484"),
            ("PV_LISTEN", ""),
            ("HOME", "/root"),
        ]));
        assert_eq!(
            got,
            pairs(&[("PV_CONFIG", "/etc/old.toml"), ("PV_LISTEN", "0.0.0.0:8484")])
        );
    }

    #[test]
    fn falls_back_to_the_legacy_file_only_when_the_new_one_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("proofvisor.toml");
        let legacy = dir.path().join("agentvisor.toml");
        assert_eq!(existing_or_legacy(current.clone(), &legacy), current);
        std::fs::write(&legacy, "").unwrap();
        assert_eq!(existing_or_legacy(current.clone(), &legacy), legacy);
        std::fs::write(&current, "").unwrap();
        assert_eq!(existing_or_legacy(current.clone(), &legacy), current);
    }
}
