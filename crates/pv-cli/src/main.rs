//! `pvctl` operations for keys, receipts, ATIF, Bridge, sessions, and load.

mod console_sync;
mod operator_revocation;
mod setup;
mod sidecar;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::{stream, StreamExt};
use pv_bridge::{BridgeManifest, EmbeddedBroker};
use pv_receipts::{Ed25519Signer, Keyring, Receipt, Signer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(
    name = "pvctl",
    version,
    about = "ProofVisor operations CLI. Run with no arguments for guided setup."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Guided setup: a few quick prompts, then a working proxy (default).
    Setup,
    /// Start ProofVisor and print where to point your AI app.
    Start,
    /// Create a provider-specific proofvisor.toml (start here).
    Init {
        /// Provider preset.
        #[arg(long, value_enum, default_value_t = setup::Preset::Openai)]
        preset: setup::Preset,
        /// Destination file (the harness finds proofvisor.toml automatically).
        #[arg(long, default_value = "proofvisor.toml")]
        output: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Override the preset's upstream base URL (required for --preset custom).
        #[arg(long)]
        upstream_url: Option<String>,
        /// Override the environment variable the API key is read from.
        #[arg(long)]
        key_env: Option<String>,
    },
    /// Diagnose the environment: config, keys, upstream, backends.
    Doctor {
        /// Skip network reachability probes.
        #[arg(long)]
        offline: bool,
    },
    /// Probe a running harness /health endpoint (for container healthchecks).
    Health {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
    },
    /// Run the loopback identity sidecar beside an application: it attaches
    /// an ProofVisor identity token to every request and forwards it to the
    /// gateway, so the application's SDKs need no code change.
    Sidecar {
        /// Settings file written by the buildpack (gateway, audience, listen,
        /// credential). Flags given explicitly override its values.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Gateway base URL [default: $PV_GATEWAY_URL].
        #[arg(long)]
        gateway: Option<String>,
        /// Gateway audience [default: $PV_AUDIENCE, then proofvisor].
        #[arg(long)]
        audience: Option<String>,
        /// Loopback address to listen on [default: 127.0.0.1:8485].
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
        /// Identity source: `cf-instance` or `token-file:<path>`
        /// [default: cf-instance].
        #[arg(long)]
        credential: Option<String>,
    },
    /// Generate and persist an Ed25519 signing seed.
    Keygen {
        /// Destination seed file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the public key (hex + key_id) derived from an Ed25519 seed
    /// file. Use this to pin a trusted public key for
    /// `pvctl receipt-verify` without ever exposing the seed.
    Pubkey {
        /// Seed file (64 hexadecimal characters of raw 32-byte seed,
        /// as produced by `pvctl keygen`).
        #[arg(long)]
        seed: PathBuf,
    },
    /// Locate the on-disk audit artifacts for a session id. Spool
    /// filenames are `sha256(session_id)[..32]` — this computes the
    /// stem and reports which artifacts (receipt, ATIF trajectory,
    /// provenance sidecar, journals, archived prior incarnations)
    /// exist for it.
    ReceiptLocate {
        /// The session id exactly as the client sent it.
        session_id: String,
        /// ATIF spool directory (`atif_spool_dir` in the harness config).
        #[arg(long, default_value = "spool/atif")]
        spool: PathBuf,
    },
    /// Remove sealed ATIF evidence pairs (`.json` + `.atif-auth`, plus
    /// their digest-bound `.close-complete` markers) older than the
    /// retention window. Same sweep the harness runs hourly when
    /// `atif_retention_days` is set; run this for one-off reclaims or
    /// from external cron when no retention is configured. Unpaired
    /// remnants, archived collision evidence, and signed receipts
    /// under `receipts/` are never touched.
    SpoolPrune {
        /// ATIF spool directory (`atif_spool_dir` in the harness config).
        #[arg(long, default_value = "spool/atif")]
        spool: PathBuf,
        /// Retention window in days; sealed pairs whose mtime is older
        /// are removed. `0` prunes every sealed pair immediately.
        #[arg(long)]
        retention_days: u32,
    },
    /// Verify a receipt offline using an independently trusted public key.
    ReceiptVerify {
        /// Receipt JSON file.
        path: PathBuf,
        /// Trusted Ed25519 public key as 64 hexadecimal characters
        /// or standard-alphabet base64 (32 bytes decoded).
        /// Repeatable: pass once per key you trust (rotation windows
        /// need both the retiring and the incoming key pinned; the
        /// receipt's `key_id` selects which one verifies it).
        #[arg(long, required = true, num_args = 1, action = clap::ArgAction::Append)]
        public_key_hex: Vec<String>,
    },
    /// Validate an ATIF trajectory.
    AtifValidate {
        /// ATIF JSON file.
        path: PathBuf,
        /// Validation mode.
        #[arg(long, value_enum, default_value_t = ValidationMode::Strict)]
        mode: ValidationMode,
    },
    /// Validate a Bridge manifest.
    ManifestValidate {
        /// Manifest YAML file.
        path: PathBuf,
    },
    /// Provision an embedded Bridge from a manifest alone.
    BridgeProvision {
        /// Manifest YAML file.
        #[arg(long)]
        manifest: PathBuf,
        /// Fresh Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Tail ordered events from an embedded Bridge partition.
    EventTail {
        /// Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Topic name.
        #[arg(long)]
        topic: String,
        /// Partition index.
        #[arg(long, default_value_t = 0)]
        partition: u32,
        /// Starting offset.
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Maximum events to print.
        #[arg(long, default_value_t = 100)]
        max: usize,
    },
    /// Promote an unsigned session through the Harness API.
    SessionPromote {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
        /// Session id.
        id: String,
        /// File containing the NHI bearer token (or PV_BEARER_TOKEN_FILE).
        #[arg(long)]
        bearer_token_file: Option<PathBuf>,
    },
    /// Revoke one token using a separate operator credential.
    TokenRevoke {
        /// Identifier from the token's jti claim.
        #[arg(long)]
        jti: String,
        /// Token namespace: upstream NHI or harness-issued exchange.
        #[arg(long, value_enum, default_value_t = operator_revocation::TokenKind::Nhi)]
        token_kind: operator_revocation::TokenKind,
        #[command(flatten)]
        options: operator_revocation::Options,
    },
    /// Revoke all currently issued tokens for an agent instance.
    InstanceRevoke {
        /// Identifier from the agent's instance_uid claim.
        #[arg(long)]
        instance_uid: String,
        #[command(flatten)]
        options: operator_revocation::Options,
    },
    /// Validate a harness TOML configuration.
    ConfigValidate {
        /// Configuration file.
        path: PathBuf,
        /// Skip the feature-capability pre-flight and check structure
        /// only. For validating a config meant for a DIFFERENT build
        /// than this pvctl (e.g. the full-feature container image)
        /// where the backend features are compiled in.
        #[arg(long)]
        structural_only: bool,
    },
    /// Replay the semantic judge's recorded decisions from an embedded
    /// Bridge: check that each follows from its verdicts under the
    /// configured thresholds, and optionally try other thresholds.
    /// Replays thresholds only (not WASM policies that read verdicts) and
    /// does not detect tampering: verify the receipts first.
    JudgeReplay {
        /// Embedded Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Harness configuration whose `[judge]` thresholds were in force
        /// when the records were written.
        #[arg(long)]
        config: PathBuf,
        /// Another configuration whose `[judge]` thresholds to try on the
        /// same records.
        #[arg(long)]
        what_if: Option<PathBuf>,
    },
    /// Export the judged calls an embedded Bridge recorded with
    /// `[judge] record_inputs = true` as a labelled set to fill in: one
    /// JSON Lines example per predicate, in the format `judge-calibrate`
    /// reads, with an empty `label` for a reviewer to set and the judge's
    /// own answer in `source` as a hint. Writes to standard output.
    JudgeExport {
        /// Embedded Bridge data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Only this predicate.
        #[arg(long)]
        predicate: Option<String>,
        /// Only calls the judge would have blocked (shadow mode) or did.
        #[arg(long)]
        would_block_only: bool,
    },
    /// Measure a configured semantic-judge adapter against a labelled set
    /// (JSON Lines) and fail when it falls below the given floors.
    JudgeCalibrate {
        /// Harness configuration holding the `[judge]` section.
        #[arg(long)]
        config: PathBuf,
        /// Name of the `[[judge.adapters]]` entry to measure.
        #[arg(long)]
        adapter: String,
        /// Labelled set, one JSON example per line.
        #[arg(long)]
        set: PathBuf,
        /// Fewest examples per predicate.
        #[arg(long, default_value_t = 1)]
        min_examples: u64,
        /// Lowest acceptable AUROC, as a probability (0.5 is chance).
        #[arg(long, default_value_t = 0.0)]
        min_auroc: f64,
        /// Lowest acceptable separation of mean positive-label
        /// probability between positive and negative examples.
        #[arg(long, default_value_t = -1.0)]
        min_separation: f64,
        /// Largest tolerated share of examples the judge failed to score.
        #[arg(long, default_value_t = 0.0)]
        max_failure_rate: f64,
        /// Require accuracy to rise with confidence.
        #[arg(long)]
        require_monotone: bool,
        /// Examples a confidence band needs to count in that check.
        #[arg(long, default_value_t = 30)]
        min_per_band: u64,
        /// Allowed accuracy drop between bands, as a probability.
        #[arg(long, default_value_t = 0.02)]
        tolerance: f64,
    },
    /// Upload locally-spooled ProofVisor session evidence to the hosted console.
    ConsoleSync {
        /// ATIF spool directory (`atif_spool_dir` in the harness config).
        #[arg(long, default_value = "spool/atif")]
        spool_dir: PathBuf,
        /// Hosted console base URL. Overrides PV_CONSOLE_URL and `[console].url`.
        #[arg(long)]
        console_url: Option<String>,
        /// Console deployment id. Overrides PV_CONSOLE_DEPLOYMENT and `[console].deployment`.
        #[arg(long)]
        deployment: Option<String>,
        /// File containing the console ingest token. Overrides PV_CONSOLE_TOKEN and `[console].token_file`.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Embedded Bridge data directory. Overrides PV_CONSOLE_BRIDGE_DIR and `[console].bridge_dir`.
        #[arg(long)]
        bridge_dir: Option<PathBuf>,
        /// Keep scanning until Ctrl-C.
        #[arg(long)]
        watch: bool,
        /// Watch polling interval in seconds.
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// JSON state file recording synced event sequences and receipts.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Print what would be uploaded without contacting the console or updating state.
        #[arg(long)]
        dry_run: bool,
        /// Also pull the console's policy bundle into the daemon's
        /// `policy_bundle_file` and report what the daemon applied.
        #[arg(long)]
        pull_policies: bool,
        /// The daemon's `policy_bundle_file`. Overrides PV_POLICY_BUNDLE_FILE.
        #[arg(long)]
        policy_bundle_file: Option<PathBuf>,
    },
    /// Generate concurrent OpenAI-compatible chat traffic and report latency.
    Loadgen {
        /// Harness base URL.
        #[arg(long, default_value = "http://127.0.0.1:8484")]
        url: String,
        /// Simultaneous requests. Use 10000 for the deployment SLA.
        ///
        /// The 10k figure assumes a Linux host with the listen backlog
        /// raised (`sysctl net.core.somaxconn=16384` and
        /// `net.ipv4.tcp_max_syn_backlog=16384`). macOS caps the
        /// backlog at `kern.ipc.somaxconn` (default 128), so a 10k
        /// simultaneous SYN burst is dropped by the KERNEL before the
        /// daemon sees it — the run reports thousands of client-side
        /// send errors while the daemon logs nothing. That is the
        /// bench box failing, not the daemon: on a stock Mac the same
        /// daemon absorbs 4k simultaneous connections with zero drops.
        #[arg(long, default_value_t = 500)]
        connections: usize,
        /// Signed or unsigned workflow header.
        #[arg(long, default_value = "signed")]
        workflow: String,
        /// File containing the NHI bearer token (or PV_BEARER_TOKEN_FILE).
        #[arg(long)]
        bearer_token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationMode {
    Strict,
    Compat,
}

/// Resolve sidecar settings (flags, then the settings file, then the
/// environment, then defaults) and run it.
async fn run_sidecar(
    config: Option<PathBuf>,
    gateway: Option<String>,
    audience: Option<String>,
    listen: Option<std::net::SocketAddr>,
    credential: Option<String>,
) -> Result<()> {
    let file = config.as_deref().map(sidecar::SidecarFile::load).transpose()?;
    let env = |name: &str| std::env::var(name).ok().filter(|value| !value.trim().is_empty());
    let gateway = gateway
        .or_else(|| file.as_ref().map(|file| file.gateway.clone()))
        .or_else(|| env("PV_GATEWAY_URL"))
        .context("the gateway URL is required (--gateway, --config, or PV_GATEWAY_URL)")?;
    let audience = audience
        .or_else(|| file.as_ref().map(|file| file.audience.clone()))
        .or_else(|| env("PV_AUDIENCE"))
        // Same pre-rename default as proofvisord's `audience`.
        .unwrap_or_else(|| "agentvisor-ai".to_owned());
    let listen = match (listen, file.as_ref()) {
        (Some(listen), _) => listen,
        (None, Some(file)) => file
            .listen
            .parse()
            .with_context(|| format!("invalid listen address {:?}", file.listen))?,
        (None, None) => std::net::SocketAddr::from(([127, 0, 0, 1], 8485)),
    };
    let credential = credential
        .or_else(|| file.as_ref().map(|file| file.credential.clone()))
        .unwrap_or_else(|| "cf-instance".to_owned());
    let options = sidecar::SidecarOptions {
        gateway,
        audience,
        credential: sidecar::Credential::parse(&credential)?,
    };
    sidecar::run(listen, options).await
}

fn main() -> std::process::ExitCode {
    // Before any thread exists, and before clap reads `env = "PV_…"`
    // fallbacks: adopt pre-rename AV_* variables (see pv_core::legacy).
    pv_core::legacy::adopt_legacy_env();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Error: could not start the async runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(async_main())
}

async fn async_main() -> std::process::ExitCode {
    // Returning `Result<()>` relied on the default
    // Termination impl printing anyhow's DEBUG format — which appends
    // a full captured backtrace whenever RUST_BACKTRACE is exported,
    // leaking 12 lines of internal frames on every well-formed user
    // error (bad TOML, missing file). Print the Display chain only.
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let Some(command) = cli.command else {
        return wizard_then_maybe_start().await;
    };
    match command {
        Command::Setup => wizard_then_maybe_start().await,
        Command::Start => setup::start().await,
        Command::Init {
            preset,
            output,
            force,
            upstream_url,
            key_env,
        } => setup::init(
            preset,
            &output,
            force,
            upstream_url.as_deref(),
            key_env.as_deref(),
        ),
        Command::Doctor { offline } => setup::doctor(offline).await,
        Command::Health { url } => setup::health(&url).await,
        Command::Sidecar {
            config,
            gateway,
            audience,
            listen,
            credential,
        } => run_sidecar(config, gateway, audience, listen, credential).await,
        Command::Keygen { output } => keygen(&output),
        Command::Pubkey { seed } => pubkey(&seed),
        Command::ReceiptLocate { session_id, spool } => receipt_locate(&session_id, &spool),
        Command::SpoolPrune {
            spool,
            retention_days,
        } => spool_prune(&spool, retention_days),
        Command::ReceiptVerify { path, public_key_hex } => receipt_verify(&path, &public_key_hex),
        Command::AtifValidate { path, mode } => atif_validate(&path, mode),
        Command::ManifestValidate { path } => manifest_validate(&path),
        Command::BridgeProvision { manifest, data_dir } => bridge_provision(&manifest, &data_dir),
        Command::EventTail {
            data_dir,
            topic,
            partition,
            offset,
            max,
        } => event_tail(&data_dir, &topic, partition, offset, max),
        Command::SessionPromote {
            url,
            id,
            bearer_token_file,
        } => session_promote(&url, &id, bearer_token_file.as_deref()).await,
        Command::TokenRevoke {
            jti,
            token_kind,
            options,
        } => {
            operator_revocation::run(
                &options,
                operator_revocation::Target::Token {
                    jti: &jti,
                    kind: token_kind,
                },
            )
            .await
        }
        Command::InstanceRevoke {
            instance_uid,
            options,
        } => operator_revocation::run(&options, operator_revocation::Target::Instance(&instance_uid)).await,
        Command::ConfigValidate {
            path,
            structural_only,
        } => config_validate(&path, structural_only),
        Command::JudgeReplay {
            data_dir,
            config,
            what_if,
        } => judge_replay(&data_dir, &config, what_if.as_deref()),
        Command::JudgeExport {
            data_dir,
            predicate,
            would_block_only,
        } => judge_export(&data_dir, predicate.as_deref(), would_block_only),
        Command::JudgeCalibrate {
            config,
            adapter,
            set,
            min_examples,
            min_auroc,
            min_separation,
            max_failure_rate,
            require_monotone,
            min_per_band,
            tolerance,
        } => {
            let floor = pv_judge::calibration::CalibrationFloor {
                min_examples,
                min_auroc_ppm: pv_judge::threshold_to_ppm(min_auroc).map_err(anyhow::Error::msg)?,
                min_separation_ppm: separation_floor_ppm(min_separation)?,
                max_failure_ppm: pv_judge::threshold_to_ppm(max_failure_rate).map_err(anyhow::Error::msg)?,
                require_monotone,
                min_per_band,
                tolerance_ppm: pv_judge::threshold_to_ppm(tolerance).map_err(anyhow::Error::msg)?,
            };
            judge_calibrate(&config, &adapter, &set, &floor).await
        }
        Command::ConsoleSync {
            spool_dir,
            console_url,
            deployment,
            token_file,
            bridge_dir,
            watch,
            interval,
            state_file,
            dry_run,
            pull_policies,
            policy_bundle_file,
        } => {
            console_sync::run(console_sync::ConsoleSyncArgs {
                spool_dir,
                console_url,
                deployment,
                token_file,
                bridge_dir,
                watch,
                interval,
                state_file,
                dry_run,
                pull_policies,
                policy_bundle_file,
            })
            .await
        }
        Command::Loadgen {
            url,
            connections,
            workflow,
            bearer_token_file,
        } => loadgen(&url, connections, &workflow, bearer_token_file.as_deref()).await,
    }
}

/// The wizard reads answers from stdin; secrets come from the terminal
/// with echo off when interactive, or from the same stream when piped
/// (scripts and tests).
async fn wizard_then_maybe_start() -> Result<()> {
    let outcome = {
        use std::io::IsTerminal as _;
        let home = std::env::home_dir().context("could not find your home folder")?;
        let stdin = std::io::stdin();
        let secrets = if stdin.is_terminal() {
            setup::SecretInput::Hidden
        } else {
            setup::SecretInput::Plain
        };
        let mut input = stdin.lock();
        setup::wizard(&home, &mut input, &secrets)?
    };
    if outcome.start_now {
        setup::start().await
    } else {
        println!("\nYour settings are saved at {}.", outcome.config_path.display());
        println!("When you're ready: pvctl start");
        Ok(())
    }
}

fn keygen(path: &Path) -> Result<()> {
    // `signer.seed()` returns `Zeroizing<[u8; 32]>`
    // directly, and the hex encoding is separately wrapped so both
    // stack and heap copies zero on drop rather than lingering in
    // freed memory recoverable from a core dump.
    use zeroize::Zeroizing;
    let signer = Ed25519Signer::generate();
    let seed = signer.seed();
    // `&*seed` avoids clippy's needless_borrows lint
    // suggestion (`*seed`) which would move 32 bytes out of the
    // Zeroizing wrapper into a fresh un-zeroized temp slot.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let encoded = Zeroizing::new(hex::encode(&*seed));
    if !install_seed_exclusive(path, &encoded)? {
        anyhow::bail!("refusing to overwrite existing key {}", path.display());
    }
    println!(
        "{}",
        serde_json::json!({
            "key_id": signer.key_id(),
            "public_key_hex": hex::encode(signer.public_key_bytes()),
            "seed_file": path,
        })
    );
    Ok(())
}

/// Load an Ed25519 seed file and print the derived public key + key_id.
/// This exists so operators can pin a trusted public key for
/// `pvctl receipt-verify` without ever exposing seed material — the
/// only bytes read from disk are the hex-encoded seed, and only the
/// derived public key is printed.
fn pubkey(path: &Path) -> Result<()> {
    use zeroize::Zeroizing;
    let encoded = Zeroizing::new(
        pv_core::fsutil::read_capped_string(path, pv_core::fsutil::MAX_CONTROL_BYTES)
            .with_context(|| format!("read signing seed {}", path.display()))?,
    );
    let bytes = Zeroizing::new(hex::decode(encoded.trim()).context("decode signing seed as hex")?);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("signing seed must contain exactly 32 bytes"))?,
    );
    // Mirror the startup-guard refusal — printing the public key of a
    // known-weak seed would give an operator false confidence that
    // their pinned key is unique to this deployment.
    if *seed == [0u8; 32] || *seed == [0xFFu8; 32] {
        anyhow::bail!(
            "signing seed at {} is a known-weak seed with a globally predictable public key; refusing to print",
            path.display()
        );
    }
    let signer = Ed25519Signer::from_seed(&seed);
    println!(
        "{}",
        serde_json::json!({
            "key_id": signer.key_id(),
            "public_key_hex": hex::encode(signer.public_key_bytes()),
            "seed_file": path,
        })
    );
    Ok(())
}

fn install_seed_exclusive(path: &Path, encoded: &str) -> Result<bool> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Same rationale as harness main.rs `install_seed_exclusive`:
    // route through `create_dir_all_synced` so newly-created ancestor
    // dirents are fsynced (a bare `create_dir_all` leaves them
    // volatile — power loss after install can drop the whole `keys/`
    // directory even though the seed itself was fsynced) and so the
    // leaf dir mode is 0o700 atomically at mkdir on Unix.
    pv_core::fsutil::create_dir_all_synced(parent)
        .with_context(|| format!("create key directory {}", parent.display()))?;
    let temporary = parent.join(format!(".pvctl-key-{}.tmp", pv_core::new_event_uid()));
    // Parity with setup.rs, harness main.rs, and
    // cold_store.rs — arm an RAII guard so a transient IO failure
    // (ENOSPC on write, EIO on sync, EROFS after hard_link, etc.)
    // cannot leave a `.pvctl-key-<uuidv7>.tmp` containing live
    // Ed25519 seed material on disk. Mode 0600 limits exposure to
    // the running user, but the tmp survives reboots, gets picked
    // up by backups, and appears in coredumps that snapshot the
    // filesystem — none of which the operator will know to purge.
    let mut guard = pv_core::fsutil::TempPathGuard::new(temporary.clone());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create key temporary file {}", temporary.display()))?;
    file.write_all(encoded.as_bytes())
        .with_context(|| format!("write key temporary file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync key temporary file {}", temporary.display()))?;
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            std::fs::remove_file(&temporary)
                .with_context(|| format!("remove key temporary file {}", temporary.display()))?;
            // The tmp is gone; disarm the guard so its Drop is a
            // no-op (unlinking a non-existent path would race with a
            // fresh keygen that happened to reuse the UUIDv7 tail).
            guard.disarm();
            // Durability is part of installation: without the parent
            // fsync, a power loss can drop the dirent and the next
            // keygen mints a DIFFERENT trust anchor. Fail with
            // explicit operator guidance — the seed FILE at `path` is
            // intact and must not be deleted; a re-run retries only
            // the durability sync.
            pv_core::fsutil::sync_directory(parent).with_context(|| {
                format!(
                    "signing seed installed at {} but the parent directory fsync failed; \
                     the seed file is intact — do NOT delete it; re-run to retry the \
                     durability sync",
                    path.display()
                )
            })?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Guard's Drop unlinks the tmp; no manual removal needed.
            // Re-establish dirent durability on every run that finds
            // the seed already installed — this is where the hard-fail
            // arm's "re-run to retry the durability sync" actually
            // happens (and it heals installs from builds that only
            // warned).
            pv_core::fsutil::sync_directory(parent).with_context(|| {
                format!(
                    "signing seed exists at {} but its parent directory fsync failed; \
                     the seed file is intact — do NOT delete it; re-run to retry",
                    path.display()
                )
            })?;
            Ok(false)
        }
        Err(error) => Err(error).with_context(|| format!("install key {}", path.display())),
    }
}

/// Read caps live in `pv_core::fsutil`
/// so both the CLI and the harness reconciler enforce identical
/// bounds. Kept as thin wrappers here for clearer local error text.
fn read_capped(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    pv_core::fsutil::read_capped(path, max_bytes).with_context(|| format!("{label} at {}", path.display()))
}

fn read_capped_str(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    pv_core::fsutil::read_capped_string(path, max_bytes)
        .with_context(|| format!("{label} at {}", path.display()))
}

/// Neutralise terminal-escape injection when printing
/// attacker-influenced strings.
///
/// Anything reachable through a trusted third party — a signed receipt
/// whose `receipt_id` was minted by a rotated/compromised signer, an
/// ATIF file that a peer produced, an HTTP body from an upstream —
/// can carry ESC / CSI / DEL / C1 bytes that reprogram the operator's
/// terminal (clear screen, spoof a green "OK" line, rewrite the
/// window title, or poison paste buffers on vulnerable emulators —
/// CVE-2003-0063 class). Replace every control byte (C0 except TAB,
/// DEL, and every C1) with U+FFFD before it flows into
/// println!/eprintln!. Also replace the Trojan-Source family
/// (CVE-2021-42574: bidi overrides/isolates, zero-width glyphs, and
/// the U+2028/U+2029 line separators — pv-core's shared dangerous
/// set): a receipt id like "safe\u{202E}suoicilam" would otherwise
/// render reversed, letting two visually identical ids differ on
/// the wire.
fn sanitize_for_terminal(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            let cp = c as u32;
            // Preserve TAB (0x09) as the one C0 whitespace we allow;
            // callers that need line-based output use format! + '\n'
            // themselves before this function sees the string.
            if cp == 0x09 {
                c
            } else if cp < 0x20
                || cp == 0x7f
                || (0x80..=0x9f).contains(&cp)
                || pv_core::text::is_bidi_or_zero_width(c)
            {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Receipts JCS-canonicalize to a few hundred bytes; even a huge
/// tool-call summary stays well under 16 MiB.
const MAX_RECEIPT_BYTES: u64 = pv_core::fsutil::MAX_RECEIPT_BYTES;

/// ATIF trajectories can carry long transcripts; 64 MiB is generous
/// (a 200k-token GPT-4 context in ASCII fits in ~800 KiB).
const MAX_ATIF_BYTES: u64 = pv_core::fsutil::MAX_ATIF_BYTES;

/// Small-file cap for operator-supplied config / manifest / bearer
/// token files.
const MAX_CONFIG_BYTES: u64 = pv_core::fsutil::MAX_CONTROL_BYTES;

/// "the filename is `sha256(session_id)[..32]` with no
/// lookup command" — the offline-verification workflow had no way to
/// go from a session id to its receipt. Compute the stem and report
/// every artifact class for it, including `archived-*` prior
/// incarnations (a recycled session id archives the previous
/// incarnation's artifact rather than overwriting it).
fn receipt_locate(session_id: &str, spool: &Path) -> Result<()> {
    let digest = pv_core::digest::sha256_hex(session_id.as_bytes());
    let stem = digest.get(..32).unwrap_or(&digest);
    let mut artifacts = serde_json::Map::new();
    let candidates: [(&str, PathBuf); 5] = [
        ("receipt", spool.join("receipts").join(format!("{stem}.json"))),
        ("atif_trajectory", spool.join(format!("{stem}.json"))),
        ("atif_provenance", spool.join(format!("{stem}.atif-auth"))),
        ("event_journal", spool.join(format!("{stem}.events.ndjson"))),
        ("journal_metadata", spool.join(format!("{stem}.session.json"))),
    ];
    for (label, path) in &candidates {
        artifacts.insert(
            (*label).to_owned(),
            serde_json::json!({
                "path": path,
                "exists": path.exists(),
            }),
        );
    }
    // Archived prior incarnations: `{stem}.archived-*` in either the
    // spool root (ATIF collisions) or receipts/ (receipt collisions).
    let mut archived: Vec<String> = Vec::new();
    for dir in [spool.to_path_buf(), spool.join("receipts")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(stem) && name.contains("archived-") {
                archived.push(entry.path().display().to_string());
            }
        }
    }
    archived.sort();
    println!(
        "{}",
        serde_json::json!({
            "session_id": session_id,
            "stem": stem,
            "artifacts": artifacts,
            "archived_prior_incarnations": archived,
        })
    );
    Ok(())
}

/// Manual, offline entry point to the sealed-ATIF retention sweep —
/// the same `prune_sealed_atif_blocking` the harness's hourly
/// `atif_retention_days` task runs, callable without a running
/// harness (external cron, one-off reclaim, decommissioning).
fn spool_prune(spool: &Path, retention_days: u32) -> Result<()> {
    let max_age = std::time::Duration::from_secs(u64::from(retention_days) * 24 * 60 * 60);
    let pruned = pv_harness::reconciler::prune_sealed_atif_blocking(spool, max_age)
        .with_context(|| format!("prune spool {}", spool.display()))?;
    println!(
        "{}",
        serde_json::json!({
            "spool": spool,
            "retention_days": retention_days,
            "pruned_pairs": pruned,
        })
    );
    Ok(())
}

fn receipt_verify(path: &Path, public_keys_hex: &[String]) -> Result<()> {
    // Use the strict deserializer that refuses duplicate
    // JSON keys at any nesting level. `pvctl receipt-verify` is the
    // primary offline audit tool — a receipt that verified here but
    // showed different content in `jq` (first-wins) would defeat
    // the whole audit posture. `Receipt::from_json_slice` closes
    // that split-brain uniformly.
    let bytes = read_capped(path, MAX_RECEIPT_BYTES, "receipt")?;
    let receipt =
        Receipt::from_json_slice(&bytes).with_context(|| format!("parse receipt {}", path.display()))?;
    // Accept multiple trusted keys so a key-rotation
    // window is operable — pv_receipts::Keyring was always
    // multi-key (selected by the receipt's key_id); only this CLI
    // flag was single-valued.
    let mut keyring = Keyring::new();
    for (index, key_hex) in public_keys_hex.iter().enumerate() {
        // Accept hex (what `pvctl pubkey` and the startup banner print)
        // AND standard base64 (what the receipt's `public_key_b64`
        // field carries) — auditors were hand-converting
        // between the two encodings of the same 32 bytes.
        let decoded = hex::decode(key_hex.trim()).or_else(|_| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(key_hex.trim())
                .map_err(|_| hex::FromHexError::InvalidStringLength)
        });
        let public_key: [u8; 32] = decoded
            .with_context(|| {
                format!(
                    "trusted public key #{} is neither hexadecimal nor base64",
                    index + 1
                )
            })?
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("trusted public key #{} must contain exactly 32 bytes", index + 1)
            })?;
        keyring
            .add_key_bytes(&public_key)
            .with_context(|| format!("trusted public key #{} is invalid", index + 1))?;
    }
    receipt.verify(&keyring).context("receipt verification failed")?;
    // Sanitise the receipt_id before printing. A signer
    // trusted by the operator could otherwise mint a receipt whose
    // receipt_id contains ESC/CSI bytes, reprogramming the auditor's
    // terminal after the "verified" line.
    println!("verified {}", sanitize_for_terminal(&receipt.body.receipt_id));
    Ok(())
}

fn atif_validate(path: &Path, mode: ValidationMode) -> Result<()> {
    let bytes = read_capped(path, MAX_ATIF_BYTES, "trajectory")?;
    let mode = match mode {
        ValidationMode::Strict => pv_atif::Mode::Strict,
        ValidationMode::Compat => pv_atif::Mode::Compat,
    };
    // `validate_bytes` refuses duplicate keys before
    // parsing (parallel to `Receipt::from_json_slice`'s
    // strict scanner) and runs `validate_value` on the untyped
    // form, which exercises unknown-field checks that the typed
    // `Trajectory` (no `deny_unknown_fields`) silently drops.
    let issues = match pv_atif::validate_bytes(&bytes, mode) {
        Ok(issues) => issues,
        Err(reason) => anyhow::bail!("parse {}: {reason}", path.display()),
    };
    if !issues.is_empty() {
        // The reconciler already
        // caps its render at first 16 + total; the CLI mirrors
        // that, and also detects the pv_atif truncation
        // marker (message contains "issue cap") so the summary
        // says "at least N" rather than reporting the capped
        // count as if it were exact.
        const ATIF_HEAD: usize = 16;
        let truncated = issues.last().is_some_and(|i| i.message.contains("issue cap"));
        // Number of "real" issues: strip the synthetic marker if
        // present. The total the user sees is a lower bound when
        // truncated, exact otherwise.
        let real_total = if truncated { issues.len() - 1 } else { issues.len() };
        let shown = issues.iter().take(ATIF_HEAD);
        for issue in shown {
            // Sanitise every field of the issue since
            // both `path` (a JSON pointer built from user JSON keys)
            // and `message` (may embed a value snippet) come from
            // attacker-supplied ATIF content.
            eprintln!(
                "{}: {}",
                sanitize_for_terminal(&issue.path),
                sanitize_for_terminal(&issue.message)
            );
        }
        if real_total > ATIF_HEAD {
            let suppressed = real_total - ATIF_HEAD;
            let qualifier = if truncated { "at least " } else { "" };
            eprintln!("... {qualifier}{suppressed} more issue(s) suppressed (showing first {ATIF_HEAD})");
        }
        if truncated {
            anyhow::bail!("ATIF validation failed with at least {real_total} issue(s) (validator truncated)");
        }
        anyhow::bail!("ATIF validation failed with {real_total} issue(s)");
    }
    println!("valid {}", path.display());
    Ok(())
}

fn manifest_validate(path: &Path) -> Result<()> {
    let yaml = read_capped_str(path, MAX_CONFIG_BYTES, "manifest")?;
    let manifest = BridgeManifest::from_yaml(&yaml).map_err(anyhow::Error::new)?;
    // `manifest.name` is operator-supplied text with no
    // control-byte restriction (see pv-bridge/src/manifest.rs::validate,
    // which only refuses YAML anchor markers). A crafted manifest with
    // an ANSI CSI sequence in `name:` would reach the operator terminal
    // unfiltered — same CVE-2003-0063 class as the receipt/atif prints
    // already fixed.
    println!(
        "valid {} topics={}",
        sanitize_for_terminal(&manifest.name),
        manifest.topics.len()
    );
    Ok(())
}

fn bridge_provision(manifest_path: &Path, data_dir: &Path) -> Result<()> {
    let yaml = read_capped_str(manifest_path, MAX_CONFIG_BYTES, "manifest")?;
    let manifest = BridgeManifest::from_yaml(&yaml).map_err(anyhow::Error::new)?;
    let started = Instant::now();
    EmbeddedBroker::provision(data_dir, &manifest).context("provision Bridge")?;
    println!(
        "provisioned {} topics={} elapsed_ms={}",
        sanitize_for_terminal(&manifest.name),
        manifest.topics.len(),
        started.elapsed().as_millis()
    );
    Ok(())
}

fn event_tail(data_dir: &Path, topic: &str, partition: u32, offset: u64, max: usize) -> Result<()> {
    // Cap `--max`. Every neighbouring CLI flag has a
    // documented cap (loadgen --connections <= 10_000, dashboard
    // limit <= 500, receipt/atif/config file caps); event-tail did
    // not, so `pvctl event-tail --max 4000000000` allocates a Vec
    // large enough to OOM the CLI on a 64-bit host. 100_000 is
    // three orders of magnitude above any operator-friendly page
    // size — a real drain use case should page with --offset.
    const MAX_EVENT_TAIL: usize = 100_000;
    if max > MAX_EVENT_TAIL {
        anyhow::bail!("--max {max} exceeds the safety cap of {MAX_EVENT_TAIL}; page with --offset instead");
    }
    // Read-only by construction: `EmbeddedBroker::open` recovers state
    // (torn-tail `set_len`, sidecar rewrite, append-handle creation),
    // which must never run beside a live daemon mid-append — a second
    // process's "repair" could truncate bytes the daemon then acks as
    // durable. `fetch_read_only` touches nothing on disk.
    for event in
        EmbeddedBroker::fetch_read_only(data_dir, topic, partition, offset, max).context("fetch events")?
    {
        println!("{}", serde_json::to_string(&event)?);
    }
    Ok(())
}

async fn session_promote(base_url: &str, id: &str, token_file: Option<&Path>) -> Result<()> {
    let url = promote_url(base_url, id)?;
    let token = bearer_token(token_file)?;
    // Every other CLI probe bounds its wait (see `doctor` and `probe_endpoint`
    // at 3 s); without an explicit timeout, a hung harness leaves this call
    // waiting forever.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(5))
        // Never follow redirects: the request carries bearer_auth, and a
        // 3xx from an in-path proxy would silently re-send the NHI token
        // to whatever the Location header names. Matches every other
        // credential-bearing client in this crate (doctor, health).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build promotion client")?;
    let mut request = client.post(url);
    if let Some(token) = token.as_ref() {
        request = request.bearer_auth(token.as_str());
    }
    let response = request.send().await.context("promote session")?;
    let status = response.status();
    // Cap the response body read. reqwest's
    // `response.text()` buffers the whole body with no built-in
    // limit; a misbehaving harness (or a stalled proxy) could keep
    // the CLI holding unbounded RAM waiting for EOF. Stream chunks
    // and refuse past MAX_CONTROL_BYTES (1 MiB — a promotion
    // receipt is a few hundred bytes).
    let body = read_capped_response(response, pv_core::fsutil::MAX_CONTROL_BYTES).await?;
    if !status.is_success() {
        // Harness error body is attacker-influencable
        // via header echoing / error messages — sanitise before
        // it lands on the operator's terminal.
        anyhow::bail!("promotion failed ({status}): {}", sanitize_for_terminal(&body));
    }
    // The promoted receipt is JSON — printing it
    // through serde_json::to_string is not attacker-controllable at
    // this layer, but the raw body could carry stray control bytes
    // if a proxy adulterates the response. Sanitise to be safe.
    println!("{}", sanitize_for_terminal(&body));
    Ok(())
}

/// Build the promotion URL with proper path-segment encoding. Session
/// ids accept any printable ASCII (see `SessionId::parse`), including
/// `/`, `?` and `#`; raw string interpolation let such an id split the
/// path or start a query string, sending the promotion to the wrong
/// route. The harness router percent-decodes `{id}` captures, so
/// encoding here round-trips exactly.
fn promote_url(base_url: &str, id: &str) -> Result<reqwest::Url> {
    let mut url =
        reqwest::Url::parse(base_url).with_context(|| format!("parse harness base URL {base_url:?}"))?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("harness base URL {base_url:?} cannot carry a path"))?
        .pop_if_empty()
        .extend(["v1", "sessions", id, "promote"]);
    Ok(url)
}

/// Capped, streaming replacement for
/// `response.text().await`. Refuses to buffer more than `max_bytes`
/// before an EOF and surfaces the cap in the error text.
async fn read_capped_response(response: reqwest::Response, max_bytes: u64) -> Result<String> {
    use futures::StreamExt as _;
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read response chunk")?;
        if buf.len().saturating_add(chunk.len()) > cap {
            anyhow::bail!("response exceeded {max_bytes} bytes; refusing to buffer");
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).context("response body was not valid UTF-8")
}

/// Records listed by `judge-replay` in each detail list; counts are
/// always complete.
const MAX_REPLAY_LISTED: usize = 100;

fn judge_thresholds(path: &Path) -> Result<pv_judge::ThresholdPolicy> {
    let text = read_capped_str(path, MAX_CONFIG_BYTES, "config")?;
    let config = pv_harness::HarnessConfig::from_toml(&text).map_err(anyhow::Error::msg)?;
    let judge = config
        .judge
        .as_ref()
        .with_context(|| format!("{} has no [judge] section", path.display()))?;
    judge.threshold_policy().map_err(anyhow::Error::msg)
}

#[derive(Default, serde::Serialize)]
struct ActionCounts {
    allow: u64,
    ask: u64,
    deny: u64,
}

impl ActionCounts {
    fn add(&mut self, action: pv_judge::JudgeAction) {
        match action {
            pv_judge::JudgeAction::Allow => self.allow += 1,
            pv_judge::JudgeAction::Ask => self.ask += 1,
            pv_judge::JudgeAction::Deny => self.deny += 1,
        }
    }
}

#[derive(Default, serde::Serialize)]
struct ToolReplay {
    judged: u64,
    /// What the thresholds decided when the call was made.
    recorded: ActionCounts,
    /// Calls judge-aware policy would have blocked (shadow mode) or did
    /// block (enforce mode), as recorded.
    would_block: u64,
    /// Calls the harness actually refused.
    refused: u64,
    /// What the `--what-if` thresholds decide.
    #[serde(skip_serializing_if = "Option::is_none")]
    what_if: Option<ActionCounts>,
}

/// Replay every judged `agent.tool_call` record in an embedded Bridge.
fn judge_export(data_dir: &Path, predicate: Option<&str>, would_block_only: bool) -> Result<()> {
    use std::io::Write as _;
    const TOPIC: &str = "agent.tool_call";
    const PAGE: usize = 10_000;
    let manifest_text = read_capped_str(
        &data_dir.join("manifest.yaml"),
        MAX_CONFIG_BYTES,
        "bridge manifest",
    )?;
    let manifest = BridgeManifest::from_yaml(&manifest_text).map_err(anyhow::Error::new)?;
    let partitions = manifest
        .topics
        .iter()
        .find(|topic| topic.name == TOPIC)
        .map(|topic| topic.partitions)
        .with_context(|| format!("the Bridge has no {TOPIC} topic"))?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let (mut judged, mut without_inputs, mut exported) = (0u64, 0u64, 0u64);
    let (mut unreadable_records, mut unreadable_arguments) = (0u64, 0u64);
    for partition in 0..partitions {
        let mut offset = 0u64;
        loop {
            let page = EmbeddedBroker::fetch_read_only(data_dir, TOPIC, partition, offset, PAGE)
                .context("read the Bridge")?;
            let Some(last) = page.last() else { break };
            offset = last.offset.saturating_add(1);
            for stored in &page {
                let event = &stored.value;
                let Some(raw) = event.pointer("/payload/judge") else {
                    continue;
                };
                judged += 1;
                let Ok(record) = serde_json::from_value::<pv_judge::JudgeRecord>(raw.clone()) else {
                    unreadable_records += 1;
                    continue;
                };
                if would_block_only && !record.would_block {
                    continue;
                }
                let Some(inputs) = &record.inputs else {
                    without_inputs += 1;
                    continue;
                };
                // Arguments that are not JSON (a record from a build that
                // redacted the text itself) would ask a reviewer to label a
                // call nobody can see: skipped and counted.
                let Ok(arguments) = serde_json::from_str::<serde_json::Value>(&inputs.arguments_json) else {
                    unreadable_arguments += 1;
                    continue;
                };
                for verdict in &record.verdicts {
                    if predicate.is_some_and(|wanted| wanted != verdict.predicate_id) {
                        continue;
                    }
                    let said = verdict.probs.iter().max_by_key(|prob| prob.ppm).map_or_else(
                        || format!("judge {}", verdict.status),
                        |top| format!("judge said {} at {}", top.label, f64::from(top.ppm) / 1e6),
                    );
                    let example = pv_judge::calibration::LabelledExample {
                        predicate_id: verdict.predicate_id.clone(),
                        tool: inputs.tool.clone(),
                        arguments: arguments.clone(),
                        context: inputs.context.clone(),
                        label: String::new(),
                        source: Some(format!(
                            "recorded {} event {}: {said}",
                            event
                                .get("session_uid")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("-"),
                            event
                                .pointer("/metadata/uid")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("-"),
                        )),
                    };
                    serde_json::to_writer(&mut out, &example)?;
                    out.write_all(b"\n")?;
                    exported += 1;
                }
            }
        }
    }
    out.flush()?;
    eprintln!(
        "{exported} examples exported from {judged} judged calls ({without_inputs} recorded without \
         inputs: set [judge] record_inputs = true to keep them; {unreadable_records} records could \
         not be read; {unreadable_arguments} skipped because their arguments are not JSON). Set \
         each `label` before `pvctl judge-calibrate` reads the file."
    );
    Ok(())
}

fn judge_replay(data_dir: &Path, config: &Path, what_if: Option<&Path>) -> Result<()> {
    use pv_judge::replay::{replay, DecisionSummary};
    const TOPIC: &str = "agent.tool_call";
    const PAGE: usize = 10_000;
    let policy = judge_thresholds(config)?;
    let other = what_if.map(judge_thresholds).transpose()?;
    let manifest_text = read_capped_str(
        &data_dir.join("manifest.yaml"),
        MAX_CONFIG_BYTES,
        "bridge manifest",
    )?;
    let manifest = BridgeManifest::from_yaml(&manifest_text).map_err(anyhow::Error::new)?;
    let partitions = manifest
        .topics
        .iter()
        .find(|topic| topic.name == TOPIC)
        .map(|topic| topic.partitions)
        .with_context(|| format!("the Bridge has no {TOPIC} topic"))?;

    let mut read = 0u64;
    let mut judged = 0u64;
    let mut mismatches = 0u64;
    let mut unreadable = 0u64;
    let mut changed = 0u64;
    let mut mismatch_list = Vec::new();
    let mut unreadable_list = Vec::new();
    let mut changed_list = Vec::new();
    let mut tools: std::collections::BTreeMap<String, ToolReplay> = std::collections::BTreeMap::new();
    for partition in 0..partitions {
        let mut offset = 0u64;
        loop {
            let page = EmbeddedBroker::fetch_read_only(data_dir, TOPIC, partition, offset, PAGE)
                .context("read the Bridge")?;
            let Some(last) = page.last() else { break };
            offset = last.offset.saturating_add(1);
            for stored in &page {
                read += 1;
                let event = &stored.value;
                let Some(raw) = event.pointer("/payload/judge") else {
                    continue;
                };
                judged += 1;
                let at = serde_json::json!({
                    "session_uid": event.get("session_uid"),
                    "event_uid": event.pointer("/metadata/uid"),
                    "partition": partition,
                    "offset": stored.offset,
                });
                let record = match serde_json::from_value::<pv_judge::JudgeRecord>(raw.clone())
                    .map_err(|error| error.to_string())
                    .and_then(|record| replay(&record, &policy).map(|decision| (record, decision)))
                {
                    Ok(pair) => pair,
                    Err(error) => {
                        unreadable += 1;
                        if unreadable_list.len() < MAX_REPLAY_LISTED {
                            unreadable_list.push(serde_json::json!({"at": at, "error": error}));
                        }
                        continue;
                    }
                };
                let (record, decision) = record;
                let tool = event
                    .pointer("/payload/tool")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let entry = tools.entry(tool.clone()).or_default();
                entry.judged += 1;
                entry.recorded.add(record.decision);
                entry.would_block += u64::from(record.would_block);
                entry.refused += u64::from(
                    event
                        .pointer("/payload/allowed")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false),
                );
                let recorded = DecisionSummary::recorded(&record);
                let replayed = DecisionSummary::of(&decision);
                if recorded != replayed {
                    mismatches += 1;
                    if mismatch_list.len() < MAX_REPLAY_LISTED {
                        mismatch_list.push(serde_json::json!({
                            "at": at, "tool": tool, "recorded": recorded, "replayed": replayed,
                        }));
                    }
                }
                if let Some(other) = &other {
                    let tried = replay(&record, other).map_err(anyhow::Error::msg)?;
                    entry
                        .what_if
                        .get_or_insert_with(ActionCounts::default)
                        .add(tried.action);
                    if tried.action != record.decision {
                        changed += 1;
                        if changed_list.len() < MAX_REPLAY_LISTED {
                            changed_list.push(serde_json::json!({
                                "at": at, "tool": tool, "recorded": recorded,
                                "what_if": DecisionSummary::of(&tried),
                            }));
                        }
                    }
                }
            }
        }
    }
    let mut report = serde_json::json!({
        "records_read": read,
        "judged": judged,
        "consistency": {
            "config": config.display().to_string(),
            "mismatches": mismatches,
            "unreadable": unreadable,
            "mismatch_examples": mismatch_list,
            "unreadable_examples": unreadable_list,
        },
        "tools": tools,
    });
    if let (Some(path), Some(object)) = (what_if, report.as_object_mut()) {
        object.insert(
            "what_if".to_owned(),
            serde_json::json!({
                "config": path.display().to_string(),
                "changed": changed,
                "changed_examples": changed_list,
            }),
        );
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    if mismatches > 0 || unreadable > 0 {
        anyhow::bail!(
            "{mismatches} recorded decision(s) do not follow from their verdicts under {} and {unreadable} \
             record(s) could not be replayed; check the receipts and the configuration in force at the time",
            config.display()
        );
    }
    Ok(())
}

/// Largest labelled set read by `judge-calibrate` (64 MiB).
const MAX_LABELLED_SET_BYTES: u64 = 64 * 1024 * 1024;

fn separation_floor_ppm(value: f64) -> Result<i64> {
    if !value.is_finite() || !(-1.0..=1.0).contains(&value) {
        anyhow::bail!("--min-separation must be between -1 and 1");
    }
    // In range by the check above.
    #[allow(clippy::cast_possible_truncation)]
    let ppm = (value * f64::from(pv_judge::PPM_ONE)).round() as i64;
    Ok(ppm)
}

async fn judge_calibrate(
    config_path: &Path,
    adapter: &str,
    set_path: &Path,
    floor: &pv_judge::calibration::CalibrationFloor,
) -> Result<()> {
    let text = read_capped_str(config_path, MAX_CONFIG_BYTES, "config")?;
    let config = pv_harness::HarnessConfig::from_toml(&text).map_err(anyhow::Error::msg)?;
    let set = read_capped_str(set_path, MAX_LABELLED_SET_BYTES, "labelled set")?;
    let examples = pv_judge::calibration::load_jsonl(&set).map_err(anyhow::Error::msg)?;
    let report = pv_harness::judge::calibrate_from_config(&config, adapter, &examples)
        .await
        .map_err(anyhow::Error::msg)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    let shortfalls = report.shortfalls(floor);
    if !shortfalls.is_empty() {
        anyhow::bail!("calibration floor not met:\n  {}", shortfalls.join("\n  "));
    }
    Ok(())
}

fn config_validate(path: &Path, structural_only: bool) -> Result<()> {
    let text = read_capped_str(path, MAX_CONFIG_BYTES, "config")?;
    let config = pv_harness::HarnessConfig::from_toml(&text).map_err(anyhow::Error::msg)?;
    // A shape-valid config is useless if it selects
    // backends the binary cannot run — previously this reported
    // "valid" for `bridge_backend = "kafka"` on a default-features
    // build and the daemon then hard-failed at boot. pvctl and
    // proofvisord are built from the same workspace feature set in
    // every shipped artifact, so pvctl's own features are the best
    // available proxy for what the daemon can run.
    // `--structural-only` opts out for configs that target a build
    // with a different feature set (the full-feature container image);
    // `make schema-check` uses it for harness.docker/container.toml.
    if !structural_only {
        let unsupported = config.unsupported_backend_requirements();
        if !unsupported.is_empty() {
            anyhow::bail!(
                "config is structurally valid but this build cannot run it:\n  {}",
                unsupported.join("\n  ")
            );
        }
    }
    // `config.listen` is operator-supplied text with no control-byte
    // restriction (validate() only shape-checks the port suffix) — the
    // same CVE-2003-0063 class as `manifest.name` above; a crafted
    // config could otherwise land raw ANSI escapes in the operator
    // terminal.
    println!(
        "valid config_version={} listen={}",
        config.config_version,
        sanitize_for_terminal(&config.listen)
    );
    Ok(())
}

async fn loadgen(
    base_url: &str,
    connections: usize,
    workflow: &str,
    token_file: Option<&Path>,
) -> Result<()> {
    if connections == 0 {
        anyhow::bail!("connections must be greater than zero");
    }
    // Cap the requested concurrency: at multi-hundred-thousand
    // connections the loadgen exhausts source ports / FDs / RAM on the
    // operator's own host before any latency numbers land, and the load
    // *test* becomes the very thing it was supposed to measure. 10k is
    // the stated SLA gate — the previous 100k cap
    // encouraged runs that a single host cannot sustain: default Linux
    // `net.ipv4.ip_local_port_range` (~28k) exhausts before hyper can
    // dial, and `RLIMIT_NOFILE` (1024–65536) trips producing thousands
    // of `Address not available` failures that look like the harness
    // is broken.
    const MAX_CONNECTIONS: usize = 10_000;
    if connections > MAX_CONNECTIONS {
        anyhow::bail!(
            "connections must be <= {MAX_CONNECTIONS} — larger values \
             exhaust source ports / FDs before producing usable results"
        );
    }
    if pv_harness::session::Workflow::parse(workflow).is_none() {
        anyhow::bail!("workflow must be signed or unsigned");
    }
    // A hung upstream must not turn `loadgen --connections 10000` into an
    // unbounded resource consumer that never fails — the load *test* would
    // otherwise mask the failure it is supposed to expose. Per-request
    // timeout bounds each in-flight probe; connect_timeout catches
    // upstream unreachable faster than TCP retransmit does. Idle pool
    // capped at 1024 — more than that is never useful and just wastes
    // FDs after the burst ends.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(connections.min(1024))
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        // No redirects: requests may carry bearer_auth (token leak on a
        // proxy-injected 3xx), and following one would silently measure
        // the redirect target instead of the configured endpoint.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build loadgen client")?;
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
    let token = bearer_token(token_file)?.map(Arc::new);
    // Unique per run: reusing ids like `load-0` across runs would bind to
    // sessions a previous run left behind — mid-close ones refuse reuse
    // with 503 "session close is completing" and quarantined ones with a
    // 400.
    let run_id = pv_core::new_event_uid();
    let started = Instant::now();
    let results: Vec<Result<u64, String>> = stream::iter(0..connections)
        .map(|index| {
            let client = client.clone();
            let url = url.clone();
            let workflow = workflow.to_owned();
            let token = token.clone();
            let run_id = run_id.clone();
            async move {
                let request_started = Instant::now();
                let mut request = client
                    .post(url)
                    .header("x-pv-session", format!("load-{run_id}-{index}"))
                    .header("x-pv-workflow", workflow)
                    .json(&serde_json::json!({
                        "model": "loadgen",
                        "stream": true,
                        "messages": [{"role": "user", "content": "health check"}],
                    }));
                if let Some(token) = token.as_ref() {
                    request = request.bearer_auth(token.as_str());
                }
                let response = request.send().await.map_err(|error| error.to_string())?;
                let status = response.status();
                // Cap loadgen response body reads. With
                // `stream: true`, an SSE response accumulates whole
                // via `.bytes()` — a stalled server could pin each
                // of `--connections 10_000` tasks to unbounded RAM,
                // turning the load test into the fault it was meant
                // to expose. Refuse past 4 MiB per response.
                use futures::StreamExt as _;
                let mut stream = response.bytes_stream();
                let mut total = 0usize;
                const LOADGEN_MAX_RESPONSE: usize = 4 * 1024 * 1024;
                while let Some(chunk) = stream.next().await {
                    let bytes = chunk.map_err(|error| error.to_string())?;
                    total = total.saturating_add(bytes.len());
                    if total > LOADGEN_MAX_RESPONSE {
                        return Err(format!("response exceeded {LOADGEN_MAX_RESPONSE} bytes"));
                    }
                }
                if !status.is_success() {
                    return Err(format!("HTTP {status}"));
                }
                Ok(u64::try_from(request_started.elapsed().as_micros()).unwrap_or(u64::MAX))
            }
        })
        .buffer_unordered(connections)
        .collect()
        .await;
    let mut latencies = Vec::with_capacity(connections);
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(latency) => latencies.push(latency),
            Err(error) => failures.push(error),
        }
    }
    latencies.sort_unstable();
    println!(
        "connections={} success={} failed={} wall_ms={} p50_us={} p95_us={} p99_us={}",
        connections,
        latencies.len(),
        failures.len(),
        started.elapsed().as_millis(),
        percentile(&latencies, 50),
        percentile(&latencies, 95),
        percentile(&latencies, 99),
    );
    if !failures.is_empty() {
        anyhow::bail!(
            "{} load requests failed; first: {}",
            failures.len(),
            failures.first().map(String::as_str).unwrap_or("unknown")
        );
    }
    Ok(())
}

/// Read the NHI bearer token into a `Zeroizing` buffer. The token is a
/// credential at least as sensitive as an API key — every allocation
/// that holds it (the raw read and the trimmed copy) is zero-on-drop so
/// a post-run core dump or heap scan does not expose it verbatim.
/// Mirrors the wizard's `ask_secret_line` discipline.
fn bearer_token(path: Option<&Path>) -> Result<Option<zeroize::Zeroizing<String>>> {
    let path = path
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("PV_BEARER_TOKEN_FILE").map(PathBuf::from));
    path.map(|path| {
        // Refuse a bearer token file that any other local
        // user can read. On a shared-tenant host, a 0o644 token file
        // in ~/.pvctl/ leaks the operator's credentials to every
        // process running as another uid. Mirrors the harness's own
        // discipline for signing seed / HMAC secret files (see
        // `require_owner_only_mode`).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::symlink_metadata(&path)
                .with_context(|| format!("stat bearer token {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "bearer token file {} is a symbolic link; refuse to follow (planted-symlink hazard)",
                    path.display()
                );
            }
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "bearer token file {} has mode 0o{mode:03o}; must be 0o600 (chmod 600 {})",
                    path.display(),
                    path.display()
                );
            }
        }
        let raw = zeroize::Zeroizing::new(read_capped_str(&path, MAX_CONFIG_BYTES, "bearer token")?);
        let token = zeroize::Zeroizing::new(raw.trim().to_owned());
        if token.is_empty() {
            anyhow::bail!("bearer token file {} is empty", path.display());
        }
        Ok(token)
    })
    .transpose()
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted.get(index.saturating_sub(1)).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn cli_covers_required_commands() {
        for args in [
            vec!["pvctl", "init", "--preset", "ollama"],
            vec!["pvctl", "doctor", "--offline"],
            vec!["pvctl", "health"],
            vec!["pvctl", "keygen", "--output", "key.seed"],
            vec![
                "pvctl",
                "receipt-verify",
                "receipt.json",
                "--public-key-hex",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            vec!["pvctl", "atif-validate", "trajectory.json"],
            vec!["pvctl", "manifest-validate", "bridge.yaml"],
            vec!["pvctl", "config-validate", "harness.toml"],
            vec!["pvctl", "loadgen", "--connections", "10000"],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
    }

    /// Regression: session ids accept any printable ASCII, so a raw
    /// `format!` URL let ids containing `/`, `?` or `#` split the path
    /// or start a query/fragment — promoting the wrong route entirely.
    /// The builder must percent-encode the id as one path segment.
    #[test]
    fn promote_url_percent_encodes_reserved_session_id_characters() {
        let url = promote_url("http://localhost:8080", "sess?x/y#z").unwrap();
        assert_eq!(url.path(), "/v1/sessions/sess%3Fx%2Fy%23z/promote");
        assert_eq!(url.query(), None, "id must not leak into the query");
        assert_eq!(url.fragment(), None, "id must not leak into the fragment");
        // Trailing slash on the base must not double up.
        let url = promote_url("http://localhost:8080/", "plain-id").unwrap();
        assert_eq!(url.path(), "/v1/sessions/plain-id/promote");
        // A base URL carrying a path prefix keeps it.
        let url = promote_url("http://localhost:8080/proxy", "plain-id").unwrap();
        assert_eq!(url.path(), "/proxy/v1/sessions/plain-id/promote");
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let values: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[], 99), 0);
    }

    /// Terminal sanitizer covers both escape classes: CVE-2003-0063
    /// (C0/C1/DEL control bytes) and CVE-2021-42574 (Trojan-Source bidi
    /// overrides/isolates + U+2028/U+2029). A receipt id minted by a
    /// compromised signer must not render reversed or reprogram the
    /// operator's terminal when echoed by receipt-verify / promote.
    #[test]
    fn sanitize_for_terminal_neutralises_controls_and_bidi() {
        // Control bytes (old coverage, must keep working).
        assert_eq!(sanitize_for_terminal("a\u{1b}[2Jb"), "a\u{FFFD}[2Jb");
        assert_eq!(sanitize_for_terminal("a\u{9d}b\u{7f}c"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(sanitize_for_terminal("keep\ttab"), "keep\ttab");
        // Trojan-Source family: every bidi override/isolate and the
        // line/paragraph separators are replaced.
        for c in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}',
            '\u{2069}', '\u{2028}', '\u{2029}', '\u{200B}', '\u{FEFF}',
        ] {
            let sanitized = sanitize_for_terminal(&format!("safe{c}payload"));
            assert_eq!(sanitized, "safe\u{FFFD}payload", "unsanitised {c:?}");
        }
        // Legitimate non-ASCII text passes through untouched.
        assert_eq!(sanitize_for_terminal("réseau 支付 ✓"), "réseau 支付 ✓");
    }

    /// `install_seed_exclusive` must not leave a tmp
    /// containing seed material on disk when installation does not
    /// complete. Exercised here on the AlreadyExists branch: the SEED
    /// path is pre-occupied, install returns `Ok(false)`, and the
    /// parent dir contains only the pre-existing file — no
    /// `.pvctl-key-*.tmp` orphan carrying real seed hex. (The tmp name
    /// itself is a fresh `new_event_uid()`, so tmp-phase failures are
    /// not injectable from here; `TempPathGuard`'s own tests in fsutil
    /// cover that phase.)
    #[test]
    fn install_seed_exclusive_leaves_no_orphan_on_pre_hardlink_failure() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("proofvisor.seed");
        // Impossible to inject a failure into write_all/sync_all
        // without unsafe, but we CAN force `open(create_new)` to
        // return AlreadyExists by pre-planting the tmp name.
        // Because the tmp uses `new_event_uid()`, we don't know the
        // exact name — but the TempPathGuard test lives in fsutil.
        // Here we exercise the AlreadyExists branch on the SEED path
        // itself (path==seed_path already occupied): install returns
        // Ok(false) and no `.pvctl-key-*.tmp` is left behind.
        std::fs::write(&seed_path, b"pre-existing").unwrap();
        let installed = install_seed_exclusive(&seed_path, "aa".repeat(32).as_str()).unwrap();
        assert!(!installed, "seed already installed must return Ok(false)");
        let orphans: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".pvctl-key-") && n.ends_with(".tmp"))
            .collect();
        assert!(
            orphans.is_empty(),
            "install_seed_exclusive left {orphans:?} on disk after AlreadyExists — TempPathGuard did not fire"
        );
        // The original pre-existing seed file is untouched.
        assert_eq!(std::fs::read(&seed_path).unwrap(), b"pre-existing");
    }

    /// `event_tail` refuses --max above the safety cap
    /// so a typo (`--max 999999999`) cannot OOM the CLI by
    /// preallocating a proportional Vec inside bridge.fetch. The
    /// tempdir passed in doesn't need a real manifest — the cap
    /// check fires before EmbeddedBroker::open.
    #[test]
    fn event_tail_refuses_max_above_safety_cap() {
        let dir = tempfile::tempdir().unwrap();
        let err = event_tail(dir.path(), "any-topic", 0, 0, 100_001).unwrap_err();
        let text = format!("{err:?}");
        assert!(
            text.contains("safety cap"),
            "expected safety-cap rejection, got {text}"
        );
    }

    /// `sanitize_for_terminal` neutralises every control
    /// byte that could reprogram the operator's terminal. A signer
    /// trusted by the operator could otherwise mint a receipt whose
    /// receipt_id contains ESC/CSI/DEL/C1 bytes and hijack the
    /// output of `pvctl receipt-verify`.
    #[test]
    fn sanitize_for_terminal_neutralises_ansi_escapes() {
        // ESC (0x1b) — the C0 prefix for ANSI CSI sequences.
        let evil = "OK\u{1b}[2J\u{1b}[Hspoofed";
        let cleaned = sanitize_for_terminal(evil);
        assert!(!cleaned.contains('\u{1b}'), "ESC survived: {cleaned:?}");
        // CSI (0x9b) — the single-byte 8-bit-terminal equivalent.
        let evil2 = "line\u{9b}2J";
        assert!(!sanitize_for_terminal(evil2).contains('\u{9b}'));
        // DEL (0x7f).
        assert!(!sanitize_for_terminal("a\u{7f}b").contains('\u{7f}'));
        // NUL and other C0 (except TAB which we preserve).
        assert!(!sanitize_for_terminal("a\u{00}b").contains('\u{00}'));
        assert!(!sanitize_for_terminal("a\nb").contains('\n'));
        assert_eq!(sanitize_for_terminal("safe\tstring"), "safe\tstring");
        // Regular UTF-8 characters (multi-byte) survive.
        assert_eq!(sanitize_for_terminal("héllo"), "héllo");
    }
}
