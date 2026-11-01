# Platform support

What runs where, and how it was verified. Every claim below was
exercised against real binaries — install, boot, policy verdicts,
budget blocks, receipt seal/verify, tamper rejection — not inferred
from "it compiles". (Verification rounds 93–99, September 2026.)

## Tier 1 — prebuilt binaries (installer default)

`curl -fsS https://proofvisor.com/install.sh | sh` downloads these,
verifies the SHA-256, installs, and smoke-runs them on your machine.

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | **Static** — runs on every x86_64 Linux regardless of glibc age or libc flavor. Verified on Ubuntu 24.04/22.04, Debian 12/11, Rocky 8 (glibc 2.28), Amazon Linux 2023, Fedora 42, Arch, openSUSE Leap 15.6, Alpine 3.20. |
| `aarch64-unknown-linux-musl` | Static; verified on Ubuntu 22.04, Debian 12, Alpine 3.20, Fedora 42 (arm64). |
| `aarch64-apple-darwin` | Verified on macOS 14+ (Apple silicon). |
| `x86_64-apple-darwin` | Verified on macOS 15 (Intel). |
| `x86_64-unknown-linux-gnu` | Also published; needs glibc ≥ 2.38. The installer prefers musl. |

## Tier 2 — build from source (verified working)

The installer falls back to `cargo install` from the public repo on
any other Unix (or force it with `PV_INSTALL_SOURCE=1`). These
targets were built and run through the full gate battery under
emulation:

| Target | Notes |
|---|---|
| `aarch64-unknown-linux-gnu` | Also exercised nightly in CI. |
| `armv7-unknown-linux-gnueabihf` | 32-bit ARM (Raspberry Pi OS 32-bit). The policy sandbox uses wasmtime's portable interpreter where no native JIT exists. Expect a long compile on a Pi. |
| `riscv64gc-unknown-linux-gnu` | Native cranelift JIT backend. |
| `powerpc64le-unknown-linux-gnu` | Works from v0.1.0-rc.4; earlier builds hit a per-arch `O_NOFOLLOW` constant bug that fail-closed every session (fixed, regression-tested on ppc64le). |
| `s390x-unknown-linux-gnu` | Big-endian. Receipts sealed on s390x verify on little-endian hosts and vice versa — the receipt framing and signatures are endian-clean. |

## Receipts are portable

A receipt sealed on any platform above verifies with `pvctl
receipt-verify` on any other — across architecture, bitness (32→64),
and endianness (BE⇄LE) — because verification hashes a canonical
byte frame (`agentvisor-receipt-v2\0` + big-endian length + body).

## Windows

Native Windows x64 (`x86_64-pc-windows-msvc`) is supported for the
daemon and the CLI, with the differences listed below. Everything else
in this repository (installer, systemd unit, container images, the
hosted console) is Unix-only and needs WSL on a Windows machine.

How it is verified (2026-10-31): the whole workspace, including every
test target, compiles for the Windows target from the development
machine (`cargo check --workspace --all-targets --target
x86_64-pc-windows-gnu` with the MinGW-w64 toolchain, zero errors), and
the `windows` job in `.github/workflows/ci.yml` builds `proofvisord`
and `pvctl` with MSVC on `windows-latest` and runs the workspace unit
tests (`cargo test --workspace --lib`) there. Each release tag also
builds `proofvisor-<version>-x86_64-pc-windows-msvc.zip`
(`proofvisord.exe`, `pvctl.exe`) in `release.yml`. The binaries have
not been run through the install-and-boot battery on Windows hardware
that the Tier-1 targets went through, so Windows is a Tier-2 target.

Works natively:

- The HTTP gateway (`/v1/chat/completions`, `/mcp`, `/v1/mcp`), the
  WASM policy sandbox (wasmtime, cranelift), budgets, loop detection,
  the embedded Bridge and the evidence spool on NTFS, receipt sealing,
  and offline verification with `pvctl receipt-verify`. Receipts sealed
  on Windows verify on any other platform and vice versa (see
  "Receipts are portable").
- `pvctl` in general, including `pvctl setup`, `pvctl doctor`,
  `pvctl pubkey`, console sync and the sidecar.
- Graceful shutdown: the daemon stops on Ctrl-C (and on the console
  control events Windows maps to it) through `tokio::signal::ctrl_c`,
  running the same drain sequence as SIGTERM on Unix, including
  `shutdown_ready_drain_s`.

Differs from Unix (the Unix behaviour is compiled out with
`#[cfg(unix)]`):

- **Secret-file permission checks are not enforced.** On Unix the
  daemon and `pvctl` refuse a signing seed, HMAC secret, backend bearer
  file, AuthZEN token file or revocation file unless it is a regular
  file with mode `0600` and not a symbolic link, and they create spool,
  receipt and Bridge files with mode `0600` and `O_NOFOLLOW`. Windows
  has no POSIX mode bits, so these checks accept any readable regular
  file and new files inherit the directory's NTFS ACL. Operators must
  restrict the configuration, secret and spool directories to the
  service account themselves (for example `icacls <dir>
  /inheritance:r /grant:r "<account>:(OI)(CI)F"`); the daemon does not
  verify the ACL. Treat a world-readable seed on Windows as a
  misconfiguration the software will not catch.
- **Directory fsync is a no-op.** The spool's parent-directory `fsync`
  (durability of a rename across a crash) has no Windows equivalent in
  the standard library and is skipped.
- **No POSIX signals.** There is no SIGTERM or SIGHUP. Service
  managers that stop a process without a console control event (for
  example the Windows Service Control Manager) are not wired; run the
  daemon in a console session, under WSL, or under a wrapper that
  delivers Ctrl-C / Ctrl-Break. `pvctl` cannot forward a termination
  signal to a child daemon on Windows.
- **Unix domain sockets** are not available, so `pvctl doctor` reports
  a Redis `unix://` endpoint as unreachable on Windows rather than
  probing it.
- **Not available natively:** `install.sh`, `deploy/systemd/`, the
  Docker/Compose and Kubernetes manifests, the Cloud Foundry buildpack
  and the hosted console (`server/`). Use WSL or a Linux host for
  these. Download the `.zip` from the GitHub release instead of running
  the installer.
- **Tests:** the integration tests that spawn the daemon, send SIGKILL
  or SIGTERM, or assert mode bits are `#[cfg(unix)]`; the Windows CI
  job runs the unit tests only.

## Hosted console (self-host)

`server/Dockerfile` builds and passes the full API e2e suite (128
checks as of 2026-10-30) on both `linux/amd64` and `linux/arm64`. The
build stage uses `node:22` on Debian 13; the runtime stage is Google's
Distroless Node 22 image (Debian 13, non-root, no shell), with Prisma
auto-migrate and a fail-closed production env guard.

## Continuously verified

- `public-consumer.yml` (nightly): installer on 4 real runners
  (linux x64/arm64, macOS arm64/x64), 3 containers (Ubuntu 22.04,
  Debian 12, Alpine — old glibc + musl), the `PV_INSTALL_SOURCE=1`
  source build, and the full outsider quickstart.
- `release.yml`: every tag builds all Tier-1 targets; the installer
  pin bump and Pages deploy chain automatically.
