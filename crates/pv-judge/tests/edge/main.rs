//! Edge cases of the judge crate: rendering, length checks, adapters and
//! stricter TypeSafe answers. They share one test binary to keep CI's
//! disk use down: each file directly under `tests/` links into a binary
//! of its own.

// The shared fixtures build a local ONNX model; only `hardening`, which
// needs that feature anyway, uses them.
#[cfg(feature = "onnx")]
#[path = "../common/mod.rs"]
mod common;

mod core;
mod hardening;
mod render_task_lines;
mod typesafe;
mod typesafe_redaction;
