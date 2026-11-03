//! Adversarial and edge-case tests of the semantic judge through the live
//! router. They share one test binary: each file directly under `tests/`
//! links into a binary of its own, more than a hundred megabytes with
//! debug information, and CI's disk is limited.

#[path = "../common/mod.rs"]
mod common;

mod decoding_edges;
mod edge_probe;
mod hardening;
mod restore_inputs_promotion;
mod spool_turns;
mod window_edges;
