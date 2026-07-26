//! Windows elevation effect layer.
//!
//! STUB (Task 9 interim): `detect`/`is_elevated` are placeholders so the
//! cross-platform dispatchers in `elevation.rs`/`plan.rs` compile on Windows
//! through Tasks 10-11. Task 12 replaces this file with the real
//! token-based detection (`TokenElevation` + integrity level). No Windows
//! elevation test exercises these values before Task 12.

use super::plan::{BackendSet, Host, Os};

/// STUB — replaced by Task 12's `TokenElevation` query.
pub(super) fn is_elevated() -> bool {
    false
}

/// STUB — replaced by Task 12's real detection.
pub(super) fn detect() -> Host {
    Host {
        elevated: is_elevated(),
        has_tty: false,
        available: BackendSet::default(),
        os: Os::Windows,
    }
}
