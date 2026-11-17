//! macOS pid-snapshot tests, split by topic into one file per section: failure fallback
//! branches, the ppid join, and the snapshot's completeness.

#[path = "macos_tests/failure_fallback.rs"]
mod failure_fallback;

#[path = "macos_tests/ppid_join.rs"]
mod ppid_join;

#[path = "macos_tests/snapshot.rs"]
mod snapshot;
