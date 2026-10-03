//! Labels the lib's tests declare for skuld to select by.

/// Marks the driver in `test_reexec_tests` that checks a label lane cannot leak into a re-exec.
#[skuld::label]
pub const REEXEC_SELFCHECK: skuld::Label;
