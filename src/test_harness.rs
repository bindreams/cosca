//! Labels the lib's tests declare for skuld to select by.

/// Marks a test run under a label selection, to check that selection does not leak into re-exec'd children.
#[skuld::label]
pub const REEXEC_SELFCHECK: skuld::Label;
