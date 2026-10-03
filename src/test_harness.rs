//! Labels the lib's tests declare for skuld to select by.

/// Marks a test run under a label selection, to check that selection does not leak into re-exec'd children.
#[skuld::label]
pub const REEXEC_SELFCHECK: skuld::Label;

/// Selects the root lanes' tests: the `ROOT` group, and the modules whose tests those lanes run whole.
#[skuld::label]
pub const ROOT: skuld::Label;

/// Selects the tests that unshare namespaces and mounts (the `NAMESPACES` group).
#[skuld::label]
pub const NAMESPACES: skuld::Label;

/// Selects the test that maps a drive letter for the whole logon session.
#[skuld::label]
pub const DRIVE_MAPPING: skuld::Label;
