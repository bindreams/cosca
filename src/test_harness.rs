//! Labels the lib's tests declare for skuld to select by.

/// Marks a test run under a label selection, to check that selection does not leak into re-exec'd children.
#[skuld::label]
pub const REEXEC_SELFCHECK: skuld::Label;

/// Selects the tests that unshare namespaces and mounts (the `NAMESPACES` group).
#[skuld::label]
pub const NAMESPACES: skuld::Label;

/// Selects the path-resolution canaries and surveys (the `PATH_PROBES` group).
#[skuld::label]
pub const PATH_PROBES: skuld::Label;

/// Selects the probes that elevate through `ShellExecuteEx` (the `SHELL_EXECUTE` group).
#[skuld::label]
pub const SHELL_EXECUTE: skuld::Label;

/// Selects the probes that execute batch files through `ShellExecuteEx` (the `SHELL_PROBES` group).
#[skuld::label]
pub const SHELL_PROBES: skuld::Label;

/// Selects the token and logon probes (the `ELEVATION_ROUTES` group).
#[skuld::label]
pub const ELEVATION_ROUTES: skuld::Label;

/// Selects the one `SHELL_PROBES` probe that runs alone: a trailing dot on an existing extensionless file.
#[skuld::label]
pub const ISOLATED_TRAILING_DOT: skuld::Label;

/// Selects the one `SHELL_PROBES` probe that runs alone: `PATHEXT` against an existing extensionless file.
#[skuld::label]
pub const ISOLATED_PATHEXT_PRECEDENCE: skuld::Label;

/// Selects the one `SHELL_PROBES` probe that runs alone: whether an existing extensionless file ever launches.
#[skuld::label]
pub const ISOLATED_EXISTING_EXTENSIONLESS: skuld::Label;
