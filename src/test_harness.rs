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

/// Selects the `SETUID` group's tests.
#[skuld::label]
pub const SETUID: skuld::Label;

/// Selects the setuid test that is also run as root (the `setuid-root` lane).
#[skuld::label]
pub const SETUID_ROOT: skuld::Label;

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

/// Isolated `SHELL_PROBES` probe: a trailing dot on an existing extensionless file.
#[skuld::label]
pub const ISOLATED_TRAILING_DOT: skuld::Label;

/// Isolated `SHELL_PROBES` probe: `PATHEXT` against an existing extensionless file.
#[skuld::label]
pub const ISOLATED_PATHEXT_PRECEDENCE: skuld::Label;

/// Isolated `SHELL_PROBES` probe: whether an existing extensionless file ever launches.
#[skuld::label]
pub const ISOLATED_EXISTING_EXTENSIONLESS: skuld::Label;

/// Selects the `CGROUP` group's tests, and the tests whose names contain `cgroup`.
#[skuld::label]
pub const CGROUP: skuld::Label;

/// Selects the tests that a drop after a reap still kills a cgroup's tree.
#[skuld::label]
pub const CGROUP_DROP: skuld::Label;
