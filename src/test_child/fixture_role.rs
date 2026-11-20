//! The roles the lib's test binary plays when a test re-runs it as a fixture process. [`main`](crate)
//! calls [`run_if_requested`] before the runner starts. [`FixtureRole::argv`] is the one place a flag
//! becomes an argument, and [`ROLES`] is the one place a flag is dispatched, to the first role with it. A
//! role left out of [`ROLES`] is never dispatched, so [`FixtureRole::argv`] asserts that exactly one role
//! in the table has its flag.
//!
//! The product's own helper launches (the elevation shim, the console-event proxy) are dispatched by
//! `main` itself, ahead of these. They are the product's [`role`](crate::role)s; these are not.

use std::ffi::{OsStr, OsString};

/// A fixture process the test binary can be re-run as.
pub(crate) struct FixtureRole {
    flag: &'static str,
    run: fn(&[OsString]) -> !,
}

impl FixtureRole {
    /// `run` gets the arguments after `flag` and ends the process by its own means.
    pub(crate) const fn new(flag: &'static str, run: fn(&[OsString]) -> !) -> Self {
        Self { flag, run }
    }

    /// The arguments, after the test binary's path, that start this role with `rest`.
    pub(crate) fn argv(&self, rest: &[&OsStr]) -> Vec<OsString> {
        assert_eq!(
            ROLES.iter().filter(|role| role.flag == self.flag).count(),
            1,
            "ROLES must hold the fixture role {:?} once: a process started with it would run no role, or another's",
            self.flag
        );
        std::iter::once(OsString::from(self.flag))
            .chain(rest.iter().map(|&arg| arg.to_owned()))
            .collect()
    }

    /// This test binary, as a command (see [`test_reexec::command`](crate::test_reexec::command)) that
    /// starts this role with `rest`.
    pub(crate) fn command(&self, rest: &[&OsStr]) -> std::process::Command {
        let mut command = crate::test_reexec::command(std::env::current_exe().expect("current_exe"));
        command.args(self.argv(rest));
        command
    }
}

static ROLES: &[&FixtureRole] = &[
    #[cfg(target_os = "linux")]
    &crate::elevation::shim::owner_helper::ROLE,
    &super::blocked_tree_root::ROLE,
    &super::signal_tree::ROOT,
    &super::signal_tree::LEAF,
    #[cfg(target_os = "linux")]
    &super::zombie_leader_root::ROLE,
];

/// Plays the role named by argument 1, if any; does not return when it does.
pub(crate) fn run_if_requested() {
    let args: Vec<OsString> = std::env::args_os().collect();
    let Some(flag) = args.get(1) else { return };
    if let Some(role) = ROLES.iter().find(|role| flag == role.flag) {
        (role.run)(&args[2..])
    }
}
