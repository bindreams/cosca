//! The environment a unix child gets, built in the parent: this process's, changed by the command's
//! ops. The one reading of it that the program lookup ([`super::lookup`]) and the Linux spawn's env block
//! share, so the `PATH` that is searched is the `PATH` the child has.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use crate::command::{Command, EnvOp};

/// The environment `cmd`'s child gets, read from this process's once: its environment with `cmd`'s ops
/// applied, then the nesting marker if the spawn gives one (see [`child_env_over`] for the form). The
/// marker is decided here, from the same reading, so that the program is searched for over the `PATH` the
/// child has: the marker dedups an environment that carries `PATH` twice.
pub(super) fn child_env_of(cmd: &Command) -> Vec<(OsString, OsString)> {
    let inherited: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let marker_present = inherited.iter().any(|(key, _)| key == crate::containment::NESTED_ENV);
    let marker = crate::containment::marks_child_environment(&cmd.contain_request(), marker_present);
    child_env_over(inherited.into_iter(), cmd.env_ops(), marker)
}

/// `inherited` with `ops` applied in order, then the nesting marker if `marker`, as std gives it to a
/// child: in key order and without duplicates when anything changes it, and with every `name=value` entry
/// as it is (in `environ`'s order, duplicates kept) when nothing does. An entry with no `=` is not a
/// variable and is dropped, as std drops it under any env op.
pub(super) fn child_env_over(
    inherited: impl Iterator<Item = (OsString, OsString)>,
    ops: &[EnvOp],
    marker: bool,
) -> Vec<(OsString, OsString)> {
    if ops.is_empty() && !marker {
        return inherited.collect();
    }
    let mut env: BTreeMap<OsString, OsString> = inherited.collect();
    for op in ops {
        match op {
            EnvOp::Set(key, value) => {
                env.insert(key.clone(), value.clone());
            }
            EnvOp::Remove(key) => {
                env.remove(key);
            }
            EnvOp::Clear => env.clear(),
        }
    }
    if marker {
        env.insert(OsString::from(crate::containment::NESTED_ENV), OsString::from("1"));
    }
    env.into_iter().collect()
}

/// The `PATH` of `env`: the first entry, as `getenv` reads it. `None` when it has none.
pub(super) fn path_of(env: &[(OsString, OsString)]) -> Option<&OsStr> {
    env.iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_os_str())
}
