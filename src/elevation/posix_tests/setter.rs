//! An elevated program is named by argv[0] alone: `executable()` and `raw_executable()` are
//! refused on every POSIX backend, root or not, before anything is read or run.

use super::super::rewrite_with_host;
use super::cwd::every_backend_host;
use super::rewrite_tests::{derived_argv, macos_gui_host};
use crate::command::Command;
use crate::elevation::plan::Host;
use crate::elevation::{ArgvRefusals, Auth, Backend};
use crate::error::Error;

/// Each backend a host can plan, as `(name, backend, auth, host, the words it refuses in)`.
fn backends(elevated: bool) -> Vec<(&'static str, Backend, Auth, Host, &'static ArgvRefusals)> {
    let cli = || Host {
        elevated,
        ..every_backend_host()
    };
    let posix = &super::super::ARGV_REFUSALS;
    vec![
        ("sudo", Backend::Sudo, Auth::NonInteractive, cli(), posix),
        ("doas", Backend::Doas, Auth::NonInteractive, cli(), posix),
        ("pkexec", Backend::Pkexec, Auth::Gui, cli(), posix),
        (
            "osascript",
            Backend::Auto,
            Auth::Gui,
            macos_gui_host(elevated),
            &crate::elevation::macos::ARGV_REFUSALS,
        ),
    ]
}

/// `set` names `program` on a command whose argv[0] is that program too, under every backend,
/// root or not; each must be refused in that backend's words. A relative `current_dir`, which
/// the macOS gate refuses on its own, must not come first.
fn assert_refused(setter: &str, set: fn(&mut Command, &str), programs: &[&str]) {
    for elevated in [false, true] {
        for (name, backend, auth, host, words) in backends(elevated) {
            for &program in programs {
                for cwd in [None, Some("sub")] {
                    let mut c = Command::new();
                    c.args([program, "-u"])
                        .elevation_backend(backend)
                        .elevation_auth(auth.clone());
                    set(&mut c, program);
                    if let Some(d) = cwd {
                        c.current_dir(d);
                    }
                    let at = format!("{name}, elevated={elevated}, {setter}({program:?}), cwd={cwd:?}");
                    match rewrite_with_host(&mut c, &host) {
                        Err(Error::Unsupported { op, platform, detail }) => {
                            assert_eq!(platform, words.platform, "{at}");
                            assert_eq!(
                                op,
                                format!("{} of a program set by {setter}()", words.op_prefix),
                                "{at}"
                            );
                            assert_eq!(detail, words.setter, "{at}");
                        }
                        Err(other) => panic!("{at}: expected Unsupported, got {other}"),
                        Ok(rw) => panic!("{at}: accepted as {:?}", derived_argv(&rw)),
                    }
                }
            }
        }
    }
}

/// Mutant: the gate's setter rule matches `raw_executable()` alone.
#[skuld::test]
fn an_elevated_executable_is_refused() {
    assert_refused(
        "executable",
        |c, p| {
            c.executable(p);
        },
        &["/usr/bin/id", "id"],
    );
}

/// Mutant: the gate's setter rule matches `executable()` alone.
#[skuld::test]
fn an_elevated_raw_executable_is_refused() {
    assert_refused(
        "raw_executable",
        |c, p| {
            c.raw_executable(p);
        },
        &["/usr/bin/id", "tool"],
    );
}
