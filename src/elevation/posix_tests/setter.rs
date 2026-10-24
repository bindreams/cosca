//! An elevated program is named by argv[0] alone: `executable()` and `raw_executable()` are
//! refused on every POSIX backend, root or not, before anything is read or run.

use super::super::rewrite_with_host;
use super::cwd::every_backend_host;
use super::rewrite_tests::{derived_argv, macos_gui_host};
use crate::command::Command;
use crate::elevation::pkexec::PkexecVersion;
use crate::elevation::plan::Host;
use crate::elevation::{ArgvRefusals, Auth, Backend, Secret};
use crate::error::Error;
use crate::Stdio;

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

/// A second reason to refuse the request, which the setter refusal must come ahead of: it edits
/// the command or the host, for the backend named. Where it has no meaning for that backend it
/// leaves both alone.
type Fault = fn(&mut Command, &mut Host, Backend);

/// Each [`Fault`]. A leading-dash program under pkexec is a `programs` entry instead.
const FAULTS: &[(&str, Fault)] = &[
    ("no other fault", |_, _, _| {}),
    // Refused by the macOS gate alone.
    ("a relative current_dir", |c, _, _| {
        c.current_dir("sub");
    }),
    ("fd 3", |c, _, _| {
        c.fd(3, Stdio::pipe_out()).unwrap();
    }),
    ("env_clear", |c, _, _| {
        c.env_clear();
    }),
    ("Auth::Stdin with a caller-set stdin", |c, _, backend| {
        if backend == Backend::Sudo {
            c.elevation_auth(Auth::Stdin(Secret::new("pw")));
            c.stdin(Stdio::pipe()).unwrap();
        }
    }),
    // Refused by the planner, after the gate.
    ("a pkexec too old for --keep-cwd", |_, host, _| {
        host.pkexec_version = PkexecVersion::Parsed {
            version: "0.105".into(),
            release: None,
        };
    }),
];

/// `set` names `program` on a command whose argv[0] is that program too, under every backend,
/// root or not and with every [`Fault`]; each must be refused in that backend's words. Every
/// case runs, so a misplaced rule is reported with each fault it lets ahead.
fn assert_refused(setter: &str, set: fn(&mut Command, &str), programs: &[&str]) {
    let mut wrong = Vec::new();
    for elevated in [false, true] {
        for (name, backend, auth, host, words) in backends(elevated) {
            for &program in programs {
                for &(fault, apply) in FAULTS {
                    let mut c = Command::new();
                    c.args([program, "-u"])
                        .elevation_backend(backend)
                        .elevation_auth(auth.clone());
                    set(&mut c, program);
                    let mut host = host.clone();
                    apply(&mut c, &mut host, backend);
                    let at = format!("{name}, elevated={elevated}, {setter}({program:?}), {fault}");
                    match rewrite_with_host(&mut c, &host) {
                        Err(Error::Unsupported { op, platform, detail }) => {
                            let want_op = format!("{} of a program set by {setter}()", words.op_prefix);
                            if (platform, &op, &detail) != (words.platform, &want_op, &words.setter.to_owned()) {
                                wrong.push(format!("{at}: refused as {op:?}: {detail}"));
                            }
                        }
                        Err(other) => wrong.push(format!("{at}: expected Unsupported, got {other}")),
                        Ok(rw) => wrong.push(format!("{at}: accepted as {:?}", derived_argv(&rw))),
                    }
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} cases:
{}",
        wrong.len(),
        wrong.join(
            "
"
        )
    );
}

/// Mutant: the gate's setter rule matches `raw_executable()` alone.
#[skuld::test]
fn an_elevated_executable_is_refused() {
    assert_refused(
        "executable",
        |c, p| {
            c.executable(p);
        },
        &["/usr/bin/id", "id", "-x"],
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
        &["/usr/bin/id", "tool", "-x"],
    );
}
