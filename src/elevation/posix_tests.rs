use super::build_argv;
use crate::elevation::{Auth, Backend};
use std::ffi::{OsStr, OsString};

fn s(v: &[&str]) -> Vec<OsString> {
    v.iter().map(|x| OsString::from(*x)).collect()
}
fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
        .collect()
}

#[test]
fn sudo_noninteractive_names_env_in_preserve_env_with_terminator() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("/usr/bin/systemctl"),
        &s(&["restart", "nginx"]),
        &env(&[("FOO", "bar")]),
    )
    .unwrap();
    assert_eq!(
        argv,
        s(&[
            "/usr/bin/sudo",
            "-n",
            "--preserve-env=FOO",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx"
        ])
    );
    // The VALUE never appears in argv (it is set in sudo's own env by the rewrite).
    assert!(!argv.iter().any(|a| a.to_string_lossy().contains("bar")));
}

#[test]
fn sudo_preserve_env_joins_multiple_names() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("id"),
        &[],
        &env(&[("A", "1"), ("B", "2")]),
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-n", "--preserve-env=A,B", "--", "id"]));
}

#[test]
fn sudo_interactive_no_env_has_no_flags() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::Interactive,
        OsStr::new("id"),
        &s(&["-u"]),
        &[],
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "--", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::Stdin(crate::elevation::Secret::new("pw")),
        OsStr::new("id"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-S", "--", "id"]));
}

#[test]
fn sudo_askpass_uses_dash_a() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::Askpass("/usr/bin/ssh-askpass".into()),
        OsStr::new("id"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-A", "--", "id"]));
}

#[test]
fn sudo_rejects_an_unforwardable_env_name() {
    for bad in [("A,B", "1"), ("A=C", "1"), ("PÄTH", "1"), ("", "1"), ("1BAD", "1")] {
        let r = build_argv(
            Backend::Sudo,
            OsStr::new("/usr/bin/sudo"),
            &Auth::NonInteractive,
            OsStr::new("id"),
            &[],
            &env(&[bad]),
        );
        assert!(
            matches!(r, Err(crate::error::Error::Unsupported { .. })),
            "expected reject for {bad:?}"
        );
    }
}

#[test]
fn doas_noninteractive_no_env_emits_dash_n() {
    let argv = build_argv(
        Backend::Doas,
        OsStr::new("/usr/bin/doas"),
        &Auth::NonInteractive,
        OsStr::new("id"),
        &s(&["-u"]),
        &[],
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/doas", "-n", "--", "id", "-u"]));
}

#[test]
fn run0_forces_pipe_and_forwards_env_via_setenv() {
    let argv = build_argv(
        Backend::Run0,
        OsStr::new("/usr/bin/run0"),
        &Auth::NonInteractive,
        OsStr::new("id"),
        &[],
        &env(&[("A", "1"), ("B", "2")]),
    )
    .unwrap();
    assert_eq!(
        argv,
        s(&[
            "/usr/bin/run0",
            "--pipe",
            "--no-ask-password",
            "--setenv=A=1",
            "--setenv=B=2",
            "--",
            "id"
        ])
    );
}

#[test]
fn run0_rejects_an_unforwardable_env_name() {
    let r = build_argv(
        Backend::Run0,
        OsStr::new("/usr/bin/run0"),
        &Auth::NonInteractive,
        OsStr::new("id"),
        &[],
        &env(&[("A=B", "1")]),
    );
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
}

#[test]
fn pkexec_gui_disables_internal_agent_and_uses_no_terminator() {
    // No `--` for pkexec (its option loop mis-parses it); --disable-internal-agent pins
    // the graphical-only contract.
    let argv = build_argv(
        Backend::Pkexec,
        OsStr::new("/usr/bin/pkexec"),
        &Auth::Gui,
        OsStr::new("id"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(argv, s(&["/usr/bin/pkexec", "--disable-internal-agent", "id"]));
    assert!(
        !argv.iter().any(|a| a == &OsString::from("--")),
        "pkexec must not emit a -- terminator"
    );
}

#[test]
fn pkexec_rejects_a_leading_dash_program() {
    // With no `--` shield, a leading-dash program would be mis-parsed as a pkexec option.
    let r = build_argv(
        Backend::Pkexec,
        OsStr::new("/usr/bin/pkexec"),
        &Auth::Gui,
        OsStr::new("-prog"),
        &[],
        &[],
    );
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
    // An `=` in the program path is safe under pkexec (no assignment parsing).
    let ok = build_argv(
        Backend::Pkexec,
        OsStr::new("/usr/bin/pkexec"),
        &Auth::Gui,
        OsStr::new("/opt/we=ird"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(ok, s(&["/usr/bin/pkexec", "--disable-internal-agent", "/opt/we=ird"]));
}

#[test]
fn terminator_protects_a_program_with_equals_or_leading_dash() {
    let eq = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("/opt/we=ird"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(eq, s(&["/usr/bin/sudo", "-n", "--", "/opt/we=ird"]));
    let dash = build_argv(
        Backend::Doas,
        OsStr::new("/usr/bin/doas"),
        &Auth::Interactive,
        OsStr::new("-prog"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(dash, s(&["/usr/bin/doas", "--", "-prog"]));
}

#[cfg(unix)]
#[test]
fn resolve_in_path_var_finds_an_executable_in_a_temp_dir() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("sudo");
    std::fs::write(&f, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let got = super::resolve_in_path_var(dir.path().as_os_str(), "sudo");
    assert_eq!(got, Some(f));
}

#[cfg(unix)]
#[test]
fn resolve_skips_a_non_executable_same_named_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("sudo");
    std::fs::write(&f, b"not exec").unwrap(); // mode 0644 — no exec bit
    let got = super::resolve_in_path_var(dir.path().as_os_str(), "sudo");
    assert_eq!(got, None, "a non-executable file named sudo must be skipped");
}

#[cfg(unix)]
#[test]
fn empty_path_element_is_not_resolved_from_cwd() {
    // `resolve_in_path_var` is PURE (it takes the PATH string as a parameter), so
    // this is tested directly against explicit PATH values — no process-global
    // chdir, and thus no cross-test race and no leaked CWD on a mid-test panic.

    // A single empty PATH element must be skipped, never treated as "." (CWD).
    assert_eq!(super::resolve_in_path_var(OsStr::new(""), "sudo"), None);

    // A mid-string empty element is skipped too: put a non-matching dir, then the
    // empty element, then the real match — so the empty branch is actually exercised
    // (matching in an earlier element would let a skip bug pass silently).
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sudo = dir.path().join("sudo");
    std::fs::write(&sudo, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_var = format!("/nonexistent::{}", dir.path().display());
    let got = super::resolve_in_path_var(OsStr::new(&path_var), "sudo");
    assert_eq!(
        got,
        Some(sudo),
        "a mid-string empty PATH element must be skipped, not resolved"
    );

    // A PATH consisting only of empty elements resolves nothing.
    assert_eq!(super::resolve_in_path_var(OsStr::new(":"), "sudo"), None);
}

const FIXTURE_RELATIVE_PATH_ELEMENTS_MARKER: &str = "COSCA_FIXTURE_RELATIVE_PATH_ELEMENTS";

/// A relative `PATH` element (`relbin`, `.`) names a directory under the cwd at detection time, and
/// a backend found there would be exec-checked against one directory and run from another — or
/// not found by path at all. The planted `relbin/sudo` sits in the fixture's real cwd, so skipping
/// it is observable only if the element is refused rather than merely missed.
#[cfg(unix)]
#[test]
fn relative_path_elements_are_never_resolved() {
    use std::os::unix::fs::PermissionsExt;
    let cwd = tempfile::tempdir().unwrap();
    for dir in ["relbin", "abs"] {
        let sudo = cwd.path().join(dir).join("sudo");
        std::fs::create_dir_all(sudo.parent().unwrap()).unwrap();
        std::fs::write(&sudo, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    crate::test_child::run_fixture_with_cwd(
        crate::test_child::fixture_path!(fixture_relative_path_elements_are_never_resolved),
        cwd.path(),
        FIXTURE_RELATIVE_PATH_ELEMENTS_MARKER,
    );
}

/// The child half of [`relative_path_elements_are_never_resolved`], run with the prepared
/// directory as its real cwd; inert in an ordinary suite run.
#[cfg(unix)]
#[test]
fn fixture_relative_path_elements_are_never_resolved() {
    let Some(cwd) = crate::test_child::expected_cwd(FIXTURE_RELATIVE_PATH_ELEMENTS_MARKER) else {
        return;
    };
    for relative in ["relbin", ".", "./relbin"] {
        assert_eq!(
            super::resolve_in_path_var(OsStr::new(relative), "sudo"),
            None,
            "{relative}"
        );
    }
    let abs = cwd.join("abs");
    let path_var = format!("relbin:{}", abs.display());
    assert_eq!(
        super::resolve_in_path_var(OsStr::new(&path_var), "sudo"),
        Some(abs.join("sudo")),
        "a relative element must be skipped, not resolved ahead of an absolute one"
    );
}

#[cfg(unix)]
mod rewrite_tests {
    use super::super::{password_line, rewrite_with_host, PendingPassword, PosixRewrite};
    use crate::command::{Command, CommandInput, EnvOp};
    use crate::elevation::plan::{BackendSet, Host, Os};
    use crate::elevation::{Auth, Backend, ElevatedStdio, ElevatedVia};
    use crate::error::Error;
    use crate::stdio::{Fd, ResolvedStdio, Stdio};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn sudo_host() -> Host {
        Host {
            elevated: false,
            has_tty: true,
            available: BackendSet {
                run0: None,
                sudo: Some(PathBuf::from("/usr/bin/sudo")),
                doas: Some(PathBuf::from("/usr/bin/doas")),
                pkexec: None,
                osascript: None,
            },
            os: Os::Unix,
            arg_max: None,
        }
    }

    fn derived_argv(rw: &PosixRewrite) -> Vec<OsString> {
        match rw.derived.as_ref().expect("derived").input() {
            CommandInput::Argv(v) => v.clone(),
            other => panic!("expected Argv, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_is_nondestructive_and_reports_wrapped_backend() {
        let mut c = Command::new();
        c.args(["id", "-u"])
            .env("LD_PRELOAD", "/evil.so")
            .env("FOO", "bar")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        let report = rw.report.as_ref().expect("report");
        assert_eq!(report.via, ElevatedVia::Wrapped(Backend::Sudo));
        assert_eq!(report.stripped_env, vec![OsString::from("LD_PRELOAD")]);
        assert_eq!(report.stdio, ElevatedStdio::Passthrough);
        let a = derived_argv(&rw);
        assert_eq!(a[0], OsString::from("/usr/bin/sudo"));
        assert!(a.contains(&OsString::from("--preserve-env=FOO")));
        // Value is set in sudo's own env, never in argv; LD_PRELOAD is stripped everywhere.
        assert!(!a.iter().any(|x| x.to_string_lossy().contains("bar")));
        assert!(!a.iter().any(|x| x.to_string_lossy().contains("LD_PRELOAD")));
        let derived = rw.derived.as_ref().unwrap();
        assert!(derived
            .env_ops()
            .iter()
            .any(|o| matches!(o, EnvOp::Set(k, v) if k == "FOO" && v == "bar")));
        assert!(!derived
            .env_ops()
            .iter()
            .any(|o| matches!(o, EnvOp::Set(k, _) if k == "LD_PRELOAD")));
        // The caller's Command is untouched (no double-wrap on reuse).
        assert!(matches!(c.input(), CommandInput::Argv(v) if v == &[OsString::from("id"), OsString::from("-u")]));
        assert_eq!(c.env_ops().len(), 2, "caller env ops must be intact");
    }

    #[test]
    fn rewrite_twice_yields_identical_derived_argv() {
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let a1 = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).unwrap());
        let a2 = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).unwrap());
        assert_eq!(a1, a2, "reusing an elevated Command must not double-wrap");
    }

    #[test]
    fn env_remove_or_clear_plus_elevate_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"])
            .env_clear()
            .env("KEEP", "1")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        assert!(matches!(
            rewrite_with_host(&mut c, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
        let mut c2 = Command::new();
        c2.args(["id"])
            .env("A", "1")
            .env_remove("A")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        assert!(matches!(
            rewrite_with_host(&mut c2, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn doas_or_pkexec_with_env_is_unsupported() {
        let doas_host = Host {
            available: BackendSet {
                run0: None,
                sudo: None,
                doas: Some(PathBuf::from("/usr/bin/doas")),
                pkexec: None,
                osascript: None,
            },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"])
            .env("A", "1")
            .elevation_backend(Backend::Doas)
            .elevation_auth(Auth::NonInteractive);
        assert!(matches!(
            rewrite_with_host(&mut c, &doas_host),
            Err(Error::Unsupported { .. })
        ));

        let pk_host = Host {
            available: BackendSet {
                run0: None,
                sudo: None,
                doas: None,
                pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
                osascript: None,
            },
            ..sudo_host()
        };
        let mut c2 = Command::new();
        c2.args(["id"])
            .env("A", "1")
            .elevation_backend(Backend::Pkexec)
            .elevation_auth(Auth::Gui);
        assert!(matches!(
            rewrite_with_host(&mut c2, &pk_host),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn run0_forwards_env_via_setenv() {
        let host = Host {
            available: BackendSet {
                run0: Some(PathBuf::from("/usr/bin/run0")),
                sudo: None,
                doas: None,
                pkexec: None,
                osascript: None,
            },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"])
            .env("A", "1")
            .elevation_backend(Backend::Run0)
            .elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &host).expect("rewrite");
        assert!(derived_argv(&rw).contains(&OsString::from("--setenv=A=1")));
        assert!(!rw
            .derived
            .as_ref()
            .unwrap()
            .env_ops()
            .iter()
            .any(|o| matches!(o, EnvOp::Set(k, _) if k == "A")));
    }

    #[test]
    fn askpass_path_is_carried_in_the_backend_env() {
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::Askpass(PathBuf::from("/usr/bin/ssh-askpass")));
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert!(rw
            .derived
            .as_ref()
            .unwrap()
            .env_ops()
            .iter()
            .any(|o| matches!(o, EnvOp::Set(k, v) if k == "SUDO_ASKPASS" && v == "/usr/bin/ssh-askpass")));
    }

    #[test]
    fn stdin_auth_wires_fd0_to_a_file_and_defers_the_write() {
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        // Stdio::from_file(reader) resolves to ResolvedStdio::File(_).
        assert!(matches!(
            rw.derived.as_ref().unwrap().fds().get(&Fd::STDIN),
            Some(ResolvedStdio::File(_))
        ));
        assert!(
            rw.password_write.is_some(),
            "the password write is deferred to after spawn"
        );
        // fd0 is the password channel, not the caller's stdin — reported honestly.
        assert_eq!(rw.report.as_ref().unwrap().stdio, ElevatedStdio::StdinConsumed);
    }

    #[test]
    fn stdin_auth_with_caller_configured_fd0_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        c.stdin(Stdio::pipe()).unwrap();
        assert!(matches!(
            rewrite_with_host(&mut c, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn fd_ge_3_elevated_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        c.fd(3, Stdio::pipe_out()).unwrap();
        assert!(matches!(
            rewrite_with_host(&mut c, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn run0_plus_contain_is_unsupported() {
        let host = Host {
            available: BackendSet {
                run0: Some(PathBuf::from("/usr/bin/run0")),
                sudo: None,
                doas: None,
                pkexec: None,
                osascript: None,
            },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"])
            .elevation_backend(Backend::Run0)
            .elevation_auth(Auth::NonInteractive)
            .contain();
        assert!(matches!(
            rewrite_with_host(&mut c, &host),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn commandline_elevated_is_unsupported() {
        let mut c = Command::new();
        c.commandline("id -u")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        assert!(matches!(
            rewrite_with_host(&mut c, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn distinct_argv0_with_executable_is_unsupported() {
        let mut c = Command::new();
        c.executable("/bin/busybox")
            .args(["sh", "-c", "true"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        assert!(matches!(
            rewrite_with_host(&mut c, &sudo_host()),
            Err(Error::Unsupported { .. })
        ));
    }

    fn elevated_sudo_host() -> Host {
        Host {
            elevated: true,
            ..sudo_host()
        }
    }

    #[test]
    fn already_elevated_requested_sanitizes_into_a_derived_with_no_backend() {
        // The RunAsIs (requested but already elevated) branch: no wrapper, but the
        // sanitizer STILL runs — a dangerous forwarded var must never reach the root
        // child, and the report carries the real stripped list.
        let mut c = Command::new();
        c.args(["id", "-u"])
            .env("LD_PRELOAD", "/evil.so")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &elevated_sudo_host()).expect("rewrite");
        // A derived command IS built (non-destructive), but there is no backend wrapper.
        let derived = rw
            .derived
            .as_ref()
            .expect("already-elevated still derives a sanitized command");
        assert!(rw.backend_path.is_none());
        assert!(rw.password_write.is_none());
        let report = rw.report.as_ref().unwrap();
        assert_eq!(report.via, ElevatedVia::AlreadyElevated);
        assert_eq!(report.stripped_env, vec![OsString::from("LD_PRELOAD")]);
        // The derived program is the ORIGINAL command, not a backend.
        assert!(matches!(derived.input(), CommandInput::Argv(v) if v == &[OsString::from("id"), OsString::from("-u")]));
        // The dangerous var is gone from the derived env even under root.
        assert!(!derived
            .env_ops()
            .iter()
            .any(|o| matches!(o, EnvOp::Set(k, _) if k == "LD_PRELOAD")));
        // The caller's Command is left untouched.
        assert_eq!(c.env_ops().len(), 1, "caller env ops must be intact");
    }

    #[test]
    fn structural_config_gates_are_privilege_independent() {
        // Same structurally-invalid requests must be rejected whether or not the caller
        // is already elevated (Config gates run before the RunAsIs short-circuit).
        for host in [sudo_host(), elevated_sudo_host()] {
            let mut a = Command::new();
            a.args(["id"])
                .elevation_backend(Backend::Sudo)
                .elevation_auth(Auth::NonInteractive);
            a.fd(3, Stdio::pipe_out()).unwrap();
            assert!(
                matches!(rewrite_with_host(&mut a, &host), Err(Error::Unsupported { .. })),
                "fd>=3 must reject with elevated={}",
                host.elevated
            );

            let mut b = Command::new();
            b.args(["id"])
                .env("A", "1")
                .elevation_backend(Backend::Doas)
                .elevation_auth(Auth::NonInteractive);
            let doas_host = Host {
                available: BackendSet {
                    run0: None,
                    sudo: None,
                    doas: Some(PathBuf::from("/usr/bin/doas")),
                    pkexec: None,
                    osascript: None,
                },
                ..host.clone()
            };
            assert!(
                matches!(rewrite_with_host(&mut b, &doas_host), Err(Error::Unsupported { .. })),
                ".env()+doas must reject with elevated={}",
                host.elevated
            );

            let mut d = Command::new();
            d.commandline("id -u")
                .elevation_backend(Backend::Sudo)
                .elevation_auth(Auth::NonInteractive);
            assert!(
                matches!(rewrite_with_host(&mut d, &host), Err(Error::Unsupported { .. })),
                "commandline() must reject with elevated={}",
                host.elevated
            );
        }
    }

    #[test]
    fn password_line_is_presized_and_appends_a_newline() {
        // A realloc while appending '\n' would leave an un-zeroized plaintext copy in the
        // freed buffer. `with_capacity(len+1)` guarantees AT LEAST len+1 so the push never
        // reallocates; assert the invariant (capacity >= len), not an exact capacity.
        let secret = b"hunter2";
        let line = password_line(secret);
        assert_eq!(line, b"hunter2\n");
        assert!(
            line.capacity() >= line.len(),
            "buffer must be pre-sized so the push never reallocates"
        );
    }

    #[test]
    fn write_after_spawn_writes_password_and_newline_then_eof() {
        use std::io::Read;
        let (mut reader, writer) = std::io::pipe().unwrap();
        let pp = PendingPassword {
            writer,
            secret: crate::elevation::Secret::new("pw"),
        };
        pp.write_after_spawn().expect("password delivered");
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"pw\n", "the secret plus a trailing newline, then EOF");
    }

    #[test]
    fn write_after_spawn_is_ok_when_the_backend_never_reads_fd0() {
        // A cached-credential / NOPASSWD sudo closes fd0 without reading: not an AuthFailed.
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let pp = PendingPassword {
            writer,
            secret: crate::elevation::Secret::new("pw"),
        };
        assert!(
            pp.write_after_spawn().is_ok(),
            "reader-gone with zero bytes written is not a failure"
        );
    }

    #[test]
    fn write_after_spawn_delivers_a_password_larger_than_the_pipe_buffer() {
        // Forces the partial-write path: the buffer fills, `write` returns WouldBlock after
        // a partial write, and the writer must poll for writability (a real fd event, no
        // timer) and finish — never truncate and report a false success.
        use std::io::Read;
        let (mut reader, writer) = std::io::pipe().unwrap();
        let secret_bytes = vec![b'x'; 1 << 20]; // 1 MiB, far exceeds the ~64 KiB pipe buffer
        let pp = PendingPassword {
            writer,
            secret: crate::elevation::Secret::new(secret_bytes.clone()),
        };
        let drain = std::thread::spawn(move || {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).unwrap();
            buf
        });
        pp.write_after_spawn().expect("large password delivered in full");
        let got = drain.join().unwrap();
        assert_eq!(got.len(), secret_bytes.len() + 1);
        assert_eq!(&got[..secret_bytes.len()], &secret_bytes[..]);
        assert_eq!(got[secret_bytes.len()], b'\n');
    }

    // ===== macOS graphical elevation, planned on ANY unix host =====

    fn macos_gui_host(elevated: bool) -> Host {
        Host {
            elevated,
            has_tty: false,
            available: BackendSet {
                run0: None,
                sudo: Some(PathBuf::from("/usr/bin/sudo")),
                doas: None,
                pkexec: None,
                osascript: Some(PathBuf::from("/usr/bin/osascript")),
            },
            os: Os::MacOs,
            arg_max: Some(1_048_576),
        }
    }

    #[test]
    fn macos_gui_rewrites_to_osascript() {
        let mut c = Command::new();
        c.args(["/usr/bin/id", "-u"]).elevation_auth(Auth::Gui);
        let rw = rewrite_with_host(&mut c, &macos_gui_host(false)).expect("macos gui rewrite");
        let derived = rw.derived.expect("a derived command");
        let CommandInput::Argv(argv) = derived.input() else {
            panic!("argv expected")
        };
        assert_eq!(argv[0], OsString::from("/usr/bin/osascript"));
        assert_eq!(argv[1], OsString::from("-e"));
        assert!(argv[2].to_str().unwrap().contains("with administrator privileges"));
        assert_eq!(rw.backend_path, Some(PathBuf::from("/usr/bin/osascript")));
        assert!(rw.password_write.is_none());
        let report = rw.report.expect("a report");
        assert_eq!(report.via, ElevatedVia::MacosOsascript);
        assert_eq!(report.stdio, ElevatedStdio::OsascriptRelay);
    }

    #[test]
    fn macos_gui_uses_the_macos_gate_not_the_posix_one() {
        // .contain() is legal under sudo and illegal under osascript; the gate
        // choice is what makes the difference, so assert the macOS message.
        let mut c = Command::new();
        c.args(["/usr/bin/id"]).contain().elevation_auth(Auth::Gui);
        // `PosixRewrite` has no `Debug`, so the error is named rather than the whole
        // Result — the same reason the sibling arms below spell `Ok(_)` out.
        match rewrite_with_host(&mut c, &macos_gui_host(false)) {
            Err(Error::Unsupported { platform, .. }) => assert_eq!(platform, "macos"),
            Err(other) => panic!("expected a macos Unsupported, got {other}"),
            Ok(_) => panic!("expected a macos Unsupported, got a successful rewrite"),
        }
    }

    #[test]
    fn the_macos_gui_gate_is_privilege_independent() {
        // The crate's stated invariant: a structural verdict is a property of the
        // REQUEST, never of ambient privilege. If this flipped, a developer testing
        // as root would see .contain() accepted and ship it, and every unprivileged
        // user would hit a hard Unsupported at runtime.
        for elevated in [false, true] {
            let mut c = Command::new();
            c.args(["/usr/bin/id"]).contain().elevation_auth(Auth::Gui);
            match rewrite_with_host(&mut c, &macos_gui_host(elevated)) {
                Err(Error::Unsupported { platform, .. }) => assert_eq!(platform, "macos"),
                Err(other) => panic!("expected a macos Unsupported (elevated={elevated}), got {other}"),
                Ok(_) => panic!("the verdict must not flip on ambient privilege (elevated={elevated})"),
            }
        }
    }

    #[test]
    fn an_already_root_macos_gui_caller_runs_unwrapped() {
        // With a clean config the short-circuit still applies: no osascript.
        let mut c = Command::new();
        c.args(["/usr/bin/id"]).elevation_auth(Auth::Gui);
        let rw = rewrite_with_host(&mut c, &macos_gui_host(true)).expect("already-root rewrite");
        assert_eq!(rw.report.expect("a report").via, ElevatedVia::AlreadyElevated);
        assert!(rw.backend_path.is_none(), "no wrapper runs when already elevated");
    }

    #[test]
    fn a_forced_backend_with_gui_gets_the_planners_verdict_not_the_trampolines() {
        // Backend::Sudo + Auth::Gui never reaches osascript, so the message must be
        // about the backend pairing, not about the authorization trampoline.
        let mut c = Command::new();
        c.args(["/usr/bin/id"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::Gui);
        match rewrite_with_host(&mut c, &macos_gui_host(false)) {
            Err(Error::Unsupported { detail, .. }) => {
                assert!(detail.contains("Backend::Auto"), "{detail}");
                assert!(!detail.contains("trampoline"), "{detail}");
            }
            Err(other) => panic!("expected Unsupported, got {other}"),
            Ok(_) => panic!("Backend::Sudo + Auth::Gui must not resolve on macOS"),
        }
    }

    #[test]
    fn a_missing_osascript_keeps_the_honest_backend_verdict_through_the_dispatch() {
        // The gate is chosen from the REQUEST, so a missing osascript still takes
        // the macOS gate; it passes on this clean config, and the planner's honest
        // BackendUnavailable then reaches the caller verbatim rather than being
        // pre-empted by a structural complaint.
        let mut host = macos_gui_host(false);
        host.available.osascript = None;
        let mut c = Command::new();
        c.args(["/usr/bin/id"]).elevation_auth(Auth::Gui);
        match rewrite_with_host(&mut c, &host) {
            Err(Error::Elevation { kind, detail }) => {
                assert_eq!(kind, crate::error::ElevationErrorKind::BackendUnavailable);
                assert!(detail.contains("osascript"), "{detail}");
            }
            Err(other) => panic!("expected BackendUnavailable, got {other}"),
            Ok(_) => panic!("a missing osascript must not resolve to a rewrite"),
        }
    }

    #[test]
    fn macos_non_gui_auth_still_takes_the_posix_path() {
        let mut c = Command::new();
        c.args(["/usr/bin/id"]).elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &macos_gui_host(false)).expect("sudo rewrite");
        assert_eq!(rw.backend_path, Some(PathBuf::from("/usr/bin/sudo")));
    }

    /// The elevation rewrite must carry the marker suppression onto the derived command, or the
    /// derived `sudo …` spawn would install a marker its own wrapper immediately destroys.
    /// `.contain()` + `Backend::Sudo` is NOT structurally rejected (only `Run0` is), so this path
    /// is reachable and must be tested through the REAL rewrite, not just the setter/getter pair.
    #[test]
    fn rewrite_suppresses_the_fd_marker_on_the_derived_command_while_keeping_containment() {
        let mut c = Command::new();
        c.args(["id", "-u"])
            .contain_with(crate::ContainMode::Strongest)
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        let derived = rw.derived.as_ref().expect("derived");
        assert!(
            derived.fd_marker_suppressed(),
            "transfer_process_attrs must suppress the fd marker on the derived sudo command, or \
             an elevated contained spawn would claim a guarantee sudo's closefrom destroys"
        );
        assert_eq!(
            derived.contain_request().mode,
            Some(crate::ContainMode::Strongest),
            "the caller's containment REQUEST must still cross the rewrite unchanged — only the \
             fd marker specifically is suppressed, not containment as a whole"
        );
    }

    /// `RunAsIs`'s derived command spawns the ORIGINAL program directly — no `sudo`/`doas`/
    /// `pkexec` wrapper, hence no `closefrom` to destroy the marker. Suppressing it there
    /// would falsely claim a guarantee that already holds; a root process spawning a
    /// contained child on this path must still get the marker.
    #[test]
    fn already_elevated_requested_does_not_suppress_the_fd_marker() {
        let mut c = Command::new();
        c.args(["id", "-u"])
            .contain_with(crate::ContainMode::Strongest)
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &elevated_sudo_host()).expect("rewrite");
        let derived = rw.derived.as_ref().expect("derived");
        assert!(
            !derived.fd_marker_suppressed(),
            "RunAsIs spawns the original program with no wrapper; suppressing the marker here \
             is a false justification and loses setsid-proof containment for no reason"
        );
    }

    // ===== raw_executable(): the wrapper is handed an absolute path =====

    fn exact_tool(cwd: Option<&str>) -> Command {
        let mut c = Command::new();
        c.raw_executable("tool")
            .args(["tool", "-x"])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        c
    }

    /// [`exact_tool`] under `pkexec`, a backend that moves its cwd and so gets a completed path.
    fn pkexec_tool(cwd: Option<&str>) -> Command {
        let mut c = exact_tool(cwd);
        c.elevation_backend(Backend::Pkexec).elevation_auth(Auth::Gui);
        c
    }

    /// `pkexec` searches its own `PATH` for a bare name, so a bare `tool` would load whatever that
    /// search finds instead of the file in the child's working directory.
    #[test]
    fn a_bare_exact_program_reaches_pkexec_completed_against_the_childs_cwd() {
        let rw = rewrite_with_host(&mut pkexec_tool(Some("/work")), &every_backend_host()).expect("rewrite");
        let a = derived_argv(&rw);
        assert!(a.ends_with(&[OsString::from("/work/tool"), "-x".into()]), "{a:?}");
    }

    #[test]
    fn a_bare_exact_program_without_a_cwd_is_completed_against_the_process_cwd() {
        // Reads the process cwd twice (here and in the rewrite); no test in this binary moves it
        // (`tests/no_chdir_guard.rs`), so both readings agree.
        let rw = rewrite_with_host(&mut pkexec_tool(None), &every_backend_host()).expect("rewrite");
        let want = std::env::current_dir().unwrap().join("tool").into_os_string();
        assert!(derived_argv(&rw).contains(&want), "{:?}", derived_argv(&rw));
    }

    /// `RunAsIs` spawns the program itself; it must be the completed one there too.
    #[test]
    fn an_already_elevated_exact_program_is_spawned_as_an_unelevated_one_is() {
        for cwd in [Some("/work"), Some("sub"), None] {
            let rw = super::super::rewrite_with_host_and_cwd(&mut exact_tool(cwd), &elevated_sudo_host(), || {
                panic!("no backend runs, so nothing needs this process's cwd as a path")
            })
            .expect("rewrite");
            let derived = rw.derived.as_ref().expect("derived");
            assert!(
                matches!(derived.executable_spec(), Some(crate::command::ExecutableSpec::Exact(p)) if p == std::path::Path::new("tool")),
                "{:?}",
                derived.executable_spec()
            );
            assert_eq!(derived_argv(&rw), [OsString::from("tool"), "-x".into()]);
            assert_eq!(derived.cwd(), cwd.map(std::path::Path::new));
        }
    }

    #[test]
    fn an_elevated_exact_program_that_names_no_file_is_refused() {
        for n in ["", ".", "dir/"] {
            let mut c = Command::new();
            c.raw_executable(n)
                .args([n])
                .elevation_backend(Backend::Sudo)
                .elevation_auth(Auth::NonInteractive);
            match rewrite_with_host(&mut c, &sudo_host()) {
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
                other => panic!(
                    "{n:?} names no file and must be Io(InvalidInput), got {:?}",
                    other.err()
                ),
            }
        }
    }

    /// The derived command's working directory: absolute, and the directory `program` was
    /// completed against — one reading of the process cwd for both.
    fn assert_runs_where_completed(rw: &PosixRewrite, program: &OsString) {
        let cwd = rw.derived.as_ref().expect("derived").cwd().expect("a pinned cwd");
        assert!(cwd.is_absolute(), "{cwd:?}");
        assert_eq!(Some(cwd), std::path::Path::new(program).parent(), "{program:?}");
    }

    /// Under a wrapper, with a relative `current_dir` or none.
    #[test]
    fn an_elevated_exact_programs_cwd_is_the_directory_it_was_completed_against() {
        for cwd in [Some("sub"), None] {
            let rw = rewrite_with_host(&mut pkexec_tool(cwd), &every_backend_host()).expect("rewrite");
            let a = derived_argv(&rw);
            assert_runs_where_completed(&rw, &a[a.len() - 2]);
        }
    }

    /// A second reading could differ from the first, loading the program from one directory and
    /// running it in another — for every backend that needs a path.
    #[test]
    fn a_rewrite_reads_the_process_cwd_exactly_once() {
        let mut gui = exact_tool(None);
        gui.elevation_backend(Backend::Auto).elevation_auth(Auth::Gui);
        let cases = [(pkexec_tool(None), every_backend_host()), (gui, macos_gui_host(false))];
        for (mut c, host) in cases {
            let reads = std::cell::Cell::new(0);
            let rw = super::super::rewrite_with_host_and_cwd(&mut c, &host, || {
                reads.set(reads.get() + 1);
                Ok(PathBuf::from("/proc-cwd"))
            })
            .expect("rewrite");
            let via = rw.report.as_ref().map(|r| r.via.clone());
            assert_eq!(reads.get(), 1, "{via:?}");
            // A build that re-read the real cwd behind the injected one would pass the count alone.
            let derived = rw.derived.as_ref().expect("derived");
            assert_eq!(derived.cwd(), Some(std::path::Path::new("/proc-cwd")), "{via:?}");
            let argv = derived_argv(&rw);
            // pkexec is handed the completed path; osascript's script `cd`s to the directory.
            assert!(
                argv.iter().any(|a| {
                    let a = a.to_string_lossy();
                    a == "/proc-cwd/tool" || a.contains("cd -P -- /proc-cwd && exec ./tool")
                }),
                "{via:?}: {argv:?}"
            );
        }
    }

    /// Negative control: a `Search` program's relative `current_dir` is passed through.
    #[test]
    fn an_elevated_search_programs_relative_cwd_is_passed_through() {
        let mut c = exact_tool(Some("sub"));
        c.executable("tool");
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert_eq!(
            rw.derived.as_ref().expect("derived").cwd(),
            Some(std::path::Path::new("sub"))
        );
    }

    /// The backend runs in another process and needs a path; a cwd with none fails loudly, with the
    /// OS's kind kept.
    #[test]
    fn an_elevated_exact_program_in_a_cwd_with_no_path_says_why() {
        let r = super::super::rewrite_with_host_and_cwd(&mut pkexec_tool(None), &every_backend_host(), || {
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        });
        match r {
            Err(Error::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(e.to_string().contains("working directory as a path"), "{e}");
                let errno = std::error::Error::source(&e)
                    .and_then(|s| s.downcast_ref::<std::io::Error>())
                    .and_then(std::io::Error::raw_os_error);
                assert_eq!(errno, Some(libc::EACCES), "the errno must survive as the source");
            }
            Err(other) => panic!("expected Io, got {other}"),
            Ok(_) => panic!("a cwd with no path cannot be handed to the backend"),
        }
    }

    /// A host offering every CLI backend, for a request that names one.
    fn every_backend_host() -> Host {
        Host {
            available: BackendSet {
                run0: Some(PathBuf::from("/usr/bin/run0")),
                sudo: Some(PathBuf::from("/usr/bin/sudo")),
                doas: Some(PathBuf::from("/usr/bin/doas")),
                pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
                osascript: None,
            },
            ..sudo_host()
        }
    }

    /// The rewrite with `/proc-cwd` as this process's cwd.
    fn rewrite_at_proc_cwd(c: &mut Command, host: &Host) -> PosixRewrite {
        super::super::rewrite_with_host_and_cwd(c, host, || Ok(PathBuf::from("/proc-cwd"))).expect("rewrite")
    }

    /// Its presence marks a deliberate re-exec of [`fixture_elevated_exact_in_an_unlinked_cwd`].
    const FIXTURE_UNLINKED_CWD_ENV: &str = "COSCA_FIXTURE_UNLINKED_CWD";

    /// Inert in an ordinary suite run. Re-executed by
    /// [`an_elevated_exact_program_in_an_unlinked_cwd_fails_at_the_read`], it waits for one byte on
    /// stdin — sent once its cwd has been removed — then rewrites for `pkexec`.
    #[test]
    fn fixture_elevated_exact_in_an_unlinked_cwd() {
        use std::io::Read;
        if std::env::var_os(FIXTURE_UNLINKED_CWD_ENV).is_none() {
            return;
        }
        std::io::stdin().read_exact(&mut [0u8; 1]).expect("gate byte");
        assert!(std::env::current_dir().is_err(), "precondition: the cwd is unlinked");
        match rewrite_with_host(&mut pkexec_tool(None), &every_backend_host()) {
            Err(Error::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
                assert!(e.to_string().contains("working directory as a path"), "{e}");
            }
            Err(other) => panic!("expected Io(NotFound), got {other}"),
            Ok(_) => panic!("an unlinked cwd has no path to hand pkexec"),
        }
    }

    /// An unlinked cwd has no path on any OS: the read itself fails, with `NotFound`, where an
    /// unsearchable ancestor fails it only on macOS. The cwd is removed from under a child this
    /// test spawned in it, so this process's own cwd never moves.
    #[test]
    fn an_elevated_exact_program_in_an_unlinked_cwd_fails_at_the_read() {
        use std::io::Write;
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("gone");
        std::fs::create_dir(&dir).expect("mkdir");
        let mut child = {
            // Every fork in this binary holds it; see `crate::test_child::run_fixture_with_cwd`.
            let _guard = crate::child::spawn::spawn_lock();
            std::process::Command::new(std::env::current_exe().expect("current_exe"))
                .args([
                    "--test-threads=1",
                    "--exact",
                    crate::test_child::fixture_path!(fixture_elevated_exact_in_an_unlinked_cwd),
                ])
                .env(FIXTURE_UNLINKED_CWD_ENV, "1")
                .current_dir(&dir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the fixture")
        };
        std::fs::remove_dir(&dir).expect("rmdir the fixture's cwd");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"x")
            .expect("release the fixture");
        let out = child.wait_with_output().expect("wait");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `sudo` and `doas` keep the cwd they are started in, so they are handed `./tool` and started
    /// in the caller's directory: they read the name against that directory OBJECT after
    /// authenticating, and a rename of an ancestor during the prompt cannot swap the file.
    #[test]
    fn a_cwd_keeping_backend_gets_the_program_anchored_to_the_inherited_cwd() {
        for backend in [Backend::Sudo, Backend::Doas] {
            for cwd in [None, Some("sub"), Some("/work")] {
                let mut c = exact_tool(cwd);
                c.elevation_backend(backend);
                let rw = super::super::rewrite_with_host_and_cwd(&mut c, &every_backend_host(), || {
                    panic!("{backend:?} needs no path to this process's cwd")
                })
                .expect("rewrite");
                let a = derived_argv(&rw);
                assert!(
                    a.ends_with(&[OsString::from("--"), "./tool".into(), "-x".into()]),
                    "{backend:?} {cwd:?}: {a:?}"
                );
                assert_eq!(
                    rw.derived.as_ref().expect("derived").cwd(),
                    cwd.map(std::path::Path::new)
                );
            }
        }
    }

    /// `pkexec` and `run0` start the program in a directory of their own choosing, so they get an
    /// absolute path, completed against one reading of the process cwd.
    #[test]
    fn a_cwd_moving_backend_gets_the_program_completed() {
        for backend in [Backend::Pkexec, Backend::Run0] {
            let auth = if backend == Backend::Pkexec {
                Auth::Gui
            } else {
                Auth::NonInteractive
            };
            let mut c = exact_tool(None);
            c.elevation_backend(backend).elevation_auth(auth);
            let rw = rewrite_at_proc_cwd(&mut c, &every_backend_host());
            let a = derived_argv(&rw);
            assert!(a.ends_with(&[OsString::from("/proc-cwd/tool"), "-x".into()]), "{a:?}");
            assert_eq!(
                rw.derived.as_ref().expect("derived").cwd(),
                Some(std::path::Path::new("/proc-cwd"))
            );
        }
    }

    /// Negative control: a `Search` program still reaches the wrapper as written.
    #[test]
    fn an_elevated_search_program_is_passed_as_written() {
        let mut c = Command::new();
        c.executable("tool")
            .args(["tool", "-x"])
            .current_dir("/work")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let a = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).expect("rewrite"));
        assert_eq!(
            a[a.len() - 3..],
            [OsString::from("--"), "tool".into(), "-x".into()],
            "{a:?}"
        );
    }
}
