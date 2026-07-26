use super::build_argv;
use crate::elevation::{Auth, Backend};
use std::ffi::{OsStr, OsString};

fn s(v: &[&str]) -> Vec<OsString> {
    v.iter().map(|x| OsString::from(*x)).collect()
}
fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
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
        s(&["/usr/bin/sudo", "-n", "--preserve-env=FOO", "--", "/usr/bin/systemctl", "restart", "nginx"])
    );
    // The VALUE never appears in argv (it is set in sudo's own env by the rewrite).
    assert!(!argv.iter().any(|a| a.to_string_lossy().contains("bar")));
}

#[test]
fn sudo_preserve_env_joins_multiple_names() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-n", "--preserve-env=A,B", "--", "id"]));
}

#[test]
fn sudo_interactive_no_env_has_no_flags() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Interactive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "--", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Stdin(crate::elevation::Secret::new("pw")), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-S", "--", "id"]));
}

#[test]
fn sudo_askpass_uses_dash_a() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Askpass("/usr/bin/ssh-askpass".into()), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-A", "--", "id"]));
}

#[test]
fn sudo_rejects_an_unforwardable_env_name() {
    for bad in [("A,B", "1"), ("A=C", "1"), ("PÄTH", "1"), ("", "1"), ("1BAD", "1")] {
        let r = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[bad]));
        assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })), "expected reject for {bad:?}");
    }
}

#[test]
fn doas_noninteractive_no_env_emits_dash_n() {
    let argv = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::NonInteractive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/doas", "-n", "--", "id", "-u"]));
}

#[test]
fn run0_forces_pipe_and_forwards_env_via_setenv() {
    let argv = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/run0", "--pipe", "--no-ask-password", "--setenv=A=1", "--setenv=B=2", "--", "id"]));
}

#[test]
fn run0_rejects_an_unforwardable_env_name() {
    let r = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A=B", "1")]));
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
}

#[test]
fn pkexec_gui_disables_internal_agent_and_uses_no_terminator() {
    // No `--` for pkexec (its option loop mis-parses it); --disable-internal-agent pins
    // the graphical-only contract.
    let argv = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/pkexec", "--disable-internal-agent", "id"]));
    assert!(!argv.iter().any(|a| a == &OsString::from("--")), "pkexec must not emit a -- terminator");
}

#[test]
fn pkexec_rejects_a_leading_dash_program() {
    // With no `--` shield, a leading-dash program would be mis-parsed as a pkexec option.
    let r = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("-prog"), &[], &[]);
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
    // An `=` in the program path is safe under pkexec (no assignment parsing).
    let ok = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("/opt/we=ird"), &[], &[]).unwrap();
    assert_eq!(ok, s(&["/usr/bin/pkexec", "--disable-internal-agent", "/opt/we=ird"]));
}

#[test]
fn terminator_protects_a_program_with_equals_or_leading_dash() {
    let eq = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("/opt/we=ird"), &[], &[]).unwrap();
    assert_eq!(eq, s(&["/usr/bin/sudo", "-n", "--", "/opt/we=ird"]));
    let dash = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::Interactive, OsStr::new("-prog"), &[], &[]).unwrap();
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
    assert_eq!(got, Some(sudo), "a mid-string empty PATH element must be skipped, not resolved");

    // A PATH consisting only of empty elements resolves nothing.
    assert_eq!(super::resolve_in_path_var(OsStr::new(":"), "sudo"), None);
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
            },
            os: Os::Unix,
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
        assert!(derived.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, v) if k == "FOO" && v == "bar")));
        assert!(!derived.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, _) if k == "LD_PRELOAD")));
        // The caller's Command is untouched (no double-wrap on reuse).
        assert!(matches!(c.input(), CommandInput::Argv(v) if v == &[OsString::from("id"), OsString::from("-u")]));
        assert_eq!(c.env_ops().len(), 2, "caller env ops must be intact");
    }

    #[test]
    fn rewrite_twice_yields_identical_derived_argv() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        let a1 = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).unwrap());
        let a2 = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).unwrap());
        assert_eq!(a1, a2, "reusing an elevated Command must not double-wrap");
    }

    #[test]
    fn env_remove_or_clear_plus_elevate_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).env_clear().env("KEEP", "1").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
        let mut c2 = Command::new();
        c2.args(["id"]).env("A", "1").env_remove("A").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(rewrite_with_host(&mut c2, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn doas_or_pkexec_with_env_is_unsupported() {
        let doas_host = Host {
            available: BackendSet { run0: None, sudo: None, doas: Some(PathBuf::from("/usr/bin/doas")), pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).env("A", "1").elevation_backend(Backend::Doas).elevation_auth(Auth::NonInteractive);
        assert!(matches!(rewrite_with_host(&mut c, &doas_host), Err(Error::Unsupported { .. })));

        let pk_host = Host {
            available: BackendSet { run0: None, sudo: None, doas: None, pkexec: Some(PathBuf::from("/usr/bin/pkexec")) },
            ..sudo_host()
        };
        let mut c2 = Command::new();
        c2.args(["id"]).env("A", "1").elevation_backend(Backend::Pkexec).elevation_auth(Auth::Gui);
        assert!(matches!(rewrite_with_host(&mut c2, &pk_host), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn run0_forwards_env_via_setenv() {
        let host = Host {
            available: BackendSet { run0: Some(PathBuf::from("/usr/bin/run0")), sudo: None, doas: None, pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).env("A", "1").elevation_backend(Backend::Run0).elevation_auth(Auth::NonInteractive);
        let rw = rewrite_with_host(&mut c, &host).expect("rewrite");
        assert!(derived_argv(&rw).contains(&OsString::from("--setenv=A=1")));
        assert!(!rw.derived.as_ref().unwrap().env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, _) if k == "A")));
    }

    #[test]
    fn askpass_path_is_carried_in_the_backend_env() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Askpass(PathBuf::from("/usr/bin/ssh-askpass")));
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert!(rw.derived.as_ref().unwrap().env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, v) if k == "SUDO_ASKPASS" && v == "/usr/bin/ssh-askpass")));
    }

    #[test]
    fn stdin_auth_wires_fd0_to_a_file_and_defers_the_write() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        // Stdio::from_file(reader) resolves to ResolvedStdio::File(_).
        assert!(matches!(rw.derived.as_ref().unwrap().fds().get(&Fd::STDIN), Some(ResolvedStdio::File(_))));
        assert!(rw.password_write.is_some(), "the password write is deferred to after spawn");
        // fd0 is the password channel, not the caller's stdin — reported honestly.
        assert_eq!(rw.report.as_ref().unwrap().stdio, ElevatedStdio::StdinConsumed);
    }

    #[test]
    fn stdin_auth_with_caller_configured_fd0_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        c.stdin(Stdio::pipe()).unwrap();
        assert!(matches!(rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn fd_ge_3_elevated_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        c.fd(3, Stdio::pipe_out()).unwrap();
        assert!(matches!(rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn run0_plus_contain_is_unsupported() {
        let host = Host {
            available: BackendSet { run0: Some(PathBuf::from("/usr/bin/run0")), sudo: None, doas: None, pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Run0).elevation_auth(Auth::NonInteractive).contain();
        assert!(matches!(rewrite_with_host(&mut c, &host), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn commandline_elevated_is_unsupported() {
        let mut c = Command::new();
        c.commandline("id -u").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn distinct_argv0_with_executable_is_unsupported() {
        let mut c = Command::new();
        c.executable("/bin/busybox").args(["sh", "-c", "true"])
            .elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    fn elevated_sudo_host() -> Host {
        Host { elevated: true, ..sudo_host() }
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
        let derived = rw.derived.as_ref().expect("already-elevated still derives a sanitized command");
        assert!(rw.backend_path.is_none());
        assert!(rw.password_write.is_none());
        let report = rw.report.as_ref().unwrap();
        assert_eq!(report.via, ElevatedVia::AlreadyElevated);
        assert_eq!(report.stripped_env, vec![OsString::from("LD_PRELOAD")]);
        // The derived program is the ORIGINAL command, not a backend.
        assert!(matches!(derived.input(), CommandInput::Argv(v) if v == &[OsString::from("id"), OsString::from("-u")]));
        // The dangerous var is gone from the derived env even under root.
        assert!(!derived.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, _) if k == "LD_PRELOAD")));
        // The caller's Command is left untouched.
        assert_eq!(c.env_ops().len(), 1, "caller env ops must be intact");
    }

    #[test]
    fn structural_config_gates_are_privilege_independent() {
        // Same structurally-invalid requests must be rejected whether or not the caller
        // is already elevated (Config gates run before the RunAsIs short-circuit).
        for host in [sudo_host(), elevated_sudo_host()] {
            let mut a = Command::new();
            a.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
            a.fd(3, Stdio::pipe_out()).unwrap();
            assert!(matches!(rewrite_with_host(&mut a, &host), Err(Error::Unsupported { .. })),
                "fd>=3 must reject with elevated={}", host.elevated);

            let mut b = Command::new();
            b.args(["id"]).env("A", "1").elevation_backend(Backend::Doas).elevation_auth(Auth::NonInteractive);
            let doas_host = Host {
                available: BackendSet { run0: None, sudo: None, doas: Some(PathBuf::from("/usr/bin/doas")), pkexec: None },
                ..host.clone()
            };
            assert!(matches!(rewrite_with_host(&mut b, &doas_host), Err(Error::Unsupported { .. })),
                ".env()+doas must reject with elevated={}", host.elevated);

            let mut d = Command::new();
            d.commandline("id -u").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
            assert!(matches!(rewrite_with_host(&mut d, &host), Err(Error::Unsupported { .. })),
                "commandline() must reject with elevated={}", host.elevated);
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
        assert!(line.capacity() >= line.len(), "buffer must be pre-sized so the push never reallocates");
    }

    #[test]
    fn write_after_spawn_writes_password_and_newline_then_eof() {
        use std::io::Read;
        let (mut reader, writer) = std::io::pipe().unwrap();
        let pp = PendingPassword { writer, secret: crate::elevation::Secret::new("pw") };
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
        let pp = PendingPassword { writer, secret: crate::elevation::Secret::new("pw") };
        assert!(pp.write_after_spawn().is_ok(), "reader-gone with zero bytes written is not a failure");
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
}
