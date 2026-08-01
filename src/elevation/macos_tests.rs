use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::{build_rewrite, build_shell_command, reject_structural_gui_config, wrap_do_shell_script};
use crate::command::{Command, CommandInput};
use crate::elevation::{ElevatedStdio, ElevatedVia};
use crate::error::{ElevationErrorKind, Error, QuoteErrorKind};

fn args(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn shell(program: &str, a: &[&str], cwd: Option<&str>) -> String {
    let bytes = build_shell_command(OsStr::new(program), &args(a), cwd.map(Path::new)).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn gui_cmd() -> Command {
    let mut c = Command::new();
    c.args(["/usr/bin/id", "-u"])
        .elevation_auth(crate::elevation::Auth::Gui);
    c
}

fn assert_rejected(c: &Command, needle: &str) {
    match reject_structural_gui_config(c) {
        Err(Error::Unsupported { platform, detail, .. }) => {
            assert_eq!(platform, "macos");
            assert!(detail.contains(needle), "detail {detail:?} must mention {needle:?}");
        }
        other => panic!("expected a macos Unsupported mentioning {needle:?}, got {other:?}"),
    }
}

// ===== composition =====

#[test]
fn the_shell_command_execs_the_quoted_argv() {
    // `exec` so the payload replaces /bin/sh rather than sitting under it.
    assert_eq!(shell("/usr/bin/id", &["-u"], None), "exec /usr/bin/id -u");
}

#[test]
fn every_argv_element_is_shell_quoted() {
    // Hand-derived from the POSIX quoter's documented rule (single-quote wrap, `'`
    // written as '"'"'), not from running the code.
    assert_eq!(
        shell("/bin/echo", &["a b", "it's", "$HOME", "`id`"], None),
        r#"exec /bin/echo 'a b' 'it'"'"'s' '$HOME' '`id`'"#
    );
}

#[test]
fn a_working_directory_becomes_an_explicit_cd() {
    // `do shell script` does not carry a cwd across the authorization trampoline,
    // so the cwd is stated in the command rather than assumed.
    assert_eq!(
        shell("/usr/bin/id", &[], Some("/tmp/a dir")),
        "cd -- '/tmp/a dir' && exec /usr/bin/id"
    );
}

#[test]
fn the_script_is_a_single_do_shell_script_statement() {
    let cmd = build_shell_command(OsStr::new("/usr/bin/id"), &args(&["-u"]), None).unwrap();
    assert_eq!(
        wrap_do_shell_script(&cmd, None).unwrap(),
        "do shell script \"exec /usr/bin/id -u\" \
         with administrator privileges without altering line endings"
    );
}

#[test]
fn both_quoting_layers_compose() {
    // Layer 1 wraps the argument in single quotes; layer 2 escapes the embedded
    // double quotes. Derived by hand from the two grammars.
    let cmd = build_shell_command(OsStr::new("/bin/echo"), &args(&[r#"he said "hi""#]), None).unwrap();
    assert_eq!(
        wrap_do_shell_script(&cmd, None).unwrap(),
        "do shell script \"exec /bin/echo 'he said \\\"hi\\\"'\" \
         with administrator privileges without altering line endings"
    );
}

#[test]
fn non_utf8_argv_is_rejected_before_it_can_be_mangled() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'a', 0xff]);
        let cmd = build_shell_command(OsStr::new("/bin/echo"), &[bad], None).unwrap();
        let e = wrap_do_shell_script(&cmd, None).unwrap_err();
        // `ref q`: a by-value binding would partially move `e`, which the message
        // then borrows (E0382).
        assert!(
            matches!(e, Error::Quote(ref q) if q.kind == QuoteErrorKind::NonUtf8),
            "{e}"
        );
    }
}

#[test]
fn non_ascii_passes_through_unaltered() {
    // A CJK-named file argument to an ASCII-named tool is an ordinary macOS
    // command, not an exotic one. The bytes must reach the script verbatim; that
    // they survive the REAL osascript is asserted by
    // `both_quoting_layers_survive_a_real_osascript_round_trip`.
    let cmd = build_shell_command(
        OsStr::new("/bin/echo"),
        &args(&["\u{4e2d}\u{6587}.txt", "caf\u{e9}", "\u{1f389}"]),
        None,
    )
    .unwrap();
    let script = wrap_do_shell_script(&cmd, None).unwrap();
    assert!(script.contains("\u{4e2d}\u{6587}.txt"), "{script}");
    assert!(script.contains("\u{1f389}"), "{script}");
}

#[cfg(windows)]
#[test]
fn an_os_string_with_no_byte_form_is_a_typed_error_not_a_panic() {
    // The `not(unix)` arm of `os_bytes` exists to turn a WTF-16 OsString that has
    // no byte form into a typed error. Windows is the only place it is live, so it
    // is the only place it can be tested — and untested, a future edit could make
    // it panic (which the crate's rules forbid) with nothing to catch it.
    use std::os::windows::ffi::OsStringExt;
    let lone_surrogate = OsString::from_wide(&[0xD800]);
    let e = build_shell_command(OsStr::new("/bin/echo"), &[lone_surrogate], None).unwrap_err();
    assert!(
        matches!(e, Error::Quote(ref q) if q.kind == QuoteErrorKind::NonUtf8),
        "{e}"
    );

    // `pos` is documented as a byte offset, so it must be MEASURED, not fabricated:
    // "ok" is two UTF-8 bytes, so the lone surrogate after it is at offset 2.
    let with_prefix = OsString::from_wide(&[0x006F, 0x006B, 0xD800]);
    let e = build_shell_command(OsStr::new("/bin/echo"), &[with_prefix], None).unwrap_err();
    match e {
        Error::Quote(q) => {
            assert_eq!(q.kind, QuoteErrorKind::NonUtf8);
            assert_eq!(q.pos, 2, "the offset must point at the first unrepresentable unit");
        }
        other => panic!("expected a Quote error, got {other:?}"),
    }

    // A multi-byte valid prefix counts in BYTES, not code units: U+00E9 is two.
    let multibyte = OsString::from_wide(&[0x00E9, 0xD800]);
    let e = build_shell_command(OsStr::new("/bin/echo"), &[multibyte], None).unwrap_err();
    match e {
        Error::Quote(q) => assert_eq!(q.pos, 2),
        other => panic!("expected a Quote error, got {other:?}"),
    }
}

/// The exact script length for an argument of `n` safe characters. Derived by
/// composing, so the boundary test probes the comparison itself.
fn script_len_for_arg(n: usize) -> usize {
    let cmd = build_shell_command(OsStr::new("/bin/echo"), &[OsString::from("x".repeat(n))], None).unwrap();
    wrap_do_shell_script(&cmd, None).unwrap().len()
}

#[test]
fn the_length_guard_accepts_exactly_arg_max_and_rejects_one_more() {
    let n = 1000;
    let exact = script_len_for_arg(n);
    let cmd = build_shell_command(OsStr::new("/bin/echo"), &[OsString::from("x".repeat(n))], None).unwrap();
    assert!(
        wrap_do_shell_script(&cmd, Some(exact)).is_ok(),
        "a script of exactly arg_max bytes must be accepted"
    );
    match wrap_do_shell_script(&cmd, Some(exact - 1)) {
        // Elevation, NOT Unsupported: the same command succeeds on a host with a
        // larger kern.argmax, so this can never be a permanent platform verdict.
        Err(Error::Elevation { kind, detail }) => {
            assert_eq!(kind, ElevationErrorKind::CommandTooLong);
            assert!(detail.contains(&exact.to_string()), "{detail}");
            assert!(detail.contains(&(exact - 1).to_string()), "{detail}");
        }
        other => panic!("expected CommandTooLong, got {other:?}"),
    }
}

#[test]
fn an_unknown_arg_max_disables_the_guard_rather_than_guessing() {
    let cmd = build_shell_command(OsStr::new("/bin/echo"), &[OsString::from("x".repeat(9_000))], None).unwrap();
    assert!(wrap_do_shell_script(&cmd, None).is_ok());
}

// ===== structural gate =====

#[test]
fn a_plain_argv_command_is_accepted() {
    // `gui_cmd()` is default-constructed, so kill_on_drop is already `true`. This
    // pins that the default does NOT make the whole path unreachable.
    assert!(gui_cmd().kill_on_drop_flag(), "the builder default is assumed here");
    assert!(reject_structural_gui_config(&gui_cmd()).is_ok());
}

#[test]
fn a_relative_program_is_rejected_so_roots_path_never_chooses_the_binary() {
    let mut c = Command::new();
    c.args(["mytool", "--apply"])
        .elevation_auth(crate::elevation::Auth::Gui);
    assert_rejected(&c, "absolute");
}

#[test]
fn absoluteness_is_judged_by_posix_rules_not_the_build_hosts() {
    // `/usr/bin/id` must be accepted and `C:\tool.exe` rejected on EVERY host —
    // `Path::is_absolute` gets both backwards on Windows.
    let mut ok = Command::new();
    ok.args(["/usr/bin/id"]).elevation_auth(crate::elevation::Auth::Gui);
    assert!(reject_structural_gui_config(&ok).is_ok());

    let mut windows_style = Command::new();
    windows_style
        .args([r"C:\tool.exe"])
        .elevation_auth(crate::elevation::Auth::Gui);
    assert_rejected(&windows_style, "absolute");
}

#[test]
fn a_relative_working_directory_is_rejected() {
    // It would resolve against two different bases: this process's directory for
    // osascript, and the trampoline's for the `cd --` inside the script.
    let mut c = gui_cmd();
    c.current_dir("subdir");
    assert_rejected(&c, "absolute");
}

#[test]
fn containment_is_rejected_because_the_payload_leaves_our_tree() {
    let mut c = gui_cmd();
    c.contain();
    assert_rejected(&c, "trampoline");
}

#[test]
fn env_forwarding_is_rejected() {
    let mut c = gui_cmd();
    c.env("A", "1");
    assert_rejected(&c, "environment");
}

#[test]
fn a_high_fd_is_rejected() {
    let mut c = gui_cmd();
    c.fd(3, crate::Stdio::null()).unwrap();
    assert_rejected(&c, "fd >= 3");
}

#[test]
fn only_null_and_inherit_are_accepted_on_stdin() {
    // Every resolution with content behind it, including the `Merge` that
    // `Stdio::merge` produces — an allow-list, so nothing new slips through.
    let mut piped = gui_cmd();
    piped.stdin(crate::Stdio::pipe()).unwrap();
    assert_rejected(&piped, "stdin");

    let f = tempfile::tempfile().expect("tempfile");
    let mut filed = gui_cmd();
    filed.stdin(crate::Stdio::from_file(f)).unwrap();
    assert_rejected(&filed, "stdin");

    let mut merged = gui_cmd();
    merged.stdout(crate::Stdio::pipe()).unwrap();
    merged.stdin(crate::Stdio::merge(crate::Fd::STDOUT)).unwrap();
    assert_rejected(&merged, "stdin");

    for allowed in [crate::Stdio::null(), crate::Stdio::inherit()] {
        let mut ok = gui_cmd();
        ok.stdin(allowed).unwrap();
        assert!(reject_structural_gui_config(&ok).is_ok());
    }
}

#[test]
fn stdout_and_stderr_may_be_captured_because_they_carry_the_relay() {
    // These are osascript's OWN streams. Capturing them is how the caller sees the
    // relayed stdout at all, so `.output()` and `.read()` must work.
    let mut c = gui_cmd();
    c.stdout(crate::Stdio::pipe()).unwrap();
    c.stderr(crate::Stdio::pipe()).unwrap();
    c.stdin(crate::Stdio::null()).unwrap();
    assert!(
        reject_structural_gui_config(&c).is_ok(),
        "output()/read() must be usable"
    );
}

#[test]
fn a_commandline_command_is_rejected() {
    let mut c = Command::new();
    c.commandline("id -u").elevation_auth(crate::elevation::Auth::Gui);
    assert_rejected(&c, "argv");
}

#[test]
fn an_empty_command_is_rejected() {
    // BOTH internal spellings of "no program", which are separately reachable: a
    // fresh Command is `CommandInput::Empty`, while `.args([])` takes the `_ =>`
    // arm of `Command::args` and yields `CommandInput::Argv(vec![])`.
    let mut fresh = Command::new();
    fresh.elevation_auth(crate::elevation::Auth::Gui);
    assert_rejected(&fresh, "program");

    let mut empty_argv = Command::new();
    empty_argv
        .args::<[&str; 0], &str>([])
        .elevation_auth(crate::elevation::Auth::Gui);
    assert!(
        matches!(empty_argv.input(), CommandInput::Argv(v) if v.is_empty()),
        "this test only means something if .args([]) really yields Argv(vec![])"
    );
    assert_rejected(&empty_argv, "program");
}

#[test]
fn an_argv0_distinct_from_executable_is_rejected() {
    let mut c = Command::new();
    c.executable("/usr/bin/id")
        .args(["not-id", "-u"])
        .elevation_auth(crate::elevation::Auth::Gui);
    assert_rejected(&c, "argv[0]");
}

#[cfg(windows)]
#[test]
fn the_gate_reports_a_byte_formless_program_as_a_quote_error() {
    // Not as "not absolute": the leading-slash test cannot even run on an OsStr
    // with no byte form, so the gate must surface the real reason.
    use std::os::windows::ffi::OsStringExt;
    let mut c = Command::new();
    c.args([OsString::from_wide(&[0xD800])])
        .elevation_auth(crate::elevation::Auth::Gui);
    let e = reject_structural_gui_config(&c).unwrap_err();
    assert!(
        matches!(e, Error::Quote(ref q) if q.kind == QuoteErrorKind::NonUtf8),
        "{e}"
    );
}

#[test]
fn a_matching_executable_yields_that_program_and_the_remaining_args() {
    // The `Some(exe)` success arm substitutes `exe` for argv[0] and slices the
    // tail; pin the returned pair, not merely the absence of a rejection.
    let mut c = Command::new();
    c.executable("/usr/bin/id")
        .args(["/usr/bin/id", "-u", "-r"])
        .elevation_auth(crate::elevation::Auth::Gui);
    let (program, rest) = super::program_and_args(&c).expect("matching executable");
    assert_eq!(program, OsString::from("/usr/bin/id"));
    assert_eq!(rest, args(&["-u", "-r"]));
}

// ===== derived command =====

#[test]
fn the_derived_command_is_osascript_dash_e_with_one_script_argument() {
    let mut c = gui_cmd();
    let (derived, report) = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
    let CommandInput::Argv(argv) = derived.input() else {
        panic!("derived command must be an argv");
    };
    assert_eq!(argv.len(), 3, "exactly osascript, -e, and ONE script argument");
    assert_eq!(argv[0], OsString::from("/usr/bin/osascript"));
    assert_eq!(argv[1], OsString::from("-e"));
    assert_eq!(
        argv[2],
        OsString::from(
            "do shell script \"exec /usr/bin/id -u\" \
             with administrator privileges without altering line endings"
        )
    );
    assert_eq!(report.via, ElevatedVia::MacosOsascript);
    assert_eq!(report.stdio, ElevatedStdio::OsascriptRelay);
    assert!(report.stripped_env.is_empty(), "no env crosses, so none is stripped");
}

#[test]
fn the_derived_command_carries_no_elevation_request() {
    // Otherwise spawning the derived command would re-enter the elevation branch.
    let mut c = gui_cmd();
    let (derived, _) = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
    assert!(!derived.elevation_request().enabled);
}

#[test]
fn kill_on_drop_reaches_the_derived_command() {
    // The async spawn recurses and re-reads this flag off the derived command, so a
    // caller opting out must not be silently overridden by the builder default.
    for requested in [true, false] {
        let mut c = gui_cmd();
        c.kill_on_drop(requested);
        let (derived, _) = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
        assert_eq!(derived.kill_on_drop_flag(), requested);
    }
}

#[test]
fn kill_on_drop_warns_that_it_cannot_reach_the_payload() {
    // The builder default sets the flag, so this is the DEFAULT path: dropping the
    // child SIGKILLs osascript while the root payload keeps running, unobservable.
    // That must never be silent, so the spawn says so.
    //
    // The capture buffer is process-global and every sibling test that calls
    // build_rewrite with the default flag writes the same sentence, so BOTH halves
    // key on a program path unique to this test — otherwise the negative assertion
    // would race a concurrent sibling's record.
    const LOUD: &str = "/usr/bin/cosca-koddrop-probe-loud";
    const QUIET: &str = "/usr/bin/cosca-koddrop-probe-quiet";
    crate::log_capture::install();

    let mark = crate::log_capture::mark();
    let mut c = Command::new();
    c.args([LOUD]).elevation_auth(crate::elevation::Auth::Gui);
    c.kill_on_drop(true);
    let _ = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
    assert!(
        crate::log_capture::contains_since(mark, LOUD),
        "a kill_on_drop child must be warned about, not silently orphaned"
    );

    // Opting out is the quiet path — no warning to ignore.
    let mark = crate::log_capture::mark();
    let mut quiet = Command::new();
    quiet.args([QUIET]).elevation_auth(crate::elevation::Auth::Gui);
    quiet.kill_on_drop(false);
    let _ = build_rewrite(&mut quiet, Path::new("/usr/bin/osascript"), None).unwrap();
    assert!(!crate::log_capture::contains_since(mark, QUIET));
}

#[test]
fn the_cwd_reaches_both_osascript_and_the_payload() {
    let mut c = gui_cmd();
    c.current_dir("/tmp");
    let (derived, _) = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
    // Set on osascript so a bogus directory fails at spawn with a precise Io error…
    assert_eq!(derived.cwd(), Some(Path::new("/tmp")));
    let CommandInput::Argv(argv) = derived.input() else {
        unreachable!()
    };
    // …and stated in the script, so the payload's cwd does not depend on whether
    // the trampoline happens to carry it.
    assert!(
        argv[2].to_str().unwrap().contains("cd -- /tmp && exec"),
        "{:?}",
        argv[2]
    );
}

#[test]
fn the_length_guard_is_enforced_through_the_rewrite() {
    let mut c = gui_cmd();
    let e = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), Some(10)).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Elevation {
                kind: ElevationErrorKind::CommandTooLong,
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn the_rewrite_preserves_the_callers_argv_and_moves_its_fds() {
    // Non-destructive on `input`/`env_ops`, matching the POSIX rewrite's contract —
    // but the fd table is deliberately MOVED, because `ResolvedStdio::File` is not
    // `Clone`. Both halves are asserted so neither can regress unnoticed.
    let mut c = gui_cmd();
    c.stdout(crate::Stdio::pipe()).unwrap();
    let before = format!("{:?}", c.input());
    let (derived, _) = build_rewrite(&mut c, Path::new("/usr/bin/osascript"), None).unwrap();
    assert_eq!(format!("{:?}", c.input()), before, "argv must survive the rewrite");
    assert!(c.env_ops().is_empty());
    assert!(c.fds().is_empty(), "the caller's fds are moved, not copied");
    assert!(
        derived.fds().contains_key(&crate::Fd::STDOUT),
        "the moved fds must land on the derived command"
    );
}

// ===== real osascript (macOS CI, ungated, no dialog) =====

/// The crate's own elevated script with ONLY the privilege clause removed, so
/// running it raises no dialog while both quoting layers stay exactly the
/// production ones. Asserts the removal matched — a renamed clause must not
/// silently turn this into a test of an unmodified string.
#[cfg(target_os = "macos")]
fn crate_script_without_the_privilege_clause(program: &OsStr, args: &[OsString]) -> String {
    const CLAUSE: &str = " with administrator privileges";
    let shell_command = build_shell_command(program, args, None).unwrap();
    let script = wrap_do_shell_script(&shell_command, None).unwrap();
    assert!(script.contains(CLAUSE), "the privilege clause moved: {script}");
    script.replace(CLAUSE, "")
}

// UNGATED, macOS only: drives the CRATE's quoting through the real AppleScript
// parser and the real /bin/sh, with no elevation and no dialog. A bug in either
// layer shows up as a mangled argv here.
#[cfg(target_os = "macos")]
#[test]
fn both_quoting_layers_survive_a_real_osascript_round_trip() {
    let nasty = [
        "a b",
        "it's",
        r#"he said "hi""#,
        "$HOME `id` $(id)",
        r"back\slash",
        "semi;colon & pipe|",
        "tab\there",
        // The newline and CR cases are why `without altering line endings` is
        // mandatory: without it `do shell script` rewrites them.
        "line\nbreak",
        "carriage\rreturn",
        "crlf\r\npair",
        "",
        "--",
        "trailing ",
        // ---- Controls with no AppleScript escape. The crate passes these through
        // rather than refusing them on the inference that "no numeric escape" means
        // "no representation". THIS is the measurement that decides whether that is
        // right: if any of them fails to round-trip, `escape_literal` must reject
        // exactly the failing ones, with this test as the evidence.
        "\u{1b}[31mred\u{1b}[0m",
        "bell\u{7}here",
        "vtab\u{b}here",
        "ff\u{c}here",
        "del\u{7f}here",
        // ---- Non-ASCII. `osascript(1)` documents no encoding for `-e`, so this
        // block IS the specification: it decides whether the crate may pass
        // non-ASCII through. A CJK-named file argument to an ASCII-named tool is an
        // ordinary command on a UTF-8 filesystem, so refusing the class would reject
        // real users; these cases prove it instead of assuming it.
        "\u{4e2d}\u{6587}\u{6587}\u{4ef6}.txt",
        "\u{440}\u{443}\u{441}\u{441}\u{43a}\u{438}\u{439}",
        "\u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629}",
        // Precomposed vs decomposed: byte-DIFFERENT, canonically equivalent. If
        // anything on the path normalizes (Apple filesystems historically did),
        // these two collapse into one value and the comparison catches it.
        "caf\u{e9}",
        "cafe\u{301}",
        "\u{1f389}\u{1f680}",
        "mixed \u{65e5}\u{672c}\u{8a9e} and \u{3b5}\u{3bb}\u{3bb} and ascii",
    ];
    // The payload is `/bin/sh` and system tools only — no crate binary. A unit test
    // cannot rely on `cosca_testbin`: cargo builds `[[bin]]` targets only when a
    // non-lib target is selected, and CI has a darwin `--lib` leg. `$@` receives the
    // fixture as real argv, and each element is hex-dumped so the TEXT relay cannot
    // corrupt the comparison.
    const DUMP: &str = r#"for a in "$@"; do printf %s "$a" | od -An -tx1 -v | tr -d ' \n'; echo; done"#;
    let mut argv: Vec<OsString> = vec![
        OsString::from("-c"),
        OsString::from(DUMP),
        OsString::from("sh"), // $0
    ];
    argv.extend(nasty.iter().map(OsString::from));
    let script = crate_script_without_the_privilege_clause(OsStr::new("/bin/sh"), &argv);

    let mut c = Command::new();
    c.args([
        OsString::from("/usr/bin/osascript"),
        OsString::from("-e"),
        script.into(),
    ]);
    let relayed = c.read().expect("osascript output");

    // The expectation is the Rust-side UTF-8 bytes, hex-encoded. `od` dumps what
    // /bin/sh ACTUALLY received, so any re-encoding, normalization or truncation
    // anywhere between `wrap_do_shell_script` and the shell shows up as a diff.
    let expected: Vec<String> = nasty
        .iter()
        .map(|s| s.as_bytes().iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    let got: Vec<&str> = relayed.trim_end_matches('\n').split('\n').collect();
    assert_eq!(got, expected, "argv was mangled crossing the two quoting layers");

    // Guard the guard: the NFC and NFD spellings must stay DISTINCT in the output.
    // If they were ever equal, the fixture would have stopped testing normalization
    // without failing. Looked up by value so reordering cannot silently mis-target.
    let hex = |s: &str| -> String { s.as_bytes().iter().map(|b| format!("{b:02x}")).collect() };
    let nfc = hex("caf\u{e9}");
    let nfd = hex("cafe\u{301}");
    assert_ne!(nfc, nfd, "the NFC/NFD pair must remain byte-distinct");
    assert!(got.contains(&nfc.as_str()) && got.contains(&nfd.as_str()));
}

// UNGATED, macOS only: feeds the crate's UNMODIFIED elevated script to osacompile,
// which parses without executing. This is the one property of the real script the
// round trip cannot reach — that `with administrator privileges` is syntactically
// valid next to `without altering line endings` — and it needs no dialog. The output
// goes to a real temp file: `osacompile` creates its `-o` target as a file, so a
// device path would risk failing for reasons unrelated to the script.
#[cfg(target_os = "macos")]
#[test]
fn the_administrator_script_compiles() {
    let shell_command = build_shell_command(OsStr::new("/usr/bin/id"), &args(&["-u"]), None).unwrap();
    let script = wrap_do_shell_script(&shell_command, None).unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("script.scpt");

    let mut c = Command::new();
    c.args([
        OsString::from("/usr/bin/osacompile"),
        OsString::from("-o"),
        out_path.clone().into_os_string(),
        OsString::from("-e"),
        script.clone().into(),
    ]);
    let out = c.output().expect("osacompile output");
    assert!(
        out.status.success(),
        "the elevated script does not compile: {script}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_path.exists(), "osacompile reported success but wrote nothing");
}

// UNGATED, macOS only: MEASURES the claim `wrap_do_shell_script` documents — that
// `with timeout` does not govern `do shell script` under osascript, so the default
// event timeout cannot cut a long-running elevated payload short. Asserting the
// mechanism rather than the default's numeric value keeps this to a few seconds: if
// an explicit 2-second bound does not fire on a 5-second payload, the 120-second
// default cannot fire either — same dispatch path, larger bound.
//
// If this ever fails with -1712 ("AppleEvent timed out"), the doc claim is wrong and
// `wrap_do_shell_script` must emit a timeout clause (or surface the bound as a typed
// error), with this test as the evidence.
#[cfg(target_os = "macos")]
#[test]
fn a_timeout_clause_does_not_bound_do_shell_script() {
    let shell_command = build_shell_command(OsStr::new("/bin/sleep"), &args(&["5"]), None).unwrap();
    let body = crate::quote::applescript::escape_literal(&shell_command).unwrap();
    let bounded = format!(
        "with timeout of 2 seconds
do shell script \"{body}\" without altering line endings
end timeout"
    );

    let mut c = Command::new();
    c.args([
        OsString::from("/usr/bin/osascript"),
        OsString::from("-e"),
        bounded.into(),
    ]);
    let out = c.output().expect("osascript output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a 2s `with timeout` must not bound a 5s do-shell-script payload: {stderr}"
    );
    assert!(
        !stderr.contains("-1712"),
        "the payload was cut short by the Apple event timeout: {stderr}"
    );
}
