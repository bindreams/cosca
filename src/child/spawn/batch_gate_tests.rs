//! Unit tests for the batch gate: the spellings Windows resolves to a `.bat`/`.cmd`, the NUL
//! refusal, the refusal's advice, and an exhaustive comparison against the rule it replaced. The
//! component-level oracle is in `batch_gate/oracle_tests.rs`.

use crate::command::Command;
use crate::error::Error;

/// Why `is_batch_program` no longer spells out the as-written reading beside the stream reading.
///
/// If `is_batch_by_shell` fires on a name, the LAST piece `ntfs_stream_names` yields from it
/// carries the same final dot and the same extension, so the stream reading fires too:
///
/// - a `:` AFTER the last dot would land inside the extension and stop the rule firing, so every
///   `:` is before it and the split leaves the dot in the last piece;
/// - the trim takes only spaces and dots, and an extension ending in `t` or `d` loses nothing;
/// - the drive prefix, if any, is two characters with no dot in them.
///
/// So the disjunct was unreachable — no string in this alphabet reaches it — and its documented
/// witness (`x.exe:payload.bat`, which is refused as the piece `payload.bat`) stopped being one
/// when `ntfs_stream_names` went from yielding the first piece to yielding every piece.
///
/// Deleting it would have been silent: with the disjunct present this property holds trivially.
/// Asserted here so that the day `ntfs_stream_names` stops yielding the piece that holds the last
/// dot, the loss is a failure and not a quietly narrower gate.
#[test]
fn the_stream_reading_subsumes_the_shell_reading() {
    let mut missed = Vec::new();
    for_every_string(6, |probe| {
        if super::streams::is_batch_by_shell(probe) && !super::is_batch_program(probe) {
            missed.push(probe.to_string());
        }
    });
    assert_eq!(
        missed,
        Vec::<String>::new(),
        "the shell reads these as batch names and the stream reading let them through"
    );
}

/// END TO END WITH THE PLATFORM FORCED — the whole Windows composition
/// (`win32_effective_file_name` -> `is_batch_program`) on every lane, not just the two Windows
/// ones.
#[test]
fn reject_batch_path_on_windows_refuses_every_spelling_that_reaches_a_batch_file() {
    use std::path::Path;
    for probe in [
        "x.bat",
        "x.CMD",
        r"C:\dir\x.bat",
        // Win32 trims trailing dots and spaces off a component.
        "x.bat ",
        "x.bat.",
        // `Path::file_name()` is `None` for these while `GetFullPathNameW` collapses them straight
        // back to the batch file.
        r"x.bat\y\..",
        "x.bat/y/..",
        r"C:\dir\x.bat\y\..",
        r"..\x.bat\y\..",
        r"x.cmd\y\..",
        // A dots-and-spaces segment BEFORE a `..` is a name the `..` pops (measured), exposing the
        // batch file before it.
        r"y\x.bat\...\..",
        r"y\x.bat\.. \..",
        r"y\x.bat\ \..",
        r"y\x.bat\. \..",
        // A dots-and-spaces component trims away to nothing and drops out, exposing the component
        // before it — which here is the batch file.
        r"x.bat\...",
        r"x.bat\ ",
        r"x.bat\.. .",
        // Data streams. A component ending in `:` is a file, not a drive prefix, and the drive
        // prefix that IS one must not be mistaken for a stream separator.
        "x.bat:s",
        "x.bat:",
        "x.bat: ",
        "C:x.bat:s",
        "x.exe:payload.bat",
        "x.exe:payload.bat:",
        "x.exe:payload.bat:$DATA",
        // The name IS the extension; `Path::extension()` reports `None` for it.
        ".bat",
        // A UNC SHARE is a root `..` cannot pop, so a batch-named share stays the effective name
        // however many `..` follow it — see `win32_effective_file_name`.
        r"\\srv\x.bat",
        r"\\srv\x.bat\..",
        "//srv/x.bat/..",
        r"\/srv\x.cmd\..",
        "\\\\srv\\x.bat\\.. ",
        r"\\srv\x.bat\y\..\..",
        r"\\srv\x.bat \..",
        r"\\srv\x.bat.\..",
        r"\\srv\x.bat:s\..",
        // The share is reached through `..` too: a UNC path may not pop past it either way.
        r"\\srv\x.bat\y\..\..\..",
        // Not the share but a file under it, popped back to.
        r"\\srv\share\x.bat\y\..",
        // A server with no share under it names no file at all.
        r"\\server",
        // The root is positional; see `win32_effective_file_name`.
        r"\\...\x.bat\y\..",
        r"\\x.bat\y\..",
        // A device path, and the slash spellings of `\\?\` that are plain paths: only `\\.\` or
        // `\\?\` is the root, and `..` pops the device name like any other component (measured).
        r"\\.\x.bat\y\..",
        "//?/x.bat/y/..",
        r"\\.\C:\..\..\x.bat",
        "//?/C:/dir/x.bat.",
        r"\\?/C:\dir\x.bat.",
        "//?/C:/dir/x.bat/y/..",
        // Popped past the device name, these resolve to the bare `\\.\` or `\\?\`, which names no
        // file (measured).
        r"\\.\x.bat\..",
        r"\\.\C:\..",
        r"\\.\y\..",
        r"\\.\x.bat\y\..\..",
        "//./y/..",
        "//?/C:/..",
        r"\\?/C:\..",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} reaches a batch file on Windows"
        );
    }
    for probe in [
        "x.exe",
        "batch",
        "x.batch",
        r"C:\dir\tool.exe",
        // Pops back onto a named ancestor rather than off the end, and that ancestor is `dir` —
        // which is what `GetFullPathNameW` hands std, so it is the right name to judge.
        r"C:\dir\x.bat\..",
        // A dots-and-spaces component drops out without popping, so the batch file stays covered
        // by `y`. Measured: `x.bat\y\...` resolves to `…\x.bat\y\`.
        r"x.bat\y\...",
        r"x.bat\y\.. .",
        r"x.bat\y\....",
        r"x.bat\y\.. ..",
        r"x.bat\y\ ",
        // `.. ` is dots and spaces too, not `..` with a space: measured on x64 and arm64 runners,
        // `x.bat\y\.. ` resolves to `…\x.bat\y\`.
        r"x.bat\y\.. ",
        r"x.bat\y\..  ",
        // An interior dots-and-spaces segment is a name the `..` pops, so these land on `b`, `y`
        // and `a`: measured, `y\x.bat\...\..` resolves to `y\x.bat`.
        r"a\...\..\b",
        r"x.bat\y\...\..",
        r"x.bat\y\.. \..",
        r"a\...\..",
        r"x\ ",
        // A UNC share name is not a batch file either, and the pops below it are clamped away.
        r"\\server\share",
        r"\\server\share\..",
        r"\\server\share\x.bat\..",
        r"\\server\share\tool.exe",
        // A device path pops back to its device name, measured: `\\.\C:` and `\\.\pipe`. The
        // device name is an ordinary component, so `\\.\C:` names `C:`, not a bare drive.
        r"\\.\C:\x.bat\..",
        r"\\.\pipe\x.bat\..",
        r"\\.\C:",
        "//./C:/...",
        r"\\.\C:\tool.exe",
        "//?/C:/dir/tool.exe",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_ok(),
            "{probe:?} names no batch file and must stay spawnable"
        );
    }
}

/// A path that names no file OF ITS OWN is refused, because what it resolves to is a name this
/// gate cannot see.
///
/// Popping past the first component does not annihilate a RELATIVE path: `GetFullPathNameW` keeps
/// popping into the ancestors of the process's current directory, and `std::process` applies
/// `has_bat_extension` to THAT result. With a cwd of `C:\w.bat` — a directory, which Windows
/// permits — `x\..` resolves to `C:\w.bat`, std substitutes `cmd.exe`, and the caller's
/// `.commandline()` tail reaches it through `raw_arg` with no cmd escaping at all. The PATH
/// search is the same hole spelled differently: `.` resolves to `PATHDIR`, which
/// `GetFileAttributesW` accepts because a directory is a file.
///
/// The rooted probes below cannot reach the cwd — `C:\` and `/` clamp at the root — and are
/// refused for the shape rather than for that danger. Either way the refusal costs nothing: with
/// every named component popped away, what is left to resolve is a directory (the current one, an
/// ancestor, a drive's current directory, a root), and a directory is never a loadable image.
#[test]
fn reject_batch_path_on_windows_refuses_a_path_that_names_no_file_of_its_own() {
    use std::path::Path;
    for probe in [
        // Pops back to the current directory, whose name the gate cannot see.
        r"x\..",
        "..",
        ".",
        r"a\b\..\..",
        r"x.bat\..",
        "x.bat/..",
        // Dots-and-spaces components: they drop out, and these paths have nothing else in them.
        " ..",
        "....",
        r" \ ",
        // Rooted: the popping clamps at the root instead of walking into the cwd's ancestors, and
        // a root is not an image either.
        r"\x\..",
        r"C:\x\..",
        // Resolves to the current directory of another drive.
        "x:.",
        "C:",
        "c:",
        // Names nothing at all.
        "",
        "/",
        r"C:\",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} names no file of its own and resolves to a directory Windows picks"
        );
    }
}

/// Each refusal must advise the fix for the reason it refused. The two messages send the caller
/// somewhere materially different — one says route through cmd.exe yourself, the other says name
/// the executable — so handing out the wrong one is a bug even though the verdict is right.
///
/// `x.bat\...\..` reaches `x.bat`: the interior `...` is a name the `..` pops.
#[test]
fn the_refusal_advises_the_fix_for_the_reason_it_refused() {
    use std::path::Path;
    let detail = |probe: &str| match super::reject_batch_path_on(Path::new(probe), true) {
        Err(Error::Unsupported { detail, .. }) => detail,
        other => panic!("{probe:?} must be refused, got {other:?}"),
    };
    for probe in [
        r"x.bat\y\..",
        "x.bat",
        r"C:\bin\x.exe:p.bat",
        r"\\?\C:\x.bat",
        r"x.bat\...\..",
    ] {
        assert!(
            detail(probe).contains("cmd.exe batch escaping is not implemented"),
            "{probe:?} reaches a batch file, so it must advise the cmd.exe route: {}",
            detail(probe)
        );
    }
    // A name that names no file is refused on its shape, before any search: `InvalidInput`, as
    // `crate::resolve` refuses one.
    let invalid = |probe: &str| invalid_input_message(super::reject_batch_path_on(Path::new(probe), true));
    // `\\.\x.bat\..` resolves to the bare `\\.\`: no file, and no batch file either.
    for probe in [r"x\..", ".", "C:", r"\\.\x.bat\..", ""] {
        assert!(
            invalid(probe).contains("names no file of its own"),
            "{probe:?} names no file, so it must advise naming the executable: {}",
            invalid(probe)
        );
    }
    // A verbatim path resolves against nothing, so the reason it names no file is its own.
    assert!(
        invalid(r"\\?\C:\dir\..").contains("never normalised"),
        "a verbatim `..` must not be explained by the current directory: {}",
        invalid(r"\\?\C:\dir\..")
    );
}

/// A drive prefix is a prefix, so only the FIRST component can be one. Everywhere else `a:` is
/// the file `a` opened through its unnamed data stream, exactly like `x.exe:`.
///
/// Judging the shape alone — one unit and a colon — made the verdict depend on how
/// long the name happens to be: `C:\bin\a:` was refused as "names no file" while `C:\bin\x.exe:`,
/// the same spelling of the same thing, was accepted.
#[test]
fn a_drive_prefix_is_one_only_at_the_front_of_the_path() {
    use std::path::Path;
    // At the front: a bare drive prefix resolves to that drive's current directory, a name this
    // gate cannot see.
    for probe in ["C:", "c:", "a:", r"C:\", "x:."] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} is a bare drive prefix and names no file"
        );
    }
    // Anywhere else it is an ordinary name with an unnamed stream.
    for probe in [r"C:\bin\a:", r"bin\a:", r"bin\C:", "x.exe:", r"\a:"] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_ok(),
            "{probe:?} names a file and must stay spawnable"
        );
    }
    // The relaxation must not reach a batch name hiding in that position.
    for probe in [r"C:\bin\a.bat:", r"C:\bin\x.exe:p.bat"] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} still reaches a batch file"
        );
    }
}

/// A drive prefix is ANY one UTF-16 unit followed by `:`, not only a letter.
///
/// `RtlDetermineDosPathNameType_U` tests nothing but `Path[1] == ':'` (ReactOS
/// `RtlDetermineDosPathNameType_Ustr`, Wine `RtlDetermineDosPathNameType_U`), and
/// `RtlGetFullPathName_U` then resolves the rest against that drive's current directory, or its
/// root. So `1:..` pops a current directory exactly as `C:..` does, and names a file this gate
/// cannot see. A character outside the BMP is two units, so `Path[1]` is its low surrogate and the
/// path is plain-relative: `𝒳:..` names the file `𝒳` through an empty stream.
#[test]
fn any_one_utf16_unit_before_a_colon_is_a_drive_prefix() {
    use std::path::Path;
    for probe in [
        "1:",
        "1:.",
        "1:..",
        r"1:\",
        r"1:\x.bat\..",
        "é:",
        "é:..",
        ".:",
        "::",
        // A lone surrogate reaches the gate as U+FFFD, one unit, through `to_string_lossy`.
        "\u{FFFD}:..",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} is drive-relative and names no file"
        );
    }
    for probe in ["é:x.bat", r"1:\x.bat", "1:x.bat:s", r"\\.\é:\..\x.bat"] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} reaches a batch file"
        );
    }
    for probe in [
        "𝒳:..",
        "𝒳:",
        r"x\1:",
        r"x\é:..",
        r"\\.\é:",
        r"1:\tool.exe",
        r"é:\tool.exe",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_ok(),
            "{probe:?} names a file that is no batch file"
        );
    }
    assert_eq!(
        super::streams::ntfs_stream_names("é:x.bat:s").collect::<Vec<_>>(),
        ["x.bat", "s"]
    );
    assert_eq!(super::streams::ntfs_stream_names("𝒳:x").collect::<Vec<_>>(), ["𝒳", "x"]);
}

/// The same with a real lone surrogate, which only a Windows `OsStr` can carry.
#[cfg(windows)]
#[test]
fn a_lone_surrogate_before_a_colon_is_a_drive_prefix() {
    use std::os::windows::ffi::OsStringExt;
    let wide: Vec<u16> = [0xD800].into_iter().chain(":..".encode_utf16()).collect();
    let probe = std::ffi::OsString::from_wide(&wide);
    assert!(
        super::reject_batch_path_on(std::path::Path::new(&probe), true).is_err(),
        "a lone surrogate is one unit, so this is drive-relative and names no file"
    );
}

/// A verbatim `\\?\` path is judged by std's verbatim rule, which is not std's rule for any
/// other path.
///
/// Measured on Windows runners, both architectures, twice: a file named `...`, `....`, `" "` or
/// `"x "` is creatable, listable and openable through a `\\?\` path, and both `CreateProcessW`
/// and `std::process` spawn it — exit 0 — while the plain spelling of the same name fails with
/// access-denied. Refusing those was refusing a genuinely loadable executable.
///
/// The other half comes from std's source: for a verbatim program `is_batch_file` is a literal
/// test of the last four UTF-16 units of the string, and the prefix comes off first only when
/// `GetFullPathNameW` round-trips the rest unchanged. So `\\?\C:\x.bat.` keeps its prefix and
/// ends in `bat.`, and cmd.exe is not substituted — while the plain `C:\x.bat.` has its trailing dot
/// trimmed on the way through `GetFullPathNameW` and reaches the batch file. The gate refuses both
/// all the same, as the stricter verdict; the names it must still accept are the ones only the
/// prefix can reach.
///
/// `..` is the one component that names nothing even here: no collapse happens, and the object
/// manager rejects the literal name (measured: `ERROR_INVALID_NAME`). Refusing it costs nothing.
#[test]
fn a_verbatim_path_is_judged_the_way_std_judges_one() {
    use std::path::Path;
    // std's literal suffix test fires: these are the verbatim paths that reach cmd.exe.
    for probe in [
        r"\\?\C:\x.bat",
        r"\\?\C:\dir\x.CMD",
        // The batch name ends the string, so the literal test fires on it too.
        r"\\?\C:\dir\x.exe:p.bat",
        r"\\?\UNC\server\share\x.bat",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} is what std hands to cmd.exe"
        );
    }
    // Nothing is collapsed here, so `..` stays literal — and no file may be called that.
    for probe in [r"\\?\C:\dir\..", r"\\?\C:\.."] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} names no file even verbatim"
        );
    }
    // std's literal test passes these, and the image loads like any other; refused all the same,
    // as the stricter verdict (see `a_normalised_batch_path_is_refused_by_suffix_on_every_stream_piece`).
    for probe in [r"\\?\C:\x.bat.", r"\\?\C:\x.bat "] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_err(),
            "{probe:?} trims to a batch name"
        );
    }
    // Loadable, and measured to be: the prefix is how you spell a name Win32 cannot otherwise
    // reach, and std's literal test misses all of them.
    for probe in [
        r"\\?\C:\dir\....",
        r"\\?\C:\dir\...",
        r"\\?\C:\dir\ ",
        r"\\?\C:\dir\x ",
        r"\\?\C:\dir\tool.exe",
        // Not loadable either, but nothing here can reach cmd.exe and the OS's own error says
        // more about why than a refusal would. Only `..` is singled out, because only `..` is a
        // verdict this gate already gave.
        r"\\?\C:\dir\.",
        r"\\?\C:\dir\",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_ok(),
            "{probe:?} is a loadable image on a measured Windows runner"
        );
    }
    // The plain spelling is a different file and keeps its verdict: Win32 trims the trailing dot
    // and space off these and reaches the batch file.
    for plain in [r"C:\x.bat.", r"C:\x.bat "] {
        assert!(
            super::reject_batch_path_on(Path::new(plain), true).is_err(),
            "{plain:?} still resolves to the batch file"
        );
    }
    // A data stream of a batch file is refused under the prefix as it is without: std hands
    // `CreateProcessW` the same string for each pair, and whether that launches cmd.exe is
    // unmeasured. See `verbatim_refusal`.
    for stream in [
        r"C:\x.bat:s",
        r"C:\x.bat:",
        r"C:\x.bat::$DATA",
        r"C:\x.bat.:s",
        r"C:\x.exe:p.bat:$DATA",
    ] {
        for probe in [stream.to_string(), format!(r"\\?\{stream}")] {
            assert!(
                super::reject_batch_path_on(Path::new(&probe), true).is_err(),
                "{probe:?} is refused until kernelbase is measured"
            );
        }
    }
    // A stream of a file that is no batch file stays accepted.
    for probe in [r"\\?\C:\x.exe:s", r"\\?\C:\dir\x.exe::$DATA"] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), true).is_ok(),
            "{probe:?} is a stream of no batch file"
        );
    }
}

/// The POSIX half of the same gate, also with the platform forced: past the NUL check it refuses
/// NOTHING. Every spelling the Win32 half above refuses is listed here accepted, so a `win32`
/// argument dropped on the floor — or a Win32 rule that leaked out of its branch — fails here
/// rather than only on a Linux or macOS lane at spawn time.
#[test]
fn reject_batch_path_on_posix_refuses_nothing_but_a_nul() {
    use std::path::Path;
    for probe in [
        // Plain batch names: an ordinary executable to this host, which `a_posix_host_runs_
        // its_own_executable_named_bat` proves by running one.
        "x.bat",
        "x.CMD",
        "dir/x.bat",
        "x.exe:payload.bat",
        // `\\` is an ordinary filename character off Win32, so none of the Win32 collapses,
        // prefixes or stream splits describe anything here.
        r"x.bat\y\..",
        r"C:\dir\x.bat",
        r"\\?\C:\x.bat",
        r"\\srv\x.bat\..",
        "report.cmd:archived",
        "x.bat ",
        "backup.cmd.",
        ".bat",
        // Names no file — POSIX resolves nothing further, so it simply fails to spawn.
        "",
        "/",
        ".",
        "x/..",
    ] {
        assert!(
            super::reject_batch_path_on(Path::new(probe), false).is_ok(),
            "{probe:?} is a legal POSIX program token and must stay spawnable"
        );
    }
}

/// The refusal's advice must name a route that EXISTS. `.commandline()` on its own is not one:
/// its first token becomes the program and lands straight back in this gate.
///
/// Asked of the Win32 verdict as data, so the wording is pinned from every host; the production
/// leg below shows the loop is real on the host that has it.
#[test]
fn the_refusal_advises_a_route_that_is_not_itself_refused() {
    let err = super::reject_batch_path_on(std::path::Path::new("x.bat"), true)
        .expect_err("the first token of `commandline(\"x.bat --flag\")` is refused");
    let Error::Unsupported { detail, .. } = &err else {
        panic!("got {err:?}")
    };
    assert!(
        !detail.contains("use .commandline() to pass"),
        "the message advises the very call that just failed: {detail}"
    );
    // What it advises instead: cmd.exe as the loaded image, with a line the caller escaped for
    // cmd.exe itself. The program token is `cmd.exe` on both routes, and that is not a batch file.
    super::reject_batch_path_on(std::path::Path::new("cmd.exe"), true).expect("the advised route must not be refused");

    #[cfg(windows)]
    {
        let mut looped = Command::new();
        looped.commandline("x.bat --flag");
        crate::child::spawn::build_std_command(&looped).expect_err("commandline() alone is still gated");

        let mut advised = Command::new();
        advised
            .executable("cmd.exe")
            .commandline(r#"cmd.exe /c "x.bat" --flag"#);
        assert!(crate::child::spawn::routes_to_raw_backend(&advised));
        crate::child::spawn::windows_raw::reject_batch_program(&advised)
            .expect("the advised route must not be refused");
    }
}

// The batch gate reads the prefix Win32 would load =====

/// An `OsString` carrying an interior NUL, built natively on either platform family (`OsStr` has
/// no portable constructor that can express one).
fn with_interior_nul(prefix: &str, suffix: &str) -> std::ffi::OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(suffix.as_bytes());
        std::ffi::OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = prefix.encode_utf16().chain([0]).chain(suffix.encode_utf16()).collect();
        std::ffi::OsString::from_wide(&units)
    }
}

/// `Path::extension()` of `token` — the value [`super::reject_batch_path_on`] must NOT key on.
fn extension_of(token: &std::ffi::OsStr) -> Option<String> {
    std::path::Path::new(token)
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
}

/// The `op` of an `Unsupported` refusal; panics on anything else, naming what came back.
fn unsupported_op<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Unsupported { op, .. }) => op,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// The `Display` of an `Io(InvalidInput)` refusal; panics on anything else.
fn invalid_input_message<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

/// The gate under a Win32 verdict, spelled as a value so this host can ask for it.
fn on_win32(token: &std::ffi::OsStr) -> Result<(), Error> {
    super::reject_batch_path_on(std::path::Path::new(token), true)
}

/// The gate under a POSIX verdict, ditto.
fn on_posix(token: &std::ffi::OsStr) -> Result<(), Error> {
    super::reject_batch_path_on(std::path::Path::new(token), false)
}

/// The Win32 verdict refuses an interior NUL too, on BOTH NUL/batch shapes — the derivation is in
/// [`super::reject_batch_path_on`]'s doc. Neither may come back as the batch refusal: on
/// `setup` + NUL + `.bat` Win32 loads `setup`, which carries no batch vector at all, and on
/// `setup.bat` + NUL + `junk` the caller's defect is the NUL that made a `.bat`-suffixed token
/// load a batch file.
///
/// Pinned on the gate itself because the gate is the std backend's ONLY NUL check: an `Ok` here is
/// a token the crate hands to `std::process` for its internals to catch or not.
#[test]
fn an_interior_nul_is_refused_on_the_win32_verdict_too() {
    let nul_then_bat = with_interior_nul("setup", ".bat");
    let bat_then_nul = with_interior_nul("setup.bat", "junk");

    // Premise: the extension is inverted on both shapes, which is why the gate cannot use it.
    assert_eq!(extension_of(&nul_then_bat), Some("bat".to_owned()));
    assert_ne!(extension_of(&bat_then_nul), Some("bat".to_owned()));

    for token in [&nul_then_bat, &bat_then_nul] {
        // An `Ok`, or the `Unsupported` batch refusal, panics in the helper.
        let msg = invalid_input_message(on_win32(token));
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
        assert!(
            !msg.contains('\0'),
            "the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
}

/// The truncation is a WIN32 fact, so it decides nothing off Win32. On POSIX `x.bat` + NUL +
/// `junk` names no file at all — there is nothing to truncate, no cmd.exe, and no CVE-2024-24576
/// to audit — so the honest verdict is the NUL, and blaming batch escaping is the very
/// misattribution the prefix rule exists to remove, one platform over.
#[test]
fn a_nul_bearing_program_is_diagnosed_as_a_nul_off_win32() {
    for token in [
        with_interior_nul("x.bat", "junk"),
        with_interior_nul("x", ".bat"),
        with_interior_nul("/usr/bin/ls", "junk"),
    ] {
        let msg = invalid_input_message(on_posix(&token));
        for wrong in ["cmd.exe", "CVE-2024-24576", "windows", "Win32"] {
            assert!(
                !msg.contains(wrong),
                "a POSIX refusal must not mention {wrong:?}: {msg}"
            );
        }
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
        assert!(
            !msg.contains('\0'),
            "the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
}

/// The same token, the two platform verdicts, from one host: `win32` is data rather than a `cfg!`
/// precisely so both are reachable here. Both refuse the NUL, but each names its own reason — off
/// Win32 nothing truncates, so citing the truncation would send a Linux caller to audit a platform
/// they are not on.
#[test]
fn each_verdict_gives_the_nul_refusal_its_own_reason() {
    let bat_then_nul = with_interior_nul("x.bat", "junk");
    assert!(invalid_input_message(on_win32(&bat_then_nul)).contains("truncate"));
    assert!(!invalid_input_message(on_posix(&bat_then_nul)).contains("truncate"));
}

/// The WRAPPER, which none of the tests above reach: they spell `win32` out as data, so pinning
/// [`super::reject_batch_path`]'s `cfg!(windows)` argument to `true` leaves every one of them
/// green while POSIX callers get the Win32 diagnosis back.
#[test]
fn the_gate_wrapper_asks_for_this_hosts_verdict() {
    let bat_then_nul = with_interior_nul("setup.bat", "junk");
    let nul_then_bat = with_interior_nul("setup", ".bat");
    let via_host = |t: &std::ffi::OsStr| super::reject_batch_path(std::path::Path::new(t));

    let clean_bat = std::ffi::OsString::from(r"C:\tools\setup.bat");

    if cfg!(windows) {
        assert!(unsupported_op(via_host(&clean_bat)).contains("setup.bat"));
    } else {
        assert!(via_host(&clean_bat).is_ok(), "no cmd.exe here to blame");
    }
    // The NUL verdict is the same either way; the clean `.bat` above is what the argument decides.
    for token in [&bat_then_nul, &nul_then_bat] {
        let msg = invalid_input_message(via_host(token));
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
    }
}

/// The batch rule is a WIN32 verdict — why, in [`super::reject_batch_path_on`]'s doc. Both legs
/// matter: the NUL arm above must not have swallowed the rule where it does apply, and the rule
/// must not reach a host with no cmd.exe to blame.
#[test]
fn a_clean_batch_program_is_a_win32_verdict_only() {
    let token = std::ffi::OsString::from(r"C:\tools\setup.bat");
    assert!(unsupported_op(on_win32(&token)).contains("setup.bat"));
    assert!(
        on_posix(&token).is_ok(),
        "off Win32 a .bat is judged by the host that will actually run it"
    );
}

/// What makes that POSIX arm a correction rather than a preference: here `.bat` is an ordinary
/// suffix, and the gate refused a command this host executes.
#[cfg(unix)]
#[test]
fn a_posix_host_runs_its_own_executable_named_bat() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("deploy.bat");
    // The write is serialized against every other spawn's `fork`, and the guard is dropped before
    // OUR spawn — `spawn_unelevated` takes the same lock, and a `std::sync::Mutex` is not
    // reentrant, so holding it across `spawn()` deadlocks. Scoping it to the write is what the
    // race needs anyway: `fs::write`'s descriptor is writable, and a `fork` inside that window
    // leaves the forked child holding it until it execs, during which `execve` on this script
    // returns ETXTBSY. Measured: CI's linux/amd64 lane failed exactly that way while every other
    // lane passed. Once the descriptor is closed, no later spawn can inherit it.
    {
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&script, "#!/bin/sh\nexit 7\n").expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let mut c = Command::new();
    c.args([script.as_os_str()]);
    let child = c.spawn().expect("a .bat this host can run must not be refused");
    assert_eq!(
        child.wait().expect("wait").code(),
        Some(7),
        "the host ran the script, so its own exit code must come back"
    );
}

/// The std backend is the DEFAULT Windows path: `args([..])` with no `executable()` and no
/// fd >= 3 is false for `routes_to_raw_backend`, so it reaches the gate through
/// [`crate::child::spawn::build_std_command`] with no NUL check of its own.
///
/// Host-independent on purpose: what it pins is that the gate judges the token the CALLER named.
///
/// The KIND is asserted on every host, not just off Win32: this token's extension is the one the
/// batch rule could plausibly claim, so an `.expect_err` alone would be satisfied on a Windows run
/// by the very misattribution the gate exists to prevent.
#[test]
fn the_std_backend_judges_the_program_token_the_caller_named() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup.bat", "junk")]);
    // An `Ok`, or the `Unsupported` batch refusal, panics in the helper.
    let msg = invalid_input_message(crate::child::spawn::build_std_command(&c));
    assert!(
        !msg.contains('\0'),
        "the refusal must not carry a raw NUL into logs: {msg:?}"
    );
}

/// The mirror shape on the same default path: `C:\tools\setup` + NUL + `.bat` must come back as
/// the NUL, never as the batch vector — what Win32 would load is `C:\tools\setup`, which carries
/// no batch vector at all.
///
/// Asserted as an `Io(InvalidInput)` and not merely as "not `Unsupported`": an `Ok` satisfies the
/// negative form, which cannot tell "refused for the right reason" from "not refused at all" —
/// and what follows an `Ok` here is `std::process`, whose own NUL check is an internal of another
/// crate for this one to be leaning on.
#[test]
fn the_std_backend_does_not_blame_the_batch_vector_for_a_truncated_prefix() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup", ".bat")]);
    invalid_input_message(crate::child::spawn::build_std_command(&c));
}

/// THE PLATFORM WIRING, on the spellings only the Win32 branch reaches.
/// [`the_gate_wrapper_asks_for_this_hosts_verdict`] pins the same argument on a clean `.bat`;
/// these two discriminate the rest of the rule, which a wrapper hard-coded to either constant
/// would take with it.
///
/// `x.bat ` is the sharper of the pair: Win32 strips the trailing space and reaches the batch
/// file, so Windows must refuse it — while on POSIX it is an ordinary filename that must stay
/// spawnable. A single expectation cannot satisfy both, so this kills both mutants.
#[test]
fn the_gate_wrapper_carries_the_hosts_verdict_into_the_win32_only_spellings() {
    use std::path::Path;
    let trailing_space = super::reject_batch_path(Path::new("x.bat "));
    let leading_dot_only = super::reject_batch_path(Path::new(".bat"));
    if cfg!(windows) {
        assert!(
            trailing_space.is_err(),
            "Windows must refuse `x.bat ` — NTFS reaches x.bat"
        );
        assert!(
            leading_dot_only.is_err(),
            "Windows must refuse `.bat` — PathFindExtension reads .bat"
        );
    } else {
        assert!(
            trailing_space.is_ok(),
            "POSIX must keep `x.bat ` spawnable — a legal filename"
        );
        assert!(
            leading_dot_only.is_ok(),
            "POSIX must keep `.bat` spawnable — no extension there"
        );
    }
}

/// The alphabet that can spell the hazard: `x.bat`, `x.cmd`, both separators, the stream
/// separator, and the trailing space and dot Win32 strips.
const ALPHABET: [char; 12] = ['x', '.', 'b', 'a', 't', 'c', 'm', 'd', ' ', ':', '\\', '/'];

/// Every string of length `0..=max_len` over [`ALPHABET`].
fn for_every_string(max_len: u32, mut probe: impl FnMut(&str)) {
    let mut buf = String::new();
    for len in 0..=max_len {
        for mut index in 0..ALPHABET.len().pow(len) {
            buf.clear();
            for _ in 0..len {
                buf.push(ALPHABET[index % ALPHABET.len()]);
                index /= ALPHABET.len();
            }
            probe(&buf);
        }
    }
}

/// The gate this replaced, as a differential oracle — with the dot rule written out rather
/// than delegated back to `Path::extension`, or both sides of property 2 below would be the same
/// call and the comparison could not fail.
///
/// `Path::extension`'s contract, restated: the file name minus everything up to and including its
/// LAST dot, and no extension at all when the name has no dot or its only dot is the first
/// character. The file-name split stays `Path`'s, because it is host-dependent (`\` separates on
/// Windows and does not on POSIX) and is not the part at risk.
pub(super) fn the_extension_rule_this_replaced(prog: &std::path::Path) -> bool {
    let Some(name) = prog.file_name() else { return false };
    let name = name.to_string_lossy();
    match name.rfind('.') {
        None | Some(0) => false,
        Some(dot) => {
            let ext = name[dot + 1..].to_ascii_lowercase();
            ext == "bat" || ext == "cmd"
        }
    }
}

/// [`the_extension_rule_this_replaced`] as Windows applied it to a `\\?\` path, spelled out
/// because this host's `Path` cannot apply it: under the prefix only `\` separates and nothing is
/// trimmed, so the file name is the last `\`-separated piece AS WRITTEN. macOS's `Path` instead
/// splits `\\?\x.bat/` at the `/`, drops the empty tail and reports `x.bat` — a refusal the old
/// rule never made on the host it ran on.
pub(super) fn verbatim_extension_rule_this_replaced(text: &str) -> bool {
    let name = text.rsplit('\\').next().expect("rsplit yields at least one piece");
    match name.rfind('.') {
        None | Some(0) => false,
        Some(dot) => {
            let ext = name[dot + 1..].to_ascii_lowercase();
            ext == "bat" || ext == "cmd"
        }
    }
}

/// Exhaustive over CHARACTERS: every string of length <= 5 over [`ALPHABET`], which is arbitrary
/// punctuation soup no component-shaped generator would ever emit.
///
/// It is not exhaustive over this gate's HISTORY, and must not be read as if it were. Every
/// spelling that has actually bypassed the gate is longer than five characters — `x.bat:` is 6,
/// `C:x.bat:s` is 9, `x.bat\y\..` is 10 — so a bug has to be re-findable inside a five-character
/// budget before this test can see it. The length that matters is reached by
/// `the_gate_agrees_with_a_component_level_resolver`, which generates whole components instead of
/// characters; this one covers the short strings that generator's vocabulary cannot spell.
///
/// 1. No REGRESSION: nothing the old rule refused may be newly accepted. Widening a security gate
///    must never narrow it somewhere else.
/// 2. Nothing refused on POSIX: `main` made the batch rule a Win32 verdict, and every probe here
///    is NUL-free, so the POSIX verdict has nothing left to say about any of them.
/// 3. No batch suffix accepted on Windows: the property the whole gate exists for.
#[test]
fn the_gate_never_accepts_what_the_rule_it_replaced_refused() {
    let mut newly_accepted = Vec::new();
    let mut posix_refused = Vec::new();
    let mut batch_accepted = Vec::new();
    for_every_string(5, |probe| {
        let path = std::path::Path::new(probe);
        let replaced = the_extension_rule_this_replaced(path);
        let windows = super::reject_batch_path_on(path, true).is_err();
        if replaced && !windows {
            newly_accepted.push(probe.to_string());
        }
        if super::reject_batch_path_on(path, false).is_err() {
            posix_refused.push(probe.to_string());
        }
        if (probe.ends_with(".bat") || probe.ends_with(".cmd")) && !windows {
            batch_accepted.push(probe.to_string());
        }
    });
    assert_eq!(newly_accepted, Vec::<String>::new(), "refused before, accepted now");
    assert_eq!(
        posix_refused,
        Vec::<String>::new(),
        "the POSIX verdict refuses nothing but a NUL"
    );
    assert_eq!(
        batch_accepted,
        Vec::<String>::new(),
        "accepted a name ending in a batch extension"
    );
}

/// Normalisation leaves batch names `Path::extension()` cannot see: `.bat` is a bare name to it,
/// and a data-stream piece hides behind `:`. Each is refused behind `\\?\` too, trailing dots and
/// spaces included: that is the stricter of two verdicts, taken where this gate once disagreed with
/// a suffix rule applied to every stream piece of the final component, each trimmed of trailing
/// dots and spaces. std's literal verbatim test passes `\\?\C:\t\x.bat.`, so refusing it is an
/// over-refusal as far as std goes; how kernelbase reads it is unmeasured.
#[test]
fn a_normalised_batch_path_is_refused_by_suffix_on_every_stream_piece() {
    for p in [
        r"C:\t\.bat",
        r"C:\t\SETUP.CMD",
        r"C:\t\x.exe:payload.bat",
        r"C:\t\x.bat::$DATA",
        r"C:\t\x.bat.:s",
        r"C:\t\x.bat :s",
        r"C:\t\x.bat.",
        r"C:\t\x.bat ",
        r"C:\t\x.cmd. .",
        r"C:\t\a/x.bat.",
    ] {
        for probe in [p.to_string(), format!(r"\\?\{p}")] {
            assert_eq!(
                unsupported_op(super::reject_batch_path_on(std::path::Path::new(&probe), true)),
                format!("running {probe}")
            );
        }
    }
    for p in [
        r"C:\t\setup.exe",
        r"C:\t\setup.bat.exe",
        r"C:\t.bat\setup.exe",
        r"C:\t\batch",
    ] {
        for probe in [p.to_string(), format!(r"\\?\{p}")] {
            assert!(
                super::reject_batch_path_on(std::path::Path::new(&probe), true).is_ok(),
                "{probe}"
            );
        }
    }
}

/// Argv and command-line commands on the default std route (no `executable()`, no fd >= 3).
#[cfg(windows)]
fn std_routed(args: &[&str], lines: &[&str]) -> Vec<(String, Command)> {
    let mut out = Vec::new();
    for &n in args {
        let mut c = Command::new();
        c.args([n]);
        out.push((format!("args([{n:?}])"), c));
    }
    for &l in lines {
        let mut c = Command::new();
        c.commandline(l);
        out.push((format!("commandline({l:?})"), c));
    }
    for (via, c) in &out {
        assert!(
            !crate::child::spawn::routes_to_raw_backend(c),
            "{via} must take the std route"
        );
    }
    out
}

/// std runs a batch file through cmd.exe once `GetFullPathNameW` has trimmed the name, and a
/// `commandline()` tail reaches it unescaped, so these must be refused as they are on the raw route.
#[cfg(windows)]
#[test]
fn the_std_route_refuses_a_batch_only_normalisation_exposes() {
    // Trailing dot; one trailing space; a file named `.bat`.
    for (via, c) in std_routed(&["x.bat.", "x.bat ", ".bat"], &["x.bat. a&b"]) {
        match crate::child::spawn::build_std_command(&c) {
            Err(Error::Unsupported { .. }) => {}
            other => panic!("{via}: expected Unsupported, got {:?}", other.map(|_| "a command")),
        }
    }
}

#[cfg(windows)]
#[test]
fn the_std_route_accepts_an_exe_named_like_a_batch() {
    for (via, c) in std_routed(&["x.bat.exe", "tool.exe"], &["x.bat.exe a&b"]) {
        if let Err(e) = crate::child::spawn::build_std_command(&c) {
            panic!("{via}: {e:?}");
        }
    }
}
