//! Unit tests for the batch gate: the spellings Windows resolves to a `.bat`/`.cmd`, the NUL
//! refusal, and an exhaustive comparison against a component-level oracle.

use crate::command::Command;
use crate::error::Error;

/// The NTFS normalisation, as pure string logic — runs on every host.
///
/// Windows resolves `x.bat `, `x.bat.` and `x.bat:s` all to `x.bat`. This pins the PIECES, which
/// is not the verdict — `is_batch_program` is where the pieces become one.
#[test]
fn ntfs_stream_names_splits_off_every_stream_then_trims_space_and_dot() {
    for (probe, want) in [
        ("x.bat ", vec!["x.bat"]),
        ("x.bat.", vec!["x.bat"]),
        ("x.bat:s", vec!["x.bat", "s"]),
        ("x.bat. ", vec!["x.bat"]),
        ("x.bat::$DATA", vec!["x.bat", "", "$DATA"]),
        // EVERY piece, not just the first. Truncating at the first `:` reads `x.exe:payload.bat:`
        // as the file `x.exe` and loses the batch name entirely.
        ("x.exe:payload.bat:", vec!["x.exe", "payload.bat", ""]),
        // A leading drive prefix is a drive, not a stream separator, so it is not among the names
        // yielded. No verdict rides on that today — a drive is one UTF-16 unit and so is never
        // a batch name — but it did when only the first piece was read, which is how `C:x.bat:s`
        // came to be allowed while `x.bat:s` was refused.
        ("C:x.bat:s", vec!["x.bat", "s"]),
        ("c:x.bat", vec!["x.bat"]),
        // Two letters before the colon is a file name, not a drive.
        ("ab:x.bat", vec!["ab", "x.bat"]),
        // Any one UTF-16 unit before the colon is a drive, as `RtlDetermineDosPathNameType_U` has it.
        (".:x.bat", vec!["x.bat"]),
        ("é:x.bat", vec!["x.bat"]),
        // ORDER witnesses. `x.bat:s ` does NOT discriminate — both orders yield `x.bat`, because
        // trim-then-split still splits. These three do: trim-then-split would leave the trailing
        // character attached and the extension check would miss it.
        ("x.bat.:s", vec!["x.bat", "s"]),
        ("x.bat :s", vec!["x.bat", "s"]),
        ("x.bat. :s", vec!["x.bat", "s"]),
        // Untouched: Win32 strips only spaces and periods, so a tab names a different file.
        ("x.bat\t", vec!["x.bat\t"]),
        // Leading characters are never trimmed — `trim_matches` instead of `trim_end_matches`
        // would turn `..bat` into `bat` and flip it from refused to allowed.
        ("..bat", vec!["..bat"]),
        ("x.exe", vec!["x.exe"]),
    ] {
        assert_eq!(super::ntfs_stream_names(probe).collect::<Vec<_>>(), want, "{probe:?}");
    }
}

/// The shell's extension rule, which is NOT `Path::extension()` — it takes the last `.` anywhere.
/// Both divergences matter: a name that IS `.bat`, and a batch extension hiding after a data
/// stream separator.
#[test]
fn is_batch_by_shell_follows_the_last_dot_anywhere_in_the_name() {
    for yes in [
        ".bat",
        ".cmd",
        "x.bat",
        "x.CMD",
        "x.exe:payload.bat",
        "tool:go.bat",
        "a.b.c.bat",
    ] {
        assert!(super::is_batch_by_shell(yes), "{yes:?} must read as a batch name");
    }
    for no in ["x.exe", "batch", "x.batch", "bat", "x.bat ", "x.bat:s", "x.bat."] {
        // The last three are batch files only after NTFS normalisation — the other half of the
        // rule. This predicate alone must not claim them.
        assert!(
            !super::is_batch_by_shell(no),
            "{no:?} must not read as a batch name here"
        );
    }
}

/// THE WINDOWS DECISION, exercised from every host: `is_batch_program` is pure string logic, so
/// it runs everywhere rather than on the two Windows lanes alone — the same reason
/// [`super::reject_batch_path_on`] takes its platform as a parameter.
///
/// Every probe here is grouped by the piece of `ntfs_stream_names` it depends on. That is the
/// only reading left — see `the_stream_reading_subsumes_the_shell_reading` for why a second one
/// would add no refusal.
#[test]
fn is_batch_program_on_windows_refuses_every_stream_piece() {
    // The name itself, after Win32's trailing-character trim.
    for probe in [
        "x.bat ", "x.bat.", "x.cmd ", "x.bat. ", "x.bat.:s", "x.bat:s", "x.CMD:s",
    ] {
        assert!(super::is_batch_program(probe), "{probe:?} trims to a batch file");
    }
    // The batch name is in a LATER piece, so a check that reads the extension off the whole
    // string misses it: `x.exe:payload.bat:` reads as extension `bat:` and `C:x.bat:s` as `bat:s`.
    for probe in ["x.exe:payload.bat:", "x.exe:payload.bat:$DATA", "C:x.bat:s"] {
        assert!(
            super::is_batch_program(probe),
            "{probe:?} hides the batch name in a later stream piece"
        );
    }
    // The batch name is in the FIRST piece, so a check that reads only the LAST misses it.
    for probe in ["x.bat:", "x.bat:s", "x.bat::$DATA"] {
        assert!(
            super::is_batch_program(probe),
            "{probe:?} hides the batch name in the first stream piece"
        );
    }
    // A middle piece: neither first nor last.
    assert!(super::is_batch_program("a:x.bat:s"));
    // The stream name alone is the batch file; the file it hangs off is not.
    for probe in ["x.exe:payload.bat", "notepad.exe:p.cmd", "tool:go.bat", "x.txt:a.bat"] {
        assert!(
            super::is_batch_program(probe),
            "{probe:?} runs out of a batch-named stream"
        );
    }
    // A name that IS the extension — `Path::extension()` reports None for it.
    for probe in [".bat", ".cmd"] {
        assert!(super::is_batch_program(probe), "{probe:?} is a batch name");
    }
    // Plain forms, and lookalikes that must stay allowed.
    assert!(super::is_batch_program("x.bat"));
    assert!(!super::is_batch_program("x.exe"));
    assert!(!super::is_batch_program("x.batch"));
    assert!(!super::is_batch_program("batch"));
}

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
        if super::is_batch_by_shell(probe) && !super::is_batch_program(probe) {
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
/// ones. Without it, reverting this gate to the `Path::extension()` rule it replaced stayed green
/// on four of six, and the `..` collapse had no coverage off Windows.
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
        // A dots-and-spaces segment BEFORE a `..` has two readings — dropped, or kept as a name the
        // `..` then pops — and each exposes a different component. Only the final position is
        // measured, so the gate refuses when either reading reaches a batch file.
        r"y\x.bat\...\..",
        r"y\x.bat\.. \..",
        r"y\x.bat\ \..",
        r"x.bat\y\...\..",
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
        // Both readings of the interior `...` land on `b`.
        r"a\...\..\b",
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
/// The gate takes two readings of an interior dots-and-spaces segment, and one path can refuse
/// for a different reason under each: `x.bat\...\..` names no file if the `...` drops out and
/// `x.bat` if it is a name the `..` pops. The batch reason wins, because only it names the vector.
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
    // `\\.\x.bat\..` resolves to the bare `\\.\`: no file, and no batch file either.
    for probe in [r"x\..", ".", "C:", r"\\.\x.bat\.."] {
        assert!(
            detail(probe).contains("names no file of its own"),
            "{probe:?} names no file, so it must advise naming the executable: {}",
            detail(probe)
        );
    }
    // A verbatim path resolves against nothing, so the reason it names no file is its own.
    assert!(
        detail(r"\\?\C:\dir\..").contains("never normalised"),
        "a verbatim `..` must not be explained by the current directory: {}",
        detail(r"\\?\C:\dir\..")
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
        super::ntfs_stream_names("é:x.bat:s").collect::<Vec<_>>(),
        ["x.bat", "s"]
    );
    assert_eq!(super::ntfs_stream_names("𝒳:x").collect::<Vec<_>>(), ["𝒳", "x"]);
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
/// ends in `bat.`, cmd.exe is not substituted, and the image
/// loads like any other — while the plain `C:\x.bat.` has its trailing dot trimmed on the way
/// through `GetFullPathNameW` and reaches the batch file. Same name, different resolution, so the
/// gate must not give them the same verdict.
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
    // Loadable, and measured to be: the prefix is how you spell a name Win32 cannot otherwise
    // reach, and std's literal test misses all of them.
    for probe in [
        r"\\?\C:\x.bat.",
        r"\\?\C:\x.bat ",
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

/// A refused spawn must not have mutated this process first. `clear_std_handle_inheritance` is a
/// real, process-global, un-undone `SetHandleInformation` on our own std handles, so running it
/// before the refusal would leave a disposition-less side effect behind.
///
/// The two legs differ by one bit and are one `#[test]` so their order is guaranteed; `cargo
/// test` gives each test its own thread, so the thread-local seam starts clean. The positive leg
/// is what stops the negative one passing on a seam that was never wired.
///
/// The real handle flags are deliberately NOT measured instead: the mutation is process-global
/// and permanent, so any earlier contained spawn in this binary would already have made that
/// observation meaningless.
#[cfg(windows)]
#[test]
fn a_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.executable("cmd").args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

/// An environment key with an embedded NUL is refused before the process-global handle mutation
/// too. The seam's wiring is proven by the positive leg of the test above.
#[cfg(windows)]
#[test]
fn a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("an embedded NUL must be refused");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
}

/// The std-path counterpart of the test above. The std backend reaches the same process-global
/// mutation through `containment::prepare`, which composes and validates the creation-flag word
/// at its top — a separate ordering the raw backends' tests cannot see.
///
/// Argv-only and no `executable()`, asserted through `routes_to_raw_backend` so a future routing
/// change cannot quietly turn this into a third raw-backend test.
#[cfg(windows)]
#[test]
fn a_refused_std_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    assert!(
        !crate::child::spawn::routes_to_raw_backend(&refused),
        "this leg is only a std-path proof while the command stays off the raw backend"
    );
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
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
/// green while POSIX callers get the Win32 diagnosis back — the regression this round already
/// fixed once, in the gate the helper is only half of.
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
/// Before this round it read `std::process::Command::get_program()`, and std's Unix constructor
/// had already swapped a NUL-bearing program for a `<string-with-nul>` sentinel — so on this host
/// the call returned `Ok` and the token reached `spawn`.
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

/// The Win32 path collapse, as pure logic — runs on every host, unlike the gate that uses it.
///
/// `win32_effective_file_name` is only *called* under `cfg!(windows)`, so mutating its internals
/// is invisible to the other four CI lanes. Testing it directly is what keeps the `..` collapse
/// and the trailing-character order gated everywhere rather than only on the Windows runners.
#[test]
fn win32_effective_file_name_collapses_the_way_win32_resolves() {
    use std::path::Path;
    for (probe, want) in [
        // `..` collapses, so the batch file IS the effective name — the bypass.
        (r"x.bat\y\..", Some("x.bat")),
        ("x.bat/y/..", Some("x.bat")),
        (r"C:\dir\x.bat\y\..", Some("x.bat")),
        // Only a segment that is exactly `..` pops. `.. ` is a dots-and-spaces segment, and a final
        // one drops out: measured, `x.bat\y\.. ` resolves to `…\x.bat\y\`.
        (r"x.bat\y\.. ", Some("y")),
        (r"x.bat\y\..  ", Some("y")),
        // `.` is skipped.
        (r"x.bat\.", Some("x.bat")),
        // Ordinary trailing dots and spaces come off the final component.
        ("x.bat ", Some("x.bat")),
        ("x.bat.", Some("x.bat")),
        // The `..` pops `x.bat` and the stack is empty. Win32 does not stop there — it pops on
        // into the current directory's ancestors — so this names a file whose name is not in the
        // string, which is why the gate refuses `None` rather than accepting it.
        (r"x.bat\..", None),
        // A repeated separator is a separator, never a component: reaching the dots-and-spaces arm
        // it would drop `y` and expose the batch file.
        (r"x.bat\\y", Some("y")),
        // Plain cases unchanged.
        (r"C:\dir\tool.exe", Some("tool.exe")),
        ("tool", Some("tool")),
        // A data stream is part of the name, not a prefix to drop — only a BARE drive is, and
        // only in the position a drive prefix can occupy.
        ("x.bat:", Some("x.bat:")),
        ("x.bat: ", Some("x.bat:")),
        ("C:x.bat:s", Some("C:x.bat:s")),
        (r"C:\bin\a:", Some("a:")),
        (r"\C:", Some("C:")),
        // Names no file.
        ("", None),
        ("/", None),
        (r"C:\", None),
        ("C:", None),
        ("c:", None),
        // A UNC SHARE is a root. Win32 never pops one — the effective name stays the share, which
        // is a NAMED final component and so is judged like any other. Model it as a path with no
        // root and `..` reduces every one of these to `srv`, which is not a batch name, and the
        // gate accepts a token `std::process` hands to cmd.exe.
        (r"\\srv\x.bat\..", Some("x.bat")),
        ("//srv/x.bat/..", Some("x.bat")),
        (r"\/srv\x.cmd\..", Some("x.cmd")),
        ("\\\\srv\\x.bat\\.. ", Some("x.bat")),
        (r"\\srv\x.bat\y\..\..", Some("x.bat")),
        (r"\\srv\x.bat\y\..\..\..", Some("x.bat")),
        // The share is trimmed like any other component before it is judged.
        (r"\\srv\x.bat \..", Some("x.bat")),
        (r"\\srv\x.bat.\..", Some("x.bat")),
        // The root is POSITIONAL, and a floor one component too deep is an acceptance: skip the
        // dots-only server here and the root becomes `x.bat\y`, `..` is clamped, and `y` is judged
        // while Win32 resolves `\\...\x.bat`.
        (r"\\...\x.bat\y\..", Some("x.bat")),
        (r"\\\x.bat\y\..", Some("x.bat")),
        (r"\\..\x.bat\y\..", Some("x.bat")),
        // A device path's root is `\\.\` alone, and `..` pops the device name (measured).
        (r"\\.\x.bat\y\..", Some("x.bat")),
        (r"\\.\C:\x.bat\..", Some("C:")),
        (r"\\.\pipe\x.bat\..", Some("pipe")),
        (r"\\.\C:\..\..\x.bat", Some("x.bat")),
        (r"\\.\C:\tool.exe", Some("tool.exe")),
        (r"\\.\C:", Some("C:")),
        ("//./C:/...", Some("C:")),
        (r"\\.\x.bat\..", None),
        (r"\\.\C:\..", None),
        (r"\\.\y\..", None),
        (r"\\.\x.bat\y\..\..", None),
        (r"\\.\", None),
        (r"\\.", None),
        // The slash spellings of `\\?\` are device paths the same way (measured).
        ("//?/x.bat/y/..", Some("x.bat")),
        ("//?/C:/dir/x.bat/y/..", Some("x.bat")),
        (r"\\?/C:\dir\x.bat.", Some("x.bat")),
        (r"/\?\C:\dir\x.bat.", Some("x.bat")),
        (r"\/?\C:\dir\x.bat.", Some("x.bat")),
        ("//?/C:/..", None),
        // Collapsed onto the root, a batch-named SERVER is judged too — whether `..` inside the
        // root collapses is unmeasured, and if it does this is `\\x.bat`.
        (r"\\x.bat\y\..", Some("x.bat")),
        // ...and so it is with no `..` at all: `\\x.bat\y` is a share root, which is a directory.
        (r"\\x.bat\y", Some("x.bat")),
        (r"\\x.bat\y\tool.exe", Some("tool.exe")),
        // A server with no share names no file: there is nothing under it to load. Nor does a
        // share that trims away to nothing.
        (r"\\server", None),
        (r"\\server\", None),
        (r"\\server\..", None),
        (r"\\", None),
        // An ordinary share, and a file under one.
        (r"\\server\share", Some("share")),
        (r"\\server\share\tool.exe", Some("tool.exe")),
        (r"\\server\share\x.bat\..", Some("share")),
        // A dots-and-spaces component — neither `.` nor `..`, yet nothing survives the trim —
        // drops out and leaves the component before it. Measured on a Windows runner:
        // `x.bat\y\...` resolves to `…\x.bat\y\`, so `y` is what stays.
        (r"x.bat\y\...", Some("y")),
        (r"x.bat\y\.. .", Some("y")),
        (r"x.bat\y\....", Some("y")),
        (r"x.bat\y\.. ..", Some("y")),
        (r"x.bat\y\ ", Some("y")),
        // With nothing between it and the batch file, that is what it leaves.
        (r"x.bat\...", Some("x.bat")),
    ] {
        assert_eq!(
            super::win32_effective_file_name(Path::new(probe), super::Interior::Dropped).as_deref(),
            want,
            "{probe:?}"
        );
    }
}

/// The OTHER reading of an interior dots-and-spaces segment: kept as a name, which a later `..`
/// pops instead of the component before it. Microsoft's path-format rules read it this way — only
/// the final segment is trimmed, and three or more periods are "a valid file/directory name" — as
/// does Wine's `collapse_path`, which reproduces both final-position measurements. A final one
/// still drops out under this reading.
#[test]
fn an_interior_dots_segment_may_be_a_name_a_later_pop_removes() {
    use std::path::Path;
    for (probe, dropped, named) in [
        (r"y\x.bat\...\..", Some("y"), Some("x.bat")),
        (r"y\x.bat\.. \..", Some("y"), Some("x.bat")),
        (r"y\x.bat\ \..", Some("y"), Some("x.bat")),
        (r"x.bat\y\...\..", Some("x.bat"), Some("y")),
        (r"a\...\..\b", Some("b"), Some("b")),
        // Final: dropped under both.
        (r"x.bat\y\...", Some("y"), Some("y")),
        (r"x.bat\...", Some("x.bat"), Some("x.bat")),
        // A trailing run of them is final too.
        (r"x.bat\...\ ", Some("x.bat"), Some("x.bat")),
    ] {
        for (interior, want) in [(super::Interior::Dropped, dropped), (super::Interior::Named, named)] {
            assert_eq!(
                super::win32_effective_file_name(Path::new(probe), interior).as_deref(),
                want,
                "{probe:?} read {interior:?}"
            );
        }
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
fn the_extension_rule_this_replaced(prog: &std::path::Path) -> bool {
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
fn verbatim_extension_rule_this_replaced(text: &str) -> bool {
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

/// What Win32 does with one path component. The classification is declared, not derived, so the
/// oracle below never re-implements the code it checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Comp {
    /// An ordinary name. `batch` is whether it reaches a batch file when it ends up final.
    Name { batch: bool },
    /// An empty segment: a repeated separator mid-path, a root at the front — and, TWICE at the
    /// front, the `\\` that opens a UNC root. Kept apart from [`Comp::Skip`] for that last reason.
    Empty,
    /// Contributes nothing: `.`.
    Skip,
    /// Pops the component before it: exactly `..`.
    Pop,
    /// Only dots and spaces, yet neither `.` nor `..` — `...`, `.. `, a lone space. FINAL, Win32
    /// trims it away to nothing and it drops out (measured). Interior it is kept as a name a later
    /// `..` pops (measured, not yet asserted by the Windows probe); [`oracle_refuses`] takes the
    /// dropped reading as well until it is.
    Dots,
    /// A bare drive prefix. Names no file when it ends up final — but only in the path's FIRST
    /// position, the only one a drive prefix can occupy. Anywhere else it is an ordinary name
    /// carrying an unnamed data stream.
    DrivePrefix,
    /// A drive prefix and `..` in one component: `1:..`. In the FIRST position it is that drive's
    /// current directory popped once — somewhere only the per-drive cwd can name, and so nothing
    /// this oracle can see. Anywhere else it trims to `1:`, an ordinary name.
    DriveUp,
    /// `?`: an ordinary name, except right after the leading `\\`, where like `.` it marks a
    /// device root.
    QuestionMark,
}

/// The vocabulary the component generator draws from: one entry per behaviour Win32 has, plus the
/// spellings that have historically been read wrong.
const COMPONENTS: [(&str, Comp); 18] = [
    ("", Comp::Empty),
    (".", Comp::Skip),
    ("..", Comp::Pop),
    // Not `..` with a space: measured, it drops out like every other dots-and-spaces segment.
    (".. ", Comp::Dots),
    ("...", Comp::Dots),
    (" ", Comp::Dots),
    ("y", Comp::Name { batch: false }),
    ("x.exe", Comp::Name { batch: false }),
    ("x.bat", Comp::Name { batch: true }),
    ("x.bat ", Comp::Name { batch: true }),
    ("x.bat.", Comp::Name { batch: true }),
    ("x.bat:s", Comp::Name { batch: true }),
    ("x.bat.:s", Comp::Name { batch: true }),
    ("x.exe:p.bat", Comp::Name { batch: true }),
    (".bat", Comp::Name { batch: true }),
    ("..bat", Comp::Name { batch: true }),
    ("C:", Comp::DrivePrefix),
    ("?", Comp::QuestionMark),
];

/// Drive prefixes that are not an ASCII letter, which Win32 reads as drives all the same:
/// `RtlDetermineDosPathNameType_U` asks only whether `Path[1]` is `:`. `\u{FFFD}` is what a lone
/// surrogate becomes through `to_string_lossy`, and so what the gate sees of one on Windows. `𝒳`
/// is two UTF-16 units, so `𝒳:` is no drive.
const DRIVE_SPELLINGS: [(&str, Comp); 6] = [
    ("1:", Comp::DrivePrefix),
    ("é:", Comp::DrivePrefix),
    ("\u{FFFD}:", Comp::DrivePrefix),
    ("1:..", Comp::DriveUp),
    ("é:..", Comp::DriveUp),
    ("𝒳:", Comp::Name { batch: false }),
];

/// A component read as a ROOT segment of a UNC path, where Win32 takes it by position and never
/// interprets it: the only question left is whether its name is a batch file, and whether it has a
/// name at all once trimmed.
fn as_root_name(comp: Comp) -> Option<bool> {
    match comp {
        Comp::Name { batch } => Some(batch),
        Comp::DrivePrefix | Comp::DriveUp | Comp::QuestionMark => Some(false),
        Comp::Empty | Comp::Skip | Comp::Pop | Comp::Dots => None,
    }
}

/// Where a path made of these components ends up under one reading of its interior [`Comp::Dots`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Landing {
    /// A final name; whether it is a batch file.
    Name(bool),
    /// No final name of its own: popped into the cwd's ancestors, a bare drive, a bare root.
    NoFile,
    /// Collapsed onto a UNC root `\\server\share`.
    UncRoot,
}

/// The root a path opens with, as far as [`oracle_landing`] cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Root {
    /// None, a drive, or a single separator: a first-position drive prefix is a drive.
    Plain,
    /// `\\server\share`, which no `..` pops.
    Unc,
    /// `\\.\`, or a slash spelling of `\\?\`: nothing after it is part of the root.
    Device,
}

/// Walk `rest` (the components after any UNC or device root) as a stack, with interior
/// [`Comp::Dots`] either dropped (`dots_named == false`) or kept as a name a later `..` pops. A
/// FINAL run of them drops out under both — the measured case.
fn oracle_landing(rest: &[Comp], root: Root, dots_named: bool) -> Landing {
    #[derive(Clone, Copy)]
    enum Entry {
        Name(bool),
        Drive,
        Dots,
    }
    let mut stack: Vec<Entry> = Vec::new();
    for (i, comp) in rest.iter().enumerate() {
        match comp {
            Comp::Empty | Comp::Skip => {}
            Comp::Dots if dots_named => stack.push(Entry::Dots),
            Comp::Dots => {}
            // An empty stack is the root, wherever there is one; popping it is a no-op.
            Comp::Pop => {
                stack.pop();
            }
            // A drive prefix is a prefix only at the very front; elsewhere it is a stream spelling
            // of a file named `C`, which is not a batch name.
            Comp::DrivePrefix if i == 0 && root == Root::Plain => stack.push(Entry::Drive),
            // Popped at once: nothing of it survives, and an empty stack under a plain root is
            // the unseeable cwd.
            Comp::DriveUp if i == 0 && root == Root::Plain => {}
            Comp::DrivePrefix | Comp::DriveUp | Comp::QuestionMark => stack.push(Entry::Name(false)),
            Comp::Name { batch } => stack.push(Entry::Name(*batch)),
        }
    }
    while matches!(stack.last(), Some(Entry::Dots)) {
        stack.pop();
    }
    match stack.last() {
        Some(Entry::Name(batch)) => Landing::Name(*batch),
        Some(Entry::Drive) => Landing::NoFile,
        Some(Entry::Dots) => unreachable!("trailing dots were just dropped"),
        None if root == Root::Unc => Landing::UncRoot,
        None => Landing::NoFile,
    }
}

/// Whether the gate must refuse a path made of these components, resolved the way Win32 resolves
/// one: a stack, `..` pops, and a final name that is a batch file — or no final name at all —
/// refuses.
///
/// Independent of the gate's PARSING, which is the part that has ever been wrong: the components
/// are known here by construction, while `win32_effective_file_name` has to recover them from the
/// joined string, and that re-parse is where every bypass in this gate's history has lived.
///
/// A UNC ROOT is modelled here on its own terms, not borrowed from the gate. Two leading
/// [`Comp::Empty`] are the `\\`; the next two components are server and share, by position, and no
/// `..` pops below them — the path then resolves to `\\server\share`, whose share is the final
/// name. Without that model this oracle treated every rooted path as rootless and ACCEPTED
/// `\\y\x.bat\..` exactly as the gate did, so their agreement proved only that one model was
/// self-consistent.
///
/// A DEVICE root is `\\` followed by `.` or `?` and then a separator or the end: `\\.\` and the
/// slash spellings of `\\?\` (measured: `//?/` and `\\?/` open files like plain paths). Only it is
/// the root — measured, `\\.\C:\x.bat\..` resolves to `\\.\C:` and `\\.\C:\..` to the bare
/// `\\.\` — so the device name is an ordinary component `..` pops, and popped to nothing the
/// path names no file. The literal `\\?\` is std's verbatim prefix, which this oracle does not
/// model; [`compare_gate_with_oracle`] judges those probes by std's literal test instead.
///
/// An interior [`Comp::Dots`] is measured as kept, but not yet asserted by the Windows probe, so
/// the truth here is still "refuse if either reading reaches a batch file or no file" — the same
/// hedge the gate takes.
///
/// Agreement with an oracle hides whatever the two share. This one shares the classification in
/// [`COMPONENTS`] and the "no final name refuses" rule, and nothing else.
fn oracle_refuses(components: &[Comp]) -> bool {
    if let [Comp::Empty, Comp::Empty, Comp::Skip | Comp::QuestionMark, rest @ ..] = components {
        return [false, true]
            .into_iter()
            .any(|dots_named| match oracle_landing(rest, Root::Device, dots_named) {
                Landing::Name(batch) => batch,
                Landing::NoFile => true,
                Landing::UncRoot => unreachable!("a device path has no UNC root"),
            });
    }
    let (root, rest) = match components {
        [Comp::Empty, Comp::Empty, rest @ ..] => match rest {
            [server, share, rest @ ..] => (Some((*server, *share)), rest),
            // `\\server` alone, or less: no share, nothing loadable.
            _ => return true,
        },
        _ => (None, components),
    };
    [false, true].into_iter().any(|dots_named| {
        let kind = if root.is_some() { Root::Unc } else { Root::Plain };
        match oracle_landing(rest, kind, dots_named) {
            Landing::Name(batch) => batch,
            Landing::NoFile => true,
            // Collapsed onto `\\server\share`: the share is what std tests.
            Landing::UncRoot => {
                let (_, share) = root.expect("only a UNC path lands on a UNC root");
                as_root_name(share).unwrap_or(true)
            }
        }
    })
}

/// The one over-refusal the gate declares and the oracle does not share: a path collapsed onto its
/// UNC root is refused for a batch-named SERVER as well as a batch-named share, because whether
/// `..` inside the root is collapsed is unmeasured. It may only ever LICENSE a refusal — an
/// acceptance the oracle refuses is a failure whatever this says.
fn declared_unc_over_refusal(components: &[Comp]) -> bool {
    let [Comp::Empty, Comp::Empty, server, _share, rest @ ..] = components else {
        return false;
    };
    as_root_name(*server) == Some(true)
        && [false, true]
            .into_iter()
            .any(|dots_named| oracle_landing(rest, Root::Unc, dots_named) == Landing::UncRoot)
}

/// The tally of one exhaustive comparison over [`COMPONENTS`].
#[derive(Default, Debug)]
struct Tally {
    probes: u64,
    refused: u64,
    accepted: u64,
    declared_over_refusals: u64,
    /// The gate accepted what the oracle refuses. A hole.
    holes: Vec<String>,
    /// The gate refused what the oracle accepts, outside the declared over-refusal.
    undeclared_over_refusals: Vec<String>,
    /// The gate accepted what the rule it replaced refused.
    newly_accepted: Vec<String>,
    /// The same probe behind `\\?\`: accepted, yet std's literal verbatim test reads it as a batch
    /// file.
    verbatim_holes: Vec<String>,
}

/// Every path of `min_depth..=max_depth` components over `vocab`, under both separators, judged
/// by the gate and by [`oracle_refuses`].
fn compare_gate_with_oracle(vocab: &[(&'static str, Comp)], min_depth: u32, max_depth: u32) -> Tally {
    let mut tally = Tally::default();
    for sep in ["\\", "/"] {
        for depth in min_depth..=max_depth {
            for index in 0..vocab.len().pow(depth) {
                let path = nth_path(vocab, depth, index);
                judge(&mut tally, &path, sep);
            }
        }
    }
    tally
}

/// Like [`compare_gate_with_oracle`] at one depth, with each of `slotted` inserted at `slot`.
fn compare_gate_with_oracle_slotted(
    vocab: &[(&'static str, Comp)],
    depth: u32,
    slot: usize,
    slotted: &[(&'static str, Comp)],
) -> Tally {
    let mut tally = Tally::default();
    for sep in ["\\", "/"] {
        for index in 0..vocab.len().pow(depth) {
            for extra in slotted {
                let mut path = nth_path(vocab, depth, index);
                path.insert(slot, *extra);
                judge(&mut tally, &path, sep);
            }
        }
    }
    tally
}

/// The `index`th path of `depth` components over `vocab`.
fn nth_path(vocab: &[(&'static str, Comp)], depth: u32, mut index: usize) -> Vec<(&'static str, Comp)> {
    (0..depth)
        .map(|_| {
            let component = vocab[index % vocab.len()];
            index /= vocab.len();
            component
        })
        .collect()
}

/// Judge one path, joined with `sep`, by the gate and by [`oracle_refuses`], into `tally`.
fn judge(tally: &mut Tally, path: &[(&str, Comp)], sep: &str) {
    let texts: Vec<&str> = path.iter().map(|(text, _)| *text).collect();
    let kinds: Vec<Comp> = path.iter().map(|(_, kind)| *kind).collect();
    let probe = texts.join(sep);
    let path = std::path::Path::new(&probe);
    let want = oracle_refuses(&kinds);
    let got = super::reject_batch_path_on(path, true).is_err();
    tally.probes += 1;
    if the_extension_rule_this_replaced(path) && !got {
        tally.newly_accepted.push(probe.clone());
    }
    // The verbatim axis: std tests a `\\?\` program as the literal string, so a batch suffix is
    // exactly what it substitutes cmd.exe for.
    let verbatim = format!(r"\\?\{probe}");
    let verbatim_path = std::path::Path::new(&verbatim);
    let verbatim_got = super::reject_batch_path_on(verbatim_path, true).is_err();
    let lower = verbatim.to_ascii_lowercase();
    if (lower.ends_with(".bat") || lower.ends_with(".cmd")) && !verbatim_got {
        tally.verbatim_holes.push(verbatim.clone());
    }
    if verbatim_extension_rule_this_replaced(&verbatim) && !verbatim_got {
        tally.newly_accepted.push(verbatim);
    }
    // `?` after a leading `\\` spells std's verbatim prefix itself: std tests the literal string,
    // and so does this.
    if probe.starts_with(r"\\?\") {
        let lower = probe.to_ascii_lowercase();
        if (lower.ends_with(".bat") || lower.ends_with(".cmd")) && !got {
            tally.verbatim_holes.push(probe);
        }
        return;
    }
    match (want, got) {
        (true, false) => tally.holes.push(probe),
        (false, true) if declared_unc_over_refusal(&kinds) => {
            tally.declared_over_refusals += 1;
        }
        (false, true) => tally.undeclared_over_refusals.push(probe),
        (_, true) => tally.refused += 1,
        (_, false) => tally.accepted += 1,
    }
}

/// Assert `tally` found no disagreement, and that it saw both verdicts.
fn assert_agreement(mut tally: Tally) -> Tally {
    // Truncated: a broken gate disagrees on tens of thousands of probes and the list is unreadable.
    tally.holes.truncate(20);
    tally.undeclared_over_refusals.truncate(20);
    tally.newly_accepted.truncate(20);
    tally.verbatim_holes.truncate(20);
    assert_eq!(
        tally.verbatim_holes,
        Vec::<String>::new(),
        "a verbatim batch suffix accepted"
    );
    assert_eq!(
        tally.holes,
        Vec::<String>::new(),
        "the gate accepts what Win32 resolves to a batch file"
    );
    assert_eq!(
        tally.undeclared_over_refusals,
        Vec::<String>::new(),
        "the gate refuses what Win32 does not resolve to a batch file"
    );
    assert_eq!(
        tally.newly_accepted,
        Vec::<String>::new(),
        "refused before, accepted now"
    );
    // A generator that emitted only refusals (or only acceptances) would agree with a gate that
    // had lost the other answer entirely, and would say nothing while doing it.
    assert!(tally.refused > 1000 && tally.accepted > 1000, "{tally:?}");
    tally
}

/// Exhaustive over COMPONENTS: every path up to five components deep over [`COMPONENTS`], under
/// both separators, checked against a resolver that works from the component list instead of the
/// string.
///
/// This is the envelope the character-level test cannot reach. Its shortest interesting probe,
/// `.bat\a\..`, is nine characters; enumerating that many characters over a twelve-character
/// alphabet is 12^9 — over five billion probes — and the spellings that have actually bypassed
/// this gate all live out there. Five components is the least that reaches a UNC pop:
/// `\\srv\x.bat\..` is `["", "", "srv", "x.bat", ".."]`.
///
/// Every probe is judged a second time behind `\\?\`, where no oracle is needed: std's verbatim
/// test is a literal suffix check, so a `.bat`/`.cmd` suffix must be refused and nothing else is
/// asserted.
///
/// Exact agreement but for one declared over-refusal: the gate is allowed to refuse a directory
/// and is not allowed to refuse `y\x.bat\..`, which loads `y`. Carries the no-regression property
/// at this length as well — nothing the rule it replaced refused may come out accepted.
#[test]
fn the_gate_agrees_with_a_component_level_resolver() {
    let tally = assert_agreement(compare_gate_with_oracle(&COMPONENTS, 1, 5));
    // One that never reached the declared over-refusal would never have exercised a UNC root
    // collapse.
    assert!(tally.declared_over_refusals > 0, "{tally:?}");
}

/// The same comparison over [`COMPONENTS`] plus [`DRIVE_SPELLINGS`]: every path up to four
/// components, and at five a drive spelling in the share or device slot (`\\.\1:\..` is
/// `["", "", ".", "1:", ".."]`). Adding them to the depth-five run above would triple its cost.
#[test]
fn the_gate_agrees_on_every_drive_spelling() {
    let vocab: Vec<(&str, Comp)> = COMPONENTS.iter().chain(&DRIVE_SPELLINGS).copied().collect();
    assert_agreement(compare_gate_with_oracle(&vocab, 1, 4));
    assert_agreement(compare_gate_with_oracle_slotted(&COMPONENTS, 4, 3, &DRIVE_SPELLINGS));
}

/// The oracle's UNC model, pinned on the rows the gate once got wrong: an oracle without it
/// accepts them, and then agreeing with it proves nothing about them.
#[test]
fn the_oracle_models_a_unc_root_of_its_own() {
    let name = |batch| Comp::Name { batch };
    let e = Comp::Empty;
    // `\\y\x.bat\..`
    assert!(oracle_refuses(&[e, e, name(false), name(true), Comp::Pop]));
    // `\\y\x.bat\y\..\..`
    assert!(oracle_refuses(&[
        e,
        e,
        name(false),
        name(true),
        name(false),
        Comp::Pop,
        Comp::Pop
    ]));
    // `\\...\x.bat\y\..` — a dots-only server is a server, not a component to skip.
    assert!(oracle_refuses(&[e, e, Comp::Dots, name(true), name(false), Comp::Pop]));
    // `\\y\y\x.bat\..` pops back to the share `y`, which is no batch file.
    assert!(!oracle_refuses(&[
        e,
        e,
        name(false),
        name(false),
        name(true),
        Comp::Pop
    ]));
    // `\y\x.bat\..` has ONE leading separator: a rooted path, not a UNC one.
    assert!(!oracle_refuses(&[e, name(false), name(true), Comp::Pop]));
}

/// The oracle's device root, pinned on the rows where a UNC-shaped root disagrees with the
/// measured one: `..` pops the device name, and the bare `\\.\` names no file.
#[test]
fn the_oracle_models_a_device_root_of_its_own() {
    let name = |batch| Comp::Name { batch };
    let (e, dot, q) = (Comp::Empty, Comp::Skip, Comp::QuestionMark);
    // `\\.\x.bat\..` and `\\.\y\..` resolve to `\\.\`.
    assert!(oracle_refuses(&[e, e, dot, name(true), Comp::Pop]));
    assert!(oracle_refuses(&[e, e, dot, name(false), Comp::Pop]));
    // `\\.\C:\..`: the device name `C:` pops like any other.
    assert!(oracle_refuses(&[e, e, dot, Comp::DrivePrefix, Comp::Pop]));
    // `\\.\C:` names `C:`, a device, not a bare drive.
    assert!(!oracle_refuses(&[e, e, dot, Comp::DrivePrefix]));
    // `//?/C:/...` is a device path too, and the final `...` drops out.
    assert!(!oracle_refuses(&[e, e, q, Comp::DrivePrefix, Comp::Dots]));
    // `\\.\C:\..\..\x.bat`
    assert!(oracle_refuses(&[
        e,
        e,
        dot,
        Comp::DrivePrefix,
        Comp::Pop,
        Comp::Pop,
        name(true)
    ]));
    // `\\.\y\x.bat\..`
    assert!(!oracle_refuses(&[e, e, dot, name(false), name(true), Comp::Pop]));
}

/// The oracle's reading of `.. ` and of an interior dots-and-spaces segment, pinned for the same
/// reason as its UNC root: the gate got both wrong once, and an oracle that shared the mistake
/// would have agreed with it.
#[test]
fn the_oracle_reads_dots_and_spaces_on_its_own_terms() {
    let name = |batch| Comp::Name { batch };
    // `x.bat\y\.. ` — final, so it drops out and `y` is the name.
    assert!(!oracle_refuses(&[name(true), name(false), Comp::Dots]));
    // `y\x.bat\...\..` — kept as a name, the `..` pops it and exposes `x.bat`.
    assert!(oracle_refuses(&[name(false), name(true), Comp::Dots, Comp::Pop]));
    // `x.bat\y\...\..` — dropped, the `..` pops `y` and exposes `x.bat`.
    assert!(oracle_refuses(&[name(true), name(false), Comp::Dots, Comp::Pop]));
    // `a\...\..\b` — both readings land on `b`.
    assert!(!oracle_refuses(&[name(false), Comp::Dots, Comp::Pop, name(false)]));
}

/// Normalisation leaves batch names `Path::extension()` cannot see: `.bat` is a bare name to it,
/// and a data-stream piece hides behind `:`.
#[test]
fn a_normalised_batch_path_is_refused_by_suffix_on_every_stream_piece() {
    for p in [
        r"C:\t\.bat",
        r"C:\t\SETUP.CMD",
        r"C:\t\x.exe:payload.bat",
        r"C:\t\x.bat::$DATA",
        r"C:\t\x.bat.:s",
        r"C:\t\x.bat :s",
    ] {
        assert_eq!(
            unsupported_op(crate::child::spawn::reject_normalised_batch_path(std::path::Path::new(p))),
            format!("running {p}")
        );
    }
    for p in [
        r"C:\t\setup.exe",
        r"C:\t\setup.bat.exe",
        r"C:\t.bat\setup.exe",
        r"C:\t\batch",
    ] {
        assert!(
            crate::child::spawn::reject_normalised_batch_path(std::path::Path::new(p)).is_ok(),
            "{p}"
        );
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
        assert!(!crate::child::spawn::routes_to_raw_backend(c), "{via} must take the std route");
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
