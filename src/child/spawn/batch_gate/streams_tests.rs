/// The NTFS normalisation, as pure string logic — runs on every host.
///
/// `x.bat ` and `x.bat.` resolve to `x.bat`, and `x.bat:s` names a stream of it. This pins the
/// PIECES, which is not the verdict — `is_batch_program` is where the pieces become one.
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
        // a batch name.
        ("C:x.bat:s", vec!["x.bat", "s"]),
        ("c:x.bat", vec!["x.bat"]),
        // Two letters before the colon is a file name, not a drive.
        ("ab:x.bat", vec!["ab", "x.bat"]),
        // Any one UTF-16 unit before the colon is a drive, as `RtlDetermineDosPathNameType_U` has it.
        (".:x.bat", vec!["x.bat"]),
        ("é:x.bat", vec!["x.bat"]),
        // Split before trimming, though `GetFullPathNameW` keeps `x.bat.:s` and `x.bat :s` as they
        // are (measured): reading them as `x.bat` is the conservative choice, and trim-then-split
        // would leave the trailing character attached for the extension check to miss.
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
    // After a drive prefix, which is stripped: `x.bat` is the FIRST piece here.
    assert!(super::is_batch_program("a:x.bat:s"));
    // A middle piece: neither first nor last, with and without a drive prefix before it.
    for probe in ["a:x.exe:x.bat:s", "x.exe:x.bat:s"] {
        assert!(
            super::is_batch_program(probe),
            "{probe:?} hides the batch name in a middle piece"
        );
    }
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
