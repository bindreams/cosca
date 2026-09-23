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
        // Collapsed onto the root, a batch-named SERVER is judged too — an over-refusal, since a
        // `..` inside the root is never collapsed (measured).
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
            super::win32_effective_file_name(Path::new(probe)).as_deref(),
            want,
            "{probe:?}"
        );
    }
}

/// An interior dots-and-spaces segment is kept as a name, which a later `..` pops instead of the
/// component before it — measured on x64 and arm64 runners, for segments ending in a period and in
/// a space alike, by `tests/windows_path_resolution/dots_and_spaces.rs`'s `an_interior_segment_loses_only_a_single_trailing_period`. A final one drops out.
#[test]
fn an_interior_dots_segment_is_a_name_a_later_pop_removes() {
    use std::path::Path;
    for (probe, want) in [
        (r"y\x.bat\...\..", Some("x.bat")),
        (r"y\x.bat\....\..", Some("x.bat")),
        (r"y\x.bat\.. \..", Some("x.bat")),
        (r"y\x.bat\. \..", Some("x.bat")),
        (r"y\x.bat\ \..", Some("x.bat")),
        (r"y\x.bat\  \..", Some("x.bat")),
        (r"x.bat\y\...\..", Some("y")),
        (r"a\...\..\b", Some("b")),
        (r"a\...\..", Some("a")),
        // Final: dropped.
        (r"x.bat\y\...", Some("y")),
        (r"x.bat\...", Some("x.bat")),
        // A trailing run of them is final too.
        (r"x.bat\...\ ", Some("x.bat")),
    ] {
        assert_eq!(
            super::win32_effective_file_name(Path::new(probe)).as_deref(),
            want,
            "{probe:?}"
        );
    }
}
