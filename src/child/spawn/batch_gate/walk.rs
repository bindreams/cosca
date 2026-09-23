//! The batch gate's component walker: the final name a path resolves to under Win32's
//! normalisation, as measured.

use super::streams::is_batch_program;

/// The final component of `prog` as Win32 will resolve it, collapsing `.` and `..` and stripping
/// the trailing dots and spaces Win32 removes from every component.
///
/// `Path::file_name()` is not good enough here, and the gap is exploitable. It returns `None` for
/// any path whose last component is `..`, so `x.bat\y\..` slipped the gate untouched — while
/// `GetFullPathNameW` collapses it straight back to `x.bat`, and `std::process` then detects the
/// batch extension and hands the program to `cmd.exe`. The same file refused as `x.bat` was
/// accepted spelled `x.bat\y\..`.
///
/// Only a segment that is exactly `..` pops, and only one that is exactly `.` is skipped. A
/// segment that is only dots and spaces yet is neither (`...`, `.. `, `.. .`, a lone space) is
/// something else, and what depends on where it stands:
///
/// - **Final**, it trims away to nothing and DROPS OUT, popping nothing. Measured on x64 and arm64
///   runners for `...`, `....`, `.. .`, `.. ..`, `" "`, `". "` and `".. "`: `x.bat\y\` plus any
///   of them resolves to `…\x.bat\y\`, so `y` survives and the batch file stays covered.
/// - **Interior**, it is kept as a name a later `..` pops — a lone trailing `.` comes off, a run of
///   two or more does not, spaces never do. Measured on x64 and arm64 runners, for segments ending
///   in a period and in a space alike, by the Windows path canary's
///   `an_interior_segment_loses_only_a_single_trailing_period`: `y\x.bat\...\..` resolves to
///   `y\x.bat`. Microsoft's path-format rules read it the same way (only the final segment is
///   trimmed, and three or more periods are "a valid file/directory name"), as does Wine's
///   `collapse_path`.
///
/// `None` means the path named no file of its own: it was empty, was a bare root or drive prefix,
/// or popped its own components away. That last case did NOT collapse to nothing — a relative
/// path goes on popping into the ancestors of the current directory, so `x\..` resolves to
/// whatever the cwd is and `.` resolves to the cwd itself, while a rooted one clamps at its root.
/// The name is real, this gate just cannot see it, which is why [`reject_batch_path_on`] refuses
/// `None` rather than accepting it. A data-stream spelling is not that — `x.bat:` names a file and
/// comes back as one.
///
/// # A UNC root has a NAME, and `..` never pops it
///
/// `\\server\share` is a root the way `C:\` is, but unlike `C:\` its last component is a name.
/// Win32 skips server and share before it collapses anything (ReactOS's `RtlpCollapsePath` calls
/// `RtlpSkipUNCPrefix` first; .NET pins `\\LOCALHOST\share5\..` resolving to `\\LOCALHOST\share5`),
/// so no number of `..` reaches past the share, and a share named `x.bat` stays the effective name.
/// Walk a UNC path as if it had no root and every one of `\\srv\x.bat\..`, `//srv/x.bat/..`,
/// `\/srv\x.cmd\..` and `\\srv\x.bat\y\..\..` reduces to `srv` — not a batch
/// name, so the gate returns `Ok` on a token `std::process` hands straight to `cmd.exe`, and
/// `make_bat_command_line` appends the rest of a `.commandline()` verbatim. `GetFullPathNameW`
/// does no I/O, so the share need not exist for that to happen.
///
/// Server and share are POSITIONAL: Win32 takes the two segments after the `\\` without reading
/// them, so a `..`, dots-only, empty or one-space segment there is part of the root rather than an
/// operation on it (measured by the Windows path probe's
/// `dotdot_stops_at_the_unc_share_but_not_at_a_device_name`). A lone `.` or `?` in the server slot is the exception: that is a device root, below.
/// That position has to be exact, not merely deep enough. A floor set one component too DEEP
/// suppresses a pop Win32 performs, and the final name moves to a later component: skip the
/// dots-only server in `\\...\x.bat\y\..` and the root becomes `x.bat\y`, the pop is clamped
/// away, and the gate judges `y` while Win32 resolves `\\...\x.bat`.
///
/// # A device root is `\\.\` alone, and `..` pops the device name
///
/// A device path is not a UNC path with a `.` server. Measured on x64 and arm64 runners (the
/// Windows path probe's `dotdot_stops_at_the_unc_share_but_not_at_a_device_name` canary):
/// `\\.\C:\x.bat\..` resolves to `\\.\C:`, `\\.\C:\..` and `\\.\x.bat\y\..\..` to the bare
/// `\\.\`, and `\\.\C:\..\..\x.bat` to `\\.\x.bat`. So the device name is an ordinary component —
/// `\\.\C:` names `C:`, a device rather than a bare drive — and a path popped back to `\\.\`
/// names no file, which is refused like any other.
///
/// `?` in the same slot is the same root when any separator in the marker is a `/`: `//?/`,
/// `\\?/`, `/\?\` and `\/?\` resolve like `\\?\` in `GetFullPathNameW`, and `//?/` and `\\?/` open
/// `x.bat` through `x.bat.` like a plain path (measured, `verbatim_marker_spellings_resolve_alike`
/// and `a_trailing_dot_or_space_reaches_the_batch_file_only_when_plain`). Only the literal `\\?\`
/// is verbatim to std, and it never arrives: [`verbatim_refusal`] owns it.
///
/// # The token, not the resolved path
///
/// This runs on the program token AS WRITTEN, so it has to predict what that string resolves to
/// instead of resolving it. Two over-refusals are the price, both unchanged by the measurement
/// above. A path that pops past its own first component lands somewhere only the cwd can name, so
/// the gate refuses every one rather than guess. And a path whose final component drops out
/// resolves to a name with a trailing separator — `x.bat\...` is `…\x.bat\`, which std's
/// `has_bat_extension` does NOT read as a batch file — yet the gate judges the exposed `x.bat` and
/// refuses. Moving resolution ahead of the gate collapses both into a suffix test on the resolved
/// path and leaves nothing left to predict.
pub(super) fn win32_effective_file_name(prog: &std::path::Path) -> Option<String> {
    let text = prog.as_os_str().to_string_lossy();
    // Each surviving component, paired with whether it is the path's FIRST segment — the only
    // position a drive prefix can occupy.
    let mut stack: Vec<(&str, bool)> = Vec::new();
    let mut segments = text.split(['/', '\\']).enumerate();
    // A UNC root: the two segments after the leading pair, taken by POSITION and never collapsed.
    // `None` for a root with no share at all — `\\server` names nothing loadable. A device root
    // (`.` or `?` in the server slot) is the leading three segments alone, so it leaves `root`
    // `None` and everything after it on the walk.
    let root = if starts_with_two_separators(&text) {
        segments.nth(1).expect("two separators are two empty segments");
        let (_, server) = segments.next()?;
        if matches!(server, "." | "?") {
            None
        } else {
            let (_, share) = segments.next()?;
            Some((server, share))
        }
    } else {
        None
    };
    for (position, segment) in segments {
        // A repeated separator, never a component.
        if segment.is_empty() {
            continue;
        }
        if segment == "." {
            continue;
        }
        if segment == ".." {
            // Popping an empty stack under a UNC root is popping into the root, which Win32
            // clamps at; `pop` on an empty stack is exactly that no-op.
            stack.pop();
            continue;
        }
        // Ordinary component: Win32 drops trailing dots and spaces. Nothing left of it means a
        // dots-and-spaces component (see the doc), kept as an EMPTY name, which a later `..` can
        // pop and which is never a batch file.
        let name = segment.trim_end_matches([' ', '.']);
        stack.push((name, position == 0));
    }
    // Whatever is final drops out, however many of them trail.
    while stack.last().is_some_and(|(name, _)| name.is_empty()) {
        stack.pop();
    }
    if stack.is_empty() {
        if let Some((server, share)) = root {
            return unc_root_name(server, share);
        }
    }
    let (last, leading) = stack.pop()?;
    // A BARE drive prefix names no file — and only the first segment can be one. Elsewhere a
    // component ending in `:` is a data-stream spelling of a real file: `a:` is the file `a`, just
    // as `x.exe:` is the file `x.exe`, and returning `None` for either made the gate refuse a
    // loadable image over a one-character name.
    if leading && is_drive_prefix(last) {
        return None;
    }
    Some(last.to_string())
}

/// The name a path collapsed onto its UNC root resolves to, judged conservatively.
///
/// Win32 resolves it to `\\server\share`, so the share is the name std tests. The server is
/// judged as well, and a batch-named server is returned in preference to the share: an
/// over-refusal, since a `..` inside the root is never collapsed and the server keeps its trailing
/// dots and spaces (measured: `\\...\x.bat\y\..` resolves to `\\...\x.bat` and `\\srv.\x.bat\y\..`
/// to `\\srv.\x.bat`). A share that trims away to nothing names no file, which is refused too.
fn unc_root_name(server: &str, share: &str) -> Option<String> {
    let server = server.trim_end_matches([' ', '.']);
    if is_batch_program(server) {
        return Some(server.to_string());
    }
    let share = share.trim_end_matches([' ', '.']);
    (!share.is_empty()).then(|| share.to_string())
}

/// Whether the path opens with the two separators that make Win32 read a UNC root. Either
/// separator spells it in either position: `\\srv`, `//srv` and `\/srv` are one path to Win32.
fn starts_with_two_separators(text: &str) -> bool {
    let mut chars = text.chars();
    matches!((chars.next(), chars.next()), (Some('\\' | '/'), Some('\\' | '/')))
}

/// A bare drive prefix: one UTF-16 unit, then `:`, and nothing else.
fn is_drive_prefix(component: &str) -> bool {
    drive_prefix_len(component) == Some(component.len())
}

/// The byte length of the drive prefix `text` opens with, if any: any ONE UTF-16 unit, then `:`,
/// as Win32 reads `Path[1]` (ReactOS `RtlDetermineDosPathNameType_Ustr`, Wine
/// `RtlDetermineDosPathNameType_U`). `1:`, `é:`, and the U+FFFD a lone surrogate becomes through
/// `to_string_lossy` are drives; `𝒳:` (two units) is not. The rule is
/// `crate::resolve::drive_len`'s, so the batch gate and the resolver read one drive the same way.
pub(crate) fn drive_prefix_len(text: &str) -> Option<usize> {
    crate::resolve::drive_len(text.as_bytes())
}

#[cfg(test)]
#[path = "walk_tests.rs"]
mod walk_tests;
