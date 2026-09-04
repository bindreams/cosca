//! Windows `CommandLineToArgvW`-compatible command-line construction.
//!
//! Operates on UTF-16 code units so the algorithm is testable on any host;
//! a `#[cfg(windows)]` test validates it against the real OS parser.
//!
//! This module builds ([`join_wide`]) and parses ([`split_wide`]) the
//! command-line string for PE images launched via `CreateProcess`,
//! implementing exactly the quoting rules `CommandLineToArgvW` uses in both
//! directions (MSVCRT / Win32 argv parsing). It does NOT handle `cmd.exe`
//! metacharacter escaping: `.bat`/`.cmd` invocation (the actual BatBadBut /
//! CVE-2024-24576 vector) requires a separate escaping layer, which this
//! module does not provide.

use crate::error::QuoteError;

const SPACE: u16 = b' ' as u16;
const TAB: u16 = b'\t' as u16;
const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

fn is_blank(c: u16) -> bool {
    c == SPACE || c == TAB
}

fn needs_quotes(arg: &[u16]) -> bool {
    arg.is_empty() || arg.iter().any(|&c| is_blank(c))
}

/// Join argv into a single command-line string per the MSVCRT rules that
/// `CommandLineToArgvW` reverses. Intended for argv[1..]; the program name
/// (`argv[0]`) is passed separately as `lpApplicationName`.
pub fn join_wide(args: &[&[u16]]) -> Vec<u16> {
    let mut cmd: Vec<u16> = Vec::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            cmd.push(SPACE);
        }
        append_arg(&mut cmd, arg);
    }
    cmd
}

fn append_arg(cmd: &mut Vec<u16>, arg: &[u16]) {
    let quote = needs_quotes(arg);
    if quote {
        cmd.push(QUOTE);
    }
    let mut backslashes: usize = 0;
    for &x in arg {
        if x == BACKSLASH {
            backslashes += 1;
        } else {
            if x == QUOTE {
                // Already emitted `backslashes` backslashes; add `backslashes + 1`
                // more so a literal quote is preceded by 2n+1 backslashes.
                cmd.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        cmd.push(x);
    }
    if quote {
        // Double the trailing backslash run before the closing quote (2n).
        cmd.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        cmd.push(QUOTE);
    }
}

/// Like [`first_token_wide`], but also returns the remainder of the command
/// line AFTER the first token (with the separating whitespace consumed). Used
/// to feed `raw_arg` the args-only portion (std prepends the program itself).
/// Returns `None` only for empty/whitespace-only input.
pub fn first_token_and_rest_wide(cmd: &[u16]) -> Option<(Vec<u16>, Vec<u16>)> {
    let mut i = 0usize;
    while i < cmd.len() && is_blank(cmd[i]) {
        i += 1;
    }
    if i >= cmd.len() {
        return None;
    }
    let mut first = Vec::new();
    if cmd[i] == QUOTE {
        i += 1;
        while i < cmd.len() && cmd[i] != QUOTE {
            first.push(cmd[i]);
            i += 1;
        }
        if i < cmd.len() {
            i += 1; // consume the closing quote
        }
    } else {
        while i < cmd.len() && !is_blank(cmd[i]) {
            first.push(cmd[i]);
            i += 1;
        }
    }
    // Skip the whitespace separating the first token from the rest.
    while i < cmd.len() && is_blank(cmd[i]) {
        i += 1;
    }
    Some((first, cmd[i..].to_vec()))
}

/// Extract the program token (`argv[0]`) from a command line, for deriving
/// `lpApplicationName` from a user-supplied `commandline`.
///
/// Deliberate deviation from `CommandLineToArgvW`'s `argv[0]` handling: leading
/// whitespace is skipped and empty/whitespace-only input returns `None`. The OS
/// does not skip leading whitespace: on an empty string it substitutes the
/// module path as `argv[0]`; on a whitespace-only string it returns `""` as
/// `argv[0]`. In both cases this function returns `None`. The token shape
/// otherwise matches: a leading `"` runs to the next `"` (or to the end if
/// unterminated); an unquoted token runs to the next space/tab; backslashes
/// are literal here (no escaping).
pub fn first_token_wide(cmd: &[u16]) -> Option<Vec<u16>> {
    first_token_and_rest_wide(cmd).map(|(first, _)| first)
}

/// Split a Windows command line into argv — the inverse of [`join_wide`] and
/// of the real `CommandLineToArgvW` (shell32.dll), mirroring
/// [`crate::quote::posix::split`]'s shape over UTF-16 code units.
///
/// # `argv[0]`
///
/// `argv[0]` is parsed by [`first_token_and_rest_wide`] — see its docs (and
/// [`first_token_wide`]'s) for the exact OS deviation on leading
/// whitespace/empty input and the program-token quoting rule.
///
/// # `argv[1..]`
///
/// Parsed with the full MSVCRT backslash/quote rules `CommandLineToArgvW`
/// applies past the first argument: a run of `n` backslashes immediately
/// before a `"` collapses to `n/2` literal backslashes, and the quote either
/// becomes a literal `"` (`n` odd) or toggles "inside quotes" (`n` even) —
/// this much is documented and is the direct inverse of `append_arg`
/// ([`join_wide`]'s internal encoder). Beyond that, *bare* (non-backslash-
/// escaped) quotes are counted by a running total that persists across the
/// whole token — ordinary characters do not touch it, and neither does a
/// backslash-escaped quote — and is undocumented but not arbitrary: verified
/// against Wine's/ReactOS's `CommandLineToArgvW` source
/// (`dll/win32/shell32/wine/shell32_main.c`), the total resets to 0 in
/// exactly two cases: as soon as it reaches 3 (emitting one literal `"`), or
/// when a maximal run of *consecutive* bare quotes ends while the total sits
/// at 2 (no literal `"` either way). Because the total is not reset by
/// ordinary characters in between, the same two-bare-quote shape means
/// different output depending on what came before: `a""b` -> `ab` (a fresh
/// run of exactly 2 bare quotes — the total goes 0->1->2 and the run ends
/// there, hitting the reset-at-2 case, no literal `"`), but `"a""b"` -> `a"b`
/// (the opening `"` already left the total at 1, so the embedded `""` — part
/// of the same consecutive run as far as the total is concerned — pushes it
/// 1->2->3, hitting the reset-at-3 case instead: one literal `"` is
/// emitted). This differs from the simpler even/odd-only rule the MSVCRT
/// `main()` startup parser uses (reimplemented by `std::env::args()`), which
/// is a different, more limited parser than shell32's actual
/// `CommandLineToArgvW`.
///
/// # Errors
///
/// `CommandLineToArgvW`'s grammar has no error states — an unterminated
/// quote just runs to the end, and a backslash not before a quote is always
/// literal — so this function always returns `Ok`. It still returns
/// `Result<_, QuoteError>` to match [`crate::quote::posix::split`]'s shape;
/// no Windows-specific [`crate::error::QuoteErrorKind`] variant exists.
pub fn split_wide(cmd: &[u16]) -> Result<Vec<Vec<u16>>, QuoteError> {
    let Some((first, rest)) = first_token_and_rest_wide(cmd) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(1);
    out.push(first);
    out.extend(split_rest_wide(&rest));
    Ok(out)
}

/// Parse `argv[1..]` from the remainder of a command line, after `argv[0]`
/// and its separating whitespace have already been removed. See
/// [`split_wide`]'s doc comment for the exact rules, including the mod-3
/// bare-quote-run rule. Ported directly from the verified
/// `CommandLineToArgvW` reference algorithm, using eager backslash-writing
/// plus retroactive `Vec::truncate` in place of that algorithm's in-place
/// pointer rewind.
fn split_rest_wide(rest: &[u16]) -> Vec<Vec<u16>> {
    let mut out: Vec<Vec<u16>> = Vec::new();
    let n = rest.len();
    let mut i = 0usize;

    while i < n && is_blank(rest[i]) {
        i += 1;
    }
    if i >= n {
        return out;
    }

    let mut buf: Vec<u16> = Vec::new();
    let mut qcount: usize = 0;
    let mut bcount: usize = 0;

    while i < n {
        let c = rest[i];
        if is_blank(c) && qcount == 0 {
            out.push(std::mem::take(&mut buf));
            bcount = 0;
            while i < n && is_blank(rest[i]) {
                i += 1;
            }
            if i >= n {
                return out;
            }
        } else if c == BACKSLASH {
            buf.push(c);
            bcount += 1;
            i += 1;
        } else if c == QUOTE {
            // `buf` currently ends with exactly `bcount` backslashes just
            // pushed by the branch above (bcount is reset to 0 on every
            // other branch), so both truncations below are in-bounds.
            debug_assert!(buf.len() >= bcount, "backslash run exceeds buffer length");
            if bcount.is_multiple_of(2) {
                // Even run: the backslashes just written collapse to half as
                // many literal backslashes; the quote toggles "inside quotes".
                let new_len = buf.len() - bcount / 2;
                buf.truncate(new_len);
                qcount += 1;
            } else {
                // Odd run: collapses to (bcount - 1) / 2 literal backslashes
                // plus one literal quote.
                let new_len = buf.len() - (bcount / 2 + 1);
                buf.truncate(new_len);
                buf.push(QUOTE);
            }
            i += 1;
            bcount = 0;
            // Count further consecutive bare quotes: every 3 collapse to one
            // literal `"`; `qcount` already accounts for the quote above.
            while i < n && rest[i] == QUOTE {
                qcount += 1;
                if qcount == 3 {
                    buf.push(QUOTE);
                    qcount = 0;
                }
                i += 1;
            }
            if qcount == 2 {
                qcount = 0;
            }
        } else {
            buf.push(c);
            bcount = 0;
            i += 1;
        }
    }
    out.push(buf);
    out
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
