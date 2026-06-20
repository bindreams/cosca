//! Windows `CommandLineToArgvW`-compatible command-line construction.
//!
//! Operates on UTF-16 code units so the algorithm is testable on any host;
//! a `#[cfg(windows)]` test validates it against the real OS parser.
//!
//! This module builds the command-line string for PE images launched via
//! `CreateProcess`, implementing exactly the quoting rules that
//! `CommandLineToArgvW` reverses (MSVCRT / Win32 argv parsing). It does NOT
//! handle `cmd.exe` metacharacter escaping: `.bat`/`.cmd` invocation (the
//! actual BatBadBut / CVE-2024-24576 vector) requires a separate escaping
//! layer and is deferred to spec §8.

const SPACE: u16 = b' ' as u16;
const TAB: u16 = b'\t' as u16;
const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

fn needs_quotes(arg: &[u16]) -> bool {
    arg.is_empty() || arg.iter().any(|&c| c == SPACE || c == TAB)
}

/// Join argv into a single command-line string per the MSVCRT rules that
/// `CommandLineToArgvW` reverses. Intended for argv[1..]; the program name
/// (argv[0]) is passed separately as `lpApplicationName`.
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

/// Extract the program token (argv[0]) from a command line, for deriving
/// `lpApplicationName` from a user-supplied `commandline`.
///
/// Deliberate deviation from `CommandLineToArgvW`'s argv[0] handling: leading
/// whitespace is skipped and empty/whitespace-only input returns `None`. The OS
/// does not skip leading whitespace: on an empty string it substitutes the
/// module path as argv[0]; on a whitespace-only string it returns `""` as
/// argv[0]. In both cases our function returns `None`. The token shape
/// otherwise matches: a leading `"` runs to the next `"` (or to the end if
/// unterminated); an unquoted token runs to the next space/tab; backslashes
/// are literal here (no escaping).
pub fn first_token_wide(cmd: &[u16]) -> Option<Vec<u16>> {
    let mut i = 0usize;
    while i < cmd.len() && (cmd[i] == SPACE || cmd[i] == TAB) {
        i += 1;
    }
    if i >= cmd.len() {
        return None;
    }
    let mut out = Vec::new();
    if cmd[i] == QUOTE {
        i += 1;
        while i < cmd.len() && cmd[i] != QUOTE {
            out.push(cmd[i]);
            i += 1;
        }
    } else {
        while i < cmd.len() && cmd[i] != SPACE && cmd[i] != TAB {
            out.push(cmd[i]);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
