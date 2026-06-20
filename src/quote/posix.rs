//! Strict-POSIX (IEEE 1003.1-2024 §2.2) word splitting, byte-oriented.
//!
//! Ported from JetBrains qodana-cli `internal/foundation/shlex` (Apache-2.0).
//! Deviations from strict POSIX, preserved from the original:
//!   1. CR (0x0D) is whitespace; `\<CR><LF>` is a line continuation. A bare
//!      `\<CR>` (no `<LF>`) is NOT a continuation — it falls to the `\X` rule.
//!   2. `#` is never a comment introducer (we split argv, not scripts).
//!   3. `$`, backtick, `$(...)`, `${...}` are literal — this is a lexer, not a shell.

use crate::error::{QuoteError, QuoteErrorKind};

#[derive(Clone, Copy)]
enum State {
    Whitespace,
    Word,
    SingleQuote,
    DoubleQuote,
}

/// Split `s` into argv words. Empty/whitespace-only input yields an empty vec.
pub fn split(s: &[u8]) -> Result<Vec<Vec<u8>>, QuoteError> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut state = State::Whitespace;
    let mut has_token = false;
    let mut quote_open = 0usize;
    let mut i = 0usize;

    while i < s.len() {
        let c = s[i];
        match state {
            State::Whitespace => {
                if is_ws(c) {
                    i += 1;
                } else if c == b'\'' {
                    state = State::SingleQuote;
                    has_token = true;
                    quote_open = i;
                    i += 1;
                } else if c == b'"' {
                    state = State::DoubleQuote;
                    has_token = true;
                    quote_open = i;
                    i += 1;
                } else if c == b'\\' {
                    if i + 1 >= s.len() {
                        return Err(QuoteError::new(i, QuoteErrorKind::TrailingBackslash));
                    }
                    if let Some(consumed) = line_continuation(s, i) {
                        i += consumed;
                    } else {
                        buf.push(s[i + 1]);
                        i += 2;
                        has_token = true;
                        state = State::Word;
                    }
                } else {
                    buf.push(c);
                    has_token = true;
                    state = State::Word;
                    i += 1;
                }
            }
            State::Word => {
                if is_ws(c) {
                    emit(&mut out, &mut buf, &mut has_token);
                    state = State::Whitespace;
                    i += 1;
                } else if c == b'\'' {
                    state = State::SingleQuote;
                    quote_open = i;
                    i += 1;
                } else if c == b'"' {
                    state = State::DoubleQuote;
                    quote_open = i;
                    i += 1;
                } else if c == b'\\' {
                    i = backslash_unquoted(s, i, &mut buf)?;
                } else {
                    buf.push(c);
                    i += 1;
                }
            }
            State::SingleQuote => {
                if c == b'\'' {
                    state = State::Word;
                } else {
                    buf.push(c);
                }
                i += 1;
            }
            State::DoubleQuote => {
                if c == b'"' {
                    state = State::Word;
                    i += 1;
                } else if c == b'\\' {
                    i = backslash_in_dquote(s, i, &mut buf)?;
                } else {
                    buf.push(c);
                    i += 1;
                }
            }
        }
    }

    match state {
        State::Whitespace | State::Word => {
            emit(&mut out, &mut buf, &mut has_token);
            Ok(out)
        }
        State::SingleQuote => Err(QuoteError::new(quote_open, QuoteErrorKind::UnterminatedSingleQuote)),
        State::DoubleQuote => Err(QuoteError::new(quote_open, QuoteErrorKind::UnterminatedDoubleQuote)),
    }
}

fn is_ws(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
}

fn emit(out: &mut Vec<Vec<u8>>, buf: &mut Vec<u8>, has_token: &mut bool) {
    if *has_token {
        out.push(std::mem::take(buf));
        *has_token = false;
    }
}

/// `i` is at a backslash, outside any quotes. Returns the next index.
fn backslash_unquoted(s: &[u8], i: usize, buf: &mut Vec<u8>) -> Result<usize, QuoteError> {
    if i + 1 >= s.len() {
        return Err(QuoteError::new(i, QuoteErrorKind::TrailingBackslash));
    }
    if let Some(consumed) = line_continuation(s, i) {
        return Ok(i + consumed);
    }
    buf.push(s[i + 1]);
    Ok(i + 2)
}

/// `i` is at a backslash, inside double quotes. Returns the next index.
fn backslash_in_dquote(s: &[u8], i: usize, buf: &mut Vec<u8>) -> Result<usize, QuoteError> {
    if i + 1 >= s.len() {
        return Err(QuoteError::new(i, QuoteErrorKind::TrailingBackslash));
    }
    if let Some(consumed) = line_continuation(s, i) {
        return Ok(i + consumed);
    }
    match s[i + 1] {
        n @ (b'$' | b'`' | b'"' | b'\\') => {
            buf.push(n);
            Ok(i + 2)
        }
        _ => {
            // Backslash is literal; the next byte is re-processed next iteration.
            buf.push(b'\\');
            Ok(i + 1)
        }
    }
}

/// If `i` (at a backslash) begins a line continuation, return its total byte
/// length (2 for `\<LF>`, 3 for `\<CR><LF>`). Precondition: `i + 1 < s.len()`.
fn line_continuation(s: &[u8], i: usize) -> Option<usize> {
    match s[i + 1] {
        b'\n' => Some(2),
        b'\r' if i + 2 < s.len() && s[i + 2] == b'\n' => Some(3),
        _ => None,
    }
}

/// Safe bytes need no quoting (CPython `shlex` safe set: alnum plus `_@%+=:,./-`).
const SAFE: [bool; 256] = build_safe();

const fn build_safe() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        t[i] = matches!(b,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
            | b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-');
        i += 1;
    }
    t
}

/// Shell-escape `s` so `split` parses it back as exactly one token.
/// NOT idempotent on unsafe input — required for round-trip correctness.
pub fn quote(s: &[u8]) -> Vec<u8> {
    if s.is_empty() {
        return b"''".to_vec();
    }
    if s.iter().all(|&b| SAFE[b as usize]) {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(s.len() + 2);
    out.push(b'\'');
    for &b in s {
        if b == b'\'' {
            out.extend_from_slice(br#"'"'"'"#);
        } else {
            out.push(b);
        }
    }
    out.push(b'\'');
    out
}

/// Join argv into a POSIX command line such that `split(join(args)) == args`.
pub fn join(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, a) in args.iter().enumerate() {
        if idx > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(&quote(a));
    }
    out
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
