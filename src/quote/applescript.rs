//! AppleScript double-quoted string-literal escaping.
//!
//! The grammar (Apple TN2065, *do shell script in AppleScript*) is small: inside a
//! `"…"` literal, `\"` is a quote and `\\` is a backslash, and `\n`/`\r`/`\t` are
//! the three character escapes.
//!
//! AppleScript source is decoded as UTF-8, so this operates on text, not bytes;
//! non-UTF-8 input is a typed error.

use crate::error::{QuoteError, QuoteErrorKind};

/// Escape `bytes` as the BODY of an AppleScript double-quoted string literal. The
/// surrounding quotes are the caller's to add.
///
/// Only NUL is refused. It is the one byte with no representation anywhere on this
/// path — it cannot appear in argv at all, since exec takes NUL-terminated strings.
/// Every other control passes through raw: `\n` and `\r` are escaped above for a
/// MEASURED reason (a raw newline ends an AppleScript statement), but nothing shows
/// ESC/BEL/VT/FF/DEL failing inside a literal, and "no numeric escape exists" does
/// not imply "no representation exists". Refusing them would refuse an
/// ANSI-coloured argument that succeeds under sudo, pkexec and UAC, on an
/// inference; `both_quoting_layers_survive_a_real_osascript_round_trip` drives them
/// through real `osascript` instead.
pub fn escape_literal(bytes: &[u8]) -> Result<String, QuoteError> {
    let s = std::str::from_utf8(bytes).map_err(|e| QuoteError::new(e.valid_up_to(), QuoteErrorKind::NonUtf8))?;
    let mut out = String::with_capacity(s.len() + 2);
    for (pos, c) in s.char_indices() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\0' => return Err(QuoteError::new(pos, QuoteErrorKind::UnrepresentableChar)),
            c => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "applescript_tests.rs"]
mod applescript_tests;
