use super::escape_literal;
use crate::error::QuoteErrorKind;

/// An INDEPENDENT un-escaper, written from the AppleScript literal grammar
/// (TN2065: `\"` is a quote, `\\` is a backslash; `\n`, `\r`, `\t` are the three
/// character escapes), NOT from `escape_literal`. Panics on anything the grammar
/// does not define, so a sloppy escaper cannot round-trip by accident.
fn unescape_literal(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut it = s.bytes();
    while let Some(b) = it.next() {
        if b != b'\\' {
            assert!(b != b'"', "a raw quote must never appear in a literal body");
            assert!(b != b'\n' && b != b'\r', "LF/CR must always be escaped");
            out.push(b);
            continue;
        }
        match it.next().expect("a literal body never ends in a lone backslash") {
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            other => panic!("undefined AppleScript escape \\{}", other as char),
        }
    }
    out
}

#[test]
fn tn2065_worked_examples() {
    // Straight from TN2065: `a "quote" mark` and `a back\slash`.
    assert_eq!(escape_literal(br#"a "quote" mark"#).unwrap(), r#"a \"quote\" mark"#);
    assert_eq!(escape_literal(br"a back\slash").unwrap(), r"a back\\slash");
}

#[test]
fn safe_text_is_returned_verbatim() {
    assert_eq!(escape_literal(b"/usr/bin/id -u").unwrap(), "/usr/bin/id -u");
    assert_eq!(escape_literal(b"").unwrap(), "");
}

#[test]
fn control_characters_use_the_defined_escapes() {
    assert_eq!(escape_literal(b"a\nb").unwrap(), r"a\nb");
    assert_eq!(escape_literal(b"a\rb").unwrap(), r"a\rb");
    assert_eq!(escape_literal(b"a\tb").unwrap(), r"a\tb");
}

#[test]
fn round_trips_through_an_independent_unescaper() {
    let cases: &[&[u8]] = &[
        b"",
        b"plain",
        br#"he said "hi""#,
        br"C:\not\a\path",
        b"'single' \"double\" `backtick` $dollar",
        b"newline\nand\ttab\rand\rcr",
        b"\\\"\\\"\\\"",
        "unicode: \u{e9}\u{4e2d}\u{1f600}".as_bytes(),
        br#"'; rm -rf /; echo '"#,
        br"trailing backslash\",
    ];
    for c in cases {
        let escaped = escape_literal(c).unwrap_or_else(|e| panic!("{c:?}: {e}"));
        assert_eq!(&unescape_literal(&escaped)[..], *c, "round-trip failed for {c:?}");
    }
}

#[test]
fn non_utf8_input_is_rejected_at_its_offset() {
    let e = escape_literal(b"ok\xffbad").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::NonUtf8);
    assert_eq!(e.pos, 2);
}

#[test]
fn nul_is_rejected_not_dropped() {
    // Dropping or substituting would silently change the command.
    let e = escape_literal(b"a\0b").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnrepresentableChar);
    assert_eq!(e.pos, 1);
}

#[test]
fn other_controls_pass_through_raw_rather_than_being_refused_on_inference() {
    // Verified against real osascript by
    // `both_quoting_layers_survive_a_real_osascript_round_trip`; if that fails on
    // macOS CI, the refusal comes back here with the evidence attached.
    for bytes in [
        b"a\x07b".as_slice(),
        b"\x1b[0m".as_slice(),
        b"a\x0bb".as_slice(),
        b"a\x0cb".as_slice(),
        b"a\x7fb".as_slice(),
    ] {
        let escaped = escape_literal(bytes).unwrap_or_else(|e| panic!("{bytes:?}: {e}"));
        assert_eq!(&unescape_literal(&escaped)[..], bytes, "{bytes:?}");
    }
}
