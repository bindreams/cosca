use crate::error::QuoteErrorKind;
use crate::quote::posix::split;

fn s(input: &str) -> Vec<Vec<u8>> {
    split(input.as_bytes()).expect("should parse")
}
fn strs(input: &str) -> Vec<String> {
    s(input).into_iter().map(|w| String::from_utf8(w).unwrap()).collect()
}

// (A) Python posix_data port — adapted from CPython Lib/test/test_shlex.py (PSF-licensed).
// Test vectors (input/expected pairs) are factual data, not copyrighted expression.

#[test]
fn py_single_word() {
    assert_eq!(strs("x"), ["x"]);
}
#[test]
fn py_two_words() {
    assert_eq!(strs("foo bar"), ["foo", "bar"]);
}
#[test]
fn py_leading_ws() {
    assert_eq!(strs(" foo bar"), ["foo", "bar"]);
}
#[test]
fn py_leading_trailing_ws() {
    assert_eq!(strs(" foo bar "), ["foo", "bar"]);
}
#[test]
fn py_multi_ws() {
    assert_eq!(strs("foo   bar  bla     fasel"), ["foo", "bar", "bla", "fasel"]);
}
#[test]
fn py_embedded_runs() {
    assert_eq!(strs("x y  z              xxxx"), ["x", "y", "z", "xxxx"]);
}
#[test]
fn py_bs_x() {
    assert_eq!(strs(r"\x bar"), ["x", "bar"]);
}
#[test]
fn py_bs_space_x() {
    assert_eq!(strs(r"\ x bar"), [" x", "bar"]);
}
#[test]
fn py_bs_space() {
    assert_eq!(strs(r"\ bar"), [" bar"]);
}
#[test]
fn py_bs_x_mid() {
    assert_eq!(strs(r"foo \x bar"), ["foo", "x", "bar"]);
}
#[test]
fn py_bs_space_x_mid() {
    assert_eq!(strs(r"foo \ x bar"), ["foo", " x", "bar"]);
}
#[test]
fn py_bs_space_mid() {
    assert_eq!(strs(r"foo \ bar"), ["foo", " bar"]);
}
#[test]
fn py_dq_word() {
    assert_eq!(strs(r#"foo "bar" bla"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_all_dq() {
    assert_eq!(strs(r#""foo" "bar" "bla""#), ["foo", "bar", "bla"]);
}
#[test]
fn py_mixed_dq() {
    assert_eq!(strs(r#""foo" bar "bla""#), ["foo", "bar", "bla"]);
}
#[test]
fn py_dq_start() {
    assert_eq!(strs(r#""foo" bar bla"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_sq_word() {
    assert_eq!(strs(r#"foo 'bar' bla"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_all_sq() {
    assert_eq!(strs(r#"'foo' 'bar' 'bla'"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_mixed_sq() {
    assert_eq!(strs(r#"'foo' bar 'bla'"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_sq_start() {
    assert_eq!(strs(r#"'foo' bar bla"#), ["foo", "bar", "bla"]);
}
#[test]
fn py_adjacent_dq() {
    assert_eq!(
        strs(r#"blurb foo"bar"bar"fasel" baz"#),
        ["blurb", "foobarbarfasel", "baz"]
    );
}
#[test]
fn py_adjacent_sq() {
    assert_eq!(
        strs(r#"blurb foo'bar'bar'fasel' baz"#),
        ["blurb", "foobarbarfasel", "baz"]
    );
}
#[test]
fn py_empty_dq_mid() {
    assert_eq!(strs(r#"foo "" bar"#), ["foo", "", "bar"]);
}
#[test]
fn py_empty_sq_mid() {
    assert_eq!(strs("foo '' bar"), ["foo", "", "bar"]);
}
#[test]
fn py_triple_empty_dq() {
    assert_eq!(strs(r#"foo "" "" "" bar"#), ["foo", "", "", "", "bar"]);
}
#[test]
fn py_triple_empty_sq() {
    assert_eq!(strs("foo '' '' '' bar"), ["foo", "", "", "", "bar"]);
}
#[test]
fn py_bs_dq_unquoted() {
    assert_eq!(strs(r#"\""#), [r#"""#]);
}
#[test]
fn py_dq_bs_dq() {
    assert_eq!(strs(r#""\"""#), [r#"""#]);
}
#[test]
fn py_dq_bs_space() {
    assert_eq!(strs(r#""foo\ bar""#), [r"foo\ bar"]);
} // \<space> in dQ: both literal
#[test]
fn py_dq_bs_bs_space() {
    assert_eq!(strs(r#""foo\\ bar""#), [r"foo\ bar"]);
} // \\ in dQ: consume one
#[test]
fn py_dq_bs_bs_space_bs_dq() {
    assert_eq!(strs(r#""foo\\ bar\"""#), [r#"foo\ bar""#]);
}
#[test]
fn py_dq_bs_bs_close_bs_dq() {
    assert_eq!(strs(r#""foo\\" bar\""#), [r"foo\", r#"bar""#]);
}
#[test]
fn py_dq_multi() {
    assert_eq!(strs(r#""foo\\ bar\" dfadf""#), [r#"foo\ bar" dfadf"#]);
}
#[test]
fn py_dq_multi_triple_bs() {
    assert_eq!(strs(r#""foo\\\ bar\" dfadf""#), [r#"foo\\ bar" dfadf"#]);
}
#[test]
fn py_dq_multi_triple_bs_x() {
    assert_eq!(strs(r#""foo\\\x bar\" dfadf""#), [r#"foo\\x bar" dfadf"#]);
}
#[test]
fn py_dq_bs_x_mid() {
    assert_eq!(strs(r#""foo\x bar\" dfadf""#), [r#"foo\x bar" dfadf"#]);
}
#[test]
fn py_bs_sq_unquoted() {
    assert_eq!(strs(r"\'"), ["'"]);
}
#[test]
fn py_sq_bs_space() {
    assert_eq!(strs(r"'foo\ bar'"), [r"foo\ bar"]);
}
#[test]
fn py_sq_bs_bs_space() {
    assert_eq!(strs(r"'foo\\ bar'"), [r"foo\\ bar"]);
}
#[test]
fn py_mixed_hard() {
    assert_eq!(strs(r#""foo\\\x bar\" df'a\ 'df""#), [r#"foo\\x bar" df'a\ 'df"#]);
}
#[test]
fn py_bs_dq_foo() {
    assert_eq!(strs(r#"\"foo"#), [r#""foo"#]);
}
#[test]
fn py_bs_dq_foo_bs_x() {
    assert_eq!(strs(r#"\"foo\x"#), [r#""foox"#]);
}
#[test]
fn py_dq_bs_x() {
    assert_eq!(strs(r#""foo\x""#), [r"foo\x"]);
}
#[test]
fn py_dq_bs_trailing_space() {
    assert_eq!(strs(r#""foo\ ""#), [r"foo\ "]);
}
#[test]
fn py_bs_space_mid_word() {
    assert_eq!(strs(r"foo\ xx"), ["foo xx"]);
}
#[test]
fn py_bs_space_bs_x() {
    assert_eq!(strs(r"foo\ x\x"), ["foo xx"]);
}
#[test]
fn py_bs_space_bs_x_bs_dq() {
    assert_eq!(strs(r#"foo\ x\x\""#), [r#"foo xx""#]);
}
#[test]
fn py_dq_bs_space_bs_x() {
    assert_eq!(strs(r#""foo\ x\x""#), [r"foo\ x\x"]);
}
#[test]
fn py_dq_bs_space_bs_x_bs_bs() {
    assert_eq!(strs(r#""foo\ x\x\\""#), [r"foo\ x\x\"]);
}
#[test]
fn py_dq_mix_adjacent() {
    assert_eq!(strs(r#""foo\ x\x\\""foobar""#), [r"foo\ x\x\foobar"]);
}
#[test]
fn py_dq_mix_adjacent_bs_sq() {
    assert_eq!(strs(r#""foo\ x\x\\"\'"foobar""#), [r"foo\ x\x\'foobar"]);
}
#[test]
fn py_dq_mix_adjacent_bs_sq_embedded_sq() {
    assert_eq!(strs(r#""foo\ x\x\\"\'"fo'obar""#), [r"foo\ x\x\'fo'obar"]);
}
#[test]
fn py_dq_adjacent_with_sq_dont() {
    assert_eq!(
        strs(r#""foo\ x\x\\"\'"fo'obar" 'don'\''t'"#),
        [r"foo\ x\x\'fo'obar", "don't"]
    );
}
#[test]
fn py_dq_adjacent_trailing_bs_bs() {
    assert_eq!(
        strs(r#""foo\ x\x\\"\'"fo'obar" 'don'\''t' \\"#),
        [r"foo\ x\x\'fo'obar", "don't", r"\"]
    );
}
#[test]
fn py_literal_faces() {
    assert_eq!(strs(":-) ;-)"), [":-)", ";-)"]);
}
#[test]
fn py_unicode() {
    assert_eq!(strs("áéíóú"), ["áéíóú"]);
}

// (B) Python-is-wrong per POSIX: strict POSIX consumes the backslash before $, `, and <LF>
// inside "...". Python preserves it. We follow POSIX.

#[test]
fn dq_escaped_dollar() {
    assert_eq!(strs(r#""\$""#), ["$"]);
}
#[test]
fn dq_escaped_backtick() {
    assert_eq!(strs("\"\\\x60\""), ["`"]);
}
#[test]
fn dq_line_cont() {
    assert_eq!(strs("\"foo\\\nbar\""), ["foobar"]);
}

// (C) Python agrees with POSIX on these.

#[test]
fn dq_escaped_quote() {
    assert_eq!(strs(r#""\"""#), [r#"""#]);
}
#[test]
fn dq_escaped_backslash() {
    assert_eq!(strs(r#""\\""#), [r"\"]);
}
#[test]
fn dq_non_special() {
    assert_eq!(strs(r#""\P""#), [r"\P"]);
}

// (D) Windows path matrix.

#[test]
fn win_quoted_single_bs() {
    assert_eq!(strs(r#""C:\Projects\qodana-cli""#), [r"C:\Projects\qodana-cli"]);
}
#[test]
fn win_quoted_double_bs() {
    assert_eq!(strs(r#""C:\\Projects\\qodana-cli""#), [r"C:\Projects\qodana-cli"]);
}
#[test]
fn win_forward_slash() {
    assert_eq!(strs("C:/Projects/qodana-cli"), ["C:/Projects/qodana-cli"]);
}
#[test]
fn win_unquoted_bs_consumed() {
    assert_eq!(strs(r"C:\Projects\qodana-cli"), ["C:Projectsqodana-cli"]);
}
#[test]
fn win_include_dir() {
    assert_eq!(strs(r#"-I"C:\Projects\qodana-cli""#), [r"-IC:\Projects\qodana-cli"]);
}
#[test]
fn win_program_files_plus_arg() {
    assert_eq!(
        strs(r#""C:\Program Files\LLVM\bin\clang.exe" -c "src\main.c""#),
        [r"C:\Program Files\LLVM\bin\clang.exe", "-c", r"src\main.c"],
    );
}
#[test]
fn win_post_json_single_bs() {
    assert_eq!(
        strs(r"c:\tools\clang.exe -c src\main.c"),
        ["c:toolsclang.exe", "-c", "srcmain.c"],
    );
}
#[test]
fn win_post_json_quoted() {
    assert_eq!(
        strs(r#""c:\tools\clang.exe" -c "src\main.c""#),
        [r"c:\tools\clang.exe", "-c", r"src\main.c"],
    );
}

// (E) Adjacent quoting / empty-token concatenation.

#[test]
fn dq_adjacent() {
    assert_eq!(strs(r#""a""b""#), ["ab"]);
}
#[test]
fn sq_adjacent() {
    assert_eq!(strs("'a''b'"), ["ab"]);
}
#[test]
fn dq_then_sq() {
    assert_eq!(strs(r#""a"'b'"#), ["ab"]);
}
#[test]
fn sq_then_dq() {
    assert_eq!(strs(r#"'a'"b""#), ["ab"]);
}
#[test]
fn word_dq_word() {
    assert_eq!(strs(r#"a"b"c"#), ["abc"]);
}
#[test]
fn dq_word_dq() {
    assert_eq!(strs(r#""a"b"c""#), ["abc"]);
}
#[test]
fn foo_empty_dq() {
    assert_eq!(strs(r#"foo"""#), ["foo"]);
}
#[test]
fn empty_dq_foo() {
    assert_eq!(strs(r#"""foo"#), ["foo"]);
}
#[test]
fn bare_empty_dq() {
    assert_eq!(strs(r#""""#), [""]);
}
#[test]
fn two_adjacent_empty_dq() {
    assert_eq!(strs("\"\"\"\""), [""]);
}
#[test]
fn foo_dq_empty_dq_bar() {
    assert_eq!(strs(r#"foo "" bar"#), ["foo", "", "bar"]);
}
#[test]
fn foo_sq_empty_sq_bar() {
    assert_eq!(strs("foo '' '' bar"), ["foo", "", "", "bar"]);
}

// (F) Whitespace — all blank inputs yield empty vec.

#[test]
fn ws_empty() {
    assert!(split(b"").unwrap().is_empty());
}
#[test]
fn ws_space() {
    assert!(split(b" ").unwrap().is_empty());
}
#[test]
fn ws_tab() {
    assert!(split(b"\t").unwrap().is_empty());
}
#[test]
fn ws_lf() {
    assert!(split(b"\n").unwrap().is_empty());
}
#[test]
fn ws_cr() {
    assert!(split(b"\r").unwrap().is_empty());
}
#[test]
fn ws_runs() {
    assert!(split(b"   ").unwrap().is_empty());
}
#[test]
fn ws_crlf() {
    assert!(split(b"\r\n").unwrap().is_empty());
}
#[test]
fn ws_a_cr_b() {
    assert_eq!(strs("a\rb"), ["a", "b"]);
}
#[test]
fn ws_a_crlf_b() {
    assert_eq!(strs("a\r\nb"), ["a", "b"]);
}
#[test]
fn ws_trailing_space() {
    assert_eq!(strs("a "), ["a"]);
}
#[test]
fn ws_double_space_mid() {
    assert_eq!(strs("a  b"), ["a", "b"]);
}
#[test]
fn ws_leading_and_trailing() {
    assert_eq!(strs(" a "), ["a"]);
}
#[test]
fn ws_all_types() {
    assert!(split(b" \t\n\r").unwrap().is_empty());
}

// (G) Literal special chars (documented deviations).

#[test]
fn hash_mid_word() {
    assert_eq!(strs("foo#bar"), ["foo#bar"]);
}
#[test]
fn hash_at_start() {
    assert_eq!(strs("#foo"), ["#foo"]);
}
#[test]
fn hash_as_separate_word() {
    assert_eq!(strs("a #b c"), ["a", "#b", "c"]);
}
#[test]
fn cmd_subst() {
    assert_eq!(strs("$(rm -rf /)"), ["$(rm", "-rf", "/)",]);
}
#[test]
fn param_expansion() {
    assert_eq!(strs("${foo}"), ["${foo}"]);
}
#[test]
fn backtick_subst() {
    assert_eq!(strs("`backtick`"), ["`backtick`"]);
}
#[test]
fn shell_operators_no_ws() {
    assert_eq!(strs("a&b;c|d"), ["a&b;c|d"]);
}
#[test]
fn double_pipe() {
    assert_eq!(strs("a || b"), ["a", "||", "b"]);
}
#[test]
fn redirects_literal() {
    assert_eq!(strs("a >b <c"), ["a", ">b", "<c"]);
}

// (I) Line continuation — LF, CRLF, and bare CR (NOT line continuation).

#[test]
fn lf_unquoted_mid_word() {
    assert_eq!(strs("foo\\\nbar"), ["foobar"]);
}
#[test]
fn lf_inside_dq() {
    assert_eq!(strs("\"foo\\\nbar\""), ["foobar"]);
}
#[test]
fn lf_at_start_only() {
    assert!(split(b"\\\n").unwrap().is_empty());
}
#[test]
fn lf_split_mid() {
    assert_eq!(strs("a\\\nb c"), ["ab", "c"]);
}
#[test]
fn crlf_unquoted() {
    assert_eq!(strs("foo\\\r\nbar"), ["foobar"]);
}
#[test]
fn bare_cr_unquoted_literal() {
    assert_eq!(s("foo\\\rbar"), [b"foo\rbar".to_vec()]);
}
#[test]
fn crlf_inside_dq() {
    assert_eq!(strs("\"a\\\r\nb\""), ["ab"]);
}
#[test]
fn bare_cr_inside_dq_preserved() {
    assert_eq!(s("\"a\\\rb\""), [b"a\\\rb".to_vec()]);
}

// (S) UTF-8 pass-through.

#[test]
fn unicode_two_words() {
    assert_eq!(strs("héllo 世界"), ["héllo", "世界"]);
}
#[test]
fn unicode_inside_dq() {
    assert_eq!(strs("\"café au lait\""), ["café au lait"]);
}
#[test]
fn unicode_after_bs_unquoted() {
    assert_eq!(strs("\\é"), ["é"]);
}
#[test]
fn unicode_after_bs_in_dq() {
    assert_eq!(strs("\"\\é\""), ["\\é"]);
}

// (H) Non-ASCII bytes / NUL pass-through (byte-level, not string-level).

#[test]
fn non_ascii_bytes_pass_through() {
    let input = [b'a', 0xC3, 0xA9, b'b']; // "a", 0xC3 0xA9 (é utf8), "b"
    assert_eq!(split(&input).unwrap(), vec![input.to_vec()]);
}
#[test]
fn nul_byte_is_a_valid_word_byte() {
    assert_eq!(split(b"a\0b").unwrap(), vec![b"a\0b".to_vec()]);
}

// (H) Errors — assert typed QuoteError with exact pos and kind.

#[test]
fn error_unterminated_dq_at_start() {
    let e = split(b"\"foo").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedDoubleQuote);
    assert_eq!(e.pos, 0);
}
#[test]
fn error_unterminated_sq_at_start() {
    let e = split(b"'foo").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.pos, 0);
}
#[test]
fn error_bare_sq() {
    let e = split(b"'").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.pos, 0);
}
#[test]
fn error_empty_dq_then_unterminated_sq() {
    let e = split(b"\"\"'").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.pos, 2);
}
#[test]
fn error_mid_token_sq() {
    let e = split(b"foo'bar").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.pos, 3);
}
#[test]
fn error_mid_token_dq() {
    let e = split(b"foo\"bar").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::UnterminatedDoubleQuote);
    assert_eq!(e.pos, 3);
}
#[test]
fn error_trailing_bs_after_word() {
    let e = split(b"foo\\").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::TrailingBackslash);
    assert_eq!(e.pos, 3);
}
#[test]
fn error_trailing_bs_in_dq() {
    let e = split(b"\"foo\\").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::TrailingBackslash);
    assert_eq!(e.pos, 4);
}
#[test]
fn error_lone_bs() {
    let e = split(b"\\").unwrap_err();
    assert_eq!(e.kind, QuoteErrorKind::TrailingBackslash);
    assert_eq!(e.pos, 0);
}

use crate::quote::posix::{join, quote};

#[test]
fn quote_passes_safe_strings_through() {
    assert_eq!(quote(b"abcXYZ_0-9@%+=:,./"), b"abcXYZ_0-9@%+=:,./");
}

#[test]
fn quote_wraps_empty_in_single_quotes() {
    assert_eq!(quote(b""), b"''");
}

#[test]
fn quote_wraps_unsafe_and_escapes_single_quotes() {
    assert_eq!(quote(b"a b"), b"'a b'");
    assert_eq!(quote(b"it's"), br#"'it'"'"'s'"#);
}

#[test]
fn join_empty_is_empty() {
    let empty: Vec<&[u8]> = vec![];
    assert_eq!(join(&empty), b"");
}

#[test]
fn join_separates_with_single_space() {
    let args: Vec<&[u8]> = vec![b"a", b"b c", b"d"];
    assert_eq!(join(&args), b"a 'b c' d");
}

#[test]
fn split_join_round_trips() {
    let cases: Vec<Vec<&[u8]>> = vec![
        vec![b"echo", b"hello world"],
        vec![b"a", b"", b"c"], // empty element
        vec![br"weird $`\ chars", b"'q'"],
        vec![b"a\nb", b"\ttab"],
        vec![b"\x00\xff", b"non-utf8"], // arbitrary bytes
    ];
    for args in cases {
        let line = join(&args);
        let back = split(&line).unwrap();
        let expected: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
        assert_eq!(back, expected, "round-trip failed for {:?}", args);
    }
}

// Oracle port of qodana `join_test.go` — quoting is a security boundary
// (BatBadBut / CVE-2024-24576); the corpus is the oracle, not a spot check.

fn is_safe_byte(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
        | b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-')
}

// (L) quote — exhaustive single-byte matrix. Doubles as a property test for SAFE.
#[test]
fn quote_exhaustive_single_byte() {
    for i in 0u16..=255 {
        let b = i as u8;
        let got = quote(&[b]);
        let want: Vec<u8> = if is_safe_byte(b) {
            vec![b]
        } else if b == b'\'' {
            br#"''"'"''"#.to_vec() // 7 bytes: outer '' + replacement '"'"' + ... wraps to ''"'"''
        } else {
            vec![b'\'', b, b'\'']
        };
        assert_eq!(got, want, "quote(byte {:#04x})", b);
    }
}

// (M) quote golden table.
#[test]
fn quote_golden() {
    let cases: Vec<(&[u8], &[u8])> = vec![
        (b"", b"''"),
        (b"simple", b"simple"),
        (b"has space", b"'has space'"),
        (b"it's", br#"'it'"'"'s'"#),
        (br#"a"b"#, br#"'a"b'"#),
        (br"a\b", br"'a\b'"),
        (br"C:\Program Files", br"'C:\Program Files'"),
        (b"-flag", b"-flag"),
        (b"@domain/user", b"@domain/user"),
        (b"has\tab", b"'has\tab'"),
        (b"has\x00nul", b"'has\x00nul'"),
        (b"a\nb", b"'a\nb'"),
        (b"$foo", b"'$foo'"),
    ];
    for (input, want) in cases {
        assert_eq!(quote(input), want, "quote({:?})", input);
    }
}

// (N) join golden table.
#[test]
fn join_golden() {
    let cases: Vec<(Vec<&[u8]>, &[u8])> = vec![
        (vec![], b""),
        (vec![b"a"], b"a"),
        (vec![b"a", b"b"], b"a b"),
        (vec![b"a ", b"b"], b"'a ' b"),
        (vec![b"a", b" b"], b"a ' b'"),
        (vec![b"a", b" ", b"b"], b"a ' ' b"),
        (vec![br#""a"#, br#"b""#], br#"'"a' 'b"'"#),
        (vec![b"a", b"", b"b"], b"a '' b"),
    ];
    for (input, want) in cases {
        assert_eq!(join(&input), want, "join({:?})", input);
    }
}

/// Hand-curated argv slices for the round-trip invariant (ports `roundTripCorpus`).
fn round_trip_corpus() -> Vec<Vec<Vec<u8>>> {
    let mut corpus: Vec<Vec<Vec<u8>>> = Vec::new();
    let push = |c: &mut Vec<Vec<Vec<u8>>>, args: Vec<&[u8]>| {
        c.push(args.into_iter().map(|a| a.to_vec()).collect());
    };

    // Empty and near-empty.
    push(&mut corpus, vec![]);
    push(&mut corpus, vec![b""]);
    push(&mut corpus, vec![b"", b""]);
    push(&mut corpus, vec![b"a", b"", b"b"]);

    // Every single byte 0..=255 as a one-element slice.
    for i in 0u16..=255 {
        corpus.push(vec![vec![i as u8]]);
    }

    // NUL-containing multi-byte.
    push(&mut corpus, vec![b"a\x00b"]);
    push(&mut corpus, vec![b"\x00"]);
    push(&mut corpus, vec![b"pre\x00\x00post"]);

    // Quote-heavy.
    push(&mut corpus, vec![b"'"]);
    push(&mut corpus, vec![br#"""#]);
    push(&mut corpus, vec![br#"'""#]);
    push(&mut corpus, vec![br#"a"b'c"#]);

    // Backslash-heavy.
    push(&mut corpus, vec![br"\"]);
    push(&mut corpus, vec![br"\\"]);
    push(&mut corpus, vec![br"a\b\c"]);

    // Whitespace-heavy.
    push(&mut corpus, vec![b" "]);
    push(&mut corpus, vec![b"\t"]);
    push(&mut corpus, vec![b"\n"]);
    push(&mut corpus, vec![b"\r"]);
    push(&mut corpus, vec![b" \t\n\r "]);

    // Windows paths.
    push(&mut corpus, vec![br"C:\Projects\file"]);
    push(&mut corpus, vec![br"C:\Program Files\LLVM"]);

    // Shell specials.
    push(&mut corpus, vec![b"$foo"]);
    push(&mut corpus, vec![b"`cmd`"]);
    push(&mut corpus, vec![b"$(echo hi)"]);
    push(&mut corpus, vec![b"a;b&c|d"]);
    push(&mut corpus, vec![b"#comment"]);

    // Dash-leading.
    push(&mut corpus, vec![b"-I/usr"]);
    push(&mut corpus, vec![b"--flag=val"]);
    push(&mut corpus, vec![b"--"]);

    // UTF-8.
    push(&mut corpus, vec!["héllo 世界".as_bytes()]);
    push(&mut corpus, vec!["café".as_bytes(), b"au", b"lait"]);

    // Long mixed slice.
    let long: Vec<Vec<u8>> = (0..50)
        .map(|i| format!("arg-{i} with 'spaces' and \"quotes\"").into_bytes())
        .collect();
    corpus.push(long);

    corpus
}

/// Assert `split(join(args)) == args`, treating empty argv as the canonical
/// empty vec (join of no args is `b""`, which split yields as `[]`).
fn assert_round_trip(args: &[Vec<u8>]) {
    let refs: Vec<&[u8]> = args.iter().map(|a| a.as_slice()).collect();
    let line = join(&refs);
    let back = split(&line).expect("split(join(args)) must not error");
    assert_eq!(back, args, "round-trip mismatch; joined = {:?}", line);
}

// (O) Round-trip invariant over the hand-curated corpus.
#[test]
fn join_split_round_trip_corpus() {
    for args in round_trip_corpus() {
        assert_round_trip(&args);
    }
}

// (Q) Variable-arity round-trip — argv reconstructed from unit-separator-packed
// seeds, the deterministic analogue of the Go fuzz target.
#[test]
fn join_split_round_trip_variable_arity() {
    let seeds: &[&[u8]] = &[
        b"",
        b"\x1f",
        b"\x1f\x1f",
        b"a",
        b"a\x1fb",
        b"a b\x1fc\td",
        b"'\x1f\"",
        b"\\\x1fx",
        b"C:\\path\x1f-I/usr",
        b"he\x1fllo",
        b"\x00\x1f\x00",
    ];
    for packed in seeds {
        let args: Vec<Vec<u8>> = if packed.is_empty() {
            Vec::new()
        } else {
            packed.split(|&b| b == 0x1f).map(|s| s.to_vec()).collect()
        };
        assert_round_trip(&args);
    }
}

// (P) quote output is always a single token.
#[test]
fn quote_output_is_single_token() {
    let mut singles: Vec<Vec<u8>> = (0u16..=255).map(|i| vec![i as u8]).collect();
    singles.extend([
        b"".to_vec(),
        b"'".to_vec(),
        br#"""#.to_vec(),
        br"\".to_vec(),
        b"a b".to_vec(),
        b"a\nb".to_vec(),
        "café au lait".as_bytes().to_vec(),
        br#"'"`$()[]{}"#.to_vec(),
        b"'''''".to_vec(),
    ]);
    for s in singles {
        let out = split(&quote(&s)).expect("split(quote(s)) must not error");
        assert_eq!(out, vec![s.clone()], "quote output not a single token for {:?}", s);
    }
}

// (R) quote is NOT idempotent on unsafe input — guards the round-trip invariant
// against a future "optimization" that would re-break it.
#[test]
fn quote_not_idempotent() {
    let q1 = quote(b"'");
    let q2 = quote(&q1);
    assert_ne!(q1, q2, "quote must not be idempotent on unsafe input");
    assert_eq!(split(&q1).unwrap(), vec![b"'".to_vec()]);
    assert_eq!(split(&q2).unwrap(), vec![q1.clone()]);
}

// (T) Exhaustive never-panics + pos-in-bounds property test for split.
// Covers every state-machine transition in the POSIX parser (security boundary).
// The alphabet is chosen so that every transition in the parser state machine
// is exercised: whitespace separators, quote openers, backslash, shell specials,
// a plain word byte, and a non-ASCII byte.  The enumeration is fully
// deterministic — no randomness, no external dependencies.
//
// Input count: Σ_{k=0}^{4} 12^k = 1 + 12 + 144 + 1728 + 20736 = 22621 inputs.
#[test]
fn split_never_panics_and_pos_in_bounds_exhaustive() {
    const ALPHA: &[u8] = &[
        b' ', b'\t', b'\n', b'\r', b'\\', b'\'', b'"', b'$', b'`', b'#', b'a', 0xFF,
    ];

    // Enumerate all strings of length `len` over ALPHA by treating the index
    // as a mixed-radix counter.
    fn enumerate(len: usize, f: &mut impl FnMut(&[u8])) {
        if len == 0 {
            f(&[]);
            return;
        }
        let base = ALPHA.len();
        let total = base.pow(len as u32);
        let mut buf = vec![0u8; len];
        for mut n in 0..total {
            for slot in buf.iter_mut().rev() {
                *slot = ALPHA[n % base];
                n /= base;
            }
            f(&buf);
        }
    }

    for max_len in 0usize..=4 {
        enumerate(max_len, &mut |input: &[u8]| match split(input) {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    e.pos <= input.len(),
                    "split error pos {} out of bounds for input of len {}; input={:?}",
                    e.pos,
                    input.len(),
                    input
                );
            }
        });
    }
}

// (U) Exhaustive round-trip over small arg-vectors.
// Args drawn from a set of representative byte-strings; vector lengths 0..=3.
// Complements the hand-curated corpus with exhaustive small-cardinality coverage.
//
// Representative args: b"", b"abc", b"a b", b"a'b", b"x\\$", b"\xFF"  (6 elements).
// Vector count: Σ_{k=0}^{3} 6^k = 1 + 6 + 36 + 216 = 259 vectors.
#[test]
fn round_trip_exhaustive_small() {
    const REPR_ARGS: &[&[u8]] = &[b"", b"abc", b"a b", b"a'b", br"x\$", b"\xFF"];

    fn enumerate_vecs(len: usize, f: &mut impl FnMut(&[Vec<u8>])) {
        if len == 0 {
            f(&[]);
            return;
        }
        let base = REPR_ARGS.len();
        let total = base.pow(len as u32);
        let mut buf: Vec<Vec<u8>> = vec![vec![]; len];
        for mut n in 0..total {
            for slot in buf.iter_mut().rev() {
                *slot = REPR_ARGS[n % base].to_vec();
                n /= base;
            }
            f(&buf);
        }
    }

    for vec_len in 0usize..=3 {
        enumerate_vecs(vec_len, &mut |args: &[Vec<u8>]| {
            assert_round_trip(args);
        });
    }
}
