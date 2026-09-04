use crate::quote::windows::{first_token_and_rest_wide, first_token_wide, join_wide, split_wide};

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn jw(args: &[&str]) -> String {
    let wides: Vec<Vec<u16>> = args.iter().map(|a| w(a)).collect();
    let refs: Vec<&[u16]> = wides.iter().map(|v| v.as_slice()).collect();
    String::from_utf16(&join_wide(&refs)).unwrap()
}
fn sw(s: &str) -> Vec<Vec<u16>> {
    split_wide(&w(s)).unwrap()
}
fn sw_strings(s: &str) -> Vec<String> {
    sw(s).into_iter().map(|t| String::from_utf16(&t).unwrap()).collect()
}

#[test]
fn simple_args_separated_by_space() {
    assert_eq!(jw(&["a", "b"]), "a b");
}

#[test]
fn args_with_space_or_tab_are_quoted() {
    assert_eq!(jw(&["a b"]), "\"a b\"");
    assert_eq!(jw(&["a\tb"]), "\"a\tb\"");
}

#[test]
fn empty_arg_becomes_empty_quotes() {
    assert_eq!(jw(&["a", "", "b"]), "a \"\" b");
}

#[test]
fn embedded_quote_is_backslash_escaped() {
    // a"b  ->  a\"b
    assert_eq!(jw(&["a\"b"]), "a\\\"b");
}

#[test]
fn empty_argv_returns_empty_vec() {
    let empty: Vec<&[u16]> = vec![];
    assert_eq!(join_wide(&empty), Vec::<u16>::new());
}

#[test]
fn lone_surrogate_passes_through_verbatim() {
    // 0xD800 is an unpaired surrogate — not representable in a Rust `String`,
    // which is the core justification for the u16-based API: routing through
    // String would lose or corrupt these code units. The surrogate is not a
    // space/tab/quote/backslash, so no quoting is applied.
    let arg: &[u16] = &[b'a' as u16, 0xD800u16, b'b' as u16];
    let result = join_wide(&[arg]);
    assert_eq!(result, &[b'a' as u16, 0xD800u16, b'b' as u16]);
}

#[test]
fn lone_backslashes_not_before_quote_stay_literal() {
    assert_eq!(jw(&["a\\b"]), "a\\b");
    assert_eq!(jw(&["a\\"]), "a\\");
}

#[test]
fn multiple_consecutive_backslashes_unquoted_stay_literal() {
    // Four backslashes between letters with no spaces: no quoting triggered,
    // so the backslashes must not be doubled.
    assert_eq!(jw(&["a\\\\\\\\b"]), "a\\\\\\\\b");
}

#[test]
fn backslashes_before_quote_are_doubled_plus_one() {
    // a\"b  ->  a\\\"b   (one backslash + escaped quote)
    assert_eq!(jw(&["a\\\"b"]), "a\\\\\\\"b");
}

#[test]
fn trailing_backslashes_doubled_before_closing_quote() {
    assert_eq!(jw(&["a\\ b"]), "\"a\\ b\""); // single backslash, space forces quotes
    assert_eq!(jw(&["a b\\"]), "\"a b\\\\\""); // trailing \ doubled before closing "
}

// split_wide ================================================================

#[test]
fn split_wide_empty_input_returns_empty_vec() {
    assert_eq!(split_wide(&[]).unwrap(), Vec::<Vec<u16>>::new());
}

#[test]
fn split_wide_whitespace_only_input_returns_empty_vec() {
    assert_eq!(sw("   \t "), Vec::<Vec<u16>>::new());
}

#[test]
fn split_wide_simple_args() {
    assert_eq!(sw_strings("a b c"), vec!["a", "b", "c"]);
}

#[test]
fn split_wide_skips_leading_whitespace_before_argv0() {
    // Same deliberate deviation `first_token_wide` already documents.
    assert_eq!(sw_strings("   cmd arg"), vec!["cmd", "arg"]);
}

#[test]
fn split_wide_tab_separates_rest_args() {
    assert_eq!(sw_strings("prog\ta\tb"), vec!["prog", "a", "b"]);
}

#[test]
fn split_wide_quoted_arg_with_embedded_space() {
    assert_eq!(sw_strings("prog \"a b\""), vec!["prog", "a b"]);
}

#[test]
fn split_wide_empty_quoted_arg_between_args() {
    assert_eq!(sw_strings("prog \"\" x"), vec!["prog", "", "x"]);
}

#[test]
fn split_wide_adjacent_empty_quotes_concatenate() {
    // a""b -> ab: a fresh run of exactly 2 bare quotes (the mod-3 counter
    // goes 0->1->2 and the run ends there) resets with no literal `"`.
    assert_eq!(sw_strings("prog a\"\"b"), vec!["prog", "ab"]);
}

#[test]
fn split_wide_triple_quote_run_yields_one_literal_quote() {
    // The undocumented shell32 mod-3 rule: 3 consecutive bare quotes collapse
    // to one literal `"` with no net toggle of "inside quotes".
    assert_eq!(sw_strings("prog a\"\"\"b"), vec!["prog", "a\"b"]);
}

#[test]
fn split_wide_double_quote_inside_quoted_region_embeds_literal_quote() {
    // The classic "double a quote to embed one" idiom: "a""b" -> a"b.
    assert_eq!(sw_strings("prog \"a\"\"b\""), vec!["prog", "a\"b"]);
}

#[test]
fn split_wide_backslash_before_quote_odd_count() {
    // One backslash before a quote: (1-1)/2 = 0 literal backslashes, quote is literal.
    assert_eq!(sw_strings("prog a\\\"b"), vec!["prog", "a\"b"]);
}

#[test]
fn split_wide_backslash_before_quote_even_count() {
    // Two backslashes before a quote: 2/2 = 1 literal backslash, quote toggles.
    assert_eq!(sw_strings("prog a\\\\\"b"), vec!["prog", "a\\b"]);
}

#[test]
fn split_wide_trailing_backslash_stays_literal() {
    assert_eq!(sw_strings("prog a\\"), vec!["prog", "a\\"]);
}

#[test]
fn split_wide_backslashes_before_whitespace_stay_literal() {
    // Not just end-of-input: backslashes not immediately followed by a quote
    // are always literal, including right before a token-ending whitespace.
    assert_eq!(sw_strings("prog a\\\\ b"), vec!["prog", "a\\\\", "b"]);
}

#[test]
fn split_wide_argv0_only_no_further_args() {
    assert_eq!(sw_strings("prog"), vec!["prog"]);
}

#[test]
fn split_wide_trailing_whitespace_after_last_arg_yields_no_spurious_empty_token() {
    assert_eq!(sw_strings("prog a   "), vec!["prog", "a"]);
}

#[test]
fn split_wide_unterminated_quote_in_rest_arg_consumes_to_end() {
    // Mirrors `unterminated_opening_quote_consumes_to_end` for argv[0], but
    // through the args[1..] parser's own qcount/bcount state machine.
    assert_eq!(sw_strings("prog \"abc"), vec!["prog", "abc"]);
}

#[test]
fn split_wide_trailing_backslash_run_before_unterminated_opening_quote() {
    // Exercises the truncate-on-EOF interaction: an even backslash run
    // (halved to 1 literal `\`) immediately before a bare opening quote that
    // toggles "inside quotes" and is then never closed (consumes to end, no
    // literal `"` emitted since this quote was a toggle, not an escape).
    assert_eq!(sw_strings("prog abc\\\\\""), vec!["prog", "abc\\"]);
}

#[test]
fn split_wide_round_trips_join_wide_for_rest_args() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["a", "b"],
        vec!["a b", "a\"b", "a\\b", "a\\\"b", "trail\\", "", "tab\tx"],
        vec!["a\\\\\\\\b"],
    ];
    for rest in cases {
        let joined = jw(&rest);
        let full = format!("prog {joined}");
        let result = sw_strings(&full);
        let mut expected = vec!["prog".to_string()];
        expected.extend(rest.iter().map(|s| s.to_string()));
        assert_eq!(result, expected, "round-trip mismatch for {rest:?}");
    }
}

#[test]
fn split_wide_lone_surrogate_passes_through_verbatim() {
    // 0xD800 is an unpaired surrogate: legal as a raw code unit, not valid on
    // its own in a Rust `String`. Confirms split_wide doesn't require valid
    // UTF-16 and doesn't treat it as a delimiter/quote/backslash.
    let mut cmd: Vec<u16> = w("prog a");
    cmd.push(0xD800u16);
    cmd.push(b'b' as u16);
    let result = split_wide(&cmd).unwrap();
    let mut expected_arg = w("a");
    expected_arg.push(0xD800u16);
    expected_arg.push(b'b' as u16);
    assert_eq!(result, vec![w("prog"), expected_arg]);
}

#[cfg(windows)]
mod roundtrip {
    use super::*;

    #[link(name = "shell32")]
    extern "system" {
        fn CommandLineToArgvW(lp_cmd_line: *const u16, p_num_args: *mut i32) -> *mut *mut u16;
    }
    extern "system" {
        fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    // Parse a command line the way the OS does. Returns the argv vector.
    fn os_parse(cmdline: &[u16]) -> Vec<Vec<u16>> {
        let mut buf: Vec<u16> = cmdline.to_vec();
        buf.push(0); // NUL terminate
        let mut n: i32 = 0;
        // SAFETY: buf is NUL-terminated; the returned array is freed with LocalFree.
        unsafe {
            let argv = CommandLineToArgvW(buf.as_ptr(), &mut n);
            assert!(!argv.is_null(), "CommandLineToArgvW failed");
            debug_assert!(n >= 0);
            let mut out = Vec::with_capacity(n as usize);
            for i in 0..n as isize {
                let p = *argv.offset(i);
                let mut len = 0isize;
                while *p.offset(len) != 0 {
                    len += 1;
                }
                out.push(std::slice::from_raw_parts(p, len as usize).to_vec());
            }
            LocalFree(argv as *mut _);
            out
        }
    }

    #[test]
    fn first_token_deviates_from_os_on_leading_whitespace() {
        // "   cmd arg": OS does not skip leading whitespace, so argv[0] = "" (an
        // empty string formed by the whitespace-only prefix); our function skips
        // whitespace and returns Some("cmd").
        let input = w("   cmd arg");
        let os_argv0 = os_parse(&input).into_iter().next().unwrap_or_default();
        assert_eq!(
            String::from_utf16(&os_argv0).unwrap(),
            "",
            "OS should return empty string as argv[0] for whitespace-prefixed input"
        );
        assert_eq!(
            first("   cmd arg").as_deref(),
            Some("cmd"),
            "our function should skip leading whitespace and return the first token"
        );
        // The two results differ: OS gives "" while we give "cmd".
        assert_ne!(
            String::from_utf16(&os_argv0).unwrap(),
            "cmd",
            "OS argv[0] must not equal our result — if this fails the deviation no longer exists"
        );
    }

    #[test]
    fn join_wide_round_trips_through_os_parser() {
        // Each test case is a complete argv. The program tokens (first element of
        // every case) are simple ASCII identifiers that round-trip cleanly through
        // the OS argv[0] parser, so we compare the full parsed vector — no slicing
        // needed.
        let cases: Vec<Vec<&str>> = vec![
            vec!["plain", "args"],
            vec!["has space", "a\"b", "a\\b", "a\\\"b", "trail\\", "", "tab\tx"],
            // Four consecutive backslashes before a space: quoted context forces 2n
            // doubling, so `\\\\` (4 backslashes) becomes `\\\\\\\\` (8) inside quotes.
            vec!["prefix", "a\\\\\\\\ b"],
        ];
        for case in cases {
            let wides: Vec<Vec<u16>> = case.iter().map(|a| w(a)).collect();
            let refs: Vec<&[u16]> = wides.iter().map(|v| v.as_slice()).collect();
            let line = join_wide(&refs);
            let parsed = os_parse(&line);
            let expected: Vec<Vec<u16>> = wides.clone();
            assert_eq!(parsed, expected, "round-trip mismatch for {:?}", case);
        }
    }

    #[test]
    fn split_wide_matches_os_parse_for_representative_cases() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["plain", "args"],
            vec!["has space", "a\"b", "a\\b", "a\\\"b", "trail\\", "", "tab\tx"],
            vec!["prefix", "a\\\\\\\\ b"],
        ];
        for case in cases {
            let wides: Vec<Vec<u16>> = case.iter().map(|a| w(a)).collect();
            let refs: Vec<&[u16]> = wides.iter().map(|v| v.as_slice()).collect();
            let line = join_wide(&refs);
            let os_result = os_parse(&line);
            let our_result = split_wide(&line).unwrap();
            assert_eq!(our_result, os_result, "split_wide disagrees with OS for {:?}", case);
            assert_eq!(
                our_result, wides,
                "split_wide disagrees with original argv for {:?}",
                case
            );
        }
    }

    #[test]
    fn split_wide_matches_os_parse_for_adversarial_quote_runs() {
        // Hand-written lines exercising the shell32 mod-3 rule for runs of
        // consecutive bare quotes, plus unterminated-quote edge cases — none
        // producible by our own `join_wide`, which never emits 3+ adjacent
        // unescaped quotes or an unclosed quoted region.
        let lines = [
            "prog a\"\"\"b",
            "prog \"a\"\" b\"",
            "prog \"\"\"",
            "prog a\"\"\"\"b",
            "prog \"\"\"x",
            "prog \"abc",
            "prog abc\\\\\"",
        ];
        for line in lines {
            let cmd = w(line);
            let os_result = os_parse(&cmd);
            let our_result = split_wide(&cmd).unwrap();
            assert_eq!(our_result, os_result, "split_wide disagrees with OS for {line:?}");
        }
    }

    #[test]
    fn split_wide_deviates_from_os_like_first_token_on_leading_whitespace() {
        // Same deviation as `first_token_wide`, now exercised through the
        // full splitter: we skip leading whitespace before argv[0]; the OS
        // does not.
        let input = w("   cmd arg");
        let os_result = os_parse(&input);
        let our_result = split_wide(&input).unwrap();
        assert_ne!(our_result, os_result, "deviation should still exist for split_wide");
        assert_eq!(
            our_result,
            vec![w("cmd"), w("arg")],
            "split_wide should skip leading whitespace and return [\"cmd\", \"arg\"]"
        );
    }
}

fn first(s: &str) -> Option<String> {
    first_token_wide(&w(s)).map(|t| String::from_utf16(&t).unwrap())
}

fn split_first(s: &str) -> Option<(String, String)> {
    first_token_and_rest_wide(&w(s)).map(|(a, b)| (String::from_utf16(&a).unwrap(), String::from_utf16(&b).unwrap()))
}

#[test]
fn first_token_and_rest_splits_unquoted() {
    assert_eq!(
        split_first("git status --short"),
        Some(("git".into(), "status --short".into()))
    );
}

#[test]
fn first_token_and_rest_splits_quoted_program_with_spaces() {
    assert_eq!(
        split_first("\"C:\\Program Files\\app.exe\" --flag x"),
        Some(("C:\\Program Files\\app.exe".into(), "--flag x".into()))
    );
}

#[test]
fn first_token_and_rest_empty_rest() {
    assert_eq!(split_first("solo"), Some(("solo".into(), "".into())));
}

#[test]
fn first_token_and_rest_none_for_blank() {
    assert_eq!(split_first("   "), None);
}

#[test]
fn first_token_stops_at_whitespace() {
    assert_eq!(first("git status --short").as_deref(), Some("git"));
}

#[test]
fn first_token_skips_leading_whitespace_by_design() {
    // Deliberate deviation from CommandLineToArgvW argv[0] (which does NOT skip):
    // we resolve a program from a user command line, so leading blanks are ignored.
    assert_eq!(first("   \t cmd arg").as_deref(), Some("cmd"));
}

#[test]
fn quoted_first_token_spans_to_closing_quote() {
    assert_eq!(
        first("\"C:\\Program Files\\app.exe\" --flag").as_deref(),
        Some("C:\\Program Files\\app.exe")
    );
}

#[test]
fn unterminated_opening_quote_consumes_to_end() {
    assert_eq!(first("\"C:\\no close").as_deref(), Some("C:\\no close"));
}

#[test]
fn backslashes_are_literal_in_first_token() {
    assert_eq!(first("C:\\bin\\tool.exe x").as_deref(), Some("C:\\bin\\tool.exe"));
}

#[test]
fn empty_or_whitespace_only_has_no_first_token() {
    assert_eq!(first(""), None);
    assert_eq!(first("   \t "), None);
}

#[test]
fn mid_token_embedded_quotes_are_not_terminators() {
    // In the unquoted branch, `"` is not a space/tab so the token continues
    // through it; quotes mid-token are passed through verbatim.
    assert_eq!(first("a\"b\"c").as_deref(), Some("a\"b\"c"));
}

#[test]
fn bare_empty_quotes_yield_empty_token() {
    // `""` enters the quoted branch; the inner loop exits immediately on the
    // closing quote, returning an empty token rather than None.
    assert_eq!(first("\"\"").as_deref(), Some(""));
}
