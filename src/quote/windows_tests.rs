use crate::quote::windows::{first_token_and_rest_wide, first_token_wide, join_wide};

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn jw(args: &[&str]) -> String {
    let wides: Vec<Vec<u16>> = args.iter().map(|a| w(a)).collect();
    let refs: Vec<&[u16]> = wides.iter().map(|v| v.as_slice()).collect();
    String::from_utf16(&join_wide(&refs)).unwrap()
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
