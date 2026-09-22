use super::*;

/// Keys longer than `i32::MAX` units are compared in pieces; small pieces must give the same
/// answer as one whole-string call.
#[test]
fn chunked_comparison_matches_whole_string_comparison() {
    let keys: Vec<Vec<u16>> = [
        "",
        "a",
        "A",
        "ab",
        "AB",
        "abc",
        "abd",
        "ABCD",
        "b",
        "ß",
        "SS",
        "\u{10428}",
    ]
    .iter()
    .map(|s| s.encode_utf16().collect())
    .collect();
    for a in &keys {
        for b in &keys {
            let whole = cmp_ignore_case(a, b, MAX_CHUNK);
            for chunk in 1..=3 {
                assert_eq!(
                    cmp_ignore_case(a, b, chunk),
                    whole,
                    "{a:?} vs {b:?} in chunks of {chunk}"
                );
            }
        }
    }
}

#[test]
fn env_key_equality_follows_its_order() {
    assert_eq!(EnvKey::new(OsStr::new("Path")), EnvKey::new(OsStr::new("PATH")));
    assert_ne!(EnvKey::new(OsStr::new("ß")), EnvKey::new(OsStr::new("SS")));
}
