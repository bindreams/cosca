//! Pure parsers for `/proc/<pid>/stat` fields. In an always-compiled module so
//! the tricky comm-field handling is unit-tested on every host, not only Linux.
//!
//! The comm field (field 2) is paren-wrapped and may contain spaces and ')', so
//! we anchor on the LAST ')': index 0 of the whitespace-split tail is field 3
//! (state); `starttime` is field 22 (index 19).
//
// Compiled on every target (for host unit tests); only `linux.rs` calls these,
// so they are dead on non-Linux builds.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

fn tail(stat: &[u8]) -> Option<&str> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    std::str::from_utf8(stat.get(close + 1..)?).ok()
}

/// Field 22 (`starttime`) as RAW jiffies since boot.
pub(super) fn parse_starttime_jiffies(stat: &[u8]) -> Option<u64> {
    tail(stat)?.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Field 3 (process state) as its single state character, e.g. `b'R'`, `b'Z'`.
pub(super) fn parse_state(stat: &[u8]) -> Option<u8> {
    tail(stat)?.split_whitespace().next()?.bytes().next()
}

/// Field 4 (`ppid`, index 1 of the tail) — the parent pid. Used by the
/// containment tree-walk's `/proc` enumerator; comm-safe via the same anchor.
pub(crate) fn parse_ppid(stat: &[u8]) -> Option<u32> {
    tail(stat)?.split_whitespace().nth(1)?.parse::<u32>().ok()
}

/// Decide whether a process is *running* from its raw `/proc/<pid>/stat` bytes:
/// the starttime token must match `start` (reject a reused PID) AND the state
/// must not be zombie ('Z') or dead ('X'/'x'). Pure, so it is host-testable.
pub(super) fn running_from_stat(stat: &[u8], start: super::StartToken) -> bool {
    match parse_starttime_jiffies(stat) {
        Some(j) if super::StartToken::from_raw(j) == start => {}
        _ => return false,
    }
    match parse_state(stat) {
        Some(s) => !matches!(s, b'Z' | b'X' | b'x'),
        None => false,
    }
}

#[cfg(test)]
#[path = "stat_parse_tests.rs"]
mod stat_parse_tests;
