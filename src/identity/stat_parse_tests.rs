use super::super::StartToken;
use super::{parse_pgrp, parse_ppid, parse_starttime_jiffies, parse_state, running_from_stat};
use crate::identity::Liveness;

fn tok(v: u64) -> StartToken {
    StartToken::from_raw(v)
}

// After the comm field's LAST ')', the whitespace-split tail starts at field 3
// (state, index 0); starttime is field 22 (index 19).
#[test]
fn parses_simple_stat() {
    let stat = b"1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 8675309 0 0";
    assert_eq!(parse_starttime_jiffies(stat), Some(8675309));
    assert_eq!(parse_state(stat), Some(b'S'));
}

#[test]
fn handles_comm_containing_parens_and_spaces() {
    // comm = "a) b" — embedded ')' and space; rposition(')') must find the LAST one.
    let stat = b"7 (a) b) R 0 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 0 0";
    assert_eq!(parse_starttime_jiffies(stat), Some(55));
    assert_eq!(parse_state(stat), Some(b'R'));
}

// ppid is field 4 (index 1 of the post-comm tail). Comm-safe via the LAST ')'.
#[test]
fn parses_ppid_simple() {
    let stat = b"1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 8675309 0 0";
    assert_eq!(parse_ppid(stat), Some(1));
}

#[test]
fn parses_ppid_with_comm_containing_parens_and_spaces() {
    // comm = "a) b" — embedded ')' and space; ppid (field 4) must still be 7.
    let stat = b"9 (a) b) R 7 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 0 0";
    assert_eq!(parse_ppid(stat), Some(7));
}

#[test]
fn ppid_rejects_truncated_stat() {
    let stat = b"1 (init) S"; // no ppid token after the state
    assert_eq!(parse_ppid(stat), None);
}

/// Field 5 is the process-group id. Offsets are anchored on the last ')', so a
/// comm containing spaces and parens must not shift the answer.
#[test]
fn parse_pgrp_reads_field_five() {
    // pid 1234, comm "sh", state S, ppid 1, pgrp 4321, session 4321, ...
    let stat = b"1234 (sh) S 1 4321 4321 0 -1 4194304 100 0 0 0 1 2 3 4 20 0 1 0 987 0 0";
    assert_eq!(parse_pgrp(stat), Some(4321));
}

#[test]
fn parse_pgrp_survives_a_hostile_comm() {
    let stat = b"1234 (evil ) S 9 9 9) S 1 4321 4321 0 -1 4194304 100 0 0 0 1 2 3 4 20 0 1 0 987 0 0";
    assert_eq!(parse_pgrp(stat), Some(4321));
}

#[test]
fn parse_pgrp_rejects_a_truncated_record() {
    assert_eq!(parse_pgrp(b"1234 (sh) S 1"), None);
    assert_eq!(parse_pgrp(b"no parens here"), None);
}

#[test]
fn detects_zombie_state() {
    let stat = b"9 (gone) Z 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0";
    assert_eq!(parse_state(stat), Some(b'Z'));
}

#[test]
fn rejects_truncated_stat() {
    let stat = b"1 (init) S 0 1 1"; // far fewer than 22 fields
    assert_eq!(parse_starttime_jiffies(stat), None);
    assert_eq!(parse_state(stat), Some(b'S')); // state still readable here
}

#[test]
fn rejects_missing_close_paren() {
    let stat = b"1 (init S 0 1";
    assert_eq!(parse_starttime_jiffies(stat), None);
    assert_eq!(parse_state(stat), None);
}

// running_from_stat =====

// Fixture: state at index 0 after last ')', starttime (field 22, index 19) = 8675309.
// "pid (comm) STATE ppid pgroup session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice numthreads itrealvalue starttime ..."
fn stat_fixture(state: &str, starttime: u64) -> Vec<u8> {
    format!("1234 (myproc) {state} 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {starttime} 0 0").into_bytes()
}

#[test]
fn running_from_stat_running_state_matching_token() {
    let stat = stat_fixture("R", 8675309);
    assert_eq!(running_from_stat(&stat, tok(8675309)), Liveness::Alive);
}

#[test]
fn running_from_stat_sleeping_state_matching_token() {
    let stat = stat_fixture("S", 8675309);
    assert_eq!(running_from_stat(&stat, tok(8675309)), Liveness::Alive);
}

#[test]
fn running_from_stat_zombie_is_dead() {
    let stat = stat_fixture("Z", 8675309);
    assert_eq!(running_from_stat(&stat, tok(8675309)), Liveness::Dead);
}

#[test]
fn running_from_stat_dead_uppercase_is_dead() {
    let stat = stat_fixture("X", 8675309);
    assert_eq!(running_from_stat(&stat, tok(8675309)), Liveness::Dead);
}

#[test]
fn running_from_stat_dead_lowercase_is_dead() {
    let stat = stat_fixture("x", 8675309);
    assert_eq!(running_from_stat(&stat, tok(8675309)), Liveness::Dead);
}

#[test]
fn running_from_stat_token_mismatch_is_dead() {
    let stat = stat_fixture("R", 8675309);
    assert_eq!(running_from_stat(&stat, tok(9999999)), Liveness::Dead);
}

#[test]
fn running_from_stat_unparseable_record_is_unknown() {
    // We read the file, so the process is there — we just could not read its state.
    // Distinct from a token mismatch, which positively identifies a stranger.
    assert_eq!(running_from_stat(b"not a stat line at all", tok(1)), Liveness::Unknown);
}
