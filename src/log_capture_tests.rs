//! Pins the mark/contains_since staleness contract: a record emitted BEFORE a mark
//! must never satisfy a post-mark scan (the false-pass class under pid-reused markers).

/// `levels_since` reports each matching record's own level, in emission order — the fact a
/// "this must not be narrated at `warn`" assertion rests on.
#[test]
fn levels_since_reports_each_matching_records_level() {
    super::install();
    let mark = super::mark();
    log::debug!("log_capture level-probe 91c7");
    log::warn!("log_capture level-probe 91c7");
    log::warn!("log_capture unrelated-probe 91c7");
    assert_eq!(
        super::levels_since(mark, "log_capture level-probe 91c7"),
        vec![log::Level::Debug, log::Level::Warn],
        "levels come back in emission order, and only for matching records"
    );
}

#[test]
fn pre_mark_records_never_satisfy_a_post_mark_scan() {
    super::install();
    log::warn!("log_capture stale-probe 5f21");
    let mark = super::mark();
    assert!(
        !super::contains_since(mark, "log_capture stale-probe 5f21"),
        "a record emitted before the mark must be invisible to contains_since"
    );
    log::warn!("log_capture fresh-probe 5f21");
    assert!(
        super::contains_since(mark, "log_capture fresh-probe 5f21"),
        "a record emitted after the mark must be found"
    );
}
