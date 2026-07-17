//! Pins the mark/contains_since staleness contract: a record emitted BEFORE a mark
//! must never satisfy a post-mark scan (the false-pass class under pid-reused markers).

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
