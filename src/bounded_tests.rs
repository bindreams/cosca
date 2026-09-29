use super::assert_may_block;
#[cfg(debug_assertions)]
use super::Section;

#[test]
fn outside_a_section_a_wait_is_allowed() {
    assert_may_block("a test wait");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a test wait would block inside an async Drop")]
fn inside_a_section_a_wait_panics_in_debug() {
    let _section = Section::enter();
    assert_may_block("a test wait");
}

#[cfg(debug_assertions)]
#[test]
fn a_section_ends_when_dropped_and_nests() {
    let outer = Section::enter();
    let inner = Section::enter();
    drop(inner);
    assert!(
        std::panic::catch_unwind(|| assert_may_block("outer")).is_err(),
        "the outer section still covers this thread"
    );
    drop(outer);
    assert_may_block("after both");
}

#[cfg(debug_assertions)]
#[test]
fn a_section_is_per_thread() {
    let _section = Section::enter();
    std::thread::spawn(|| assert_may_block("another thread"))
        .join()
        .expect("a thread outside the section may block");
}
