use super::{describe_remove_failure, ChrootScratch};
use std::io;
use std::path::{Path, PathBuf};

fn os(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

#[test]
fn a_not_empty_root_names_the_entries_left_inside() {
    let inside = Ok(vec![Ok(PathBuf::from("/r/a")), Err(os(libc::EIO))]);
    let msg = describe_remove_failure(Path::new("/r"), &os(libc::ENOTEMPTY), inside);
    assert!(
        msg.contains("left [\"/r/a\", <entry error:") && msg.contains("inside it"),
        "{msg}"
    );
}

#[test]
fn an_unlistable_root_prints_the_listing_error() {
    let msg = describe_remove_failure(Path::new("/r"), &os(libc::ENOTEMPTY), Err(os(libc::EACCES)));
    assert!(msg.contains("listing it failed:"), "{msg}");
}

#[test]
fn another_error_names_its_errno_and_claims_no_leftovers() {
    let msg = describe_remove_failure(Path::new("/r"), &os(libc::EBUSY), Ok(vec![]));
    assert!(msg.contains(&format!("errno Some({})", libc::EBUSY)), "{msg}");
    assert!(!msg.contains("left"), "{msg}");
}

#[test]
fn an_untouched_scratch_finishes_and_is_removed() {
    let s = ChrootScratch::new();
    let scratch = s.scratch().to_owned();
    s.finish().expect("an empty scratch is removable");
    assert!(!scratch.exists());
}

#[test]
fn something_left_in_scratch_fails_finish_and_stays() {
    let s = ChrootScratch::new();
    let stray = s.scratch().join("stray");
    std::fs::create_dir(&stray).unwrap();
    let scratch = s.scratch().to_owned();
    let err = s.finish().unwrap_err();
    assert!(err.contains("stray"), "{err}");
    assert!(stray.is_dir(), "evidence must survive");
    std::fs::remove_dir(&stray).unwrap();
    std::fs::remove_dir(&scratch).unwrap();
}
