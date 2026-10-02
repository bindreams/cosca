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

/// What a chrooting fixture leaves behind when it bound the DB directory into `root`: the
/// mount point's directory chain, empty once its mount namespace is gone.
fn make_mount_point_chain(s: &ChrootScratch) -> PathBuf {
    let inside = s.root().join(s.db_dir().strip_prefix("/").unwrap());
    std::fs::create_dir_all(&inside).unwrap();
    inside
}

#[test]
fn finish_removes_the_db_mount_point_chain_and_the_db_directory() {
    let s = ChrootScratch::new();
    let db = s.db_dir().to_owned();
    make_mount_point_chain(&s);
    let scratch = s.scratch().to_owned();
    s.finish().expect("an empty mount point chain is removable");
    assert!(!scratch.exists());
    assert!(!db.exists(), "the DB directory outlived the scratch");
}

#[test]
fn a_file_left_in_the_db_mount_point_chain_fails_finish_and_stays() {
    let s = ChrootScratch::new();
    let inside = make_mount_point_chain(&s);
    let stray = inside.parent().unwrap().join("stray");
    std::fs::write(&stray, b"x").unwrap();
    let scratch = s.scratch().to_owned();
    let root = s.root().to_owned();
    let err = s.finish().unwrap_err();
    assert!(err.contains("stray"), "{err}");
    assert!(stray.is_file(), "evidence must survive");
    // Non-recursive removal left everything above the stray file.
    std::fs::remove_file(&stray).unwrap();
    std::fs::remove_dir(stray.parent().unwrap()).unwrap();
    std::fs::remove_dir(&root).unwrap();
    std::fs::remove_dir(&scratch).unwrap();
}

#[test]
fn the_db_directory_is_directly_under_tmp() {
    let s = ChrootScratch::new();
    assert_eq!(s.db_dir().parent(), Some(Path::new("/tmp")));
    s.finish().unwrap();
}
