//! Unit tests for [`super::setuid::check_helper`]: each panic that stops a misprovisioned lane.

use super::setuid::{check_helper, stat, Meta};
use std::ffi::OsString;
use std::path::Path;

// Selection only: `SKULD_LABELS=setuid` selects this module wholesale.
skuld::default_labels!(crate::test_harness::SETUID);

const SETUID_ROOT: Meta = Meta {
    uid: 0,
    mode: 0o104755,
    is_file: true,
};

fn stat_of(meta: Meta) -> impl FnOnce(&Path) -> std::io::Result<Meta> {
    move |_| Ok(meta)
}

fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(f).expect_err("expected a panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .expect("a string panic message")
}

#[skuld::test]
fn setuid_check_helper_accepts_a_setuid_root_file_and_an_unprivileged_caller() {
    let path = check_helper(Some("/h".into()), stat_of(SETUID_ROOT), 1000);
    assert_eq!(path, Path::new("/h"));
}

#[skuld::test]
fn setuid_check_helper_panics_naming_the_variable_when_it_is_unset() {
    let msg = panic_message(|| {
        check_helper(None, stat_of(SETUID_ROOT), 1000);
    });
    assert!(msg.contains("COSCA_TEST_SETUID_HELPER is not set"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_panics_when_the_file_is_unreadable() {
    let msg = panic_message(|| {
        check_helper(
            Some("/nope".into()),
            |_| Err(std::io::Error::from_raw_os_error(2)),
            1000,
        );
    });
    assert!(msg.contains("/nope") && msg.contains("unreadable"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_panics_when_the_path_is_not_a_regular_file() {
    let dir = Meta {
        is_file: false,
        ..SETUID_ROOT
    };
    let msg = panic_message(|| {
        check_helper(Some("/d".into()), stat_of(dir), 1000);
    });
    assert!(msg.contains("not a regular file"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_panics_unless_owned_by_root() {
    let msg = panic_message(|| {
        let meta = Meta {
            uid: 1000,
            ..SETUID_ROOT
        };
        check_helper(Some("/h".into()), stat_of(meta), 1000);
    });
    assert!(msg.contains("owned by root") && msg.contains("owner uid 1000"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_panics_without_the_set_user_id_bit() {
    let msg = panic_message(|| {
        let meta = Meta {
            mode: 0o100755,
            ..SETUID_ROOT
        };
        check_helper(Some("/h".into()), stat_of(meta), 1000);
    });
    assert!(msg.contains("set-user-ID bit") && msg.contains("mode 755"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_panics_for_a_root_caller() {
    let msg = panic_message(|| {
        check_helper(Some("/h".into()), stat_of(SETUID_ROOT), 0);
    });
    assert!(msg.contains("the caller is root"), "{msg}");
}

#[skuld::test]
fn setuid_check_helper_rejects_real_paths_that_are_not_a_setuid_root_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain");
    std::fs::write(&file, "x").unwrap();
    let cases = [
        (file, "set-user-ID bit"),
        (dir.path().to_owned(), "not a regular file"),
        (dir.path().join("missing"), "unreadable"),
    ];
    for (path, reason) in cases {
        let shown = path.clone();
        let msg = panic_message(move || {
            check_helper(Some(OsString::from(path)), stat, 1000);
        });
        assert!(
            msg.contains(reason) && msg.contains(&shown.display().to_string()),
            "{shown:?}: {msg}"
        );
    }
}
