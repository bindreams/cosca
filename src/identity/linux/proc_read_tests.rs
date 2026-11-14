use std::io;

use super::{collect_pids, read_own, OwnUnreadable, ProcDir, ReadFailure};
use crate::identity::{FakeKernel, HostKernel, Kernel};

/// What a failed read of an own file is, by the call that failed and its errno: the `openat2`'s
/// errno in the refusal table is a refusal, with no `self/stat` re-check (the kernel hides no own file
/// from its reader, so a `FakeKernel` with no `self/stat` row panics on one); every other failure is
/// the file's own, `ENOENT` and `ESRCH` included (an own file is neither hidden nor exited) and any
/// `read(2)` errno whatever it is.
///
/// Mutant: a `read(2)` errno is read as the `openat2`'s; `EPERM` asks a re-check; an own file's
/// `ENOENT` or `ESRCH` is a skip; a failure's errno is not its own.
#[skuld::test]
fn a_failed_read_of_an_own_file_is_what_its_call_and_errno_say() {
    #[derive(Clone, Copy)]
    enum Call {
        Open,
        Read,
    }
    use Call::{Open, Read};

    let dir = HostKernel.open_proc().expect("/proc opens");
    let rows = [
        (Open, libc::ENOSYS, true),
        (Open, libc::EPERM, true),
        (Open, libc::ENODEV, true),
        (Open, libc::EACCES, false),
        (Open, libc::EIO, false),
        (Open, libc::ENOENT, false),
        (Open, libc::ESRCH, false),
        (Open, libc::EXDEV, false),
        (Read, libc::ENOSYS, false),
        (Read, libc::EPERM, false),
        (Read, libc::ENODEV, false),
        (Read, libc::EIO, false),
        (Read, libc::ESRCH, false),
    ];
    for (call, errno, refused) in rows {
        let kernel = match call {
            Open => FakeKernel::new().on_read("self/status", Err(errno)),
            Read => FakeKernel::new().on_read_failing_after_open("self/status", errno),
        };
        let name = format!("{} {errno}", if matches!(call, Open) { "openat2" } else { "read(2)" });
        match read_own(&kernel, &dir, "self/status") {
            Err(OwnUnreadable::Refused(refusal)) => {
                assert!(refused, "{name}: is no refusal");
                assert_eq!(crate::error::first_os_code(&refusal.cause()), Some(errno), "{name}");
                assert!(refusal.requirement().contains("requires openat2"), "{name}");
            }
            Err(OwnUnreadable::Failed(e)) => {
                assert!(!refused, "{name}: is a refusal");
                assert_eq!(e.raw_os_error(), Some(errno), "{name}");
            }
            Ok(_) => panic!("{name}: the read has no row to succeed by"),
        }
    }
}

// Checked /proc dirfd =====

#[skuld::test]
fn the_proc_dir_reads_a_file_beneath_it() {
    let status = ProcDir::open()
        .expect("/proc opens")
        .read("thread-self/status")
        .expect("read");
    let status = String::from_utf8(status).expect("UTF-8");
    assert!(status.contains("Name:"), "{status}");
}

/// A path that leaves the directory it is opened under is refused, by the `openat2`. Mutant: "plain
/// `openat` without `RESOLVE_BENEATH`" — `..` reaches `/`.
#[skuld::test]
fn the_proc_dir_refuses_a_path_that_climbs_out_of_it() {
    let dir = ProcDir::open().expect("/proc opens");
    let Err(ReadFailure::Open(err)) = dir.read("../etc/passwd") else {
        panic!("must not leave /proc");
    };
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// An absolute path names another tree entirely. Mutant: "no `RESOLVE_BENEATH`" — the path
/// resolves from the root, and `NO_XDEV` alone allows it (the root filesystem is one mount).
#[skuld::test]
fn the_proc_dir_refuses_an_absolute_path() {
    let dir = ProcDir::open().expect("/proc opens");
    let Err(ReadFailure::Open(err)) = dir.read("/etc/passwd") else {
        panic!("must not leave /proc");
    };
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// A magic link (`self/exe`, `self/fd/N`) jumps out of the tree, so it is refused. Mutant:
/// "no `RESOLVE_NO_MAGICLINKS`".
#[skuld::test]
fn the_proc_dir_refuses_a_magic_link() {
    let dir = ProcDir::open().expect("/proc opens");
    let Err(ReadFailure::Open(err)) = dir.read("self/exe") else {
        panic!("a magic link must not be followed");
    };
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");
}

/// A file that opens and then fails `read(2)` is a failure of the read, not of the `openat2`: a
/// directory opens, and reading it is `EISDIR`. Mutant: "every failure is the `openat2`'s".
#[skuld::test]
fn the_proc_dir_says_a_failed_read_is_the_reads() {
    let dir = ProcDir::open().expect("/proc opens");
    let Err(ReadFailure::Read(err)) = dir.read("self/task") else {
        panic!("a directory opens and cannot be read");
    };
    assert_eq!(err.raw_os_error(), Some(libc::EISDIR), "{err}");
}

/// A link read says which call failed, as a file read does: a path the `openat2` refuses is `Open`
/// (`EXDEV`), and a path that opens but is no link fails `readlinkat` (`ENOENT`, which is what the
/// kernel answers a `readlinkat` of an empty path on a file that is no link). Mutant: "every failure
/// of `read_link` is the `openat2`'s".
#[skuld::test]
fn the_proc_dir_says_a_failed_link_read_is_the_reads() {
    let dir = ProcDir::open().expect("/proc opens");
    let Err(ReadFailure::Open(err)) = dir.read_link("../etc/passwd") else {
        panic!("must not leave /proc");
    };
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
    let Err(ReadFailure::Read(err)) = dir.read_link("self/status") else {
        panic!("a file opens and is no link");
    };
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err}");
}

/// The real links through the real `/proc` read as pid namespace links.
#[skuld::test]
fn this_threads_own_namespace_link_reads_through_the_proc_dir() {
    let dir = ProcDir::open().expect("/proc opens");
    let own = dir.read_link("thread-self/ns/pid").expect("read own link");
    assert!(own.starts_with(b"pid:["), "{:?}", String::from_utf8_lossy(&own));
}

// Listing =====

/// The real `/proc` holds `self`, `thread-self`, `net`, `sys`, ...; listing it must skip them, not
/// fail on them. Mutant: "every entry is a pid" — the first non-numeric name aborts the listing.
#[skuld::test]
fn pids_lists_the_numeric_entries_including_this_process() {
    let pids = ProcDir::open().expect("/proc opens").pids().expect("list");
    assert!(pids.contains(&std::process::id()), "{pids:?}");
}

fn names(list: &[&[u8]]) -> Vec<io::Result<Vec<u8>>> {
    list.iter().map(|n| Ok(n.to_vec())).collect()
}

/// Non-pid names are excluded, not errors. Mutant: "keep every name that parses" / "abort on the
/// first name that is not a pid".
#[skuld::test]
fn collect_pids_excludes_names_that_are_not_pids() {
    let listed: &[&[u8]] = &[
        b"1",
        b"self",
        b"thread-self",
        b"net",
        b"sys",
        b"",
        b"+5",
        b"-5",
        b"1a",
        b" 7",
        b"\xff\xfe",
        b"4194304",
    ];
    assert_eq!(collect_pids(names(listed)).expect("list"), vec![1, 4_194_304]);
}

/// An all-digit name that is no `u32` is a corrupt listing, never a member dropped in silence.
/// Mutant: "`.parse().ok()` drops it".
#[skuld::test]
fn collect_pids_is_an_error_for_an_all_digit_name_that_overflows() {
    for name in [&b"4294967296"[..], b"99999999999999999999"] {
        let err = collect_pids(names(&[b"1", name])).expect_err("a corrupt listing is an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains(std::str::from_utf8(name).unwrap()), "{err}");
        let cause = crate::error::chain(&err).last().expect("a chain").to_string();
        assert_eq!(cause, "number too large to fit in target type", "{err}");
        assert_eq!(crate::error::chain(&err).count(), 2, "{err}");
    }
}

/// A listing failure part-way is the listing's failure, not a shorter list.
#[skuld::test]
fn collect_pids_propagates_a_listing_error() {
    let items = vec![Ok(b"1".to_vec()), Err(io::Error::from_raw_os_error(libc::EIO))];
    let err = collect_pids(items).expect_err("listing error");
    assert_eq!(err.raw_os_error(), Some(libc::EIO));
}
