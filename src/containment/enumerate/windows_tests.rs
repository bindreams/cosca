//! The ToolHelp snapshot's row order, which the tree walk's anchor-row rule relies on.

use std::collections::HashMap;

use crate::identity::windows_fixture::{image_named, image_of};
use crate::identity::{HostKernel, OrderKey, ProcessId, RawPid, Resolved};

/// What reading a pid's order key gave; `Found(None)` is a key read refused after a successful open.
type KeyRead = Resolved<Option<OrderKey>>;

fn read_key(pid: RawPid) -> KeyRead {
    ProcessId::of_ordered_with(&HostKernel, pid, None, None, None)
        .0
        .map(|(_, order)| order)
}

/// The order key of each pid in `pids` that can be read now.
fn keys_of(pids: impl Iterator<Item = RawPid>) -> HashMap<RawPid, OrderKey> {
    pids.filter_map(|pid| match read_key(pid) {
        Resolved::Found(Some(order)) => Some((pid, order)),
        _ => None,
    })
    .collect()
}

fn describe_key(read: Option<KeyRead>) -> String {
    match read {
        None => "not listed".to_owned(),
        Some(Resolved::Gone) => "no such process".to_owned(),
        Some(Resolved::Unknown) => "open refused".to_owned(),
        Some(Resolved::Found(None)) => "opened, key read refused".to_owned(),
        Some(Resolved::Found(Some(order))) => format!("{order:?}"),
    }
}

/// [`process_parents`](super::process_parents) lists a process after its creator: for a row whose ppid
/// names a pid listed in the snapshot, whose holder is older than the row's process (so it is the
/// creator, not a later holder of its pid), the creator's row comes first. The tree walk's anchor rows
/// rest on it; the order between unrelated processes is pinned by
/// `the_toolhelp_snapshot_lists_unrelated_processes_in_creation_order`.
///
/// A pid counts only if it reads the same key before and after the snapshot, so a recycled pid fakes
/// no pair. The test spawns a child, so the pair of this process and its child is always among them.
/// A pair with a process the test cannot open (another account's, say) has no key to read, so it is
/// not covered.
///
/// Mutant: the rows are returned in another order (pid order, reversed).
#[skuld::test]
fn the_toolhelp_snapshot_lists_a_process_after_its_creator() {
    let (_child, _stdin, child) = crate::test_child::live_blocker();
    let before = keys_of(
        super::process_parents(&HostKernel)
            .expect("a snapshot")
            .into_iter()
            .map(|(pid, _)| pid),
    );
    let rows = super::process_parents(&HostKernel).expect("a snapshot");
    let after = keys_of(rows.iter().map(|&(pid, _)| pid));

    let stable: HashMap<RawPid, OrderKey> = rows
        .iter()
        .filter_map(|&(pid, _)| match (before.get(&pid), after.get(&pid)) {
            (Some(first), Some(second)) if first == second => Some((pid, *second)),
            _ => None,
        })
        .collect();
    let row_of: HashMap<RawPid, usize> = rows.iter().enumerate().map(|(row, &(pid, _))| (pid, row)).collect();

    let mut checked = 0;
    for (row, &(pid, creator)) in rows.iter().enumerate() {
        let (Some(created), Some(maker)) = (stable.get(&pid), stable.get(&creator)) else {
            continue;
        };
        if maker >= created {
            continue;
        }
        let creator_row = row_of[&creator];
        assert!(
            creator_row < row,
            "pid {pid} (row {row}) is listed before its creator {creator} (row {creator_row})"
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "the snapshot has no pair of creator and created to show an order"
    );
    let ours = rows
        .iter()
        .position(|&(pid, _)| pid == child.pid())
        .expect("the spawned child is listed");
    assert_eq!(
        rows[ours].1,
        std::process::id(),
        "the spawned child names this process as its creator"
    );
    assert!(
        row_of[&std::process::id()] < ours,
        "this process is listed before the child it spawned"
    );
}

/// [`process_parents`](super::process_parents) lists unrelated processes in the order they were
/// created, not only a creator before what it created: A is spawned, then B, then A spawns A1, so
/// A1's row follows B's though A1 is A's child. A listing in pre-order by creator (A, A1, B) keeps
/// every creator before its created and fails here. The tree walk's anchor rows rest on this order.
///
/// A1 is created only after the test wrote A's go-ahead, which it does after B was spawned; the test
/// reads A1's "ready" line before it looks, so A1 is listed by then.
///
/// A1 is not every row naming A's pid: A's hidden-console host is created a few ms after A
/// (measured) and can be listed before B, and a row can name A's pid because its creator died and A
/// took the pid. A1 is the row naming A that runs `cmd.exe`, is younger than A, and has the same order
/// key at the first key read (taken after the earlier snapshot) and after the image read, so one
/// process held the pid from the first key read through the image read.
///
/// Mutant: the rows are returned in pre-order by creator.
#[skuld::test]
fn the_toolhelp_snapshot_lists_unrelated_processes_in_creation_order() {
    use std::io::{BufRead as _, BufReader, Write as _};

    // A reads one line from its stdin, then runs A1, which reports "ready" and blocks on the rest
    // of the stdin until it is closed.
    let dir = tempfile::tempdir().expect("a temp dir");
    let script = dir.path().join("a.bat");
    std::fs::write(&script, "@echo off\r\nset /p go=\r\ncmd /C \"echo ready&more\"\r\n").expect("write a.bat");
    let mut a = crate::test_child::StdChild::spawn(
        std::process::Command::new("cmd")
            .arg("/C")
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()),
    );
    let mut a_stdin = a.stdin.take().expect("A's stdin");
    let mut a_stdout = BufReader::new(a.stdout.take().expect("A's stdout"));

    let b = crate::test_child::spawn_more_blocker();

    a_stdin.write_all(b"go\r\n").expect("send A its go-ahead");
    a_stdin.flush().expect("flush A's stdin");
    let mut line = String::new();
    a_stdout.read_line(&mut line).expect("read A1's ready line");
    assert_eq!(line.trim_end(), "ready", "A1 reported");

    // A1 is alive by now, so an earlier snapshot lists it, and its pid is held until A1 ends.
    let before: HashMap<RawPid, KeyRead> = super::process_parents(&HostKernel)
        .expect("a snapshot")
        .into_iter()
        .filter(|&(_, creator)| creator == a.id())
        .map(|(pid, _)| (pid, read_key(pid)))
        .collect();
    let rows = super::process_parents(&HostKernel).expect("a snapshot");
    let row_of = |pid: RawPid| {
        rows.iter()
            .position(|&(row, _)| row == pid)
            .expect("the process is listed")
    };
    let b_row = row_of(b.id());
    let a_row = row_of(a.id());
    assert!(a_row < b_row, "A, spawned first, is listed before B");

    // Every row that names A as its creator: its image, then its key again.
    struct NamesA {
        row: usize,
        pid: RawPid,
        before: Option<KeyRead>,
        image: windows::core::Result<Option<String>>,
        after: KeyRead,
    }
    let naming_a: Vec<NamesA> = rows
        .iter()
        .enumerate()
        .filter(|&(_, &(_, creator))| creator == a.id())
        .map(|(row, &(pid, _))| {
            let image = image_of(pid);
            NamesA {
                row,
                pid,
                before: before.get(&pid).copied(),
                image,
                after: read_key(pid),
            }
        })
        .collect();
    let a_key = match read_key(a.id()) {
        Resolved::Found(Some(key)) => key,
        other => panic!("A's own order key is unreadable: {}", describe_key(Some(other))),
    };
    let listing = || {
        let mut text = format!("B is row {b_row} (pid {}); rows naming A (pid {}):", b.id(), a.id());
        for NamesA {
            row,
            pid,
            before,
            image,
            after,
        } in &naming_a
        {
            let age = match after {
                Resolved::Found(Some(order)) if *order > a_key => " (newer than A)",
                Resolved::Found(Some(_)) => " (not newer than A)",
                _ => "",
            };
            let image = match image {
                Ok(Some(image)) => format!("{image:?}"),
                Ok(None) => "none, the process exited".to_owned(),
                Err(e) => format!("unreadable: {e}"),
            };
            text.push_str(&format!(
                "\n  row {row}, pid {pid}: key in the earlier snapshot: {}; key after the image: {}{age}; image: {image}",
                describe_key(*before),
                describe_key(Some(*after)),
            ));
        }
        text
    };

    let a1_rows: Vec<(usize, RawPid)> = naming_a
        .iter()
        .filter(|named| match (&named.before, &named.after, &named.image) {
            (Some(Resolved::Found(Some(first))), Resolved::Found(Some(second)), Ok(Some(image))) => {
                first == second && *second > a_key && image_named(image, "cmd.exe")
            }
            _ => false,
        })
        .map(|named| (named.row, named.pid))
        .collect();
    assert_eq!(a1_rows.len(), 1, "A has exactly one child A1; {}", listing());
    let (a1_row, a1_pid) = a1_rows[0];
    assert!(
        b_row < a1_row,
        "B (row {b_row}, pid {}, spawned before A1) is listed after A1 (row {a1_row}, pid {a1_pid}, A's child); {}",
        b.id(),
        listing()
    );
}
