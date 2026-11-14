//! A process whose leader thread has exited while another thread runs (a real one, from
//! [`zombie_leader_root`](crate::test_child::zombie_leader_root)): the kernel shows its leader as a
//! zombie, and the process has not exited. Linux only.

use std::io::BufRead as _;
use std::process::Stdio;

use crate::identity::stat_parse::{parse_num_threads, parse_starttime_jiffies, parse_state};
use crate::identity::{Key, Liveness, ProcessId};
use crate::Recursive;

/// The process is alive, and a child its leader thread forked keeps the process's number as its parent's,
/// which the tree walk reads: the kernel hands the child to the thread that runs, not to init.
///
/// Mutants: a `Z` record is dead whatever its thread count; the walk from such a process finds no child.
#[skuld::test]
fn a_process_whose_leader_thread_exited_is_alive_and_keeps_its_children() {
    let mut root = crate::test_spawn::spawn(
        crate::test_reexec::command(std::env::current_exe().expect("current_exe"))
            .args(crate::test_child::zombie_leader_root::argv())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .expect("spawn the root");
    let stdin = root.stdin.take().expect("piped stdin");
    let mut stdout = std::io::BufReader::new(root.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("the cat's pid");
    let cat = ProcessId::of(line.trim().parse().expect("the cat's pid"))
        .found()
        .expect("the cat's identity");
    let id = ProcessId::of(root.id()).found().expect("the root's identity");
    // The process's other thread reports that the leader began to exit: a real event, which this read
    // blocks on. The kernel marks the leader a zombie a few steps after it (the report is the exit's
    // `clear_child_tid` wake), so the `stat` is read again, with no limit, until it shows `Z`. A thread
    // pidfd of the leader does not turn readable while the process lives (measured on 6.12), so none
    // can stand in for the re-read.
    line.clear();
    stdout.read_line(&mut line).expect("the leader's exit report");
    assert_eq!(line, "exited\n");
    let stat = loop {
        let stat = std::fs::read(format!("/proc/{}/stat", root.id())).expect("the root's stat");
        if parse_state(&stat) == Some(b'Z') {
            break stat;
        }
        std::thread::yield_now();
    };
    assert!(
        parse_num_threads(&stat).is_some_and(|threads| threads > 1),
        "premise: a zombie leader whose thread runs on counts it: {}",
        String::from_utf8_lossy(&stat)
    );

    // The `/proc` read, whatever key the host gives an id (a pidfs one, on 6.9+, is read by the pidfd).
    let ticks = parse_starttime_jiffies(&stat).expect("the root's start time");
    let by_stat = ProcessId::from_parts_for_test(root.id(), Key::Ticks(ticks));
    assert_eq!(
        by_stat.is_alive(),
        Liveness::Alive,
        "the /proc read: the process has not exited"
    );
    assert_eq!(
        id.is_alive(),
        Liveness::Alive,
        "the host's own id: the process has not exited"
    );
    assert_eq!(
        id.children(Recursive::No).expect("the root's children"),
        vec![cat],
        "the cat's parent is still the root's pid"
    );

    // The thread and the cat end on the EOF, and with them the process.
    drop(stdin);
    root.wait().expect("reap the root");
}
