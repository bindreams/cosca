//! Windows: the parent ends the async spawn keeps for its accessors are overlapped, as std's kind of
//! child pipe is (the sync spawn's rows are in `child::spawn_tests`). Read before any accessor
//! takes them: the raw backend's std slots and fd >= 3, and a std-path merge target. The std
//! path's other piped slots are tokio's own.

use std::os::windows::io::AsHandle as _;

use crate::pipe::windows::is_overlapped;
use crate::pipe::ParentEnd;
use crate::stdio::{Direction, Fd, Stdio};
use crate::test_child::Console;

fn overlapped(end: &ParentEnd) -> bool {
    is_overlapped(end.as_handle()).expect("query the mode")
}

/// Mutant: the raw backend or the merge pre-pass makes its pipe with `std::io::pipe`.
#[skuld::test]
async fn the_async_spawns_parent_ends_are_overlapped() {
    // (row, pipes by slot, merge slot and target)
    type Row<'a> = (&'a str, &'a [(i32, Direction)], Option<(i32, i32)>);
    let rows: [Row; 2] = [
        (
            "raw backend",
            &[
                (0, Direction::In),
                (1, Direction::Out),
                (2, Direction::Out),
                (3, Direction::Out),
                (4, Direction::In),
            ],
            None,
        ),
        ("merge target", &[(1, Direction::Out)], Some((2, 1))),
    ];
    for (row, pipes, merge) in rows {
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(["cmd", "/C", "exit 0"]);
        for &(slot, dir) in pipes {
            cmd.fd(
                slot,
                match dir {
                    Direction::In => Stdio::pipe_in(),
                    Direction::Out => Stdio::pipe_out(),
                },
            )
            .expect("set the pipe");
        }
        if let Some((slot, target)) = merge {
            cmd.fd(slot, Stdio::merge(Fd::from(target))).expect("set the merge");
        }
        let mut child = cmd.spawn().expect("spawn");

        let kept: Vec<(Fd, &ParentEnd)> = child
            .os
            .owned_std
            .iter()
            .chain(&child.os.pipes)
            .map(|(fd, end)| (*fd, end))
            .collect();
        let mut slots: Vec<i32> = kept.iter().map(|(fd, _)| fd.raw()).collect();
        slots.sort_unstable();
        let mut expected: Vec<i32> = pipes.iter().map(|&(slot, _)| slot).collect();
        expected.sort_unstable();
        assert_eq!(slots, expected, "{row}: the spawn keeps these parent ends");
        for (fd, end) in kept {
            assert!(overlapped(end), "{row}: the parent's end for {fd} is synchronous");
        }
        child.wait().await.expect("reap");
    }
}
