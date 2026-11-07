//! A real console program on a child pipe `make_pipe` made, the parent end taken by tokio.
#![cfg(windows)]

use tokio::io::AsyncReadExt;

use crate::child::ParentEnd;
use crate::stdio::Direction;

// A synchronous end would block the reactor's thread, so a std-built end is refused, never wrapped.
// Neither call needs a runtime: the refusal comes before the registration.
#[skuld::test]
fn adopting_a_std_built_end_is_invalid_input() {
    let (r, w) = std::io::pipe().expect("pipe");
    let e = super::register_reader(crate::PipeReader::from(r)).expect_err("a std read end is synchronous");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    let e = super::register_writer(crate::PipeWriter::from(w)).expect_err("a std write end is synchronous");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
}

// A child writes on its end; the parent's end, registered with the reactor, reads to EOF.
#[skuld::test]
async fn an_adopted_read_end_reads_a_real_childs_output() {
    let (child_end, parent) = crate::child::spawn::make_pipe(Direction::Out).expect("pipe");
    let ParentEnd::Reader(reader) = parent else {
        panic!("an Out pipe keeps the read end")
    };
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "echo overlapped-e2e"])
            .stdout(std::process::Stdio::from(child_end)),
    )
    .expect("spawn writer child");
    let mut reader = super::register_reader(reader).expect("tokio takes the end");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read to EOF");
    child.wait().expect("reap");
    assert_eq!(String::from_utf8_lossy(&buf).trim(), "overlapped-e2e");
}

// The parent writes on its end; the child's end is a real child's stdin (`findstr "^"` echoes every
// line). Dropping the parent's end delivers the buffered payload, then EOF. The child's stdout is
// read through `spawn_blocking` so the runtime keeps turning.
#[skuld::test]
async fn an_adopted_write_end_feeds_a_real_childs_input() {
    use tokio::io::AsyncWriteExt;
    let (child_end, parent) = crate::child::spawn::make_pipe(Direction::In).expect("pipe");
    let ParentEnd::Writer(writer) = parent else {
        panic!("an In pipe keeps the write end")
    };
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("findstr")
            .arg("^")
            .stdin(std::process::Stdio::from(child_end))
            .stdout(std::process::Stdio::piped()),
    )
    .expect("spawn reader child");
    let mut writer = super::register_writer(writer).expect("tokio takes the end");
    writer.write_all(b"in-e2e\r\n").await.expect("write");
    drop(writer);
    let mut stdout = child.stdout.take().expect("piped stdout");
    let out = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut s = String::new();
        stdout.read_to_string(&mut s).expect("read child stdout");
        s
    })
    .await
    .expect("join");
    child.wait().expect("reap");
    assert_eq!(out.trim(), "in-e2e");
}
