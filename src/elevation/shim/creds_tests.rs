use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;

use super::{peer_credentials, recv_with_credentials, send_with_credentials, set_passcred, Creds, Received};

#[skuld::test]
fn explicit_credentials_arrive_with_the_byte() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    set_passcred(receiver.as_fd()).unwrap();
    let own = Creds::own_effective();
    send_with_credentials(sender.as_fd(), b'A', own).unwrap();
    assert_eq!(
        recv_with_credentials(receiver.as_fd()).unwrap(),
        Received::Byte(b'A', Some(own))
    );
}

#[skuld::test]
fn a_plain_send_arrives_with_the_senders_real_credentials() {
    use std::io::Write;
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    set_passcred(receiver.as_fd()).unwrap();
    sender.write_all(b"N").unwrap();
    // SAFETY: these calls have no preconditions and cannot fail.
    let real = unsafe { (libc::getpid(), libc::getuid(), libc::getgid()) };
    assert_eq!(
        recv_with_credentials(receiver.as_fd()).unwrap(),
        Received::Byte(
            b'N',
            Some(Creds {
                pid: real.0,
                uid: real.1,
                gid: real.2
            })
        )
    );
}

#[skuld::test]
fn the_credentials_are_the_senders_not_the_receivers() {
    // A process other than the receiver writes: the pid that arrives is its own.
    let (sender, receiver) = UnixStream::pair().unwrap();
    set_passcred(receiver.as_fd()).unwrap();
    let mut command = std::process::Command::new("sh");
    command.args(["-c", "printf N"]).stdout(OwnedFd::from(sender));
    let mut child = crate::test_spawn::spawn(&mut command).expect("the sender starts");
    let pid = child.id() as i32;
    let Received::Byte(b'N', Some(creds)) = recv_with_credentials(receiver.as_fd()).unwrap() else {
        panic!("a byte with credentials");
    };
    child.wait().unwrap();
    assert_ne!(pid, std::process::id() as i32);
    // SAFETY: these calls have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    assert_eq!(creds, Creds { pid, uid, gid });
}

/// Runs `body` on a thread that has given up every capability, as an unprivileged sender has none.
/// Capabilities belong to a thread, and the kernel checks the ones the sending thread holds.
fn without_capabilities<T: Send>(body: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let none = rustix::thread::CapabilitySets {
                    effective: rustix::thread::CapabilitySet::empty(),
                    permitted: rustix::thread::CapabilitySet::empty(),
                    inheritable: rustix::thread::CapabilitySet::empty(),
                };
                rustix::thread::set_capabilities(None, none).expect("a thread may always shed its capabilities");
                body()
            })
            .join()
            .expect("the sender thread")
    })
}

#[skuld::test]
fn the_kernel_refuses_credentials_that_are_not_the_senders() {
    let own = Creds::own_effective();
    let attempt = |creds: Creds| {
        let (sender, receiver) = UnixStream::pair().unwrap();
        set_passcred(receiver.as_fd()).unwrap();
        let sent = without_capabilities(|| send_with_credentials(sender.as_fd(), b'A', creds));
        (sent, receiver)
    };
    // The control: with its own credentials, the same thread without capabilities can send.
    let (sent, receiver) = attempt(own);
    sent.expect("a sender may name its own credentials");
    assert_eq!(
        recv_with_credentials(receiver.as_fd()).unwrap(),
        Received::Byte(b'A', Some(own))
    );
    // Another process's pid, or another user or group: refused with `EPERM` by the kernel.
    let others = [
        Creds {
            pid: own.pid.wrapping_add(1),
            ..own
        },
        Creds {
            uid: own.uid.wrapping_add(1),
            ..own
        },
        Creds {
            gid: own.gid.wrapping_add(1),
            ..own
        },
    ];
    for creds in others {
        let (sent, _receiver) = attempt(creds);
        let error = sent.expect_err("the kernel refuses credentials that are not the sender's");
        assert_eq!(error.raw_os_error(), Some(libc::EPERM), "{creds:?}");
    }
}

#[skuld::test]
fn eof_is_eof() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    set_passcred(receiver.as_fd()).unwrap();
    drop(sender);
    assert_eq!(recv_with_credentials(receiver.as_fd()).unwrap(), Received::Eof);
}

#[skuld::test]
fn peer_credentials_name_the_process_that_made_the_pair() {
    let (a, _b) = UnixStream::pair().unwrap();
    assert_eq!(peer_credentials(a.as_fd()).unwrap(), Creds::own_effective());
}
