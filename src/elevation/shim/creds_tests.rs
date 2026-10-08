use std::os::fd::AsFd;
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
fn a_plain_send_arrives_with_the_implicit_credentials() {
    use std::io::Write;
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    set_passcred(receiver.as_fd()).unwrap();
    sender.write_all(b"N").unwrap();
    let Received::Byte(b'N', Some(creds)) = recv_with_credentials(receiver.as_fd()).unwrap() else {
        panic!("a byte with credentials");
    };
    assert_eq!(creds.pid, std::process::id() as i32);
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
