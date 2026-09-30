//! L1: which kernel, and does a pidfd sit on pidfs?

use std::process::{Command, Stdio};

use super::KillOnDrop;

const PID_FS_MAGIC: i64 = 0x5049_4446;
const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;

struct Pidfd {
    fd: i32,
}

impl Drop for Pidfd {
    fn drop(&mut self) {
        // SAFETY: `fd` is owned by this value.
        unsafe { libc::close(self.fd) };
    }
}

fn pidfd_open(pid: u32) -> Result<Pidfd, std::io::Error> {
    // SAFETY: plain syscall with integer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(Pidfd { fd: fd as i32 })
    }
}

fn f_type(p: &Pidfd) -> i64 {
    // SAFETY: zeroed `statfs` is a valid out-parameter.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatfs(p.fd, &mut s) };
    assert_eq!(r, 0, "fstatfs: {}", std::io::Error::last_os_error());
    s.f_type as i64
}

fn st_ino(p: &Pidfd) -> u64 {
    // SAFETY: zeroed `stat` is a valid out-parameter.
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstat(p.fd, &mut s) };
    assert_eq!(r, 0, "fstat: {}", std::io::Error::last_os_error());
    s.st_ino as u64
}

#[test]
fn d0_l1_pidfs() {
    // SAFETY: zeroed `utsname` is a valid out-parameter.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut u) }, 0);
    let field = |s: &[libc::c_char]| {
        let bytes: Vec<u8> = s.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    d0!("L1", "uname_r={}", field(&u.release));
    d0!("L1", "uname_m={}", field(&u.machine));
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let pretty = os_release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .unwrap_or("<none>");
    d0!("L1", "os_release={pretty}");

    let child = KillOnDrop(
        Command::new("sleep")
            .arg("1000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep"),
    );
    let child2 = KillOnDrop(
        Command::new("sleep")
            .arg("1000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep"),
    );

    let me = pidfd_open(std::process::id()).expect("pidfd_open(self)");
    let a = pidfd_open(child.0.id()).expect("pidfd_open(child)");
    let a2 = pidfd_open(child.0.id()).expect("pidfd_open(child) again");
    let b = pidfd_open(child2.0.id()).expect("pidfd_open(child2)");

    let ft = f_type(&a);
    let kind = match ft {
        PID_FS_MAGIC => "pidfs",
        ANON_INODE_FS_MAGIC => "anon_inode",
        _ => "other",
    };
    d0!("L1", "f_type={ft:#x}");
    d0!("L1", "fs_kind={kind}");
    d0!("L1", "f_type_self={:#x}", f_type(&me));
    d0!("L1", "ino_self={}", st_ino(&me));
    d0!("L1", "ino_child={}", st_ino(&a));
    d0!("L1", "ino_child_again={}", st_ino(&a2));
    d0!("L1", "ino_child2={}", st_ino(&b));
    d0!("L1", "inos_distinct_across_processes={}", st_ino(&a) != st_ino(&b) && st_ino(&a) != st_ino(&me));
    d0!("L1", "ino_stable_for_one_process={}", st_ino(&a) == st_ino(&a2));
}
