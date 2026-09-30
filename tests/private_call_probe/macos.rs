//! M1: `proc_pidinfo` flavor 17. M2: `kern.bootsessionuuid`. M3: `proc_signal_with_audittoken`.

use std::ffi::{c_int, c_void};
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};

use super::KillOnDrop;

// Private (bsd/sys/proc_info_private.h).
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Uniq {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_orig_ppidversion: i32,
    p_reserve2: u64,
    p_reserve3: u64,
}
const _: () = assert!(std::mem::size_of::<Uniq>() == 56);

#[repr(C)]
struct AuditToken {
    val: [u32; 8],
}

extern "C" {
    fn proc_signal_with_audittoken(audittoken: *mut AuditToken, signal: c_int) -> c_int;
}

/// `(return value, errno, struct)` of `proc_pidinfo(pid, 17, arg, ..)`.
fn flavor17(pid: u32, arg: u64) -> (i32, i32, Uniq) {
    let mut u = Uniq::default();
    // SAFETY: `u` is a live 56-byte buffer.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            PROC_PIDUNIQIDENTIFIERINFO,
            arg,
            (&mut u as *mut Uniq).cast::<c_void>(),
            std::mem::size_of::<Uniq>() as c_int,
        )
    };
    let errno = if ret <= 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    (ret, errno, u)
}

fn errname(e: i32) -> String {
    match e {
        0 => "0".into(),
        libc::ESRCH => "ESRCH".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::EPERM => "EPERM".into(),
        libc::EACCES => "EACCES".into(),
        n => format!("errno{n}"),
    }
}

fn sleeper() -> KillOnDrop {
    KillOnDrop(
        Command::new("/bin/sleep")
            .arg("1000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn /bin/sleep"),
    )
}

// kqueue -----

/// A kqueue with `EVFILT_PROC` armed on `pid`.
struct Watch(c_int);

impl Watch {
    fn new(pid: u32, fflags: u32) -> Watch {
        // SAFETY: plain syscalls; `ev` is a live kevent.
        unsafe {
            let kq = libc::kqueue();
            assert!(kq >= 0, "kqueue: {}", std::io::Error::last_os_error());
            let ev = libc::kevent {
                ident: pid as usize,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let r = libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
            assert!(r >= 0, "kevent(register): {}", std::io::Error::last_os_error());
            Watch(kq)
        }
    }

    /// Blocks until the next event and returns its `fflags`. The wait is on an external event the
    /// caller has provoked; the step's `timeout-minutes` is the failure bound.
    fn next(&self) -> u32 {
        // SAFETY: `ev` is a live out-parameter.
        unsafe {
            let mut ev: libc::kevent = std::mem::zeroed();
            let r = libc::kevent(self.0, std::ptr::null(), 0, &mut ev, 1, std::ptr::null());
            assert_eq!(r, 1, "kevent(wait): {}", std::io::Error::last_os_error());
            ev.fflags
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: the kqueue is owned by this value.
        unsafe { libc::close(self.0) };
    }
}

// M1 -----

#[test]
fn d0_m1_flavor17() {
    let me = std::process::id();
    let (ret, errno, u) = flavor17(me, 1);
    d0!("M1", "self.ret={ret} errno={} uniqueid={} idversion={}", errname(errno), u.p_uniqueid, u.p_idversion);
    assert_eq!(ret, 56);

    // A live child.
    let live = sleeper();
    let (ret, errno, u) = flavor17(live.0.id(), 1);
    d0!("M1", "live.ret={ret} errno={} uniqueid={} idversion={}", errname(errno), u.p_uniqueid, u.p_idversion);
    assert_eq!(ret, 56);
    let (ret0, errno0, _) = flavor17(live.0.id(), 0);
    d0!("M1", "live.arg0.ret={ret0} errno={}", errname(errno0));

    // A zombie: NOTE_EXIT armed first, then killed and not yet reaped.
    let mut z = sleeper();
    let zpid = z.0.id();
    let (_, _, before) = flavor17(zpid, 1);
    let w = Watch::new(zpid, libc::NOTE_EXIT);
    z.0.kill().expect("kill");
    let fflags = w.next();
    d0!("M1", "zombie.event_has_note_exit={}", fflags & libc::NOTE_EXIT != 0);
    let (ret, errno, u) = flavor17(zpid, 1);
    d0!(
        "M1",
        "zombie.arg1.ret={ret} errno={} uniqueid={} same_uniqueid_as_live_read={} idversion={}",
        errname(errno),
        u.p_uniqueid,
        u.p_uniqueid == before.p_uniqueid,
        u.p_idversion
    );
    assert_eq!(ret, 56);
    assert_eq!(u.p_uniqueid, before.p_uniqueid);
    let (ret, errno, _) = flavor17(zpid, 0);
    d0!("M1", "zombie.arg0.ret={ret} errno={} (expected 0 and ESRCH)", errname(errno));
    assert_eq!((ret, errno), (0, libc::ESRCH));
    drop(w);
    let _ = z.0.wait();

    // pid 1, unprivileged.
    let (ret, errno, u) = flavor17(1, 1);
    d0!("M1", "pid1.ret={ret} errno={} uniqueid={} idversion={}", errname(errno), u.p_uniqueid, u.p_idversion);
    assert_eq!(ret, 56);

    // 50 sequential spawns: strictly increasing.
    let mut prev = 0u64;
    let (mut first, mut last, mut increasing) = (0u64, 0u64, true);
    for i in 0..50 {
        let mut c = Command::new("/usr/bin/true").spawn().expect("spawn true");
        let (ret, _, u) = flavor17(c.id(), 1);
        assert_eq!(ret, 56);
        if i == 0 {
            first = u.p_uniqueid;
        }
        increasing &= u.p_uniqueid > prev;
        prev = u.p_uniqueid;
        last = u.p_uniqueid;
        c.wait().expect("wait");
    }
    d0!("M1", "spawns50.first={first} last={last} strictly_increasing={increasing}");
    assert!(increasing);

    // Unchanged across the child's exec.
    let mut sh = KillOnDrop(
        Command::new("/bin/sh")
            .args(["-c", "read x; exec /bin/sleep 1000"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh"),
    );
    let pid = sh.0.id();
    let (_, _, pre) = flavor17(pid, 1);
    let w = Watch::new(pid, libc::NOTE_EXEC);
    let mut stdin = sh.0.stdin.take().expect("stdin");
    stdin.write_all(b"go\n").expect("write");
    drop(stdin);
    let fflags = w.next();
    d0!("M1", "exec.event_has_note_exec={}", fflags & libc::NOTE_EXEC != 0);
    let (ret, _, post) = flavor17(pid, 1);
    d0!(
        "M1",
        "exec.ret={ret} uniqueid_before={} uniqueid_after={} unchanged={} idversion_before={} idversion_after={}",
        pre.p_uniqueid,
        post.p_uniqueid,
        pre.p_uniqueid == post.p_uniqueid,
        pre.p_idversion,
        post.p_idversion
    );
    assert_eq!(pre.p_uniqueid, post.p_uniqueid);
}

// M2 -----

fn boot_session_uuid() -> String {
    let name = c"kern.bootsessionuuid";
    let mut len: usize = 0;
    // SAFETY: size query, then a read into a buffer of that size.
    unsafe {
        let r = libc::sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0);
        assert_eq!(r, 0, "sysctlbyname(size): {}", std::io::Error::last_os_error());
        let mut buf = vec![0u8; len];
        let r = libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0);
        assert_eq!(r, 0, "sysctlbyname: {}", std::io::Error::last_os_error());
        buf.truncate(len);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).expect("utf8")
    }
}

#[test]
fn d0_m2_boot_session_uuid() {
    let a = boot_session_uuid();
    let b = boot_session_uuid();
    let shaped = a.len() == 36
        && a.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() });
    d0!("M2", "kern.bootsessionuuid={a}");
    d0!("M2", "uuid_shaped={shaped} stable_across_two_reads={}", a == b);
    assert!(shaped);
    assert_eq!(a, b);
}

// M3 -----

const READY: u8 = 1;
const GOT_TERM: u8 = 2;
const GOT_USR1: u8 = 3;

extern "C" fn on_term(_: c_int) {
    // SAFETY: `write` is async-signal-safe.
    unsafe { libc::write(2, [GOT_TERM].as_ptr().cast(), 1) };
}

extern "C" fn on_usr1(_: c_int) {
    // SAFETY: `write` is async-signal-safe.
    unsafe { libc::write(2, [GOT_USR1].as_ptr().cast(), 1) };
}

/// Role child: counts signals on stderr, execs itself again on a stdin byte.
#[test]
fn d0_role_m3_child() {
    if std::env::var("D0_ROLE").as_deref() != Ok("m3") {
        return;
    }
    // SAFETY: handlers only call `write`.
    unsafe {
        libc::signal(libc::SIGTERM, on_term as extern "C" fn(c_int) as usize);
        libc::signal(libc::SIGUSR1, on_usr1 as extern "C" fn(c_int) as usize);
        libc::write(2, [READY].as_ptr().cast(), 1);
    }
    let mut b = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut b) {
            Ok(1) => {
                let err = Command::new(std::env::current_exe().expect("exe"))
                    .args(["--exact", "macos::d0_role_m3_child", "--nocapture"])
                    .env("D0_ROLE", "m3")
                    .stdout(Stdio::null())
                    .exec();
                panic!("exec: {err}");
            }
            Ok(_) => return,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read: {e}"),
        }
    }
}

struct RoleChild {
    child: KillOnDrop,
    stdin: ChildStdin,
    stderr: ChildStderr,
}

impl RoleChild {
    fn spawn() -> RoleChild {
        let mut child: Child = Command::new(std::env::current_exe().expect("exe"))
            .args(["--exact", "macos::d0_role_m3_child", "--nocapture"])
            .env("D0_ROLE", "m3")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn role child");
        let stdin = child.stdin.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut rc = RoleChild { child: KillOnDrop(child), stdin, stderr };
        rc.read_until(READY);
        rc
    }

    /// Reads marker bytes until `until` arrives; returns the markers read before it.
    fn read_until(&mut self, until: u8) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut b = [0u8; 1];
        loop {
            self.stderr.read_exact(&mut b).expect("marker");
            if b[0] == until {
                return seen;
            }
            seen.push(b[0]);
        }
    }

    fn pid(&self) -> u32 {
        self.child.0.id()
    }
}

fn token(pid: u32, idversion: i32) -> AuditToken {
    let mut t = AuditToken { val: [0; 8] };
    t.val[5] = pid;
    t.val[7] = idversion as u32;
    t
}

/// `(return value, errno)`.
fn signal(mut t: AuditToken, sig: c_int) -> (i32, i32) {
    // SAFETY: `t` is a live audit token.
    let r = unsafe { proc_signal_with_audittoken(&mut t, sig) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    (r, e)
}

/// ESRCH by return value or by errno: the libproc wrapper's convention is one of the two.
fn is_esrch((r, e): (i32, i32)) -> bool {
    r == libc::ESRCH || (r == -1 && e == libc::ESRCH)
}

fn show((r, e): (i32, i32)) -> String {
    format!("ret={r} errno={}", errname(e))
}

#[test]
fn d0_m3_audittoken() {
    // Correct token, other fields zero: SIGTERM delivered.
    let mut c = sleeper();
    let (_, _, u) = flavor17(c.0.id(), 1);
    let r = signal(token(c.0.id(), u.p_idversion), libc::SIGTERM);
    let status = c.0.wait().expect("wait");
    d0!("M3", "correct.{} child_signal={:?}", show(r), status.signal());
    assert_eq!(r.0, 0);
    assert_eq!(status.signal(), Some(libc::SIGTERM));

    // Version +/-1: ESRCH, and no delivery. The role child counts signals, so a positive control
    // sent afterwards proves the earlier ones never arrived.
    let mut rc = RoleChild::spawn();
    let pid = rc.pid();
    let (_, _, u) = flavor17(pid, 1);
    let plus = signal(token(pid, u.p_idversion + 1), libc::SIGTERM);
    let minus = signal(token(pid, u.p_idversion - 1), libc::SIGTERM);
    d0!("M3", "version_plus1.{} version_minus1.{}", show(plus), show(minus));
    assert!(is_esrch(plus) && is_esrch(minus));

    // Signal 0 with the correct token.
    let zero = signal(token(pid, u.p_idversion), 0);
    d0!("M3", "signal0.{} (expected EINVAL)", show(zero));

    // Positive control.
    let ok = signal(token(pid, u.p_idversion), libc::SIGUSR1);
    let before_control = rc.read_until(GOT_USR1);
    d0!(
        "M3",
        "control_usr1.{} markers_before_control={:?} stale_term_delivered={}",
        show(ok),
        before_control,
        before_control.contains(&GOT_TERM)
    );
    assert_eq!(ok.0, 0);
    assert!(!before_control.contains(&GOT_TERM));
    assert!(zero.0 == libc::EINVAL || (zero.0 == -1 && zero.1 == libc::EINVAL));

    // Exec: old token refused, a fresh one delivers.
    let w = Watch::new(pid, libc::NOTE_EXEC);
    rc.stdin.write_all(b"x").expect("write");
    let fflags = w.next();
    assert!(fflags & libc::NOTE_EXEC != 0);
    rc.read_until(READY); // the new image installed its handlers
    let (_, _, after) = flavor17(pid, 1);
    d0!(
        "M3",
        "exec.uniqueid_same={} idversion_before={} idversion_after={}",
        after.p_uniqueid == u.p_uniqueid,
        u.p_idversion,
        after.p_idversion
    );
    let stale = signal(token(pid, u.p_idversion), libc::SIGTERM);
    let fresh = signal(token(pid, after.p_idversion), libc::SIGUSR1);
    let before_fresh = rc.read_until(GOT_USR1);
    d0!(
        "M3",
        "exec.stale.{} exec.fresh.{} markers_before_fresh={:?} stale_term_delivered={}",
        show(stale),
        show(fresh),
        before_fresh,
        before_fresh.contains(&GOT_TERM)
    );
    assert!(is_esrch(stale));
    assert_eq!(fresh.0, 0);
    assert!(!before_fresh.contains(&GOT_TERM));
    drop(w);
    drop(rc);

    // A zombie (NOTE_EXIT seen, not reaped): ESRCH.
    let mut z = sleeper();
    let zpid = z.0.id();
    let (_, _, zu) = flavor17(zpid, 1);
    let w = Watch::new(zpid, libc::NOTE_EXIT);
    z.0.kill().expect("kill");
    w.next();
    let zr = signal(token(zpid, zu.p_idversion), libc::SIGTERM);
    d0!("M3", "zombie.{}", show(zr));
    assert!(is_esrch(zr));
    let _ = z.0.wait();
}

// M4: flavor 13 (`PROC_PIDT_SHORTBSDINFO`) and the original parent of a traced process -----

fn flavor13(pid: u32) -> (i32, i32, libc::proc_bsdshortinfo) {
    // SAFETY: zeroed is a valid bit pattern for this plain struct.
    let mut s: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `s` is a live buffer of the size passed.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            (&mut s as *mut libc::proc_bsdshortinfo).cast::<c_void>(),
            std::mem::size_of::<libc::proc_bsdshortinfo>() as c_int,
        )
    };
    let errno = if ret <= 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    (ret, errno, s)
}

fn show13(tag: &str, pid: u32) {
    let (ret, errno, s) = flavor13(pid);
    let comm: String = s.pbsi_comm.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
    d0!(
        "M4",
        "{tag}.f13 pid={pid} ret={ret} errno={} size={} pbsi_pid={} ppid={} pgid={} status={} flags={:#x} \
         PROC_FLAG_SYSTEM={} PROC_FLAG_TRACED={} uid={} comm={comm}",
        errname(errno),
        std::mem::size_of::<libc::proc_bsdshortinfo>(),
        s.pbsi_pid,
        s.pbsi_ppid,
        s.pbsi_pgid,
        s.pbsi_status,
        s.pbsi_flags,
        s.pbsi_flags & 1 != 0,
        s.pbsi_flags & 2 != 0,
        s.pbsi_uid
    );
}

/// `kinfo_proc` via `sysctl(KERN_PROC_PID)`: `(length, p_pid, p_oppid, e_ppid)`. The offsets are
/// the 64-bit `extern_proc`/`eproc` layout; `p_pid` and `e_ppid` are cross-checked by the caller.
fn kinfo(pid: u32) -> Option<(usize, i32, i32, i32)> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as c_int];
    let mut len = 0usize;
    // SAFETY: size query, then a read into a buffer of that size.
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 4, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctl(mib.as_mut_ptr(), 4, buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 || len < 568 {
            return None;
        }
        let rd = |o: usize| i32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        Some((len, rd(40), rd(44), rd(560)))
    }
}

fn show_kinfo(tag: &str, pid: u32) {
    match kinfo(pid) {
        None => d0!("M4", "{tag}.kinfo pid={pid} unavailable errno={}", errname(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))),
        Some((len, p_pid, p_oppid, e_ppid)) => d0!(
            "M4",
            "{tag}.kinfo pid={pid} len={len} p_pid={p_pid} layout_ok={} p_oppid={p_oppid} e_ppid={e_ppid}",
            p_pid == pid as i32
        ),
    }
}

fn show17(tag: &str, pid: u32) {
    let (ret, errno, u) = flavor17(pid, 1);
    d0!(
        "M4",
        "{tag}.f17 pid={pid} ret={ret} errno={} uniqueid={} puniqueid={} idversion={} orig_ppidversion={}",
        errname(errno),
        u.p_uniqueid,
        u.p_puniqueid,
        u.p_idversion,
        u.p_orig_ppidversion
    );
}

/// Role child: `PT_ATTACH`es to `D0_M4_TARGET`, reports the result, and detaches when stdin closes.
#[test]
fn d0_role_m4_tracer() {
    if std::env::var("D0_ROLE").as_deref() != Ok("m4") {
        return;
    }
    let target: i32 = std::env::var("D0_M4_TARGET").expect("target").parse().expect("pid");
    const PT_ATTACHEXC: c_int = 14;
    // SAFETY: plain ptrace requests.
    let mut r = unsafe { libc::ptrace(libc::PT_ATTACH, target, std::ptr::null_mut(), 0) };
    let mut errno = if r != 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    let mut which = "PT_ATTACH";
    if r != 0 {
        println!("D0-tracer PT_ATTACH ret={r} errno={}", errname(errno));
        r = unsafe { libc::ptrace(PT_ATTACHEXC, target, std::ptr::null_mut(), 0) };
        errno = if r != 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
        which = "PT_ATTACHEXC";
    }
    println!(
        "ATTACH via={which} ret={r} errno={} tracer_pid={} tracer_uid={}",
        errname(errno),
        std::process::id(),
        unsafe { libc::getuid() }
    );
    std::io::stdout().flush().expect("flush");
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    if r == 0 {
        // SAFETY: plain ptrace request.
        unsafe { libc::ptrace(libc::PT_DETACH, target, std::ptr::null_mut(), 0) };
    }
}

fn traced_case(tag: &str, target: u32, sudo: bool) {
    let me = std::process::id();
    show17("parent", me);
    show13(&format!("{tag}.before"), target);
    show17(&format!("{tag}.before"), target);
    show_kinfo(&format!("{tag}.before"), target);

    let exe = std::env::current_exe().expect("exe");
    let args = ["--exact", "macos::d0_role_m4_tracer", "--nocapture"];
    let mut cmd = if sudo {
        let mut c = Command::new("sudo");
        c.args(["-n", "env", "D0_ROLE=m4", &format!("D0_M4_TARGET={target}")]).arg(&exe).args(args);
        c
    } else {
        let mut c = Command::new(&exe);
        c.args(args).env("D0_ROLE", "m4").env("D0_M4_TARGET", target.to_string());
        c
    };
    let mut t = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tracer");
    let stdin = t.stdin.take().unwrap();
    let mut out = std::io::BufReader::new(t.stdout.take().unwrap());
    let mut line = String::new();
    let mut attach = None;
    loop {
        line.clear();
        if std::io::BufRead::read_line(&mut out, &mut line).expect("read") == 0 {
            break;
        }
        if line.starts_with("D0-tracer ") {
            d0!("M4", "{tag}.{}", line.trim());
        }
        if line.starts_with("ATTACH ") {
            attach = Some(line.trim().to_string());
            break;
        }
    }
    let Some(attach) = attach else {
        d0!("M4", "{tag}.tracer_never_reported sudo={sudo}");
        let _ = t.wait();
        return;
    };
    d0!("M4", "{tag}.sudo={sudo} {attach}");
    show13(&format!("{tag}.after_attach"), target);
    show17(&format!("{tag}.after_attach"), target);
    show_kinfo(&format!("{tag}.after_attach"), target);
    d0!("M4", "{tag}.original_parent_is_pid={me} (the probe)");
    drop(stdin);
    let _ = t.wait();
}

#[test]
fn d0_m4_short_bsd_info() {
    let me = std::process::id();
    // SAFETY: plain getters.
    let (ppid, pgrp) = unsafe { (libc::getppid(), libc::getpgrp()) };
    d0!("M4", "self.expected ppid={ppid} pgid={pgrp}");
    show13("self", me);
    show_kinfo("self", me);
    let live = sleeper();
    show13("live_child", live.0.id());

    show13("pid1_launchd", 1);
    show13("pid0_kernel_task", 0);

    // Zombie: NOTE_EXIT seen, not reaped.
    let mut z = sleeper();
    let zpid = z.0.id();
    let w = Watch::new(zpid, libc::NOTE_EXIT);
    z.0.kill().expect("kill");
    w.next();
    show13("zombie", zpid);
    show_kinfo("zombie", zpid);
    z.0.wait().expect("reap");
    // A gone pid: reaped just above.
    show13("gone_reaped", zpid);
    show_kinfo("gone_reaped", zpid);
    // A pid that never existed in this boot's recent range.
    show13("gone_never_allocated", 99_998);

    // Traced: a non-platform target (this test binary) and a platform one (`/bin/sleep`).
    let rc = RoleChild::spawn();
    traced_case("traced_probe_binary", rc.pid(), false);
    traced_case("traced_probe_binary_root_tracer", rc.pid(), true);
    drop(rc);
    let s = sleeper();
    traced_case("traced_bin_sleep", s.0.id(), false);
    traced_case("traced_bin_sleep_root_tracer", s.0.id(), true);
}
