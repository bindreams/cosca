#!/usr/bin/env python3
"""THROWAWAY (PR #377): prints the tracee's kinfo and thread states around the detach (COSCA_UH_DIAG=1)."""
import pathlib

KINFO = pathlib.Path("src/identity/macos/kinfo.rs")
MACHINE = pathlib.Path("src/test_support/tracer/machine.rs")
SYS = pathlib.Path("src/test_support/tracer/sys.rs")
TESTS = pathlib.Path("src/test_support/tracer_tests.rs")


def sub(path, old, new, count=1):
    s = path.read_text()
    assert s.count(old) == count, (path, old, s.count(old))
    path.write_text(s.replace(old, new))


sub(KINFO, "    pub(super) p_stat: libc::c_char,", "    pub(crate) p_stat: libc::c_char,")
sub(KINFO, "    sigwait: libc::c_int, // boolean_t", "    pub(crate) sigwait: libc::c_int, // boolean_t")
sub(KINFO, "    p_xstat: u16,", "    pub(crate) p_xstat: u16,")
sub(KINFO, "    p_siglist: libc::c_int,", "    pub(crate) p_siglist: libc::c_int,")

DIAG = r'''
pub(crate) fn diag(pid: u32, what: &str) {
    if std::env::var("COSCA_UH_DIAG").as_deref() != Ok("1") {
        return;
    }
    use crate::identity::{kinfo::kinfo, Resolved};
    let k = match kinfo(pid as _) {
        Resolved::Found(i) => format!(
            "p_stat={} sigwait={} p_xstat={} p_flag={:#x} siglist={:#x}",
            i.kp_proc.p_stat, i.kp_proc.sigwait, i.kp_proc.p_xstat, i.kp_proc.p_flag, i.kp_proc.p_siglist
        ),
        _ => "gone".to_string(),
    };
    let mut states = Vec::new();
    let mut task: [libc::proc_taskinfo; 1] = unsafe { std::mem::zeroed() };
    if pidinfo(pid, libc::PROC_PIDTASKINFO, 0, &mut task).is_ok() {
        let mut handles = vec![0u64; 64];
        if let Ok(n) = pidinfo(pid, PROC_PIDLISTTHREADS, 0, &mut handles) {
            for &h in &handles[..n / 8] {
                let mut t: [libc::proc_threadinfo; 1] = unsafe { std::mem::zeroed() };
                if pidinfo(pid, libc::PROC_PIDTHREADINFO, h, &mut t).is_ok() {
                    states.push((t[0].pth_run_state, t[0].pth_flags));
                }
            }
        }
        states.push((-1, task[0].pti_threadnum));
    }
    let line = format!("DIAG {pid} {what}: {k} threads(run_state,flags)={states:?}\n");
    use std::io::Write as _;
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}
'''
s = SYS.read_text()
s += DIAG
SYS.write_text(s)

sub(MACHINE, "                Check::Result(sys::detach(self.pid, carried))",
    "                { sys::diag(self.pid, \"before PT_DETACH\"); let r = sys::detach(self.pid, carried); sys::diag(self.pid, \"after PT_DETACH\"); Check::Result(r) }")
sub(MACHINE, """                Err(libc::EBUSY) => {
                    self.enter("S4b")?;""", """                Err(libc::EBUSY) => {
                    sys::diag(self.pid, "S4b round");
                    self.enter("S4b")?;""")
sub(MACHINE, "        let delivered = if release == Release::Deliver { signal } else { 0 };",
    "        sys::diag(self.pid, &format!(\"{tag} stop by {signal}, before the release\"));\n        let delivered = if release == Release::Deliver { signal } else { 0 };")
sub(MACHINE, "        self.report_then(\"detached\", EXIT)\n    }",
    "        sys::diag(self.pid, \"after the re-sends\");\n        self.report_then(\"detached\", EXIT)\n    }")

TEST_DIAG = '''
fn diag_after_detach(pid: u32) {
    let info = sys::peek(pid, libc::WEXITED | libc::WSTOPPED | libc::WNOHANG).expect("peek");
    eprintln!("DIAG test after detach: si_pid={} si_code={} si_status={}", info.si_pid, info.si_code, info.si_status);
    sys::diag(pid, "test after detach");
}
'''
s = TESTS.read_text()
s += TEST_DIAG
TESTS.write_text(s)
sub(TESTS, """/// Ends a tracee this test saw job-stopped, which cannot exit on its own.
fn end_stopped(tracee: crate::Child) {""", """/// Ends a tracee this test saw job-stopped, which cannot exit on its own.
fn end_stopped(tracee: crate::Child) {
    diag_after_detach(tracee.id().pid());""")
sub(TESTS, """fn run_on_to_exit(pid: u32) {
""", """fn run_on_to_exit(pid: u32) {
    diag_after_detach(pid);
""")
sub(TESTS, """fn end_detached(tracee: crate::Child, stdin: std::io::PipeWriter) {
""", """fn end_detached(tracee: crate::Child, stdin: std::io::PipeWriter) {
    diag_after_detach(tracee.id().pid());
""")

