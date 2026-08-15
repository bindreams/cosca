//! Layout/value oracles for the local kinfo_proc definition. macOS-only at runtime.

use super::*;

// The kernel must agree with our struct size exactly: for a real one-record fetch, XNU
// sets the written size to sizeof(struct kinfo_proc). (A NULL-buffer probe is NOT usable
// here — XNU inflates it by KERN_PROCSLOP = 5*sizeof, so it reports 6*sizeof for one pid.)
#[test]
fn kernel_writes_exactly_our_kinfo_proc_size() {
    let mut buf = [0u8; 2 * std::mem::size_of::<kinfo_proc>()];
    let mut size = buf.len();
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        std::process::id() as libc::c_int,
    ];
    // SAFETY: `buf`/`size` describe the buffer; sysctl writes at most `size` bytes. No
    // field is read from `buf`, so its alignment is irrelevant.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0, "sysctl fetch failed: {}", std::io::Error::last_os_error());
    assert_eq!(
        size,
        std::mem::size_of::<kinfo_proc>(),
        "kernel kinfo_proc record size disagrees with our layout"
    );
}

// The rc!=0 contract-violation arm, driven through the selector test seam (a SYNTHETIC
// invalid selector — the arm's real triggers are unconstructible with a correct mib). In
// debug builds the tripwire panics AFTER the warn executed (this test expects the panic);
// in the release lane the same straight-line code minus the compiled-out assert runs to
// `None`, which the assert below pins.
// SCOPE: the EPERM arm - a sandboxed sysctl refusal - is a DIFFERENT arm, reached by no
// test on any available machine.
#[cfg_attr(debug_assertions, should_panic(expected = "sysctl(KERN_PROC"))]
#[test]
fn an_undiagnosable_sysctl_failure_trips_the_tripwire_and_reports_unknown() {
    let r = super::read_record(std::process::id() as super::super::RawPid, -1);
    // `assert_eq!` is impossible here: `Resolved`-s derives are T-bounded and `kinfo_proc`
    // embeds a union, so it can never be `PartialEq`/`Debug`.
    assert!(r.is_unknown(), "a failed sysctl must never yield a record - or a Gone");
}

// Verifies contract_violation's warn is actually captured, not just that debug panics —
// the release lane (no should_panic) asserts the captured record directly.
#[cfg_attr(debug_assertions, should_panic(expected = "synthetic"))]
#[test]
fn contract_violation_traces_then_trips() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    super::super::contract_violation(format_args!("synthetic contract violation (test)"));
    // Only reachable in release (debug panicked above, as expected):
    assert!(
        crate::log_capture::contains_since(mark, "synthetic contract violation (test)"),
        "the warn must have fired before the (compiled-out) tripwire"
    );
}

// Value oracle: for a LIVE process the sysctl-derived token must equal the
// proc_pidinfo-derived token — a wrong `p_un` offset or padding error fails here.
// `proc_pidinfo` survives ONLY as this oracle.
#[test]
fn sysctl_token_matches_libproc_for_a_live_process() {
    let pid = std::process::id() as libc::c_int;

    let crate::identity::Resolved::Found(ours) = kinfo(pid as super::super::RawPid) else {
        panic!("self resolves via sysctl");
    };
    let ours = {
        // SAFETY: as in token_of — the kernel fills p_starttime for KERN_PROC copies.
        let t = unsafe { ours.kp_proc.p_un.p_starttime };
        t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64
    };

    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    assert_eq!(n, size, "proc_pidinfo oracle failed for self");
    let theirs = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;

    assert_eq!(ours, theirs, "sysctl and libproc disagree on self's start token");
}

// Value oracle for `P_SYSTEM`. On this host (and every recent Darwin release checked, up to
// 26.5.2), `kernproc` (pid 0) is the ONLY process carrying the flag — not `launchd`/`initproc`
// (pid 1), which xnu's `killpg1` excludes from a process-group signal by a direct `p ==
// initproc` pointer check, entirely separate from its `P_SYSTEM` test (confirmed against
// xnu's own `bsd/kern/kern_sig.c`). `libc::proc_pidinfo` cannot serve as an oracle for either
// root-owned pid measured here (pid 0 or pid 1): it fails to resolve a foreign-uid process
// without root, the same as it fails for pid 0. The positive case (pid 0) is instead
// cross-checked against a second, independently-issued sysctl call reading the WHOLE process
// table (`KERN_PROC_ALL`, a different selector/code path from `kinfo()`'s own `KERN_PROC_PID`)
// rather than trusting one query alone. The negative case is checked for both pid 1 (sysctl
// only) and this test's own process — the latter additionally cross-checked against
// `proc_pidinfo`'s independently-defined `PROC_FLAG_SYSTEM` (`sys/proc_info.h`, no `libc`
// crate constant, restated here as a local, source-cited value).
#[test]
fn p_flag_system_bit_matches_a_second_sysctl_query_and_libproc_disagrees_for_non_system() {
    const PROC_FLAG_SYSTEM: u32 = 1;

    // Positive: kernproc (pid 0), read via `kinfo()` (production code path, KERN_PROC_PID).
    let crate::identity::Resolved::Found(k) = kinfo(0) else {
        panic!("pid 0 (kernproc) resolves via sysctl KERN_PROC_PID");
    };
    assert!(
        k.kp_proc.p_flag & P_SYSTEM != 0,
        "kernproc (pid 0) must be P_SYSTEM-flagged via KERN_PROC_PID"
    );

    // Cross-check: an independently-issued KERN_PROC_ALL scan must agree pid 0 carries the
    // same bit — a different selector/code path from the KERN_PROC_PID query above.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0];
    let mut len: libc::size_t = 0;
    // SAFETY: a size query — null buffer, `len` receives the byte count.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(
        rc,
        0,
        "KERN_PROC_ALL sizing query failed: {}",
        std::io::Error::last_os_error()
    );
    let record = std::mem::size_of::<kinfo_proc>();
    let mut buf: Vec<kinfo_proc> = Vec::with_capacity(len / record + 8);
    let mut got = buf.capacity() * record;
    // SAFETY: `buf` has room for `got` bytes of records; sysctl writes at most `got`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut got,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0, "KERN_PROC_ALL fetch failed: {}", std::io::Error::last_os_error());
    // SAFETY: sysctl initialised exactly `got / record` whole records.
    unsafe { buf.set_len(got / record) };
    let kernproc = buf
        .iter()
        .find(|k| k.kp_proc.p_pid == 0)
        .expect("pid 0 (kernproc) present in a KERN_PROC_ALL scan");
    assert!(
        kernproc.kp_proc.p_flag & P_SYSTEM != 0,
        "kernproc (pid 0) must be P_SYSTEM-flagged via the independent KERN_PROC_ALL scan too"
    );

    // Negative, sysctl-only: neither pid 1 (launchd, root-owned) nor this test process is
    // P_SYSTEM-flagged. `proc_pidinfo` cannot cross-check pid 1 here — measured, it also
    // fails to resolve a foreign-uid pid without root, same as it fails for pid 0 above — so
    // only this test's own pid gets the `proc_pidinfo` cross-check, right below.
    for pid in [1, std::process::id() as libc::c_int] {
        let crate::identity::Resolved::Found(k) = kinfo(pid as super::super::RawPid) else {
            panic!("pid {pid} resolves via sysctl");
        };
        assert!(
            k.kp_proc.p_flag & P_SYSTEM == 0,
            "pid {pid} must not be P_SYSTEM-flagged via sysctl"
        );
    }

    // Negative, cross-checked: this test process itself is not PROC_FLAG_SYSTEM-flagged
    // either, via proc_pidinfo's independently-defined bit.
    let me = std::process::id() as libc::c_int;
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`.
    let n = unsafe {
        libc::proc_pidinfo(
            me,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    assert_eq!(n, size, "proc_pidinfo oracle failed for self");
    assert!(
        info.pbi_flags & PROC_FLAG_SYSTEM == 0,
        "this test process must not be PROC_FLAG_SYSTEM-flagged via proc_pidinfo"
    );
}
