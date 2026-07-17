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
#[cfg_attr(debug_assertions, should_panic(expected = "sysctl(KERN_PROC"))]
#[test]
fn read_record_flags_an_invalid_selector() {
    let r = super::read_record(std::process::id() as super::super::RawPid, -1);
    assert!(r.is_none(), "an invalid selector must never yield a record");
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

    let ours = kinfo(pid as super::super::RawPid).expect("self resolves via sysctl");
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
