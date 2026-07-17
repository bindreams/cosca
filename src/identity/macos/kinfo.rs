//! `sysctl(KERN_PROC_PID)` / `kinfo_proc` — the BSD interface that resolves ZOMBIES
//! (libproc's `proc_pidinfo` does not). libc has no apple definition for these structs,
//! so this is a minimal faithful local one. Only `p_un.p_starttime` and `p_stat` are read;
//! everything else is layout. Layout is triple-checked: the compile-time size tripwires
//! below, the kernel-size oracle, and the token-vs-libproc oracle (kinfo_tests.rs).
#![allow(non_camel_case_types)]

use super::super::RawPid;

/// `struct kinfo_proc` (LP64): `extern_proc` head + opaque `eproc` tail.
#[repr(C)]
pub(super) struct kinfo_proc {
    pub(super) kp_proc: extern_proc,
    kp_eproc: [u8; 352],
}

/// `struct extern_proc` (LP64 user copy, from XNU's proc.h). Kernel pointers are
/// represented as `u64` (they are opaque user_addr_t values in the sysctl copy).
#[repr(C)]
pub(super) struct extern_proc {
    pub(super) p_un: p_un,
    p_vmspace: u64,
    p_sigacts: u64,
    p_flag: libc::c_int,
    pub(super) p_stat: libc::c_char,
    p_pid: libc::pid_t,
    p_oppid: libc::pid_t,
    p_dupfd: libc::c_int,
    user_stack: u64,
    exit_thread: u64,
    p_debugger: libc::c_int,
    sigwait: libc::c_int, // boolean_t
    p_estcpu: libc::c_uint,
    p_cpticks: libc::c_int,
    p_pctcpu: u32, // fixpt_t
    p_wchan: u64,
    p_wmesg: u64,
    p_swtime: libc::c_uint,
    p_slptime: libc::c_uint,
    p_realtimer: itimerval,
    p_rtime: libc::timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: libc::c_int,
    p_tracep: u64,
    p_siglist: libc::c_int,
    p_textvp: u64,
    p_holdcnt: libc::c_int,
    p_sigmask: u32, // sigset_t
    p_sigignore: u32,
    p_sigcatch: u32,
    p_priority: u8,
    p_usrpri: u8,
    p_nice: libc::c_char,
    p_comm: [libc::c_char; 17], // MAXCOMLEN + 1
    p_pgrp: u64,
    p_addr: u64,
    p_xstat: u16,
    p_acflag: u16,
    p_ru: u64,
}

#[repr(C)]
pub(super) union p_un {
    p_st1: run_sleep_queue,
    pub(super) p_starttime: libc::timeval,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct run_sleep_queue {
    p_forw: u64,
    p_back: u64,
}

#[repr(C)]
struct itimerval {
    it_interval: libc::timeval,
    it_value: libc::timeval,
}

// Compile-time layout tripwire: sizeof(struct kinfo_proc) == 648 on LP64 darwin (ps and
// libtop hard-code the same). The kernel-size oracle in kinfo_tests.rs re-checks this
// against the running kernel.
const _: () = assert!(std::mem::size_of::<kinfo_proc>() == 648);
const _: () = assert!(std::mem::size_of::<extern_proc>() == 296);

/// Read one `kinfo_proc` for `pid`. `None` means "not resolvable" — the EXPECTED miss is
/// a nonexistent pid (sysctl SUCCESS with `size == 0`); a real sysctl failure or a
/// wrong-sized record is a contract violation and leaves a trace before the same `None`.
/// EINTR retries, per the codebase convention (see `wait/linux.rs`, `wait/macos.rs`).
pub(super) fn kinfo(pid: RawPid) -> Option<kinfo_proc> {
    read_record(pid, libc::KERN_PROC_PID)
}

/// The selector-parameterized core. The `selector` parameter is a TEST SEAM (production
/// always passes `KERN_PROC_PID` via `kinfo()`) — it lets a unit test drive the
/// contract-violation arm with an invalid selector.
fn read_record(pid: RawPid, selector: libc::c_int) -> Option<kinfo_proc> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, selector, pid as libc::c_int];
    loop {
        let mut info: kinfo_proc = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<kinfo_proc>();
        // SAFETY: `info` and `size` describe one kinfo_proc; sysctl writes at most `size`.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut info as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            super::contract_violation(format_args!("sysctl(KERN_PROC selector {selector}, {pid}) failed: {e}"));
            return None;
        }
        if size == 0 {
            return None;
        }
        if size != std::mem::size_of::<kinfo_proc>() {
            // Layout drift — never trust a partial/foreign-sized record.
            super::contract_violation(format_args!(
                "sysctl(KERN_PROC selector {selector}, {pid}) wrote {size} bytes, expected {}",
                std::mem::size_of::<kinfo_proc>()
            ));
            return None;
        }
        return Some(info);
    }
}

#[cfg(test)]
#[path = "kinfo_tests.rs"]
mod kinfo_tests;
