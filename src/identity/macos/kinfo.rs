//! `sysctl(KERN_PROC_PID)` / `kinfo_proc` — the BSD interface that resolves ZOMBIES and
//! EPERM-hidden cross-user processes (libproc's `proc_pidinfo` does not). libc has no apple
//! definition for these structs, so this is a minimal faithful local one. Only
//! `p_un.p_starttime`, `p_stat`, and `eproc.e_ppid` are read; everything else is layout.
//! Layout is triple-checked: the compile-time size tripwires below, the kernel-size oracle,
//! and the token-vs-libproc / ppid-vs-libproc oracles (kinfo_tests.rs).
#![allow(non_camel_case_types)]

use super::super::{RawPid, Resolved};

/// `struct kinfo_proc` (LP64): `extern_proc` head + opaque `eproc` tail.
#[repr(C)]
pub(crate) struct kinfo_proc {
    pub(crate) kp_proc: extern_proc,
    kp_eproc: [u8; 352],
}

impl kinfo_proc {
    /// Byte offset of `eproc.e_ppid` within the opaque `kp_eproc` tail (`struct eproc`:
    /// `e_paddr` + `e_sess` pointers, then `struct _pcred e_pcred`, `struct _ucred e_ucred`,
    /// `struct vmspace e_vm`, then `e_ppid`). Determined two ways before landing here — an
    /// `offsetof` probe compiled against Apple's real `sys/sysctl.h`, and a live `sysctl`
    /// call compared against `getppid()` — and re-checked on every test run by
    /// `sysctl_e_ppid_matches_libproc_across_the_live_process_table` (kinfo_tests.rs), the
    /// permanent oracle: a future SDK layout drift fails that test rather than silently
    /// misreading ppids.
    const E_PPID_OFFSET: usize = 264;

    /// `eproc.e_ppid` — the parent pid the kernel recorded in this snapshot. A checked-offset
    /// read rather than fielding the rest of `eproc`: nothing else in it is needed, and every
    /// additional fielded sub-struct (`_pcred`, `_ucred`, `vmspace`, ...) would be more
    /// hand-copied kernel ABI to keep in sync for zero benefit (see the module doc).
    pub(super) fn e_ppid(&self) -> libc::pid_t {
        const LEN: usize = std::mem::size_of::<libc::pid_t>();
        let bytes: [u8; LEN] = self.kp_eproc[kinfo_proc::E_PPID_OFFSET..kinfo_proc::E_PPID_OFFSET + LEN]
            .try_into()
            .expect("kp_eproc is 352 bytes; E_PPID_OFFSET + LEN fits with room to spare (see the tripwire below)");
        libc::pid_t::from_ne_bytes(bytes)
    }
}

// E_PPID_OFFSET must stay inside the opaque tail it reads from - a compile-time companion to
// the two size tripwires below, same reasoning.
const _: () = assert!(kinfo_proc::E_PPID_OFFSET + std::mem::size_of::<libc::pid_t>() <= 352);

/// `struct extern_proc` (LP64 user copy, from XNU's proc.h). Kernel pointers are
/// represented as `u64` (they are opaque user_addr_t values in the sysctl copy).
#[repr(C)]
pub(crate) struct extern_proc {
    pub(crate) p_un: p_un,
    p_vmspace: u64,
    p_sigacts: u64,
    pub(crate) p_flag: libc::c_int,
    pub(super) p_stat: libc::c_char,
    pub(crate) p_pid: libc::pid_t,
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
pub(crate) union p_un {
    p_st1: run_sleep_queue,
    pub(crate) p_starttime: libc::timeval,
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

/// `p_flag`'s "system process" bit, source-verified against the Xcode Command Line Tools
/// SDK: `#define P_SYSTEM 0x00000200` in `usr/include/sys/proc.h`. xnu's `killpg1` excludes
/// it from a process-group signal alongside — but independently of — `initproc` (pid 1),
/// confirmed against xnu's own `bsd/kern/kern_sig.c`. `containment::unix::group` restates
/// both exclusions (`excluded_from_sigkill_resend`). `kinfo_tests.rs` cross-checks this bit's
/// value against a second, independently-issued sysctl query and, where a live process allows
/// it, `proc_pidinfo`'s own `PROC_FLAG_SYSTEM` bit.
pub(crate) const P_SYSTEM: libc::c_int = 0x00000200;

/// Read one `kinfo_proc` for `pid`. `None` means "not resolvable" — the EXPECTED miss is
/// a nonexistent pid (sysctl SUCCESS with `size == 0`); a real sysctl failure or a
/// wrong-sized record is a contract violation and leaves a trace before the same `None`.
/// EINTR retries, per the codebase convention (see `wait/linux.rs`, `wait/macos.rs`).
pub(super) fn kinfo(pid: RawPid) -> Resolved<kinfo_proc> {
    read_record(pid, libc::KERN_PROC_PID)
}

/// The selector-parameterized core. The `selector` parameter is a TEST SEAM (production
/// always passes `KERN_PROC_PID` via `kinfo()`) — it lets a unit test drive the
/// contract-violation arm with an invalid selector.
fn read_record(pid: RawPid, selector: libc::c_int) -> Resolved<kinfo_proc> {
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
            return match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                // The OS positively says there is no such process.
                Some(libc::ESRCH) => Resolved::Gone,
                // A sandbox or hardened runtime refusing the query is the DESIGNED Unknown,
                // not a contract violation - `debug`, like every other per-pid probe.
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    log::debug!("sysctl(KERN_PROC selector {selector}, {pid}) refused: {e}");
                    Resolved::Unknown
                }
                // ENOMEM/EINVAL are neither race- nor permission-reachable. ENOMEM in
                // particular is the ONLY runtime detector for a kernel `kinfo_proc` that has
                // grown past our 648-byte definition: it fails before the size check below
                // is ever reached, and the compile-time size assert cannot fire because the
                // Rust definition is what stayed still. Keep it loud.
                _ => {
                    super::contract_violation(format_args!("sysctl(KERN_PROC selector {selector}, {pid}) failed: {e}"));
                    Resolved::Unknown
                }
            };
        }
        if size == 0 {
            return Resolved::Gone;
        }
        if size != std::mem::size_of::<kinfo_proc>() {
            // Layout drift — never trust a partial/foreign-sized record.
            super::contract_violation(format_args!(
                "sysctl(KERN_PROC selector {selector}, {pid}) wrote {size} bytes, expected {}",
                std::mem::size_of::<kinfo_proc>()
            ));
            return Resolved::Unknown;
        }
        return Resolved::Found(info);
    }
}

#[cfg(test)]
#[path = "kinfo_tests.rs"]
mod kinfo_tests;
