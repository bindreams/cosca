//! `FakeKernel`'s tables: each call kind answers its rows in the order they were stated, one per
//! call, then asks the kernel it stands over.

use std::io;

use super::fake::FakeKernel;
use super::Kernel;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{ReadErr, Record, Resolved, UniqInfo, UniqRead};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

const PID: u32 = 4242;

fn record(si_status: i32) -> Record {
    Record {
        si_code: libc::CLD_EXITED,
        si_status,
    }
}

fn unique(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo {
        unique_id,
        id_version: 1,
    })
}

fn short(ppid: u32) -> libc::proc_bsdshortinfo {
    // SAFETY: all-zero is a valid `proc_bsdshortinfo`.
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    info.pbsi_ppid = ppid;
    info
}

fn bsd(ppid: u32) -> libc::proc_bsdinfo {
    // SAFETY: all-zero is a valid `proc_bsdinfo`.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    info.pbi_ppid = ppid;
    info
}

fn kinfo_of(pid: libc::pid_t) -> kinfo_proc {
    // SAFETY: all-zero is a valid `kinfo_proc`.
    let mut info: kinfo_proc = unsafe { std::mem::zeroed() };
    info.kp_proc.p_pid = pid;
    info
}

/// A peek takes its rows in order, then the kernel under it answers. A row of another pid, and a
/// consume row, answer nothing here.
///
/// Mutant: a peek row answers a consume, or a row answers more than once.
#[skuld::test]
fn peek_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_peek(PID, Ok(Some(record(3))));
    let kernel = FakeKernel::over(&under)
        .on_peek(PID, Ok(Some(record(1))))
        .on_peek(7, Ok(None))
        .on_peek(PID, Err(io::Error::from_raw_os_error(libc::ECHILD)))
        .on_consume(PID, Ok(Some(record(9))));

    assert_eq!(kernel.peek(PID).expect("the first row"), Some(record(1)));
    assert_eq!(
        kernel.peek(PID).expect_err("the second row").raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(kernel.peek(PID).expect("the kernel under it"), Some(record(3)));
    assert_eq!(kernel.peek(7).expect("another pid's row"), None);
    assert_eq!(kernel.consume(PID).expect("the consume row"), Some(record(9)));
}

/// A consume takes its rows in order, then the kernel under it answers.
#[skuld::test]
fn consume_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_consume(PID, Ok(None));
    let kernel = FakeKernel::over(&under)
        .on_consume(PID, Ok(Some(record(1))))
        .on_consume(PID, Err(io::Error::from_raw_os_error(libc::ECHILD)));

    assert_eq!(kernel.consume(PID).expect("the first row"), Some(record(1)));
    assert_eq!(
        kernel.consume(PID).expect_err("the second row").raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(kernel.consume(PID).expect("the kernel under it"), None);
}

#[skuld::test]
fn unique_info_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_unique_info(PID, unique(3));
    let kernel = FakeKernel::over(&under)
        .on_unique_info(PID, unique(1))
        .on_unique_info(PID, UniqRead::Gone)
        .on_unique_info(7, UniqRead::Refused(libc::EPERM));

    assert_eq!(kernel.unique_info(PID), unique(1));
    assert_eq!(kernel.unique_info(PID), UniqRead::Gone);
    assert_eq!(kernel.unique_info(PID), unique(3));
    assert_eq!(kernel.unique_info(7), UniqRead::Refused(libc::EPERM));
}

#[skuld::test]
fn short_bsd_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_short_bsd(PID, Ok(short(3)));
    let kernel = FakeKernel::over(&under)
        .on_short_bsd(PID, Ok(short(1)))
        .on_short_bsd(PID, Err(ReadErr::Refused(libc::EPERM)));

    assert_eq!(kernel.short_bsd(PID).expect("the first row").pbsi_ppid, 1);
    assert_eq!(
        kernel.short_bsd(PID).map(|_| ()).expect_err("the second row"),
        ReadErr::Refused(libc::EPERM)
    );
    assert_eq!(kernel.short_bsd(PID).expect("the kernel under it").pbsi_ppid, 3);
}

#[skuld::test]
fn bsd_info_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_bsd_info(PID, Ok(bsd(3)));
    let kernel = FakeKernel::over(&under)
        .on_bsd_info(PID, Ok(bsd(1)))
        .on_bsd_info(PID, Err(ReadErr::Gone));

    assert_eq!(kernel.bsd_info(PID).expect("the first row").pbi_ppid, 1);
    assert_eq!(
        kernel.bsd_info(PID).map(|_| ()).expect_err("the second row"),
        ReadErr::Gone
    );
    assert_eq!(kernel.bsd_info(PID).expect("the kernel under it").pbi_ppid, 3);
}

#[skuld::test]
fn kinfo_rows_answer_in_order_then_the_kernel_under_it() {
    let under = FakeKernel::new().on_kinfo(PID, Resolved::Found(kinfo_of(3)));
    let kernel = FakeKernel::over(&under)
        .on_kinfo(PID, Resolved::Gone)
        .on_kinfo(PID, Resolved::Unknown);

    assert!(matches!(kernel.kinfo(PID), Resolved::Gone));
    assert!(matches!(kernel.kinfo(PID), Resolved::Unknown));
    match kernel.kinfo(PID) {
        Resolved::Found(info) => assert_eq!(info.kp_proc.p_pid, 3),
        _ => panic!("the kernel under it answers a record"),
    }
}

/// A refused registration answers its errno, a silent one registers nothing and succeeds, and then
/// the kernel under it answers.
#[skuld::test]
fn subscribe_rows_answer_in_order_then_the_kernel_under_it() {
    let kq = Kqueue::new().expect("a kqueue");
    let exit = Subscription::Process {
        pid: PID,
        signals: false,
        reap: false,
    };
    let under = FakeKernel::new().on_subscribe_refused(PID, libc::EPERM);
    let kernel = FakeKernel::over(&under)
        .on_subscribe_refused(PID, libc::ESRCH)
        .on_subscribe_silent(PID);

    assert_eq!(
        kernel.subscribe(&kq, exit).expect_err("the refusal").raw_os_error(),
        Some(libc::ESRCH)
    );
    kernel.subscribe(&kq, exit).expect("the silent row succeeds");
    assert_eq!(
        kernel
            .subscribe(&kq, exit)
            .expect_err("the kernel under it")
            .raw_os_error(),
        Some(libc::EPERM)
    );
}

/// A kernel handed over as a borrow, a `Box` or an `Arc` answers as the one it points to.
#[skuld::test]
fn a_pointer_to_a_kernel_is_a_kernel() {
    fn unique_of(kernel: impl Kernel) -> UniqRead {
        kernel.unique_info(PID)
    }
    let table = || FakeKernel::new().on_unique_info(PID, unique(5));

    let borrowed = table();
    assert_eq!(unique_of(&borrowed), unique(5));
    assert_eq!(unique_of(Box::new(table())), unique(5));
    assert_eq!(unique_of(std::sync::Arc::new(table())), unique(5));
}
