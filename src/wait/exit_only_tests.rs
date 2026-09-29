//! Tests for the pure parts of `exit_only`.

#[cfg(unix)]
mod unix {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use crate::wait::exit_only::{is_exit_record, reaped_from_record, Reaped, Record};

    fn status(code: i32, si_status: i32) -> Reaped {
        reaped_from_record(Record {
            si_code: code,
            si_status,
        })
    }

    /// `CLD_EXITED` gives the low byte as the code, dropping every other bit of `si_status`
    /// (XNU ORs `p_xhighbits` into its high byte, `kern_exit.c:3255`).
    ///
    /// Mutant: a mask-free mapping keeps the high bits in the raw status.
    #[test]
    fn an_exited_record_gives_the_low_byte_as_the_code() {
        assert_eq!(
            status(libc::CLD_EXITED, 0x0A00_0107),
            Reaped::Status(ExitStatus::from_raw(7 << 8))
        );
    }

    /// `CLD_KILLED` and `CLD_DUMPED` give the signal, and a core dump sets the core bit.
    ///
    /// Mutant: a mask-free mapping; `CLD_DUMPED` mapped like `CLD_KILLED`.
    #[test]
    fn killed_and_dumped_records_give_the_signal() {
        assert_eq!(
            status(libc::CLD_KILLED, 0x0A00_0009),
            Reaped::Status(ExitStatus::from_raw(9))
        );
        assert_eq!(
            status(libc::CLD_DUMPED, 0x0A00_000B),
            Reaped::Status(ExitStatus::from_raw(0x0B | 0x80))
        );
    }

    /// A ptrace stop is not an exit record, and the mapping is total: it becomes `Unreadable`,
    /// never a panic.
    ///
    /// Mutant: a trap read as an exit.
    #[test]
    fn a_trapped_record_is_not_an_exit_record() {
        for code in [libc::CLD_TRAPPED, libc::CLD_STOPPED, libc::CLD_CONTINUED, 0, 99] {
            assert!(!is_exit_record(code), "si_code {code}");
            assert_eq!(status(code, 5), Reaped::Unreadable { si_code: code });
        }
        for code in [libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED] {
            assert!(is_exit_record(code), "si_code {code}");
        }
    }
}
