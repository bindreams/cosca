//! What the path check reads from a directory, and the rule it applies.

use std::io;
use std::path::Path;

use std::os::fd::BorrowedFd;

use rustix::fs::Stat;

const STICKY: u32 = 0o1000;
const GROUP_OTHER_WRITE: u32 = 0o022;

/// XNU's `MNT_IGNORE_OWNERSHIP`: the volume reports every file as owned by the caller.
#[cfg(target_os = "macos")]
fn mount_ignores_ownership(mount_flags: u32) -> bool {
    mount_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
}

/// No other platform has the flag.
#[cfg(not(target_os = "macos"))]
fn mount_ignores_ownership(_: u32) -> bool {
    false
}

/// XNU's `UNKNOWNUID` (`nobody`'s old uid). Under it, XNU reports every file as owned by the caller.
#[cfg(target_os = "macos")]
const UNKNOWN_UID: u32 = 99;

/// What the path check looks at in a directory.
pub(crate) struct DirFacts {
    pub(crate) uid: u32,
    pub(crate) mode: u32,
    /// The volume does not track ownership, so `uid` says nothing.
    pub(crate) ignores_ownership: bool,
    /// An ACL entry lets someone other than the euid and root add, remove or rename entries, or
    /// grant themselves the right to. macOS only.
    pub(crate) acl_grants_others: bool,
    /// The filesystem's type (`f_type`) where the platform reports one (Linux); 0 elsewhere.
    pub(crate) fs_type: u64,
    /// The volume is not local (macOS: its mount flags lack `MNT_LOCAL`, as a network share's do).
    pub(crate) not_local: bool,
}

/// What a test makes the directory's `statfs` say: the mount flags and the filesystem type.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FsOverride {
    pub(crate) mount_flags: u32,
    pub(crate) fs_type: u64,
}

/// XNU's `MNT_LOCAL`: the volume is on a local device.
#[cfg(target_os = "macos")]
fn mount_not_local(mount_flags: u32) -> bool {
    mount_flags & libc::MNT_LOCAL as u32 == 0
}

#[cfg(not(target_os = "macos"))]
fn mount_not_local(_: u32) -> bool {
    false
}

/// Filesystems whose permissions and ownership are decided by something other than this kernel's own
/// view of local users: another host (NFS, SMB/CIFS, Ceph, AFS, kAFS, Coda, NCP, Lustre, GPFS,
/// BeeGFS, PanFS, GFS2, OCFS2, StorNext, IBRIX, ACFS, VxFS), a hypervisor or its guest tools (9p,
/// vboxsf, prl_fs, vmhgfs), or a user-space daemon (FUSE). Neither the `0700` mode nor the rename
/// protection the path check relies on holds there (root squashing, uid mapping, server-side
/// policy), and Unix sockets are not reliable on them. The list follows coreutils' `stat.c`
/// (`human_fstype`, which marks the same types remote or shared) for the types that fit that rule.
/// Local filesystems, overlayfs and eCryptfs are not listed.
const REFUSED_FILESYSTEMS: &[(u64, &str)] = &[
    (0x6969, "NFS"),
    (0x6573_5546, "FUSE"),
    (0x517B, "SMB"),
    (0xFE53_4D42, "SMB2"),
    (0xFF53_4D42, "CIFS"),
    (0x00C3_6400, "Ceph"),
    (0x5346_414F, "AFS"),
    (0x7375_7245, "Coda"),
    (0x564C, "NCP"),
    (0x0BD0_0BD0, "Lustre"),
    (0x0102_1997, "9p"),
    (0x6B41_4653, "kAFS"),
    (0x786F_4256, "vboxsf"),
    (0x7C7C_6673, "prl_fs"),
    (0xBACB_ACBC, "vmhgfs"),
    (0x4750_4653, "GPFS"),
    (0x1983_0326, "BeeGFS"),
    (0xAAD7_AAEA, "PanFS"),
    (0x0116_1970, "GFS2"),
    (0x7461_636F, "OCFS2"),
    (0xBEEF_DEAD, "StorNext"),
    (0x0131_11A8, "IBRIX"),
    (0x6163_6673, "ACFS"),
    (0xA501_FCF5, "VxFS"),
];

/// The name of the network or user-space filesystem `fs_type` is, if it is one the private directory
/// refuses.
pub(crate) fn refused_filesystem(fs_type: u64) -> Option<&'static str> {
    // `f_type` is a signed word on some architectures; the magics are 32-bit.
    let magic = fs_type & 0xFFFF_FFFF;
    REFUSED_FILESYSTEMS
        .iter()
        .find(|(m, _)| *m == magic)
        .map(|(_, name)| *name)
}

/// Why a directory is unfit to hold the private directory.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unfit {
    /// Another user could rename entries in it, or it cannot vouch for ownership.
    Writable,
    Filesystem(&'static str),
}

/// [`check_facts`], and the filesystem refusal first.
pub(crate) fn check_dir(facts: &DirFacts, euid: u32) -> Result<(), Unfit> {
    if let Some(name) = refused_filesystem(facts.fs_type) {
        return Err(Unfit::Filesystem(name));
    }
    if facts.not_local {
        return Err(Unfit::Filesystem("a volume that is not local"));
    }
    if check_facts(facts, euid) {
        Ok(())
    } else {
        Err(Unfit::Writable)
    }
}

impl DirFacts {
    /// The facts from a `stat`, the volume's mount flags (`f_flags` of `statfs`; 0 where the
    /// platform has none) and the ACL verdict.
    #[allow(
        clippy::useless_conversion,
        reason = "`st_mode` is `u16` on macOS and `u32` on Linux"
    )]
    pub(crate) fn from_parts(st: &Stat, mount_flags: u32, fs_type: u64, acl_grants_others: bool) -> Self {
        Self {
            fs_type,
            uid: st.st_uid,
            mode: st.st_mode.into(),
            ignores_ownership: mount_ignores_ownership(mount_flags),
            acl_grants_others,
            not_local: mount_not_local(mount_flags),
        }
    }

    /// The facts of the directory at `path`, whose `stat` is `st`, for an ancestor of the temp
    /// directory: only who owns it and who can change it matter, so no filesystem type is read.
    pub(crate) fn read(path: &Path, st: &Stat, euid: u32) -> io::Result<Self> {
        let mut facts = Self::from_parts(
            st,
            platform::mount_flags(path)?,
            0,
            platform::acl_grants_others(path, euid)?,
        );
        facts.not_local = false;
        Ok(facts)
    }

    /// The facts of the temp directory itself, open as `fd` at `path`, whose `stat` is `st`: its
    /// filesystem is read from the descriptor (or from `over`, in a test).
    pub(crate) fn read_fd(
        fd: BorrowedFd<'_>,
        path: &Path,
        st: &Stat,
        euid: u32,
        over: Option<FsOverride>,
    ) -> io::Result<Self> {
        let (mount_flags, fs_type) = match over {
            Some(o) => (o.mount_flags, o.fs_type),
            None => platform::fstatfs(fd)?,
        };
        Ok(Self::from_parts(
            st,
            mount_flags,
            fs_type,
            platform::acl_grants_others(path, euid)?,
        ))
    }
}

/// True if no user but `euid` and root can rename or remove the entries of this directory that
/// `euid` or root own.
///
/// In a sticky directory, others can still rename the entries they own. That is why the private
/// directory is `0700` and owned by us, which this check does not vouch for.
pub(crate) fn check_facts(facts: &DirFacts, euid: u32) -> bool {
    #[cfg(target_os = "macos")]
    if euid == UNKNOWN_UID {
        return false;
    }
    !facts.ignores_ownership
        && !facts.acl_grants_others
        && (facts.uid == 0 || facts.uid == euid)
        && (facts.mode & STICKY != 0 || facts.mode & GROUP_OTHER_WRITE == 0)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use exacl::{getfacl, AclEntry, AclEntryKind, AclOption, Perm};

    /// What lets a user other than the owner change a directory's entries, or give themselves
    /// that right.
    const ENTRY_CHANGING: Perm = Perm::WRITE
        .union(Perm::APPEND)
        .union(Perm::DELETE_CHILD)
        .union(Perm::WRITESECURITY)
        .union(Perm::CHOWN);

    /// `(f_flags, 0)` of the volume `fd` is on.
    pub(super) fn fstatfs(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<(u32, u64)> {
        use std::os::fd::AsRawFd;
        // SAFETY: an all-zero `statfs` is a valid out-parameter, and `fd` is open.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut buf) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((buf.f_flags, 0))
    }

    pub(super) fn mount_flags(path: &Path) -> io::Result<u32> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: an all-zero `statfs` is a valid out-parameter, and `c_path` is NUL-terminated.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf.f_flags)
    }

    /// The names under which `euid` and root appear in an ACL entry: their user names and their
    /// decimal uids.
    fn trusted_names(euid: u32) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for uid in [0, euid] {
            names.push(uid.to_string());
            if let Some(user) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).map_err(io::Error::from)? {
                names.push(user.name);
            }
        }
        Ok(names)
    }

    /// Every allow entry counts, inherit-only ones included: a child made here inherits them.
    pub(super) fn grants_others(entries: &[AclEntry], trusted: &[String]) -> bool {
        entries.iter().any(|e| {
            e.allow
                && e.perms.intersects(ENTRY_CHANGING)
                && !(e.kind == AclEntryKind::User && trusted.contains(&e.name))
        })
    }

    pub(super) fn acl_grants_others(path: &Path, euid: u32) -> io::Result<bool> {
        let entries = getfacl(path, AclOption::SYMLINK_ACL)?;
        Ok(grants_others(&entries, &trusted_names(euid)?))
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::io;
    use std::path::Path;

    pub(super) fn mount_flags(_: &Path) -> io::Result<u32> {
        Ok(0)
    }

    /// `(0, f_type)` of the filesystem `fd` is on.
    #[cfg(target_os = "linux")]
    pub(super) fn fstatfs(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<(u32, u64)> {
        Ok((0, rustix::fs::fstatfs(fd)?.f_type as u64))
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn fstatfs(_: std::os::fd::BorrowedFd<'_>) -> io::Result<(u32, u64)> {
        Ok((0, 0))
    }

    pub(super) fn acl_grants_others(_: &Path, _: u32) -> io::Result<bool> {
        Ok(false)
    }
}
