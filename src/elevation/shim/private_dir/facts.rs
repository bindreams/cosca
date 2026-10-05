//! What the path check reads from a directory, and the rule it applies.

use std::io;
use std::path::Path;

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
}

impl DirFacts {
    /// The facts from a `stat`, the volume's mount flags (`f_flags` of `statfs`; 0 where the
    /// platform has none) and the ACL verdict.
    #[allow(
        clippy::useless_conversion,
        reason = "`st_mode` is `u16` on macOS and `u32` on Linux"
    )]
    pub(crate) fn from_parts(st: &Stat, mount_flags: u32, acl_grants_others: bool) -> Self {
        Self {
            uid: st.st_uid,
            mode: st.st_mode.into(),
            ignores_ownership: mount_ignores_ownership(mount_flags),
            acl_grants_others,
        }
    }

    /// The facts of the directory at `path`, whose `stat` is `st`.
    pub(crate) fn read(path: &Path, st: &Stat, euid: u32) -> io::Result<Self> {
        Ok(Self::from_parts(
            st,
            platform::mount_flags(path)?,
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

    pub(super) fn acl_grants_others(_: &Path, _: u32) -> io::Result<bool> {
        Ok(false)
    }
}
