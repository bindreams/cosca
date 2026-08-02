//! Persisting a [`ProcessId`](super::ProcessId) and restoring it later.
//!
//! A `ProcessId` is `(pid, raw start token)`, and the token is whatever the kernel keeps —
//! which is not equally portable across the three backends:
//!
//! | Platform | Token | Survives a reboot? |
//! |---|---|---|
//! | Windows | creation `FILETIME` | yes — absolute 100 ns ticks since 1601 |
//! | macOS | `kinfo_proc` start µs | yes — absolute µs since 1970 |
//! | Linux | `/proc` `starttime` jiffies | **no** — counted from boot |
//!
//! A naively-serialized Linux token therefore aliases onto whichever process occupies that
//! pid after a reboot, reintroducing exactly the pid-reuse hazard `ProcessId` exists to
//! remove — and doing it silently, because the holder believes they have a strong identity.
//!
//! So the persisted form is an explicit, versioned, self-describing [`ProcessIdRecord`] and
//! the only way back is [`TryFrom`], which rejects a record from another platform, another
//! boot session, another pid namespace, or an unknown format version.
//!
//! A restored `ProcessId` says nothing about whether the process is still there — ask
//! [`ProcessId::exists`](super::ProcessId::exists) or
//! [`ProcessId::is_alive`](super::ProcessId::is_alive) for that.
//!
//! A record is meaningful only on the machine, boot session, and pid namespace that
//! produced it. Nothing stops you copying one elsewhere; on Linux it is rejected by the
//! boot identifier, and on Windows/macOS it would have to collide on both the pid and an
//! absolute sub-microsecond creation timestamp to be accepted at all.

use crate::error::{Error, RecordErrorKind};

use super::{backend, ProcessId, RawPid, StartToken};

/// The record format this build writes. A reader rejects any version it does not know,
/// so a future bump can change the fields' meaning safely. Within a version, changes are
/// additive only: a reader ignores fields it does not recognise.
pub const RECORD_VERSION: u32 = 1;

/// The OS a persisted identity was produced on. Start tokens are not comparable across
/// platforms, so this tag is checked before anything else about the token.
///
/// [`Platform::Other`] exists so a record from a newer `cosca` that supports a platform
/// this build does not still *parses* — and is then rejected by validation with a clear
/// reason, rather than failing as malformed data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    /// A tag this build does not know.
    Other(String),
}

impl Platform {
    // One `cfg`-selected definition each, rather than one function branching internally:
    // the tag must not be derivable from `std::env::consts::OS`, which is what the unit
    // test compares against.
    #[cfg(windows)]
    pub fn current() -> Platform {
        Platform::Windows
    }

    #[cfg(target_os = "linux")]
    pub fn current() -> Platform {
        Platform::Linux
    }

    #[cfg(target_os = "macos")]
    pub fn current() -> Platform {
        Platform::MacOs
    }

    /// The wire string. These three literals ARE the persisted format — never change them.
    pub fn as_str(&self) -> &str {
        match self {
            Platform::Linux => "linux",
            Platform::MacOs => "macos",
            Platform::Windows => "windows",
            Platform::Other(s) => s,
        }
    }

    /// Parse a wire string. Unknown tags become [`Platform::Other`] rather than an error,
    /// so validation — not the decoder — decides what to do with them. Public so a caller
    /// persisting records in an encoding of their own can produce the same leniency.
    pub fn from_wire(s: &str) -> Platform {
        match s {
            "linux" => Platform::Linux,
            "macos" => Platform::MacOs,
            "windows" => Platform::Windows,
            other => Platform::Other(other.to_owned()),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Platform {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

// No `use serde::Deserialize;` in the body below: a trait is already in scope inside its
// own impl block, so the import would be unused and `-D warnings` rejects it. The identical
// import inside `mod token_str` IS required — those are free functions, not an impl.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Platform {
    /// Delegates to [`Platform::from_wire`], which documents the leniency policy.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Platform, D::Error> {
        Ok(Platform::from_wire(&String::deserialize(d)?))
    }
}

/// `u64` as a decimal string — see the `token` field's doc for why.
#[cfg(feature = "serde")]
mod token_str {
    pub(super) fn serialize<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        use serde::Deserialize;
        let s = String::deserialize(d)?;
        s.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

/// A [`ProcessId`](super::ProcessId) in persistable form: inert data with no invariants.
/// Every check happens on the way back, in `TryFrom<&ProcessIdRecord> for ProcessId`.
///
/// Fields are public so a caller can persist it with an encoding of their own; `serde`
/// impls are available behind the `serde` feature.
///
/// `token` is the RAW kernel value and is opaque — its only meaning is exact equality
/// within one platform and boot session. Do not compare, order, or interpret it yourself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessIdRecord {
    /// [`RECORD_VERSION`] at the time of writing.
    #[cfg_attr(feature = "serde", serde(rename = "v"))]
    pub version: u32,
    /// The OS that produced the token.
    pub platform: Platform,
    pub pid: RawPid,
    /// The raw kernel start token. Opaque.
    ///
    /// On the wire it is a DECIMAL STRING, not a number: a Windows creation `FILETIME` is
    /// around 1.3e17, well past the 2^53 a JSON consumer with double-precision numbers can
    /// represent, and a silently-rounded token is exactly the aliasing this type prevents.
    #[cfg_attr(feature = "serde", serde(with = "token_str"))]
    pub token: u64,
    /// Linux: `/proc/sys/kernel/random/boot_id`, the boot the jiffy token is counted from.
    /// `None` on Windows and macOS, whose tokens are absolute.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub boot_id: Option<String>,
    /// Linux: the inode of `/proc/self/ns/pid`, naming the pid namespace `pid` is in.
    /// `None` on Windows and macOS, which have no pid namespaces.
    ///
    /// An additional filter, not a guarantee: the kernel reuses namespace inode numbers
    /// once a namespace is destroyed, so a match does not prove the namespace is the same
    /// one. With a recycled inode the record falls back to the protection it would have
    /// had without this field — `(pid, boot_id, token)` — never less.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub pid_ns: Option<u64>,
}

/// The live session a token has to belong to, as read from THIS host. Empty on platforms
/// whose token is an absolute timestamp and therefore self-scoping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Scope {
    pub(crate) boot_id: Option<String>,
    pub(crate) pid_ns: Option<u64>,
}

impl Scope {
    /// Consumed only by the Windows and macOS backends, whose tokens are absolute and so
    /// need no scope; the Linux backend builds a populated `Scope` directly. Dead on a
    /// Linux build, which is the platform the `-D warnings` lint job runs on.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) fn none() -> Scope {
        Scope::default()
    }
}

/// A failed read of this host's own session scope, keeping WHICH read failed. Discarding
/// that would leave a caller unable to tell an unmounted `/proc` from a refused read.
#[derive(Debug)]
pub(crate) struct ScopeReadError {
    /// The path whose read failed, as it was actually attempted.
    pub(crate) path: String,
    pub(crate) source: std::io::Error,
}

/// The single mapping from a failed scope read to the crate error, shared by both
/// directions (writing a record and restoring one). Pure, so it is tested on every host.
pub(crate) fn scope_error(e: ScopeReadError) -> Error {
    Error::IdentityRecord {
        kind: RecordErrorKind::ScopeUnreadable,
        detail: format!("{} could not be read: {}", e.path, e.source),
        source: Some(e.source),
    }
}

/// Whether `pid`, read from a file, can name a single process on `here`.
///
/// Unix reuses [`signal_target`](super::probe::signal_target) rather than restating its
/// rule: that function is what stands between the crate and `kill(-N, sig)` hitting a whole
/// process group, and there must be exactly one copy of it. Windows pids are full `DWORD`s
/// and are never a `kill(2)` target, so only zero is refused there.
fn pid_is_addressable(pid: RawPid, here: &Platform) -> bool {
    match here {
        Platform::Windows => pid != 0,
        _ => super::probe::signal_target(pid).is_some(),
    }
}

/// The crate error for a rejected record, naming the values that diverged — `kind` alone
/// says only which category failed.
pub(crate) fn reject(record: &ProcessIdRecord, scope: &Scope, kind: RecordErrorKind) -> Error {
    Error::IdentityRecord {
        kind,
        detail: format!(
            "record v{} from {} for pid {} (boot_id {:?} vs live {:?}, pid_ns {:?} vs live {:?})",
            record.version,
            record.platform.as_str(),
            record.pid,
            record.boot_id,
            scope.boot_id,
            record.pid_ns,
            scope.pid_ns,
        ),
        source: None,
    }
}

/// The whole rejection rule, pure: no OS reads, so it is compiled and tested on every host.
///
/// Order matters. Version is checked FIRST: a future format may reuse these fields with
/// different meanings, so nothing else may be believed until the version is known. The
/// platform is checked SECOND, because the pid rule below is chosen by platform.
///
/// The scope rule is one-sided by design: a field the host does not use (`None` in `scope`)
/// is ignored in the record. Since the platform tag has already matched, the two sides
/// always agree on which fields are in use.
pub(crate) fn validate(
    record: &ProcessIdRecord,
    here: &Platform,
    scope: &Scope,
) -> Result<(RawPid, u64), RecordErrorKind> {
    if record.version != RECORD_VERSION {
        return Err(RecordErrorKind::UnknownVersion);
    }
    if &record.platform != here {
        return Err(RecordErrorKind::ForeignPlatform);
    }
    if !pid_is_addressable(record.pid, here) {
        return Err(RecordErrorKind::InvalidPid);
    }
    if let Some(live) = &scope.boot_id {
        match &record.boot_id {
            None => return Err(RecordErrorKind::MissingBootSession),
            Some(saved) if saved != live => return Err(RecordErrorKind::ForeignBootSession),
            Some(_) => {}
        }
    }
    if let Some(live) = scope.pid_ns {
        match record.pid_ns {
            None => return Err(RecordErrorKind::MissingPidNamespace),
            Some(saved) if saved != live => return Err(RecordErrorKind::ForeignPidNamespace),
            Some(_) => {}
        }
    }
    Ok((record.pid, record.token))
}

/// `to_record` with the scope read passed in, so a test can hand it a failure. Everything
/// `to_record` does — including the `?` that decides whether a failed scope read aborts the
/// write — lives here, where it runs on every host.
fn record_from(id: &ProcessId, scope: Result<Scope, ScopeReadError>) -> Result<ProcessIdRecord, Error> {
    let scope = scope.map_err(scope_error)?;
    Ok(ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::current(),
        pid: id.pid,
        token: id.start.raw(),
        boot_id: scope.boot_id,
        pid_ns: scope.pid_ns,
    })
}

/// `try_from` with the scope read passed in, for the same reason as [`record_from`].
fn restore(
    record: &ProcessIdRecord,
    here: &Platform,
    scope: Result<Scope, ScopeReadError>,
) -> Result<ProcessId, Error> {
    let scope = scope.map_err(scope_error)?;
    let (pid, token) = validate(record, here, &scope).map_err(|kind| reject(record, &scope, kind))?;
    Ok(ProcessId {
        pid,
        start: StartToken::from_raw(token),
    })
}

impl ProcessId {
    /// This identity in persistable form. Restore it with `ProcessId::try_from`.
    ///
    /// `Err` only when this host cannot describe its own boot session — on Linux, `/proc`
    /// not being mounted. Emitting a record that could never be validated would be worse
    /// than failing here.
    pub fn to_record(&self) -> Result<ProcessIdRecord, Error> {
        record_from(self, backend::session_scope())
    }
}

impl TryFrom<&ProcessIdRecord> for ProcessId {
    type Error = Error;

    /// Restore a persisted identity. The ONLY way back from a record: there is deliberately
    /// no infallible from-parts constructor, because a token from another platform, boot
    /// session, or pid namespace would alias onto an unrelated process. See
    /// [`RecordErrorKind`] for every way this refuses.
    fn try_from(record: &ProcessIdRecord) -> Result<ProcessId, Error> {
        restore(record, &Platform::current(), backend::session_scope())
    }
}

impl TryFrom<ProcessIdRecord> for ProcessId {
    type Error = Error;

    fn try_from(record: ProcessIdRecord) -> Result<ProcessId, Error> {
        ProcessId::try_from(&record)
    }
}

#[cfg(test)]
#[path = "persist_tests.rs"]
mod persist_tests;

#[cfg(test)]
#[path = "persist_serde_tests.rs"]
mod persist_serde_tests;
