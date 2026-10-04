//! The shim's wire protocol (plan F, D3): the invocation argv, and the frames the shim sends cosca.
//!
//! Pure: no I/O, no system calls. The shim (F4) and cosca's link (F3) both build on it.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

/// `argv[1]` of a plain invocation. Every argument is the bytes it appears as.
const FLAG: &[u8] = b"--cosca-elevation-shim=1";
/// `argv[1]` of a hex invocation: every argument after it except [`SEPARATOR`] is lowercase hex, so
/// the text survives `osascript`, which is not byte-transparent (§17.3).
const FLAG_HEX: &[u8] = b"--cosca-elevation-shim=1x";
/// What every version's flag starts with.
const FLAG_PREFIX: &[u8] = b"--cosca-elevation-shim";
const SEPARATOR: &str = "--";
/// Index of [`SEPARATOR`]: `[exe, flag, dir, pid, identity, euid, search, "--", program, args…]`.
const SEPARATOR_AT: usize = 7;

/// A raw `errno`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(pub(crate) i32);

/// A raw signal number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signal(pub(crate) i32);

/// macOS only: cosca's `p_uniqueid` and `p_idversion` (D2). Linux passes none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShimIdentity {
    pub(crate) unique_id: u64,
    pub(crate) id_version: u32,
}

/// What the shim is told on its command line (D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShimArgs {
    /// The private directory holding cosca's listener `s` (D14).
    pub(crate) dir: PathBuf,
    pub(crate) cosca_pid: u32,
    pub(crate) cosca_identity: Option<ShimIdentity>,
    pub(crate) cosca_euid: u32,
    /// `None`: search the shim's own `PATH`. `Some`: search this one (pkexec, D11); empty is a real,
    /// empty `PATH`.
    pub(crate) search_path: Option<OsString>,
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
}

/// Why argv is not a valid shim invocation. The shim exits 120 (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ShimArgsError {
    #[error("unknown protocol version")]
    UnknownVersion,
    #[error("too few arguments")]
    TooFewArguments,
    #[error("the separator `--` is missing")]
    MissingSeparator,
    #[error("malformed hex argument")]
    BadHex,
    #[error("malformed number")]
    BadNumber,
    #[error("malformed identity")]
    BadIdentity,
    #[error("malformed search path")]
    BadSearch,
}

impl ShimArgs {
    /// `[exe, flag, dir, pid, identity, euid, search, "--", program, args…]`. With `hex`, every
    /// argument after the flag except `--` is hex.
    pub(crate) fn to_argv(&self, exe: &OsStr, hex: bool) -> Vec<OsString> {
        let identity = match self.cosca_identity {
            None => OsString::from("-"),
            Some(ShimIdentity { unique_id, id_version }) => OsString::from(format!("{unique_id}:{id_version}")),
        };
        let search = match &self.search_path {
            None => OsString::from("-"),
            Some(path) => {
                let mut token = OsString::from("P");
                token.push(path);
                token
            }
        };
        let before: [OsString; 5] = [
            self.dir.clone().into_os_string(),
            self.cosca_pid.to_string().into(),
            identity,
            self.cosca_euid.to_string().into(),
            search,
        ];
        let encode = |a: OsString| if hex { to_hex(&a) } else { a };

        let mut argv = Vec::with_capacity(SEPARATOR_AT + 1 + self.args.len() + 1);
        argv.push(exe.to_owned());
        argv.push(OsStr::from_bytes(if hex { FLAG_HEX } else { FLAG }).to_owned());
        argv.extend(before.into_iter().map(encode));
        argv.push(SEPARATOR.into());
        argv.push(encode(self.program.clone()));
        argv.extend(self.args.iter().cloned().map(encode));
        debug_assert_eq!(argv[SEPARATOR_AT], SEPARATOR);
        argv
    }

    /// `Ok(None)` when `argv` is not a shim invocation at all; an error when it claims to be one and
    /// is not valid. `argv` includes `argv[0]`.
    pub(crate) fn parse(argv: &[OsString]) -> Result<Option<ShimArgs>, ShimArgsError> {
        let Some(flag) = argv.get(1) else { return Ok(None) };
        let Some(version) = flag.as_bytes().strip_prefix(FLAG_PREFIX) else {
            return Ok(None);
        };
        let hex = if flag.as_bytes() == FLAG {
            false
        } else if flag.as_bytes() == FLAG_HEX {
            true
        } else {
            debug_assert!(!version.is_empty() || flag.as_bytes() == FLAG_PREFIX);
            return Err(ShimArgsError::UnknownVersion);
        };
        if argv.len() <= SEPARATOR_AT + 1 {
            return Err(ShimArgsError::TooFewArguments);
        }
        if argv[SEPARATOR_AT] != SEPARATOR {
            return Err(ShimArgsError::MissingSeparator);
        }

        let decoded: Vec<OsString>;
        let fields: &[OsString] = if hex {
            let mut out = Vec::with_capacity(argv.len() - 2);
            for (i, a) in argv.iter().enumerate().skip(2) {
                out.push(if i == SEPARATOR_AT { a.clone() } else { from_hex(a)? });
            }
            decoded = out;
            &decoded
        } else {
            &argv[2..]
        };
        // `fields[i]` is `argv[i + 2]`.
        let [dir, pid, identity, euid, search, _separator, program, args @ ..] = fields else {
            return Err(ShimArgsError::TooFewArguments);
        };
        Ok(Some(ShimArgs {
            dir: PathBuf::from(dir),
            cosca_pid: decimal_u32(pid)?,
            cosca_identity: parse_identity(identity)?,
            cosca_euid: decimal_u32(euid)?,
            search_path: parse_search(search)?,
            program: program.clone(),
            args: args.to_vec(),
        }))
    }
}

fn to_hex(a: &OsStr) -> OsString {
    use std::fmt::Write;
    let mut s = String::with_capacity(a.len() * 2);
    for b in a.as_bytes() {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s.into()
}

fn from_hex(a: &OsStr) -> Result<OsString, ShimArgsError> {
    let (pairs, odd) = a.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return Err(ShimArgsError::BadHex);
    }
    let nibble = |c: u8| char::from(c).to_digit(16).map(|d| d as u8).ok_or(ShimArgsError::BadHex);
    let out = pairs
        .iter()
        .map(|[hi, lo]| Ok(nibble(*hi)? << 4 | nibble(*lo)?))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(OsString::from_vec(out))
}

/// Decimal digits only: no sign, no whitespace.
fn decimal<T: std::str::FromStr>(a: &[u8]) -> Option<T> {
    if a.is_empty() || !a.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(a).ok()?.parse().ok()
}

fn decimal_u32(a: &OsStr) -> Result<u32, ShimArgsError> {
    decimal(a.as_bytes()).ok_or(ShimArgsError::BadNumber)
}

fn parse_identity(a: &OsStr) -> Result<Option<ShimIdentity>, ShimArgsError> {
    if a.as_bytes() == b"-" {
        return Ok(None);
    }
    let mut halves = a.as_bytes().split(|&b| b == b':');
    let (Some(unique_id), Some(id_version), None) = (halves.next(), halves.next(), halves.next()) else {
        return Err(ShimArgsError::BadIdentity);
    };
    Ok(Some(ShimIdentity {
        unique_id: decimal(unique_id).ok_or(ShimArgsError::BadIdentity)?,
        id_version: decimal(id_version).ok_or(ShimArgsError::BadIdentity)?,
    }))
}

fn parse_search(a: &OsStr) -> Result<Option<OsString>, ShimArgsError> {
    match a.as_bytes() {
        b"-" => Ok(None),
        [b'P', path @ ..] => Ok(Some(OsString::from_vec(path.to_vec()))),
        _ => Err(ShimArgsError::BadSearch),
    }
}

/// Why the program never ran: `F` frame kinds 1 to 4 (D3). The shim has positive evidence of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotExecuted {
    ForkFailed(Errno),
    ExecFailed(Errno),
    SetupFailed(Errno),
    TerminatedBeforeExec(Signal),
}

/// One shim to cosca frame (D3). `Hello` is the single byte `H`; the rest are a tag and a
/// little-endian `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Frame {
    /// `H`
    Hello,
    /// `S`: the program's wait status.
    Status(i32),
    /// `L`: the possibly-started program was killed after supervision failed; its wait status.
    Lost(i32),
    /// `U`: the program has exited and its status is lost. Encoded with a zero payload, ignored on
    /// decode.
    StatusLost,
    /// `F`: positive evidence the program never ran.
    NotExecuted(NotExecuted),
    /// `R`: refused after hello, with the shim's exit code.
    Refused(i32),
}

/// A frame that cannot be decoded. Both map to `ShimLost` (D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameError {
    /// A valid prefix: more bytes may follow.
    #[error("truncated frame")]
    Truncated,
    /// Never a valid frame, whatever follows.
    #[error("garbled frame")]
    Garbled,
}

const KIND_FORK: u32 = 1;
const KIND_EXEC: u32 = 2;
const KIND_SETUP: u32 = 3;
const KIND_TERM: u32 = 4;

impl Frame {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let (tag, value) = match *self {
            Frame::Hello => return vec![b'H'],
            Frame::Status(ws) => (b'S', ws),
            Frame::Lost(ws) => (b'L', ws),
            Frame::StatusLost => (b'U', 0),
            Frame::NotExecuted(n) => {
                let (kind, value) = match n {
                    NotExecuted::ForkFailed(Errno(e)) => (KIND_FORK, e),
                    NotExecuted::ExecFailed(Errno(e)) => (KIND_EXEC, e),
                    NotExecuted::SetupFailed(Errno(e)) => (KIND_SETUP, e),
                    NotExecuted::TerminatedBeforeExec(Signal(s)) => (KIND_TERM, s),
                };
                debug_assert!(
                    (1..=0xffff).contains(&value),
                    "an F value is nonzero and fits 16 bits: {value}"
                );
                (b'F', (kind << 16 | value as u32 & 0xffff) as i32)
            }
            Frame::Refused(code) => (b'R', code),
        };
        let mut out = vec![tag];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }
}

/// Decodes exactly one frame: `bytes` is the whole frame, no more and no less.
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameError> {
    let Some((&tag, payload)) = bytes.split_first() else {
        return Err(FrameError::Truncated);
    };
    if !b"HSLUFR".contains(&tag) {
        return Err(FrameError::Garbled);
    }
    if tag == b'H' {
        return if payload.is_empty() {
            Ok(Frame::Hello)
        } else {
            Err(FrameError::Garbled)
        };
    }
    let payload: [u8; 4] = match payload.len() {
        0..=3 => return Err(FrameError::Truncated),
        4 => payload.try_into().expect("length checked"),
        _ => return Err(FrameError::Garbled),
    };
    let value = i32::from_le_bytes(payload);
    Ok(match tag {
        b'S' => Frame::Status(value),
        b'L' => Frame::Lost(value),
        b'U' => Frame::StatusLost,
        b'R' => Frame::Refused(value),
        b'F' => {
            let (kind, errno_or_signo) = (value as u32 >> 16, (value & 0xffff));
            if errno_or_signo == 0 {
                return Err(FrameError::Garbled);
            }
            Frame::NotExecuted(match kind {
                KIND_FORK => NotExecuted::ForkFailed(Errno(errno_or_signo)),
                KIND_EXEC => NotExecuted::ExecFailed(Errno(errno_or_signo)),
                KIND_SETUP => NotExecuted::SetupFailed(Errno(errno_or_signo)),
                KIND_TERM => NotExecuted::TerminatedBeforeExec(Signal(errno_or_signo)),
                _ => return Err(FrameError::Garbled),
            })
        }
        _ => unreachable!("tag checked above"),
    })
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
