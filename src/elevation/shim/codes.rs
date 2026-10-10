//! The shim's exit codes. cosca does not interpret them: the frame decides. The
//! refusals after hello (122-125) are [`Refusal`](super::protocol::Refusal).

/// The possibly-started program's status was reaped by someone else (frame `U`).
pub(crate) const STATUS_LOST: i32 = 112;
/// The owner watch could not be set up.
pub(crate) const OWNER_WATCH: i32 = 116;
/// The program never ran (frame `F`).
pub(crate) const NOT_EXECUTED: i32 = 117;
/// Supervision failed after the child was created; the shim killed and reaped it (frame `L`).
pub(crate) const SUPERVISION: i32 = 118;
/// The child's own exit: the shim died before `PDEATHSIG` was armed. It never execs.
pub(crate) const NO_PARENT: i32 = 119;
/// Unknown invocation, protocol version or malformed hex.
pub(crate) const INVOCATION: i32 = 120;
/// A set-id context.
pub(crate) const SET_ID: i32 = 121;
/// The listener's pid or euid is not cosca's, checked before hello: nothing is written. After hello
/// the same code is [`Refusal::NotCosca`](super::protocol::Refusal::NotCosca).
pub(crate) const NOT_COSCA: i32 = 122;
/// Cosca exited before the start, checked before hello: nothing is written. After hello it is
/// [`Refusal::CoscaGone`](super::protocol::Refusal::CoscaGone).
pub(crate) const OWNER_GONE: i32 = 123;
/// The connection failed before hello: nothing is written.
pub(crate) const NO_ANSWER: i32 = 124;
