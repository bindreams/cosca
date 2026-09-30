#!/usr/bin/env python3
"""THROWAWAY (PR #377): COSCA_UH_MUTANT-selected mutants of the tracer helper. Run from the root."""
import pathlib

MACHINE = pathlib.Path("src/test_support/tracer/machine.rs")
SYS = pathlib.Path("src/test_support/tracer/sys.rs")
CLIENT = pathlib.Path("src/test_support/tracer.rs")


def sub(path, old, new, count=1):
    s = path.read_text()
    assert s.count(old) == count, (path, old, s.count(old))
    path.write_text(s.replace(old, new))


M_FN = '''fn m(name: &str) -> bool {
    std::env::var("COSCA_UH_MUTANT").as_deref() == Ok(name)
}

'''
sub(MACHINE, "const FIRST_BACKOFF", M_FN + "const FIRST_BACKOFF")
sub(CLIENT, "const DEFAULT_MARKER", M_FN + "const DEFAULT_MARKER")
sub(SYS, "fn errno() -> i32 {", M_FN + "fn errno() -> i32 {")

# D1: pass an ignored stop signal on. D2: deliver a caught stop signal at once.
sub(MACHINE, "let delivered = if release == Release::Deliver { signal } else { 0 };",
    "let delivered = if release == Release::Deliver || (m(\"d1\") && release == Release::Drop) || (m(\"d2\") && release == Release::Hold) { signal } else { 0 };")
# D3: keep the assertion.
sub(SYS, "let (ignored, caught) = (info.kp_proc.sig_ignored(signal), info.kp_proc.sig_caught(signal));",
    "let (ignored, caught) = (info.kp_proc.sig_ignored(signal), info.kp_proc.sig_caught(signal));\n            if m(\"d3\") { debug_assert!(!(ignored && caught), \"signal {signal} is both ignored and caught\"); }")
# H1: no setpgid.
sub(CLIENT, "let rc = unsafe { libc::setpgid(0, 0) };",
    "let rc = if m(\"h1\") { 0 } else { unsafe { libc::setpgid(0, 0) } };")
# The hard-coded SIGTSTP.
sub(MACHINE, ".unwrap_or_else(|| sys::disposition(self.pid, signal))",
    ".unwrap_or_else(|| sys::disposition(self.pid, if m(\"sigtstp\") { libc::SIGTSTP } else { signal }))")
# Extra: a SIGCONT keeps every held signal; a SIGCONT drops every held one; held not re-sent;
# a failed disposition read taken as the default action.
sub(MACHINE, "self.resend.retain(|r| !r.cancellable);",
    "self.resend.retain(|r| if m(\"cont_keeps_held\") { !r.kept } else if m(\"cont_drops_held\") { false } else { !r.cancellable });")
sub(MACHINE, "                Release::Hold => {\n                    self.resend.push(Resend {",
    "                Release::Hold => {\n                    if !m(\"held_not_resent\") { self.resend.push(Resend {")
sub(MACHINE, "                        cancellable: stopped,\n                    });",
    "                        cancellable: stopped,\n                    }); }")
# The first re-sent signal is also sent by kill(2) after the detach that delivered it.
sub(MACHINE, "if at > 0 || !carried {", "if at > 0 || !carried || m(\"carry_none\") {")
# S4 detaches from its SIGSTOP stop although a signal to re-send waits.
sub(MACHINE, "Ok(Stop::Stopped(signal)) if act == Act::Detach && signal == self.detach_signal() => {",
    "Ok(Stop::Stopped(signal)) if act == Act::Detach && (signal == self.detach_signal() || (m(\"detach_from_sigstop\") && signal == libc::SIGSTOP)) => {")
sub(MACHINE, "Err(e) => return Ok(Err(e)),",
    "Err(_) if m(\"disp_err_default\") => Release::Keep,\n                Err(e) => return Ok(Err(e)),")
