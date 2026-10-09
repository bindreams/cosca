#!/usr/bin/env python3
"""Lets graphical elevation run without a person on a disposable machine.

    sudo python3 unattended-gui-elevation.py --this-machine-is-disposable --user USER   # Linux
    sudo python3 unattended-gui-elevation.py --this-machine-is-disposable               # macOS
    python3 unattended-gui-elevation.py --this-machine-is-disposable                    # Windows, elevated, CI only
    python3 unattended-gui-elevation.py --this-machine-is-disposable --check-only       # only the guard, no change

What it changes, system-wide:

- Linux: a polkit JavaScript rule that allows USER every action, so `pkexec` (`Auth::Gui`) needs no
  authentication agent. USER must be an existing, non-root account (polkit always authorizes root, so a root
  user would make the check below prove nothing). It needs polkit 0.106 or later (earlier versions read `.pkla`
  files, not `rules.d`; CI and the devvm Linux guests, Ubuntu 24.04 with polkit 124, qualify) and systemd as PID 1: it restarts `polkit.service`, which returns once the service reports itself ready. Any
  other setup is refused before anything is written. It checks afterwards that USER can really run `pkexec`
  unattended. Every tool it needs (`pkaction`, `pkexec`, `runuser`, `systemctl`) is checked before the rule is
  written, and every command runs with a scrubbed environment (no `SYSTEMCTL_FORCE_BUS` or `DBUS_*` from the caller).
- macOS: `security authorizationdb write system.privilege.admin allow`, the right behind
  `osascript ... with administrator privileges`. It grants EVERY account and process administrator rights
  without authentication, not only a chosen user.
- Windows: `ConsentPromptBehaviorAdmin=0` ("elevate without prompting") under
  `HKLM\\...\\Policies\\System` (the 64-bit view). Hosted runner images already have it; it is set here so the
  setup does not depend on the image, and read back (it must be `0`, a `REG_DWORD`) so a lost write fails.

These weaken the machine's security for good, so the script refuses unless the machine is disposable, which takes
both the flag `--this-machine-is-disposable` and a fact about the machine:

- a GitHub-hosted runner (`GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`), or
- a devvm guest (the marker file `/etc/cosca-devvm-guest`, written by the devvm driver).

Both are virtual machines. A container is not evidence of disposability, as it is only as isolated as its mounts,
which a script cannot prove; one passes only on a disposable host (a job `container:` on a hosted runner inherits the
runner's variables).

It needs root (Linux, macOS; refused otherwise, before any change) or an elevated token (Windows) and does not
elevate itself. `sudo` resets the
environment (classic sudo and sudo-rs alike) and so drops the CI variables: pass them explicitly,
`sudo env GITHUB_ACTIONS=... RUNNER_ENVIRONMENT=... python3 ...`.
"""

import argparse
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys

POLKIT_RULE_PATH = "/etc/polkit-1/rules.d/49-cosca-unattended.rules"
POLKIT_RULE = """\
polkit.addRule(function(action, subject) {{
  if (subject.user == "{user}") {{ return polkit.Result.YES; }}
}});
"""
USER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
DEVVM_MARKER = "/etc/cosca-devvm-guest"
# What the script's subprocesses get: the caller's environment could redirect systemctl or D-Bus to another machine.
SCRUBBED_ENVIRONMENT_PREFIXES = ("DBUS_", "SYSTEMCTL_", "SYSTEMD_", "XDG_RUNTIME_DIR")


def refuse(message):
    sys.exit(f"refusing: {message}")


def require_disposable(system, environ=os.environ, exists=os.path.exists):
    """Exits unless the machine is a GitHub-hosted runner or a devvm guest (both virtual machines)."""
    if environ.get("GITHUB_ACTIONS") == "true" and environ.get("RUNNER_ENVIRONMENT") == "github-hosted":
        return
    if system in ("Linux", "Darwin") and exists(DEVVM_MARKER):
        return
    refuse(
        "this does not look like a disposable machine. Missing: a GitHub-hosted runner "
        "(GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted) or a devvm guest "
        f"({DEVVM_MARKER}, written by the devvm driver)"
    )


def scrubbed_environment(environ=os.environ):
    return {name: value for name, value in environ.items() if not name.startswith(SCRUBBED_ENVIRONMENT_PREFIXES)}


def polkit_supports_javascript_rules(version_text):
    """Whether polkit reads `rules.d` JavaScript rules (0.106 and later); None when the version can't be parsed.

    Versions are `0.105`, `0.120`, then `121` onwards.
    """
    match = re.search(r"(\d+)(?:\.(\d+))?", version_text)
    if match is None:
        return None
    major, minor = int(match.group(1)), int(match.group(2) or 0)
    return major > 0 or minor >= 106


def comm_of(pid, proc="/proc"):
    try:
        with open(f"{proc}/{pid}/comm", encoding="ascii") as comm:
            return comm.read().strip()
    except OSError:
        return None  # the process ended


def require_ordinary_user(user, getpwnam=None):
    """Exits unless USER is an existing account other than root (polkit always authorizes root)."""
    if getpwnam is None:
        import pwd  # POSIX only: Linux is the only caller

        getpwnam = pwd.getpwnam
    if user is None or not USER_PATTERN.fullmatch(user):
        sys.exit("--user must name the account polkit should authorize (letters, digits, '_', '.', '-')")
    try:
        entry = getpwnam(user)
    except KeyError:
        sys.exit(f"--user {user!r} is not an account on this machine")
    if entry.pw_uid == 0:
        sys.exit(f"--user {user!r} is root, which polkit always authorizes: the check below would prove nothing")


def enable_linux(user, isdir=os.path.isdir, init_comm=comm_of, getpwnam=None, environ=os.environ):
    require_ordinary_user(user, getpwnam)
    if not isdir("/run/systemd/system") or init_comm(1) != "systemd":
        sys.exit("refusing: this needs systemd as PID 1; run it on a CI runner or a devvm guest with systemd")
    needed = ["pkaction", "pkexec", "runuser", "systemctl"]
    missing = [tool for tool in needed if shutil.which(tool) is None]
    if missing:
        sys.exit("missing tools: " + ", ".join(missing) + " (polkit provides pkaction and pkexec)")
    env = scrubbed_environment(environ)
    version = subprocess.run(["pkaction", "--version"], check=True, capture_output=True, text=True, env=env).stdout
    supported = polkit_supports_javascript_rules(version)
    if supported is None:
        sys.exit(f"could not parse polkit's version from: {version.strip()!r}")
    if not supported:
        sys.exit(f"polkit is too old for rules.d JavaScript rules (needs 0.106 or later): {version.strip()}")

    # Atomic: polkitd never reads a half-written rule.
    temporary = POLKIT_RULE_PATH + ".new"
    with open(temporary, "w", encoding="ascii") as rule:
        rule.write(POLKIT_RULE.format(user=user))
    os.chmod(temporary, 0o644)
    os.replace(temporary, POLKIT_RULE_PATH)

    # `systemctl restart` returns once polkit.service is up: it notifies readiness (Type=notify-reload on Ubuntu 26.04).
    subprocess.run(["systemctl", "restart", "polkit"], check=True, env=env)

    # The change took effect only if the user can run pkexec with no agent and no prompt.
    check = subprocess.run(
        ["runuser", "-u", user, "--", "pkexec", "--disable-internal-agent", "/usr/bin/id", "-u"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    if check.returncode != 0 or check.stdout.strip() != "0":
        sys.exit(
            f"the polkit rule did not take effect: pkexec as {user} exited {check.returncode} "
            f"with stdout {check.stdout.strip()!r}, stderr {check.stderr.strip()!r}"
        )


def enable_macos():
    subprocess.run(
        ["security", "authorizationdb", "write", "system.privilege.admin", "allow"], check=True, env=scrubbed_environment()
    )
    right = plistlib.loads(
        subprocess.run(
            ["security", "authorizationdb", "read", "system.privilege.admin"],
            check=True,
            capture_output=True,
            env=scrubbed_environment(),
        ).stdout
    )
    if right.get("rule") != ["allow"]:
        sys.exit(f"the authorization right did not take effect: {right!r}")


def enable_windows():
    import winreg

    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, access) as handle:
        winreg.SetValueEx(handle, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
        stored = winreg.QueryValueEx(handle, "ConsentPromptBehaviorAdmin")
    if stored != (0, winreg.REG_DWORD):
        sys.exit(f"ConsentPromptBehaviorAdmin reads back {stored!r} after setting it to (0, REG_DWORD)")


ENABLERS = {"Linux": enable_linux, "Darwin": lambda user: enable_macos(), "Windows": lambda user: enable_windows()}


def main(argv, system=None, environ=os.environ, exists=os.path.exists, enablers=None, geteuid=getattr(os, "geteuid", None)):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--this-machine-is-disposable",
        action="store_true",
        help="required: states that this machine is a throwaway CI runner or devvm guest",
    )
    parser.add_argument("--user", help="Linux only: the account to authorize")
    parser.add_argument("--check-only", action="store_true", help="only check that the machine is disposable")
    args = parser.parse_args(argv)
    if not args.this_machine_is_disposable:
        refuse("this weakens the machine's security for good; pass --this-machine-is-disposable on a throwaway machine")

    system = system or platform.system()
    if args.user is not None and system != "Linux":
        sys.exit(f"--user applies to Linux only; {system} has no per-user setting")
    require_disposable(system, environ=environ, exists=exists)
    if args.check_only:
        print(f"{system}: this machine is disposable")
        return
    enable = (enablers or ENABLERS).get(system)
    if enable is None:
        sys.exit(f"unsupported platform: {system}")
    # `security` may prompt for a password, which hangs a headless guest: refuse before any change.
    if system in ("Linux", "Darwin") and geteuid is not None and geteuid() != 0:
        sys.exit("refusing: this needs root; run it with sudo")
    enable(args.user)
    print(f"unattended GUI elevation enabled on {system}")


if __name__ == "__main__":
    main(sys.argv[1:])
