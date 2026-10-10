#!/usr/bin/env python3
"""Lets graphical elevation run without a person on a disposable machine.

    sudo python3 unattended-gui-elevation.py --this-machine-is-disposable --user USER   # Linux
    sudo python3 unattended-gui-elevation.py --this-machine-is-disposable               # macOS
    python3 unattended-gui-elevation.py --this-machine-is-disposable                    # Windows, elevated, CI only
    python3 unattended-gui-elevation.py --this-machine-is-disposable --check-only       # only the guard, no change
    ... --this-machine-is-disposable [--user USER] --revert                              # puts the saved state back

What it changes, system-wide:

- Linux: a polkit JavaScript rule that allows USER every action, so `pkexec` (`Auth::Gui`) needs no
  authentication agent. USER must be an existing, non-root account (polkit always authorizes root, so a root
  user would make the check below prove nothing). It needs polkit 0.106 or later (earlier versions read `.pkla`
  files, not `rules.d`) and systemd as PID 1: it restarts `polkit.service`, which returns once the service
  reports itself ready. Any other setup is refused before anything is written. It checks afterwards that USER
  can really run `pkexec` unattended. Every tool it needs (`pkaction`, `pkexec`, `runuser`, `systemctl`) is
  checked before the rule is written, and every command runs with a scrubbed environment (no
  `SYSTEMCTL_FORCE_BUS` or `DBUS_*` from the caller).
- macOS: `security authorizationdb write system.privilege.admin allow`, the right behind
  `osascript ... with administrator privileges`. It grants EVERY account and process administrator rights
  without authentication, not only a chosen user.
- Windows: `ConsentPromptBehaviorAdmin=0` ("elevate without prompting") under
  `HKLM\\...\\Policies\\System` (the 64-bit view). Hosted runner images already have it; it is set here so the
  setup does not depend on the image, and read back (it must be `0`, a `REG_DWORD`) so a lost write fails.

These weaken the machine's security until reverted. Before it changes anything, the script writes the prior state to a
state file (`/etc/cosca-unattended-gui-elevation-state.json`; Windows: `%ProgramData%\\cosca-unattended-gui-elevation-state.json`),
and refuses to run when that file exists (a second run would save the changed state as the prior one). `--revert`
restores exactly the saved state and removes the file; the CI jobs run it on success and on failure. It does
nothing when there is no state file, and refuses a state file written for another OS or another `--user` (Linux
needs `--user` to revert, too). Reverting:

- Linux: the rule file goes back to what it was (absent: removed; present: its content restored), `polkit.service`
  restarts, and the user's `pkexec` result must be what it was before.
- macOS: the saved `system.privilege.admin` right is written back and read back.
- Windows: `ConsentPromptBehaviorAdmin` gets its saved value and type back, or is deleted if it was absent, and is
  read back.

`--revert` and enabling take the same guard, because a developer can run this in a devvm guest and has to undo it
there: the machine must be disposable, which takes both the flag `--this-machine-is-disposable` and a fact about the machine:

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
import base64
import json
import os
import platform
import plistlib
import re
import shutil
import stat
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


STATE_FILE_NAME = "cosca-unattended-gui-elevation-state.json"


def default_state_path(system, environ=os.environ):
    if system == "Windows":
        return os.path.join(environ.get("ProgramData", r"C:\ProgramData"), STATE_FILE_NAME)
    return "/etc/" + STATE_FILE_NAME


def write_state(path, system, user, prior):
    """Records the prior state. Atomic, and fails if a state file exists (a second enable would save the changed state)."""
    temporary = f"{path}.{os.getpid()}.new"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({"system": system, "user": user, "prior": prior}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, path)  # fails if `path` exists
    except FileExistsError:
        sys.exit(f"refusing: {path} exists, so an enable already ran here; run --revert first")
    finally:
        os.unlink(temporary)


def read_state(path, system, user):
    """The saved prior state, or None when there is no state file. Exits on a state file for another OS or user."""
    try:
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError:
        return None
    if state.get("system") != system or state.get("user") != user:
        sys.exit(
            f"refusing: {path} was written for {state.get('system')!r} with --user {state.get('user')!r}, "
            f"not for {system!r} with --user {user!r}"
        )
    return state["prior"]


def pkexec_grants(user, env):
    """Whether USER can run `pkexec` with no agent and no prompt."""
    check = subprocess.run(
        ["runuser", "-u", user, "--", "pkexec", "--disable-internal-agent", "/usr/bin/id", "-u"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    return check, check.returncode == 0 and check.stdout.strip() == "0"


def write_atomically(path, data, mode, uid=None, gid=None):
    """Writes `data` to `path` so a reader never sees a half-written file, and leaves no temporary file behind."""
    temporary = path + ".new"
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, mode)
        if uid is not None:
            os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def enable_linux(
    user, save, isdir=os.path.isdir, init_comm=comm_of, getpwnam=None, environ=os.environ, rule_path=POLKIT_RULE_PATH
):
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

    # The prior state: the rule file (absent, or its bytes, mode and owner) and whether USER already had a grant.
    try:
        with open(rule_path, "rb") as rule:
            prior_bytes = rule.read()
        meta = os.stat(rule_path)
        prior_rule = {
            "bytes": base64.b64encode(prior_bytes).decode("ascii"),
            "mode": stat.S_IMODE(meta.st_mode),
            "uid": meta.st_uid,
            "gid": meta.st_gid,
        }
    except FileNotFoundError:
        prior_rule = None
    save({"rule": prior_rule, "granted": pkexec_grants(user, env)[1]})

    write_atomically(rule_path, POLKIT_RULE.format(user=user).encode("ascii"), 0o644)

    # `systemctl restart` returns once polkit.service is up: it notifies readiness (Type=notify-reload on Ubuntu 26.04).
    subprocess.run(["systemctl", "restart", "polkit"], check=True, env=env)

    # The change took effect only if the user can run pkexec with no agent and no prompt.
    check, granted = pkexec_grants(user, env)
    if not granted:
        sys.exit(
            f"the polkit rule did not take effect: pkexec as {user} exited {check.returncode} "
            f"with stdout {check.stdout.strip()!r}, stderr {check.stderr.strip()!r}"
        )


def revert_linux(user, prior, environ=os.environ, rule_path=POLKIT_RULE_PATH):
    env = scrubbed_environment(environ)
    if prior["rule"] is None:
        try:
            os.unlink(rule_path)
        except FileNotFoundError:
            pass
    else:
        prior_rule = prior["rule"]
        write_atomically(
            rule_path,
            base64.b64decode(prior_rule["bytes"]),
            prior_rule["mode"],
            prior_rule["uid"],
            prior_rule["gid"],
        )
    subprocess.run(["systemctl", "restart", "polkit"], check=True, env=env)
    check, granted = pkexec_grants(user, env)
    if granted != prior["granted"]:
        sys.exit(
            f"polkit still differs from before the enable: pkexec as {user} grants={granted}, before it was "
            f"{prior['granted']} (exit {check.returncode}, stdout {check.stdout.strip()!r}, stderr {check.stderr.strip()!r})"
        )


def read_macos_right(env):
    return plistlib.loads(
        subprocess.run(
            ["security", "authorizationdb", "read", "system.privilege.admin"], check=True, capture_output=True, env=env
        ).stdout
    )


def enable_macos(save):
    env = scrubbed_environment()
    save({"right": plistlib.dumps(read_macos_right(env)).decode("utf-8")})
    subprocess.run(["security", "authorizationdb", "write", "system.privilege.admin", "allow"], check=True, env=env)
    right = read_macos_right(env)
    if right.get("rule") != ["allow"]:
        sys.exit(f"the authorization right did not take effect: {right!r}")


def revert_macos(prior):
    env = scrubbed_environment()
    saved = plistlib.loads(prior["right"].encode("utf-8"))
    subprocess.run(
        ["security", "authorizationdb", "write", "system.privilege.admin"],
        input=prior["right"].encode("utf-8"),
        check=True,
        env=env,
    )
    right = read_macos_right(env)
    # `modified` is the database's own timestamp of the write, so it can't match.
    without_timestamp = lambda right: {key: value for key, value in right.items() if key != "modified"}  # noqa: E731
    if without_timestamp(right) != without_timestamp(saved):
        sys.exit(f"the authorization right reads back {right!r} after restoring {saved!r}")


WINDOWS_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
WINDOWS_VALUE = "ConsentPromptBehaviorAdmin"


def enable_windows(save):
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_POLICY_KEY, 0, access) as handle:
        try:
            value, kind = winreg.QueryValueEx(handle, WINDOWS_VALUE)
            save({"present": True, "value": value, "type": kind})
        except FileNotFoundError:
            save({"present": False})
        winreg.SetValueEx(handle, WINDOWS_VALUE, 0, winreg.REG_DWORD, 0)
        stored = winreg.QueryValueEx(handle, WINDOWS_VALUE)
    if stored != (0, winreg.REG_DWORD):
        sys.exit(f"{WINDOWS_VALUE} reads back {stored!r} after setting it to (0, REG_DWORD)")


def revert_windows(prior):
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_POLICY_KEY, 0, access) as handle:
        if prior["present"]:
            winreg.SetValueEx(handle, WINDOWS_VALUE, 0, prior["type"], prior["value"])
            stored = winreg.QueryValueEx(handle, WINDOWS_VALUE)
            if stored != (prior["value"], prior["type"]):
                sys.exit(f"{WINDOWS_VALUE} reads back {stored!r} after restoring {(prior['value'], prior['type'])!r}")
        else:
            try:
                winreg.DeleteValue(handle, WINDOWS_VALUE)
            except FileNotFoundError:
                pass
            try:
                stored = winreg.QueryValueEx(handle, WINDOWS_VALUE)
            except FileNotFoundError:
                return
            sys.exit(f"{WINDOWS_VALUE} reads back {stored!r} after deleting it")


ENABLERS = {
    "Linux": enable_linux,
    "Darwin": lambda user, save: enable_macos(save),
    "Windows": lambda user, save: enable_windows(save),
}
REVERTERS = {
    "Linux": revert_linux,
    "Darwin": lambda user, prior: revert_macos(prior),
    "Windows": lambda user, prior: revert_windows(prior),
}


def main(
    argv,
    system=None,
    environ=os.environ,
    exists=os.path.exists,
    enablers=None,
    reverters=None,
    geteuid=getattr(os, "geteuid", None),
    state_path=None,
):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--this-machine-is-disposable",
        action="store_true",
        help="required: states that this machine is a throwaway CI runner or devvm guest",
    )
    parser.add_argument("--user", help="Linux only: the account to authorize")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-only", action="store_true", help="only check that the machine is disposable")
    mode.add_argument("--revert", action="store_true", help="put back the state the enable saved")
    args = parser.parse_args(argv)
    if not args.this_machine_is_disposable:
        refuse("this weakens the machine's security; pass --this-machine-is-disposable on a throwaway machine")

    system = system or platform.system()
    if args.user is not None and system != "Linux":
        sys.exit(f"--user applies to Linux only; {system} has no per-user setting")
    require_disposable(system, environ=environ, exists=exists)
    if args.check_only:
        print(f"{system}: this machine is disposable")
        return
    table = (reverters or REVERTERS) if args.revert else (enablers or ENABLERS)
    action = table.get(system)
    if action is None:
        sys.exit(f"unsupported platform: {system}")
    # `security` may prompt for a password, which hangs a headless guest: refuse before any change.
    if system in ("Linux", "Darwin") and geteuid is not None and geteuid() != 0:
        sys.exit("refusing: this needs root; run it with sudo")
    state_path = state_path or default_state_path(system)
    if args.revert:
        if system == "Linux" and args.user is None:
            sys.exit("--user is required to revert on Linux: the state file names the account it was written for")
        prior = read_state(state_path, system, args.user)
        if prior is None:
            print(f"no state file at {state_path}: nothing to revert")
            return
        action(args.user, prior)
        os.unlink(state_path)
        print(f"unattended GUI elevation reverted on {system}")
        return
    if os.path.exists(state_path):
        sys.exit(f"refusing: {state_path} exists, so an enable already ran here; run --revert first")
    action(args.user, lambda prior: write_state(state_path, system, args.user, prior))
    print(f"unattended GUI elevation enabled on {system}")


if __name__ == "__main__":
    main(sys.argv[1:])
