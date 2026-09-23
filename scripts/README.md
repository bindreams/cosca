# devvm — throwaway VMs for local system-affecting tests

cosca's subject matter — elevation, cgroups, Windows Job Objects, process trees — means its
most interesting tests change real system state: cgroups and cgroup leaves, Job Objects,
elevation and `ShellExecuteEx`, process trees, process-group signals, `pidfd`/`kqueue` waits
and reaping all reach outside a single process. **Those tests must never run against your own
machine.** `scripts/devvm.py` provisions throwaway VMs for that purpose, so the blast radius
of a scratch script bug is a disposable VM, not your laptop.

This is developer tooling, not shipped code and not a CI replacement — CI keeps the
regression probes; this is for the tests CI structurally cannot run (see
[Windows guests](#windows-guests) below).

## Prerequisites

Install on the host yourself — this tool does not install anything for you:

- [QEMU](https://www.qemu.org/): `brew install qemu`
- [Vagrant](https://www.vagrantup.com/): `brew install --cask hashicorp-vagrant` (the
  Homebrew cask; the Vagrant.app installer works too)
- The [vagrant-qemu](https://github.com/ppggff/vagrant-qemu) plugin, or an equivalent QEMU
  provider for Vagrant: `vagrant plugin install vagrant-qemu`
- `rsync` (ships with macOS)
- [`uv`](https://docs.astral.sh/uv/): `brew install uv` — runs `devvm.py` without a separate
  install step

Verify with `vagrant plugin list` (expect `vagrant-qemu`) and
`qemu-system-x86_64 --version` / `qemu-system-aarch64 --version`.

## Usage

```sh
uv run scripts/devvm.py list
uv run scripts/devvm.py up linux-x64
uv run scripts/devvm.py run linux-x64 -- cargo --version
uv run scripts/devvm.py ssh linux-x64
uv run scripts/devvm.py sync linux-x64      # after local changes, before the next `run`
uv run scripts/devvm.py halt linux-x64      # shut down, keep the disk
uv run scripts/devvm.py destroy linux-x64   # delete the VM and its state entirely
```

`run` executes one command; anything after `--` is passed through verbatim, e.g.:

```sh
uv run scripts/devvm.py run linux-x64 -- cargo test --features pty
```

Always `destroy` (or at least `halt`) guests you're done with — nothing here auto-expires a
running VM.

## Guests

| Guest           | Box                                    | Provider arch | Host arch it's native on |
| --------------- | -------------------------------------- | ------------- | ------------------------ |
| `linux-x64`     | `generic/ubuntu2204` (qemu, amd64)     | x86-64        | x86-64                   |
| `linux-arm64`   | `perk/ubuntu-2204-arm64` (qemu, arm64) | arm64         | arm64 (Apple Silicon)    |
| `windows-x64`   | `stromweld/windows-10` (qemu, amd64)   | x86-64        | x86-64                   |
| `windows-arm64` | _(none — see below)_                   | —             | —                        |

Both Linux boxes run Ubuntu 22.04; systemd 249 there defaults to the unified cgroup v2
hierarchy, which is why they're the guests for cosca's cgroup lanes.

On the emulated architecture, QEMU falls back to TCG (software emulation) instead of
HVF/KVM, which is dramatically slower — see [Windows guests](#windows-guests) for measured
numbers on this host.

### `windows-arm64`

No publicly available Vagrant box for Windows on arm64 targets the `qemu` or `libvirt`
provider this tool uses. Checked 2026-09-23 on Vagrant Cloud: `hbsmith/win11-arm`,
`pipegz/Windows11ARM`, `nullx/windows-arm64`, `aihua/windows-11-arm64`,
`apter-tech/windows-11-arm64`, `chicken-wire/windows-11-arm64-flutter-dev`,
`santiago-bassett/windows-11-pro-arm64-vmware`, and `Sy3Omda/Win-SRV-2025` — every one of
them publishes only `parallels`, `vmware_desktop`, or `utm` providers, none of which
vagrant-qemu (or plain libvirt) can consume. `devvm.py` refuses this guest with that
explanation rather than silently doing nothing useful.

If you need this lane: build a qcow2 image yourself from a Windows-on-ARM evaluation VHDX
(Microsoft ships these for Windows 11 ARM64) and point `qe.image_path` at it in a new
`scripts/devvm/guests/windows-arm64/Vagrantfile` (see the vagrant-qemu README's "local
qcow2" example) — this tool has no automation for that conversion.

### Windows guests

**Licensing.** `stromweld/windows-10` is a "vanilla Windows 10" box built with
[Bento](https://github.com/chef/bento) from Microsoft's free evaluation media. Evaluation
Windows installs activate on a timer and _expire_ (Windows 10 Enterprise eval is commonly
90 days from the image's build date). When this box's install expires, the fix is bumping
`config.vm.box_version` in `scripts/devvm/guests/windows-x64/Vagrantfile` to a newer build —
not disabling activation checks. This is throwaway dev tooling; don't rely on this VM
outliving a single investigation.

**Account and UAC.** The box's default `vagrant` account is an ordinary `Administrators`
member — not the built-in Administrator (SID ending `-500`), which Windows elevates
_without_ a UAC prompt regardless of settings. Every `up`/`provision` run verifies this (and
fails loudly, not silently, if it's ever untrue) and resets UAC (`EnableLUA`) to on, via
`scripts/devvm/provision/windows-account-and-uac.ps1`.

By default, `runas` elevation prompts for consent exactly like a real desktop
(`ConsentPromptBehaviorAdmin=5`, the Windows default). For unattended probe runs where a
human isn't there to click through the prompt, pass `--allow-elevation` to `up`:

```sh
uv run scripts/devvm.py up windows-x64 --allow-elevation
```

This sets `ConsentPromptBehaviorAdmin=0` (auto-approve, still logged, UAC still nominally
on) — **opt-in only**, never the default, and the tool prints a note every time it's active.

**Headless by default, and what that means for the actual UAC-prompt probe.** The guest
boots with no display (`-display none`, vagrant-qemu's default) and is reached over
WinRM/PowerShell remoting. A WinRM session is a network logon to a non-interactive session,
not the interactive console session — so it can run a probe and inspect the _result_
(`ShellExecuteExW`'s return value, the resulting process tree, event log entries) but it
cannot itself render or click through the secure-desktop consent prompt. If a probe needs a
human (or UI automation) to actually see and answer that prompt, give the guest a display —
add e.g. `qe.other_default = %w(-parallel null -monitor none -vga std -display cocoa)` to
the `qemu` provider block in the Windows Vagrantfile — and connect to the console, or RDP
into the guest instead of using `devvm.py ssh`/`run`.

**Measured timings on this host** (Apple Silicon Mac, so `windows-x64` runs under TCG
cross-arch emulation; one-time data point on 2026-09-23, not a guarantee):

| Guest                      | `up` (import → provisioned)                                        | trivial command | `destroy` |
| -------------------------- | ------------------------------------------------------------------ | --------------- | --------- |
| `linux-arm64` (native HVF) | ~75s                                                               | <1s             | ~5s       |
| `windows-x64` (TCG)        | ~13.5 min (import + first boot + WinRM ready + all 3 provisioners) | ~30s            | ~1 min    |

`windows-x64`'s `boot_timeout`/`winrm.timeout` are set to 3600s to give real headroom for a
slower host or a colder box cache; in practice first boot under TCG on this host landed
nowhere near that ceiling.

## Read-only working tree

`up` and `sync` get a filtered copy of the working tree (`.git/`, `target/`, `.tmp/`
excluded) into the guest without letting the guest write back into your actual source tree:

- **Linux guests** (`linux-x64`, `linux-arm64`): a one-shot `rsync` push to
  `~/cosca`, files landing mode `444` (directories stay `755` so later syncs can still
  add/remove files). This is `vagrant`'s built-in `rsync` synced-folder type, not a live
  mount — the guest never writes through to the host.
- **Windows guest** (`windows-x64`): no rsync binary on the box, and Vagrant's SMB synced
  folder needs a one-time macOS _System Settings → Sharing → File Sharing_ toggle plus a
  password prompt on every mount — too much friction for a throwaway VM. Instead,
  `scripts/devvm.py sync` stages a filtered copy under `.tmp/devvm/windows-x64/tree/` on the
  host, and Vagrant's `file` provisioner uploads it to `C:\cosca` over WinRM; a follow-up
  provisioner (`windows-lock-tree.ps1`) strips write access with `icacls`.

Either way this is a **convention, not a security boundary**: the connecting account is an
administrator (Linux: passwordless `sudo`; Windows: `Administrators` membership) and can
always grant itself write access back. It exists so an accidental `cargo test` writing into
its own source tree, or a stray `rm`, doesn't silently succeed.

Cargo builds need a writable output directory, since the synced tree isn't one — `devvm.py
run` sets `CARGO_TARGET_DIR` to a per-guest home directory automatically (`~/cargo-target`
on Linux, `%USERPROFILE%\cargo-target` on Windows), so `devvm.py run linux-x64 -- cargo
test` just works.

## State directories

All _mutable, throwaway_ state — the per-guest QEMU disk overlay, Vagrant's machine
metadata, the staged tree copy for Windows — lives under `.tmp/devvm/<guest>/` in this
worktree (gitignored via the repo's existing `.tmp/` rule), never in your home directory.
`devvm.py` arranges this by pointing `VAGRANT_DOTFILE_PATH` at
`.tmp/devvm/<guest>/.vagrant` for every `vagrant` invocation it makes.

**One exception, where Vagrant insists:** the downloaded box images themselves (several GB
each) and installed Vagrant plugins live in Vagrant's global home,
`~/.vagrant.d/{boxes,gems}`, same as any other Vagrant project on the machine. Vagrant ties
plugin installation and box storage to the same `VAGRANT_HOME`; redirecting it per-project
would mean reinstalling `vagrant-qemu` (and re-downloading every box) per worktree, which is
worse than the alternative. Manage that cache directly with `vagrant box list` / `vagrant
box remove <name>` when you're done with a box — `devvm.py destroy` does not touch it, only
the per-guest disk overlay in `.tmp/`.

**Disk is usually the constraint, not the tool.** Windows boxes run several GB; check `df -h`
before `up`-ing a Windows guest, and don't keep more than one Windows box downloaded at a
time (`vagrant box list`, then `vagrant box remove` the one you're done with) if space is
tight.

## Known host issue: forwarded-port collisions on some macOS hosts

On at least one Apple Silicon host (confirmed: macOS, Vagrant 2.4.9, both system Ruby 2.6.10
and Vagrant's bundled Ruby 3.3.8), `vagrant up` can fail with `ForwardPortCollision` or
`ForwardPortAutolistEmpty` for a port nothing is actually listening on. Root cause: Vagrant's
own `Vagrant::Util::IsPortOpen.is_port_open?` uses `Socket.tcp(host, port, connect_timeout:
...)`, and that non-blocking-connect code path reports every port as "open" (in use) on this
host regardless of whether anything is bound — reproduced directly against both Rubies, with
both `"0.0.0.0"` and `"127.0.0.1"`, at multiple timeout values; a plain blocking
`TCPSocket.new` against the same ports correctly raises `ECONNREFUSED`. Because the check is
wrong, the auto-correction loop burns through the entire usable port range on the first
collision and has nothing left for the second.

Each guest Vagrantfile works around this by loading
`scripts/devvm/guests/_shared/fix_macos_port_check.rb`, which monkeypatches
`is_port_open?` to use a blocking connect instead, before `vagrant up`'s port-collision
middleware runs. This is loaded unconditionally (harmless on hosts where the bug doesn't
reproduce) rather than gated behind a host check, since the same code path is used by every
provider's forwarded-port handling, not just this tool's guests.
