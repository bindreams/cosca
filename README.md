# cosca

Unified cross-platform subprocess management: spawning, stdio, process trees, stable identity, and elevation.

`std::process` hands you a child and little else. It cannot tell you whether the process you spawned is still the process you think it is, cannot tear down a process tree, cannot address a process it did not spawn, and cannot run one elevated. This crate covers those, with one API across Linux, macOS, and Windows, a `tokio` mirror behind a feature flag, and identities that can be written to disk and restored after a restart (`serde` feature).

On Linux, cosca needs `openat2` (kernel 5.6 or newer, and not blocked by a seccomp filter): it reads `/proc` only through a checked directory fd. Without it a spawn, or a by-pid identity read, fails with `Error::Unsupported` saying so.

The API is not stable; expect breaking changes in any 0.x release.

Platform requirements, including Linux 5.6 or newer, are in the crate documentation.

The design rules every change follows are in [docs/principles.md](docs/principles.md).

## Running tests

Use [`cargo nextest`](https://nexte.st/) (`cargo install cargo-nextest`), run as `cargo nextest
run`. It's what CI runs, and it's the recommended way to run cosca's suite: nextest
isolates each test in its own process, rather than sharing one process across the whole run the
way plain `cargo test` does.

The suite signals process groups and creates cgroup leaves and Job Objects, so run it in a VM
([`scripts/devvm`](scripts/README.md)), a container or CI, never directly on your machine. See
[principle 10](docs/principles.md#10-system-affecting-tests-run-in-a-sandbox).

nextest doesn't run doctests, so CI runs those separately with `cargo test --doc`. cosca has none
today. Claude Code agents in this repo deny plain `cargo test` (`.claude/settings.json`), so an
agent can't run that step locally either — it only runs in CI.

### Tests that need root

A few tests (e.g. `foreign_kill_surfaces_permission_denied` in `tests/process.rs`) declare a
runtime precondition and carry a `ROOT` label instead of assuming the environment happens to run
as root. `cargo test` reports an unmet one as `ignored`, with the reason; nextest (what CI and
this section both use) has no way to surface that reason text, only a bare skip — this repo's
`nextest.toml` at least prints `SKIP <name>` for it. Either way: never a silent skip, never a
false pass on every unprivileged machine. CI provisions root for exactly these tests (see
`.github/workflows/ci.yaml`'s "Run root-precondition tests" step) on Linux and macOS.

To run them locally:

```sh
cargo nextest run                     # first, unprivileged: creates target/debug/.skuld.db as you
cargo nextest archive --archive-file /tmp/root.tar.zst
sudo SKULD_LABELS=ROOT "$(command -v cargo-nextest)" nextest run \
    --archive-file /tmp/root.tar.zst --workspace-remap "$PWD" -E 'binary(process)'
sudo chown "$(id -u):$(id -g)" target/debug/.skuld.db* 2>/dev/null || true
```

A few things this works around:

- Plain `sudo cargo ...` doesn't find `cargo` at all on a stock Debian/Ubuntu install — `sudo`'s
  `secure_path` doesn't include `~/.cargo/bin` (rustup's install location) regardless of your own
  `PATH`. Resolving `cargo-nextest`'s own path first, then invoking that directly, sidesteps it.
- `SKULD_LABELS=ROOT`, not `-E 'test(=...)'` naming a test by hand: this filters by skuld's own
  `ROOT` label instead (nextest itself has no notion of skuld labels), so it also covers whatever
  other test picks up that label later.
- Running the plain suite once first, unprivileged, creates skuld's own coordination database
  (`target/debug/.skuld.db`) under your own uid. If root creates it instead (e.g. by running the
  `sudo` command first, on a fresh checkout), every later _unprivileged_ run in that `target/`
  fails outright with "attempt to write a readonly database" — reproduced. The final `chown` is a
  safety net for whatever WAL/SHM side files root's run may still have touched.

## License

<img align="right" width="150px" height="150px" src="https://www.apache.org/foundation/press/kit/img/the-apache-way-badge/ASF_Badge_apacheway-purple.png">

Copyright 2026, Anna Zhukova

This project is licensed under the Apache 2.0 license. The license text can be found at [LICENSE](/LICENSE).

`src/quote/posix.rs` is a Rust port of the `internal/foundation/shlex` package from [JetBrains qodana-cli](https://github.com/JetBrains/qodana-cli), used under that project's Apache 2.0 license.
