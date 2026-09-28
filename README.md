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

A few tests (e.g. `foreign_kill_surfaces_permission_denied` in `tests/process_root.rs`) declare a
runtime precondition and carry a `ROOT` label instead of assuming the environment happens to run
as root — never a silent skip, never a false pass on every unprivileged machine. CI provisions
root for exactly these tests (see `.github/workflows/ci.yaml`'s "Run root-precondition tests"
step) on Linux and macOS.

These tests spawn real children under real, different unprivileged uids and re-exec as root to do
it — never run them against this machine's own `sudo`. Run them in a throwaway container instead:

```sh
( set -e
docker run --rm --network none \
    -v "$PWD":/repo:ro \
    -v cosca-root-test-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -e COSCA_TEST_ROOT_CONSENT=1 \
    -e SKULD_LABELS=ROOT \
    -w /repo \
    rust:1 \
    bash -c 'cargo install cargo-nextest --locked --quiet && cargo nextest run -E "binary(process) | binary(process_root)"'
)
docker volume rm cosca-root-test-target
```

- The whole block is wrapped in `( set -e; … )` — a subshell, not the calling shell — so pasting
  it into an interactive terminal cannot change that shell's own error-handling behavior.
- The container's default user is already root, so no `sudo` (and none of its `secure_path`/PATH
  surprises) is needed inside it; `COSCA_TEST_ROOT_CONSENT=1` is the only thing that unlocks the
  test's real uid-switching, and it stays inside the container's own environment. The repo is
  bind-mounted read-only, and the build goes to a throwaway named volume — nothing under `target/`
  on the host is ever touched, so there is no unprivileged/privileged ownership conflict to clean
  up afterward.
- Don't lift the inner `cargo nextest run` out of the container and run it with `sudo` on the
  host: `COSCA_TEST_ROOT_CONSENT=1` is real, standing consent to switch uids and spawn/kill
  processes, and this project's own rule is that system-affecting tests run in a container or VM,
  never against this machine's own services.

## License

<img align="right" width="150px" height="150px" src="https://www.apache.org/foundation/press/kit/img/the-apache-way-badge/ASF_Badge_apacheway-purple.png">

Copyright 2026, Anna Zhukova

This project is licensed under the Apache 2.0 license. The license text can be found at [LICENSE](/LICENSE).

`src/quote/posix.rs` is a Rust port of the `internal/foundation/shlex` package from [JetBrains qodana-cli](https://github.com/JetBrains/qodana-cli), used under that project's Apache 2.0 license.
