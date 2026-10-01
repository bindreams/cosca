#!/usr/bin/env python3
"""Run a nextest command under its own profile and collect its JUnit file.

Usage: run-nextest.py <name> <command> [args...]

Runs <command> under the nextest profile `ci-<name>` (a profile of its own, see
.config/nextest.toml), through forward.py, then moves that profile's JUnit file to
`$RUNNER_TEMP/junit/<name>.xml`, where the job's single `upload-junit` step picks it up. A step
`exec`s this script, so the runner's timeout signal lands on forward.py's loop and reaches the
command's whole process tree.

The JUnit file is published only if the command ended on its own: a run that was told to stop
publishes nothing, and a run that succeeded without a file, or whose file cannot be moved, fails.
If the runner SIGKILLs this script (on Unix it never signals the command), the half-written file of
the command stays in its own profile's directory, where nothing reads it. Anything the command leaves
running (a root process the runner cannot signal) can only ever write there, never to another
step's file, and dies with the ephemeral runner VM.
"""

import os
import shutil
import sys
from pathlib import Path

import forward


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    name, command = argv[0], argv[1:]
    profile = f"ci-{name}"
    os.environ["NEXTEST_PROFILE"] = profile
    junit = Path("target/nextest") / profile / "junit.xml"
    published = Path(os.environ["RUNNER_TEMP"]) / "junit"
    published.mkdir(parents=True, exist_ok=True)
    # The profile directory is made here, as the runner user: a root nextest then writes its file
    # into a directory this script can remove it from, which a directory root made would not allow.
    junit.parent.mkdir(parents=True, exist_ok=True)
    junit.unlink(missing_ok=True)

    try:
        status, signalled = forward.run(command)
    except forward.SpawnError as error:
        print(f"::error::{error}")
        return 127

    if signalled:
        print("::warning::the run was told to stop; its JUnit file is not published")
        return status or 1
    if junit.exists():
        try:
            shutil.move(str(junit), published / f"{name}.xml")
        except OSError as error:
            print(f"::error::could not move {junit} to {published / (name + '.xml')}: {error}")
            return 1
    elif status == 0:
        print(f"::error::nextest succeeded but wrote no JUnit file at {junit}")
        return 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
