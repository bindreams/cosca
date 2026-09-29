#!/usr/bin/env python3
"""Throwaway: apply each mutant, run its tests, record RED/GREEN, restore."""
import json, subprocess, sys, pathlib

spec = json.load(open(sys.argv[1]))
results = []
for m in spec:
    for path, old, new in m["edits"]:
        p = pathlib.Path(path)
        s = p.read_text()
        assert s.count(old) == 1, f"{m['name']}: {old!r} occurs {s.count(old)}x in {path}"
        p.write_text(s.replace(old, new))
    cmd = ["cargo", "test", "--locked", "--lib", *m.get("cargo", []), "--", *m["filters"]]
    print(f"::group::{m['name']}: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    state = None
    try:
        out, _ = proc.communicate(timeout=m.get("timeout", 900))
    except subprocess.TimeoutExpired:
        # Failure bound surfaced to a human: a frozen-clock re-arm loop that never ends.
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)])
        out, _ = proc.communicate()
        state = "HUNG"
    print(out)
    print("::endgroup::", flush=True)
    if state is None:
        if "could not compile" in out or "error[E" in out:
            state = "COMPILE-ERROR"
        elif proc.returncode == 0:
            state = "GREEN"
        elif "test result: FAILED" in out:
            state = "RED"
        else:
            state = "OTHER-FAILURE"
    failed = [l.strip() for l in out.splitlines() if l.strip().endswith("FAILED") and l.startswith("test ")]
    results.append((m["name"], m["expect"], state, failed))
    subprocess.run(["git", "checkout", "--", "src"], check=True)

print("\n==== SUMMARY ====")
bad = False
for name, expect, state, failed in results:
    ok = (expect == "red" and state in ("RED", "HUNG")) or (expect == "green" and state == "GREEN")
    bad |= not ok
    print(f"{name}: {state} expected {expect} -> {'OK' if ok else 'UNEXPECTED'}")
    for f in failed:
        print(f"    {f}")
sys.exit(1 if bad else 0)
