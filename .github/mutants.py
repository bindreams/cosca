#!/usr/bin/env python3
"""Throwaway: apply each mutant, run its tests, record RED/GREEN, restore."""
import json, subprocess, sys, pathlib

spec = json.load(open(sys.argv[1]))
results = []
for m in spec:
    edits = m["edits"]
    for path, old, new in edits:
        p = pathlib.Path(path)
        s = p.read_text()
        assert s.count(old) == 1, f"{m['name']}: {old!r} occurs {s.count(old)}x in {path}"
        p.write_text(s.replace(old, new))
    cmd = ["timeout", str(m.get("timeout", 600)), "cargo", "test", "--locked", "--lib", *m.get("cargo", []), "--", *m["filters"]]
    print(f"::group::{m['name']}: {' '.join(cmd)}", flush=True)
    r = subprocess.run(cmd)
    print("::endgroup::", flush=True)
    results.append((m["name"], m["expect"], r.returncode))
    subprocess.run(["git", "checkout", "--", "src"], check=True)

print("\n==== SUMMARY ====")
bad = False
for name, expect, rc in results:
    state = "GREEN" if rc == 0 else ("HUNG (timeout)" if rc == 124 else "RED")
    ok = (expect == "red" and rc != 0) or (expect == "green" and rc == 0)
    bad |= not ok
    print(f"{name}: {state} (exit {rc}) expected {expect} -> {'OK' if ok else 'UNEXPECTED'}")
sys.exit(1 if bad else 0)
