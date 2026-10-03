#!/usr/bin/env python3
"""THROWAWAY: summarise probe-*.jsonl: counts and quantiles of each phase."""
import json, sys, glob, statistics
recs = [json.loads(l) for f in glob.glob(sys.argv[1] + "/probe-*.jsonl") for l in open(f)]
print(f"iterations: {len(recs)}")
bad = [r for r in recs if not r.get("ok")]
print(f"not ok: {len(bad)}")
for r in bad:
    print(json.dumps({k: v for k, v in r.items() if k not in ('diag',)}))
def q(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(p * len(xs)))]
for key, a, b in (("stop->still", "stop", "still"), ("still->relayed", "still", "relayed"), ("cont->c_exit", "cont", "c_exit"), ("cont->f_exit", "cont", "f_exit"), ("stop->f_exit", "stop", "f_exit")):
    xs = [r["t"][b] - r["t"][a] for r in recs if r.get("ok") and a in r["t"] and b in r["t"]]
    if xs:
        print(f"{key:15s} n={len(xs)} p50={q(xs,.5)*1e3:.2f}ms p99={q(xs,.99)*1e3:.2f}ms p999={q(xs,.999)*1e3:.2f}ms max={max(xs)*1e3:.2f}ms")
