import sys, pathlib
rp = pathlib.Path("src/relayed_probe.rs")
tw = pathlib.Path("src/tokio/wait.rs")
CAP = "            .iter()\n            .map(|(id, entry)| (*id, entry.clone_entry()))\n"
def skip(ty):
    return (rp, CAP, f"            .iter()\n            .filter(|(id, _)| **id != TypeId::of::<{ty}>())\n            .map(|(id, entry)| (*id, entry.clone_entry()))\n")
M = {
    "baseline": None,
    "skip_armed": skip("crate::wait::backend::armed_probe::Armed"),
    "skip_released": skip("crate::tokio::wait::fault_observer::Released"),
    "forget_relay": (tw, "        let _relay = relay.reinstall();\n", "        std::mem::forget(relay.reinstall());\n"),
}
m = M[sys.argv[1]]
if m:
    path, old, new = m
    s = path.read_text()
    assert s.count(old) == 1, s.count(old)
    path.write_text(s.replace(old, new))
    print("applied", sys.argv[1])
