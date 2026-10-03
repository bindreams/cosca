import os
p = "tests/windows_elevation_routes/harness.rs"
s = open(p, newline="", encoding="utf-8").read().replace("\r\n", "\n")
loop = (
    "    for (k, v) in extra {\n"
    "        map.insert(EnvKeyIgnoreCase::new(k), v.clone());\n"
    "    }\n"
)
assert loop in s
m = os.environ["MUTANT"]
if m == "drop-extra":
    s = s.replace(loop, "")
elif m == "extra-first":
    s = s.replace(loop, "")
    anchor = "    let mut map: BTreeMap<EnvKeyIgnoreCase, String> = BTreeMap::new();\n"
    assert anchor in s
    s = s.replace(anchor, anchor + loop)
open(p, "w", newline="\n", encoding="utf-8").write(s)
