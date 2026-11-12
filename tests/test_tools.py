#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The Blueberry Pie OS Authors
#
# usage: test_tools.py TEST_OD

import hashlib
import os
import plistlib
import random
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = os.path.join(HERE, "..", "tools", "dslocal-record")
TEST_OD = os.path.abspath(sys.argv[1])
failures = 0
checks = 0


def check(ok, what):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def canon(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, bytes):
        return "<" + v.hex() + ">"
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(canon(k) + ":" + canon(v[k]) for k in sorted(v)) + "}"
    raise TypeError(v)


ALPHABET = "abcXYZ019 _-é€😀ß\"\\"


def rand_string(r):
    n = r.choice([0, 1, 5, 14, 15, 16, 40, 300])
    return "".join(r.choice(ALPHABET) for _ in range(n))


def rand_value(r, depth=0):
    kinds = ["str", "bytes", "int", "bool"]
    if depth < 4:
        kinds += ["list", "dict"]
    k = r.choice(kinds)
    if k == "str":
        return rand_string(r)
    if k == "bytes":
        return bytes(r.getrandbits(8) for _ in range(r.choice([0, 3, 15, 16, 200])))
    if k == "int":
        return r.choice([0, 1, 255, 256, 65535, 65536, 2**31, 2**32 - 1, 2**32, 2**62, -1, -2,
                         -2**63, r.randint(-2**40, 2**40)])
    if k == "bool":
        return r.choice([True, False])
    if k == "list":
        return [rand_value(r, depth + 1) for _ in range(r.choice([0, 1, 3, 20]))]
    return {rand_string(r) or "k": rand_value(r, depth + 1) for _ in range(r.choice([0, 1, 4, 30]))}


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def test_plists(tmp):
    r = random.Random(7)
    src = os.path.join(tmp, "in.plist")
    out = os.path.join(tmp, "out.plist")
    for i in range(300):
        v = {"top": rand_value(r)}
        with open(src, "wb") as f:
            f.write(plistlib.dumps(v, fmt=plistlib.FMT_BINARY))
        d = run([TEST_OD, "dump", src])
        check(d.returncode == 0 and d.stdout.strip() == canon(v), "dump %d" % i)
        rt = run([TEST_OD, "roundtrip", src, out])
        check(rt.returncode == 0, "roundtrip %d" % i)
        if rt.returncode == 0:
            with open(out, "rb") as f:
                check(plistlib.loads(f.read()) == v, "roundtrip value %d" % i)
    big = {"k%d" % i: ["v%d" % i, bytes([i % 256]) * (i % 40)] for i in range(5000)}
    with open(src, "wb") as f:
        f.write(plistlib.dumps(big, fmt=plistlib.FMT_BINARY))
    check(run([TEST_OD, "roundtrip", src, out]).returncode == 0, "big roundtrip")
    with open(out, "rb") as f:
        check(plistlib.loads(f.read()) == big, "big value")


def test_seed(tmp):
    node = os.path.join(tmp, "node")
    p = run([SEED, "user", node, "--name", "pie", "--uid", "501", "--gid", "20",
             "--realname", "Pie", "--home", "/Users/pie", "--shell", "/bin/sh",
             "--password-stdin", "--iterations", "2000"], input="pie pass é\n")
    check(p.returncode == 0, "seed user: " + p.stderr)
    path = os.path.join(node, "users", "pie.plist")
    check(stat.S_IMODE(os.stat(path).st_mode) == 0o600, "seed mode")
    with open(path, "rb") as f:
        data = f.read()
    check(data.startswith(b"bplist00"), "seed binary")
    rec = plistlib.loads(data)
    check(rec["name"] == ["pie"] and rec["uid"] == ["501"] and rec["gid"] == ["20"], "seed ids")
    check(rec["generateduid"] == ["FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5"], "seed uuid")
    check(rec["passwd"] == ["********"], "seed passwd")
    check(rec["authentication_authority"] == [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"],
          "seed authority")
    inner = plistlib.loads(rec["ShadowHashData"][0])["SALTED-SHA512-PBKDF2"]
    check(len(inner["entropy"]) == 128 and len(inner["salt"]) == 32 and inner["iterations"] == 2000,
          "seed shadow shape")
    v = run([TEST_OD, "verify", path, "pie pass é"])
    check(v.returncode == 0 and v.stdout.strip() == "OK", "C verifies seed password")
    v = run([TEST_OD, "verify", path, "pie pass e"])
    check(v.returncode == 1 and v.stdout.strip() == "MISMATCH", "C rejects wrong password")
    d = run([TEST_OD, "dump", path])
    check(d.returncode == 0 and '"name":["pie"]' in d.stdout, "C reads seed record")

    p = run([SEED, "user", node, "--name", "_sshd", "--uid", "75", "--gid", "75"])
    check(p.returncode == 0, "seed system user")
    with open(os.path.join(node, "users", "_sshd.plist"), "rb") as f:
        rec = plistlib.load(f)
    check(rec["passwd"] == ["*"] and "ShadowHashData" not in rec, "system user has no password")
    check(rec["generateduid"] == ["FFFFEEEE-DDDD-CCCC-BBBB-AAAA0000004B"], "system user uuid")
    p = run([SEED, "user", node, "--name", "nobody", "--uid", "-2", "--gid", "-2"])
    with open(os.path.join(node, "users", "nobody.plist"), "rb") as f:
        rec = plistlib.load(f)
    check(rec["uid"] == ["-2"] and rec["generateduid"] == ["FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE"],
          "nobody")
    p = run([SEED, "group", node, "--name", "admin", "--gid", "80", "--member", "root",
             "--member", "pie", "--member-uuid", "ffffeeee-dddd-cccc-bbbb-aaaa000001f5"])
    check(p.returncode == 0, "seed group")
    with open(os.path.join(node, "groups", "admin.plist"), "rb") as f:
        rec = plistlib.load(f)
    check(rec["users"] == ["root", "pie"] and rec["gid"] == ["80"] and
          rec["groupmembers"] == ["FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5"] and
          rec["generateduid"] == ["ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050"], "group fields")
    check(run([SEED, "user", node, "--name", "../x", "--uid", "1", "--gid", "1"]).returncode != 0,
          "bad name refused")
    check(run([SEED, "user", node, "--name", "nl\n", "--uid", "1", "--gid", "1"]).returncode != 0 and
          not os.path.exists(os.path.join(node, "users", "nl\n.plist")), "trailing newline refused")
    check(run([SEED, "group", node, "--name", "g", "--gid", "1", "--member", "pie\n"]).returncode != 0,
          "member with a trailing newline refused")
    check(run([SEED, "member", node, "--group", "admin", "--user", "pie\n"]).returncode != 0,
          "member user with a trailing newline refused")
    check(run([SEED, "user", node, "--name", "x" * 240, "--uid", "1", "--gid", "1"]).returncode == 0,
          "240-byte name accepted")
    check(run([SEED, "user", node, "--name", "x" * 241, "--uid", "1", "--gid", "1"]).returncode != 0,
          "241-byte name refused")
    check(run([SEED, "user", node, "--name", "x", "--uid", "1", "--gid", "1",
               "--attr", "ShadowHashData=1"]).returncode != 0, "shadow attr refused")
    p = run([SEED, "user", node, "--name", "a", "--uid", "1", "--gid", "1"])
    with open(os.path.join(node, "users", "a.plist"), "rb") as f:
        first = f.read()
    p = run([SEED, "user", node, "--name", "a", "--uid", "1", "--gid", "1"])
    with open(os.path.join(node, "users", "a.plist"), "rb") as f:
        check(f.read() == first, "records without a password are reproducible")


def test_c_shadow(tmp):
    out = os.path.join(tmp, "shadow.bin")
    p = run([TEST_OD, "shadow", "hunter2", "3000", out])
    check(p.returncode == 0, "C shadow")
    with open(out, "rb") as f:
        inner = plistlib.loads(f.read())["SALTED-SHA512-PBKDF2"]
    want = hashlib.pbkdf2_hmac("sha512", b"hunter2", inner["salt"], inner["iterations"], 128)
    check(inner["entropy"] == want and inner["iterations"] == 3000, "python verifies C shadow")


def test_control():
    with open(os.path.join(HERE, "..", "debian", "control"), encoding="utf-8") as f:
        stanzas = f.read().split("\n\n")
    deps = ""
    for st in stanzas:
        fields = dict(line.split(": ", 1) for line in st.splitlines() if ": " in line and line[0] != " ")
        if fields.get("Package") == "opendirectoryd":
            deps = fields.get("Depends", "")
    check("blueberry-pie-os-init (>= 2)" in [d.strip() for d in deps.split(",")], "depends on init 2")


def main():
    with tempfile.TemporaryDirectory(prefix="odtools.") as tmp:
        test_plists(tmp)
        test_seed(tmp)
        test_c_shadow(tmp)
    test_control()
    print("%d checks, %d failures" % (checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
