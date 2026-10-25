"""The Shift+Pad 16 Boot Menu patch set.

The committed JSON is what a device applies. When the stock 1.3.0.12 binary is
present next to this repo, the test also rebuilds that JSON from the binary and
checks the two agree, then runs the on-device applier against a copy.

Run: python3 -m pytest tests/ -q
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PATCH = REPO / "patches" / "1.3.0.12-boot-menu.json"
STOCK = Path(__file__).resolve().parents[2] / "update-1.3.0" / "boot-rootfs" / "usr" / "bin" / "MPC Sample"
sys.path.insert(0, str(REPO / "tools"))
import gen_boot_menu  # noqa: E402
import mpcpatch  # noqa: E402

TARGET_SHA = "b6584cba76e416e432ad202509099d34373dc2c3d6a8fb625f5678bf0193b508"


def _load():
    spec = json.loads(PATCH.read_text())
    return spec


def test_boot_menu_patchset_is_same_length_and_disjoint():
    spec = _load()
    assert spec["schema"] == 1
    assert spec["target"]["sha256"] == TARGET_SHA
    assert spec["target"]["size"] == 119243440
    assert len(spec["result"]["sha256"]) == 64
    seen = {}
    assert spec["patches"], "patch set is empty"
    for patch in spec["patches"]:
        original = bytes.fromhex(patch["original"])
        patched = bytes.fromhex(patch["patched"])
        assert original != patched
        assert len(original) == len(patched)
        off = int(patch["offset"], 16)
        for i in range(off, off + len(original)):
            assert i not in seen, f"{patch['id']} overlaps {seen[i]}"
            seen[i] = patch["id"]
    ids = {p["id"] for p in spec["patches"]}
    assert "boot-menu-cave" in ids
    assert "list-row-count" in ids
    cave = next(p for p in spec["patches"] if p["id"] == "boot-menu-cave")
    cave_bytes = bytes.fromhex(cave["patched"])
    assert b"boot thingy\0" in cave_bytes
    assert b"/bin/sh\0" in cave_bytes
    assert b"systemd-run --unit=mpc-boot-thingy" in cave_bytes
    assert b"find /media -name mpc-boot-thingy" in cave_bytes
    assert b"--menu" in cave_bytes
    assert b"MPC SAMPLE" not in cave_bytes


@pytest.mark.skipif(not STOCK.is_file(), reason="stock MPC Sample binary is not in this checkout")
def test_boot_menu_matches_stock_binary(tmp_path):
    data = STOCK.read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA
    image, patches = gen_boot_menu.build(data)
    fresh = gen_boot_menu.patchset_dict(data, patches)
    assert fresh == _load()

    spec = _load()
    patched = mpcpatch.apply_patches(spec, data)
    mpcpatch.verify_result(spec, patched)
    assert STOCK.read_bytes() == data

    def word(buf, off):
        return struct.unpack_from("<I", buf, off)[0]

    assert word(patched, 0x16439AC) == 0xD280F000  # mov x0, #1920
    assert word(patched, 0x1644FF4) == 0xD28000A1  # mov x1, #5
    assert word(patched, 0x16438CC) == 0x54FFFE6C  # b.gt trampoline
    assert b"boot thingy\0" in patched[0x482B734:0x482B734 + len(image)]
    assert bytes(data[0x482B734:0x482B734 + len(image)]) == b"\0" * len(image)

    # Dry apply: bind-mount a copy, leave the stock file's bytes alone.
    listed = tmp_path / "sd" / "mpc-mod"
    listed.mkdir(parents=True)
    shutil.copy(REPO / "sdcard" / "mpc-mod" / "apply.sh", listed / "apply.sh")
    subprocess.run(
        [sys.executable, str(REPO / "tools" / "mpcpatch.py"), "emit-device",
         str(PATCH), "-o", str(listed / "patches.list")],
        check=True,
    )
    events = tmp_path / "events.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    real_sha = shutil.which("sha256sum") or shutil.which("shasum")
    if shutil.which("sha256sum"):
        shim = f'#!/bin/sh\nexec {real_sha} "$@"\n'
    else:
        shim = '#!/bin/sh\nexec shasum -a 256 "$@"\n'
    (bindir / "sha256sum").write_text(shim)
    (bindir / "sha256sum").chmod(0o755)
    (bindir / "mount").write_text(f'#!/bin/sh\necho "mount $*" >> "{events}"\nexit 0\n')
    (bindir / "mount").chmod(0o755)
    (bindir / "systemctl").write_text(f'#!/bin/sh\necho "systemctl $*" >> "{events}"\nexit 0\n')
    (bindir / "systemctl").chmod(0o755)
    (bindir / "pkill").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "pkill").chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}" + env.get("PATH", "")
    env["MPC_STOCK"] = str(STOCK)
    env["MPC_WORK"] = str(tmp_path / "work")
    env["MPC_NO_RESTART"] = "1"
    proc = subprocess.run(["sh", str(listed / "apply.sh")], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "mount --bind" in events.read_text()
    assert "systemctl restart" not in events.read_text()
    assert hashlib.sha256(STOCK.read_bytes()).hexdigest() == TARGET_SHA
    out = tmp_path / "work" / "MPC-Sample-patched"
    assert hashlib.sha256(out.read_bytes()).hexdigest() == spec["result"]["sha256"]
