#!/usr/bin/env python3
"""Build the Shift+Pad 16 "boot thingy" patch set from a stock MPC Sample binary.

The stock file is read and never modified. The JSON contains only offsets and
the bytes this patch writes. Firmware 1.3.0.12, /usr/bin/MPC Sample.

The running app already opens ProjectSaveLoadScreen for Shift+Pad 16, with four
rows (Load, Save, New, SD Card Access) in a 0x700-byte object. This patch:

  * allocates 0x780 bytes, one more 0x80-byte row slot
  * clones the SD Card Access row at object+0x700 and names it "boot thingy"
  * registers that row with the list and stores a row count of 5
  * on list index 4, posix_spawnp's /bin/sh to start mpc-boot-thingy
  * tears the new slot down in each destructor that already tears down the
    SD Card Access slot

The new code sits in the unused zero run at file offset 0x482b734. That range
is inside the first load segment, which the kernel maps executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

STOCK_SHA = "b6584cba76e416e432ad202509099d34373dc2c3d6a8fb625f5678bf0193b508"
STOCK_SIZE = 119243440
CAVE = 0x482B734
CAVE_LIMIT = 0x482B731 + 39375
SD_STRING = 0x45A2398
ROW_STRIDE = 0x80
SPAWN_PLT = 0xB546E8

CTOR_LO, CTOR_HI = 0x1644E3C, 0x1644F4C
CTOR_HOOK = 0x1644F4C
CTOR_RESUME = 0x1644F50
DTOR_LO, DTOR_HI = 0x1645784, 0x1645914
REG_HOOK = 0x1642F58
REG_RESUME = 0x1642F5C
CLICK_BGT = 0x16438CC
CLICK_TRAMP = 0x1643898
CLICK_GT_TARGET = 0x1643908
LIST_ADD = 0x3B71A60

CTOR_BUMP = {0x680, 0x688, 0x690, 0x698, 0x6B8, 0x6C8, 0x6D0, 0x6D8}
DTOR_BUMP = {0x688, 0x690, 0x698, 0x6A8, 0x6B8}

SIZE_SITES = (
    (0x16439AC, 0),
    (0x16439E0, 1),
    (0x1647108, 1),
    (0x1647A08, 1),
)

# The card name is not fixed (/media/MPC, /media/MPC SAMPLE, ...). Find the
# boot-thingy binary and start it as its own unit so stopping ac50 does not
# kill the menu.
SHELL = (
    "b=$(find /media -name mpc-boot-thingy -type f | head -n 1) && "
    'cp "$b" /run/mpc-boot-thingy && chmod 755 /run/mpc-boot-thingy && '
    "{ systemctl reset-failed mpc-boot-thingy.service || true; "
    "systemd-run --unit=mpc-boot-thingy --collect --no-block "
    '/run/mpc-boot-thingy "${b%/*}" --menu; } '
    '|| echo "[boot-menu] click failed" > /tmp/boot-menu-click.log'
)


class GenError(Exception):
    pass


def u32(data: bytes, pc: int) -> int:
    return struct.unpack_from("<I", data, pc)[0]


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def enc_b(pc: int, target: int, link: bool = False) -> int:
    off = (target - pc) >> 2
    if not -(1 << 25) <= off < (1 << 25):
        raise GenError(f"branch {pc:#x} -> {target:#x} is out of range")
    base = 0x94000000 if link else 0x14000000
    return base | (off & 0x3FFFFFF)


def enc_bcond(pc: int, target: int, cond: int) -> int:
    off = (target - pc) >> 2
    if not -(1 << 18) <= off < (1 << 18):
        raise GenError(f"conditional branch {pc:#x} -> {target:#x} is out of range")
    return 0x54000000 | ((off & 0x7FFFF) << 5) | cond


def enc_adrp(pc: int, rd: int, target: int) -> int:
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    if not -(1 << 20) <= imm < (1 << 20):
        raise GenError(f"adrp at {pc:#x} cannot reach {target:#x}")
    imm &= (1 << 21) - 1
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def enc_add(rd: int, rn: int, imm12: int) -> int:
    if not 0 <= imm12 < 0x1000:
        raise GenError(f"add immediate {imm12:#x} does not fit")
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def adrp_page(pc: int, word: int) -> int:
    imm = sx((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21)
    return (pc & ~0xFFF) + (imm << 12)


def is_adrp(word: int) -> bool:
    return (word & 0x9F000000) == 0x90000000


def is_add_imm(word: int) -> bool:
    return (word & 0xFFC00000) == 0x91000000


def branch_target(pc: int, word: int):
    if (word & 0xFC000000) in (0x14000000, 0x94000000):
        return pc + sx(word & 0x3FFFFFF, 26) * 4
    if (word & 0xFF000010) == 0x54000000 or (word & 0x7E000000) == 0x34000000:
        return pc + sx((word >> 5) & 0x7FFFF, 19) * 4
    return None


def bump_mem(word: int, base_reg: int, fields: set[int]) -> int:
    if is_add_imm(word) and ((word >> 5) & 31) == base_reg:
        imm = (word >> 10) & 0xFFF
        if imm in fields:
            return enc_add(word & 31, base_reg, imm + ROW_STRIDE)
        return word
    for mask, scale in ((0xF9400000, 8), (0xF9000000, 8), (0xB9400000, 4), (0xB9000000, 4)):
        if (word & 0xFFC00000) != mask or ((word >> 5) & 31) != base_reg:
            continue
        byte_off = ((word >> 10) & 0xFFF) * scale
        if byte_off not in fields:
            return word
        new_off = byte_off + ROW_STRIDE
        return (word & ~(0xFFF << 10)) | ((new_off // scale) << 10)
    return word


def relocate(data: bytes, src: int, dest: int, end: int, base_reg: int, fields: set[int], bumps_expected: int) -> bytearray:
    """Copy [src, end) to dest.

    Branches that stay inside the block keep their relative offset, so they
    still land on the moved instruction. Branches that leave the block, and
    every ADRP, are rewritten for the new PC. Row field immediates grow by
    one slot.
    """
    out = bytearray()
    bumps = 0
    for pc in range(src, end, 4):
        original = u32(data, pc)
        word = bump_mem(original, base_reg, fields)
        if word != original:
            bumps += 1
        new_pc = dest + (pc - src)
        target = branch_target(pc, word)
        if target is not None and not src <= target <= end:
            if (word & 0xFC000000) not in (0x14000000, 0x94000000):
                raise GenError(f"external short branch at {pc:#x} -> {target:#x}")
            word = enc_b(new_pc, target, link=(word & 0xFC000000) == 0x94000000)
        elif is_adrp(original):
            word = enc_adrp(new_pc, original & 31, adrp_page(pc, original))
        out += struct.pack("<I", word)
    if bumps != bumps_expected:
        raise GenError(f"clone at {src:#x} bumped {bumps} immediates, expected {bumps_expected}")
    return out


def retarget_label(blob: bytearray, dest: int, old: int, new: int) -> None:
    found = 0
    for i in range(0, len(blob) - 4, 4):
        word = struct.unpack_from("<I", blob, i)[0]
        nxt = struct.unpack_from("<I", blob, i + 4)[0]
        if not is_adrp(word) or not is_add_imm(nxt):
            continue
        if ((nxt >> 5) & 31) != (word & 31):
            continue
        if adrp_page(dest + i, word) + ((nxt >> 10) & 0xFFF) != old:
            continue
        rd = word & 31
        struct.pack_into("<I", blob, i, enc_adrp(dest + i, rd, new))
        struct.pack_into("<I", blob, i + 4, enc_add(rd, rd, new & 0xFFF))
        found += 1
    if found != 1:
        raise GenError(f"expected one reference to {old:#x}, found {found}")


def _require(data: bytes) -> None:
    if len(data) != STOCK_SIZE:
        raise GenError(f"stock size {len(data)} != {STOCK_SIZE}")
    got = hashlib.sha256(data).hexdigest()
    if got != STOCK_SHA:
        raise GenError(f"stock sha256 {got} != {STOCK_SHA}")
    expect = {
        CTOR_HOOK: 0xB002D900,
        REG_HOOK: 0xA900FFF3,
        CLICK_BGT: 0x540001EC,
        CLICK_TRAMP: 0xD503201F,
        0x1644FF4: 0xD2800081,
        0x1645784: 0xF9435ED9,
        0x1646994: 0xF9435ED9,
        0x1646098: 0xF94306B9,  # ldr x25, [x21, #0x608]
    }
    for pc, word in expect.items():
        have = u32(data, pc)
        if have != word:
            raise GenError(f"at {pc:#x}: expected {word:08x}, binary has {have:08x}")
    for pc, rd in SIZE_SITES:
        want = 0xD280E000 | rd
        have = u32(data, pc)
        if have != want:
            raise GenError(f"size immediate at {pc:#x}: {have:08x} != {want:08x}")


def build(data: bytes) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Return cave bytes (placed at CAVE) and every (offset, replacement) pair."""
    _require(data)

    blobs = [b"boot thingy\0", b"/bin/sh\0", b"-c\0", SHELL.encode() + b"\0"]
    strings: dict[str, int] = {}
    raw = bytearray()
    cursor = CAVE
    for blob, name in zip(blobs, ("boot", "sh", "dashc", "cmd")):
        strings[name] = cursor
        raw += blob
        cursor += len(blob)
    while cursor % 4:
        raw.append(0)
        cursor += 1

    code_at = cursor
    ctor = relocate(data, CTOR_LO, code_at, CTOR_HI, 19, CTOR_BUMP, 9)
    retarget_label(ctor, code_at, SD_STRING, strings["boot"])
    ctor_tail = code_at + len(ctor)
    dtor_at = ctor_tail + 4
    dtor = relocate(data, DTOR_LO, dtor_at, DTOR_HI, 22, DTOR_BUMP, 7)
    hand_at = dtor_at + len(dtor)

    hand = bytearray()
    labels: dict[str, int] = {"dtor_clone": dtor_at, "ctor_clone": code_at}
    fixups: list[tuple[int, str, object]] = []

    def mark(name: str) -> None:
        labels[name] = hand_at + len(hand)

    def emit(word: int) -> None:
        hand.extend(struct.pack("<I", word))

    def later(kind: str, target) -> None:
        fixups.append((len(hand), kind, target))
        emit(0)

    def adrp_add(name: str, rd: int) -> None:
        later("adrp", (name, rd))
        later("addlo", (name, rd))

    mark("dtor_epi")
    emit(0xF94033E0)  # ldr x0, [sp, #0x60]
    emit(0xA9407BFD)  # ldp x29, x30, [sp]
    emit(0xA94153F3)  # ldp x19, x20, [sp, #0x10]
    emit(0xA9425BF5)  # ldp x21, x22, [sp, #0x20]
    emit(0xA94363F7)  # ldp x23, x24, [sp, #0x30]
    emit(0xA9446BF9)  # ldp x25, x26, [sp, #0x40]
    emit(0xA94573FB)  # ldp x27, x28, [sp, #0x50]
    emit(0xF9435C19)  # ldr x25, [x0, #0x6b8]
    emit(0x9101C3FF)  # add sp, sp, #0x70
    emit(0xD65F03C0)  # ret

    mark("from_x22")
    emit(0xAA1603E0)  # mov x0, x22
    later("b", "dtor_body")
    mark("from_x21")
    emit(0xD102C2A0)  # sub x0, x21, #0xb0
    later("b", "dtor_body")

    mark("dtor_body")
    emit(0xD101C3FF)  # sub sp, sp, #0x70
    emit(0xA9007BFD)  # stp x29, x30, [sp]
    emit(0xA90153F3)  # stp x19, x20, [sp, #0x10]
    emit(0xA9025BF5)  # stp x21, x22, [sp, #0x20]
    emit(0xA90363F7)  # stp x23, x24, [sp, #0x30]
    emit(0xA9046BF9)  # stp x25, x26, [sp, #0x40]
    emit(0xA90573FB)  # stp x27, x28, [sp, #0x50]
    emit(0xF90033E0)  # str x0, [sp, #0x60]
    emit(0xAA0003F6)  # mov x22, x0
    later("b", "dtor_clone")

    # 0x40-byte frame. argv occupies [sp, #0x00] and the pid slot is [sp, #0x20].
    # x29/x30 sit at [sp, #0x28] so posix_spawnp's pid write does not cover them.
    mark("launch")
    emit(0xD10103FF)  # sub sp, sp, #0x40
    emit(0xA902FBFD)  # stp x29, x30, [sp, #0x28]
    adrp_add("sh", 1)
    adrp_add("dashc", 2)
    adrp_add("cmd", 3)
    emit(0xA9000BE1)  # stp x1, x2, [sp]
    emit(0xA9017FE3)  # stp x3, xzr, [sp, #0x10]
    emit(0x910083E0)  # add x0, sp, #0x20
    emit(0xAA1F03E2)  # mov x2, xzr
    emit(0xAA1F03E3)  # mov x3, xzr
    emit(0x910003E4)  # mov x4, sp
    emit(0xAA1F03E5)  # mov x5, xzr
    later("bl", SPAWN_PLT)
    emit(0xA942FBFD)  # ldp x29, x30, [sp, #0x28]
    emit(0x910103FF)  # add sp, sp, #0x40
    emit(0xD65F03C0)  # ret

    mark("click")
    emit(0x7100101F)  # cmp w0, #4
    later("b.eq", "click_do")
    later("b", CLICK_GT_TARGET)
    mark("click_do")
    later("bl", "launch")
    emit(0x2A1F03E0)  # mov w0, wzr
    emit(0xF9400BF3)  # ldr x19, [sp, #0x10]
    emit(0xA8C27BFD)  # ldp x29, x30, [sp], #0x20
    emit(0xD50323BF)  # autiasp
    emit(0xD65F03C0)  # ret

    mark("reg")
    emit(enc_add(1, 19, 0x700))
    emit(0xAA1403E0)  # mov x0, x20
    later("bl", LIST_ADD)
    emit(u32(data, REG_HOOK))
    later("b", REG_RESUME)

    mark("ctor_epi")
    emit(enc_adrp(hand_at + len(hand), 0, 0x7165000))
    later("b", CTOR_RESUME)

    for pos, kind, target in fixups:
        pc = hand_at + pos
        if kind == "adrp":
            name, rd = target
            word = enc_adrp(pc, rd, strings[name])
        elif kind == "addlo":
            name, rd = target
            if (strings[name] & ~0xFFF) != adrp_page(pc - 4, struct.unpack_from("<I", hand, pos - 4)[0]):
                raise GenError(f"{name} crosses a page between its adrp and add")
            word = enc_add(rd, rd, strings[name] & 0xFFF)
        else:
            addr = labels[target] if isinstance(target, str) else target
            if kind == "b":
                word = enc_b(pc, addr)
            elif kind == "bl":
                word = enc_b(pc, addr, link=True)
            elif kind == "b.eq":
                word = enc_bcond(pc, addr, 0)
            else:
                raise GenError(kind)
        struct.pack_into("<I", hand, pos, word)

    if labels["dtor_epi"] != hand_at:
        raise GenError("destructor epilogue is not directly after the clone")
    ctor_tail_insn = enc_b(ctor_tail, labels["ctor_epi"])
    image = bytes(raw + ctor + struct.pack("<I", ctor_tail_insn) + dtor + hand)
    if CAVE + len(image) > CAVE_LIMIT:
        raise GenError("cave spilled out of the unused zero run")
    if any(data[CAVE:CAVE + len(image)]):
        raise GenError("cave range is not unused zeros")

    patches = [
        (CAVE, image),
        (0x1644FF4, struct.pack("<I", 0xD28000A1)),
        (CLICK_BGT, struct.pack("<I", enc_bcond(CLICK_BGT, CLICK_TRAMP, 0xC))),
        (CLICK_TRAMP, struct.pack("<I", enc_b(CLICK_TRAMP, labels["click"]))),
        (CTOR_HOOK, struct.pack("<I", enc_b(CTOR_HOOK, code_at))),
        (REG_HOOK, struct.pack("<I", enc_b(REG_HOOK, labels["reg"]))),
        (0x1645784, struct.pack("<I", enc_b(0x1645784, labels["from_x22"], True))),
        (0x1646994, struct.pack("<I", enc_b(0x1646994, labels["from_x22"], True))),
        (0x1646098, struct.pack("<I", enc_b(0x1646098, labels["from_x21"], True))),
    ]
    for pc, rd in SIZE_SITES:
        patches.append((pc, struct.pack("<I", 0xD280F000 | rd)))
    patches.sort(key=lambda item: item[0])
    return image, patches


def patchset_dict(data: bytes, patches: list[tuple[int, bytes]]) -> dict:
    entries = []
    names = {
        CAVE: "boot-menu-cave",
        0x16439AC: "screen-alloc-size",
        0x16439E0: "screen-unwind-delete-size",
        0x1647108: "screen-deleting-dtor-size",
        0x1647A08: "screen-secondary-delete-size",
        0x1644FF4: "list-row-count",
        CLICK_BGT: "click-index-gt2",
        CLICK_TRAMP: "click-trampoline",
        CTOR_HOOK: "ctor-enter-clone",
        REG_HOOK: "list-register-row",
        0x1645784: "dtor-complete-hook",
        0x1646994: "dtor-deleting-hook",
        0x1646098: "dtor-secondary-hook",
    }
    descriptions = {
        "boot-menu-cave": "boot thingy row clone, destructor clone, and the posix_spawnp thunk",
        "screen-alloc-size": "operator new size 1792 -> 1920",
        "screen-unwind-delete-size": "sized delete on the factory unwind path matches the new size",
        "screen-deleting-dtor-size": "primary deleting destructor frees 1920 bytes",
        "screen-secondary-delete-size": "secondary-base deleting destructor frees 1920 bytes",
        "list-row-count": "list row count 4 -> 5",
        "click-index-gt2": "rows above 2 detour through the nop trampoline",
        "click-trampoline": "nop becomes a long branch to the index-4 check",
        "ctor-enter-clone": "after SD Card Access, construct the boot thingy row",
        "list-register-row": "register the new row with the list box",
        "dtor-complete-hook": "complete destructor also destroys the new row",
        "dtor-deleting-hook": "deleting destructor also destroys the new row",
        "dtor-secondary-hook": "secondary-base destructor also destroys the new row",
    }
    patched = bytearray(data)
    for off, repl in patches:
        pid = names[off]
        entries.append({
            "id": pid,
            "description": descriptions[pid],
            "offset": hex(off),
            "original": data[off:off + len(repl)].hex(),
            "patched": repl.hex(),
        })
        patched[off:off + len(repl)] = repl
    return {
        "schema": 1,
        "comment": [
            "boot thingy row on the Shift+Pad 16 save/load screen.",
            "Generated by tools/gen_boot_menu.py from the stock 1.3.0.12 binary.",
            "Offsets and bytes only. The stock binary is not in this file.",
        ],
        "target": {
            "name": "MPC Sample",
            "firmware_version": "1.3.0.12",
            "path_on_device": "/usr/bin/MPC Sample",
            "size": STOCK_SIZE,
            "sha256": STOCK_SHA,
        },
        "result": {"sha256": hashlib.sha256(patched).hexdigest()},
        "patches": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stock", type=Path, help="stock /usr/bin/MPC Sample from your unit")
    parser.add_argument("-o", "--out", type=Path, help="write the patch set JSON here")
    args = parser.parse_args(argv)
    try:
        data = args.stock.read_bytes()
        _image, patches = build(data)
        spec = patchset_dict(data, patches)
    except (OSError, GenError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(spec, indent=2) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out} ({len(patches)} patches, cave {len(_image)} bytes)")
        print(f"result {spec['result']['sha256']}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
