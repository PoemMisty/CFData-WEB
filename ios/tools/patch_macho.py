#!/usr/bin/env python3
"""Turn a Go darwin/arm64 binary into something iOS dyld will accept.

1. LC_BUILD_VERSION.platform  macOS(1) -> iOS(2)
2. Rewrite macOS framework paths to their iOS equivalents (in place, shorter).
"""
import struct, sys, shutil, os

LC_BUILD_VERSION = 0x32
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018

# macOS versioned framework path -> iOS path (must be shorter or equal)
PATH_MAP = {
    b"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation":
        b"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    b"/System/Library/Frameworks/Security.framework/Versions/A/Security":
        b"/System/Library/Frameworks/Security.framework/Security",
    b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation":
        b"/System/Library/Frameworks/Foundation.framework/Foundation",
    b"/usr/lib/libSystem.B.dylib": b"/usr/lib/libSystem.B.dylib",
}


def patch(path, out):
    d = bytearray(open(path, "rb").read())
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = struct.unpack("<IiiIIIII", d[:32])
    assert magic == 0xFEEDFACF, "not a 64-bit Mach-O"
    off = 32
    changes = []
    for _ in range(ncmds):
        cmd, cms = struct.unpack("<II", d[off:off + 8])
        if cmd == LC_BUILD_VERSION:
            plat, minos, sdk, ntools = struct.unpack("<IIII", d[off + 8:off + 24])
            if plat != 2:
                d[off + 8:off + 12] = struct.pack("<I", 2)
                changes.append(f"platform {plat} -> 2")
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            nameoff = struct.unpack("<I", d[off + 8:off + 12])[0]
            raw = bytes(d[off + nameoff:off + cms]).split(b"\0")[0]
            if raw in PATH_MAP:
                new = PATH_MAP[raw]
                if len(new) > len(raw):
                    raise SystemExit(f"new path too long for in-place patch: {new!r}")
                buf = new + b"\0" * (len(raw) - len(new))
                d[off + nameoff:off + nameoff + len(raw)] = buf
                changes.append(f"dylib {raw.decode()} -> {new.decode()}")
        off += cms
    open(out, "wb").write(d)
    print(f"  patched {os.path.basename(path)} -> {out}")
    for c in changes:
        print("    " + c)
    return d


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    patch(src, dst)
