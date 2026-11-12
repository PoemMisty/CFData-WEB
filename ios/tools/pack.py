#!/usr/bin/env python3
"""Assemble a TrollStore-ready iOS IPA from the ObjC shell + Go backend.

Layout expected (all paths relative to the ios/ directory):

    ios/CFData                      compiled shell binary (arm64 Mach-O)
    ios/build/cfdata-backend        Go backend, patched to iOS (see tools/patch_macho.py)
    ios/assets/AppIcon60x60@*.png   icon assets
    ios/Info.plist, entitlements.plist

Usage:
    python3 ios/tools/pack.py [output.ipa]
"""
import os
import shutil
import subprocess
import sys
import zipfile

IOS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(IOS_DIR, "build")
STAGE = os.path.join(BUILD, "stage")
APP_NAME = "CFData"
BACKEND_BIN = os.path.join(BUILD, "cfdata-backend")
SHELL_BIN = os.path.join(IOS_DIR, "CFData")
ASSETS = os.path.join(IOS_DIR, "assets")

EXTRA_FILES = [
    ("Info.plist", "Info.plist"),
    ("assets/AppIcon60x60@2x.png", "AppIcon60x60@2x.png"),
    ("assets/AppIcon60x60@3x.png", "AppIcon60x60@3x.png"),
    ("assets/logo.png", "logo.png"),
]


def main():
    out_ipa = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BUILD, "CFData-iOS.ipa")

    for path, label in ((SHELL_BIN, "shell binary"), (BACKEND_BIN, "Go backend")):
        if not os.path.isfile(path):
            raise SystemExit(f"missing {label}: {path}")

    shutil.rmtree(STAGE, ignore_errors=True)
    app = os.path.join(STAGE, "Payload", f"{APP_NAME}.app")
    os.makedirs(app, exist_ok=True)

    shutil.copyfile(SHELL_BIN, os.path.join(app, APP_NAME))
    shutil.copyfile(BACKEND_BIN, os.path.join(app, "cfdata-backend"))
    for rel_src, rel_dst in EXTRA_FILES:
        src = os.path.join(IOS_DIR, rel_src)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(app, rel_dst))
    with open(os.path.join(app, "PkgInfo"), "w") as fh:
        fh.write("APPL????")

    for name in (APP_NAME, "cfdata-backend"):
        os.chmod(os.path.join(app, name), 0o755)
        info = subprocess.run(["file", os.path.join(app, name)], capture_output=True, text=True).stdout
        print(info.strip())
        if "Mach-O" not in info:
            raise SystemExit(f"{name} is not a Mach-O binary")

    if os.path.exists(out_ipa):
        os.remove(out_ipa)
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for dirpath, _dirs, files in os.walk(STAGE):
            for fn in files:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, STAGE).replace(os.sep, "/")
                info = zipfile.ZipInfo(rel)
                mode = 0o755 if fn in (APP_NAME, "cfdata-backend") else 0o644
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    zf.writestr(info, fh.read())

    print(f"IPA: {out_ipa} ({os.path.getsize(out_ipa) / 1024 / 1024:.2f} MB)")


if __name__ == "__main__":
    main()
