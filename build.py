#!/usr/bin/env python3
import os, sys, shutil, subprocess, zipfile
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR / "out"
MODULE_DIR = SCRIPT_DIR / "magisk_module"
MODULE_ZIP = OUT_DIR / f"Aether-OptExt_{datetime.now():%Y%m%d_%H%M%S}.zip"
TARGET = "aarch64-linux-android"

def info(m): print(f"[INFO] {m}")
def warn(m): print(f"[WARN] {m}")
def die(m): print(f"[ERROR] {m}"); sys.exit(1)

def find_ndk():
    for base in [os.environ.get(k) for k in ["ANDROID_NDK_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT"]] + \
                [str(Path.home() / "Android/Sdk"), str(Path.home() / "AppData/Local/Android/Sdk"), "C:/Users/shenz/AppData/Local/Android/Sdk"]:
        if not base: continue
        base = Path(base)
        ndk_dir = base if (base / "toolchains/llvm/prebuilt").exists() else next(iter(sorted(base.glob("ndk/*"), reverse=True)), None)
        if not ndk_dir: ndk_dir = next(iter(sorted(base.glob("ndk-bundle/*"), reverse=True)), None)
        if not ndk_dir: continue
        for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-aarch64"]:
            tc = ndk_dir / "toolchains/llvm/prebuilt" / tag
            if not tc.exists(): continue
            linker = tc / "bin" / "aarch64-linux-android21-clang"
            if sys.platform == "win32": linker = linker.with_suffix(".cmd")
            if linker.exists(): info(f"NDK: {ndk_dir}"); return ndk_dir, tag, linker
    warn("无 NDK"); return None, None, None

def build(ndk_info):
    info("编译...")
    os.chdir(SCRIPT_DIR)
    env = os.environ.copy()
    if ndk_info:
        ndk_dir, host_tag, linker = ndk_info
        tc = ndk_dir / "toolchains/llvm/prebuilt" / host_tag
        env["CC_aarch64_linux_android"] = str(linker)
        env["AR_aarch64_linux_android"] = str(tc / "bin/llvm-ar")
        cargo_dir = SCRIPT_DIR / ".cargo"
        cargo_dir.mkdir(exist_ok=True)
        (cargo_dir / "config.toml").write_text(f"[target.{TARGET}]\nlinker = \"{str(linker).replace(chr(92), chr(47))}\"\n")
    if subprocess.run(["cargo", "build", "--target", TARGET, "--release"], env=env).returncode != 0:
        die("编译失败")

def fix_line_ending(path):
    with open(path, 'rb') as f: d = f.read()
    if b'\r\n' not in d: return False
    with open(path, 'wb') as f: f.write(d.replace(b'\r\n', b'\n'))
    return True

def package():
    info("打包...")
    binary = SCRIPT_DIR / "target" / TARGET / "release" / "aether-optext"
    if not binary.exists(): binary = SCRIPT_DIR / "target" / "release" / "aether-optext"
    if not binary.exists(): die("编译产物未找到")
    OUT_DIR.mkdir(exist_ok=True)
    MODULE_ZIP.unlink(missing_ok=True)
    shutil.copy2(binary, MODULE_DIR / "aether-optext")
    os.chmod(MODULE_DIR / "aether-optext", 0o755)

    # 更新版本号
    now = datetime.now()
    ver = now.strftime("%m%d-ReleasePreview")
    vc = int(now.strftime("%y%m%d"))
    prop = MODULE_DIR / "module.prop"
    prop.write_text(
        f"id=aether-optext\nname=Aether OptExt\nversion={ver}\nversionCode={vc}\nauthor=NetizenNemo\n"
        "description=Aether OptExt - Android CPU affinity optimizer\n"
    )

    for f in MODULE_DIR.glob("**/*"):
        if f.suffix in (".sh", ".prop", ".json", ".md") or f.name == "updater-script":
            if fix_line_ending(f): info(f"换行符: {f.name}")
    with zipfile.ZipFile(MODULE_ZIP, "w", zipfile.ZIP_STORED) as z:
        for root, dirs, files in os.walk(MODULE_DIR):
            for f in files:
                full = Path(root) / f; rel = str(full.relative_to(MODULE_DIR)).replace("\\", "/")
                if rel.startswith(".") or "/." in rel: continue
                z.write(binary if rel == "aether-optext" else full, rel)

def main():
    ndk_info = find_ndk()
    build(ndk_info)
    package()
    info(f"完成: {MODULE_ZIP.name} ({MODULE_ZIP.stat().st_size/1024:.0f}KB)")

if __name__ == "__main__":
    main()
