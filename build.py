#!/usr/bin/env python3
import os, sys, shutil, subprocess, zipfile
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR / "out"
MODULE_DIR = SCRIPT_DIR / "magisk_module"
MODULE_ZIP = OUT_DIR / f"Aether-OptExt_{datetime.now():%Y%m%d_%H%M%S}-OS4.zip"
TARGET = "aarch64-linux-android"

def info(m): print(f"[INFO] {m}")
def warn(m): print(f"[WARN] {m}")
def die(m): print(f"[ERROR] {m}"); sys.exit(1)

def gen_ebpf_bytecode():
    """用 WSL 编译 aya-ebpf (Rust) eBPF 程序 -> ebpf_target.o"""
    o_file = SCRIPT_DIR / "ebpf_target.o"
    # Windows 项目路径 -> WSL 路径 (/mnt/g/aether_opt_ext)
    drive = SCRIPT_DIR.drive.lower().rstrip(':')
    wsl_path = "/mnt/" + drive + SCRIPT_DIR.as_posix().split(':', 1)[1]

    script = []
    script.append('export PATH="$HOME/.cargo/bin:$PATH"')
    script.append('export LLVM_SYS_190_PREFIX="$HOME/kernel/bin/clang19"')
    script.append('cd ' + wsl_path + '/ebpf')
    script.append('cargo +nightly build --target bpfel-unknown-none --release -Zbuild-std=core 2>&1')
    script.append('EXIT=$?')
    script.append('if [ $EXIT -ne 0 ]; then exit $EXIT; fi')
    script.append('cp target/bpfel-unknown-none/release/aether-ebpf ' + wsl_path + '/ebpf_target.o')
    script.append('echo "eBPF: .o generated OK"')
    payload = chr(10).join(script)

    for distro in ["Ubuntu", None]:
        cmd = ["wsl"]
        if distro:
            cmd += ["-d", distro]
        cmd += ["bash", "-s"]
        try:
            r = subprocess.run(cmd, input=payload.encode(), capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            warn("eBPF: WSL 编译超时")
            return
        if r.returncode == 0:
            if o_file.exists():
                info("eBPF: Rust aya-ebpf 程序编译完成")
                return
            warn("eBPF: 编译成功但 .o 未生成")
            return
    warn("eBPF: WSL 不可用, 保留现有 ebpf_target.o")


def ndk_candidates(base):
    """给定路径，产出其下所有可能的 NDK 根目录。
    兼容三种布局：NDK 本体、SDK(ndk/*, ndk-bundle/*)、解压父目录(*/ 一层子目录)"""
    base = Path(base)
    if not base.exists():
        return
    if (base / "toolchains" / "llvm" / "prebuilt").exists():
        yield base
        return
    seen = set()
    for pat in ["ndk/*", "ndk-bundle/*", "*"]:
        for p in sorted(base.glob(pat), reverse=True):
            if p in seen or not p.is_dir():
                continue
            seen.add(p)
            if (p / "toolchains" / "llvm" / "prebuilt").exists():
                yield p

def pick_linker(ndk_dir):
    """从 NDK 目录解析 host tag 与 aarch64 linker，返回 (host_tag, linker) 或 None"""
    for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-aarch64"]:
        tc = ndk_dir / "toolchains" / "llvm" / "prebuilt" / tag
        if not tc.exists():
            continue
        linker = tc / "bin" / "aarch64-linux-android21-clang"
        if sys.platform == "win32":
            linker = linker.with_suffix(".cmd")
        if linker.exists():
            return tag, linker
    return None

def find_ndk():
    """找 NDK 目录用于 Rust 交叉编译。返回 (ndk_dir, host_tag, linker) 或 (None, None, None)"""
    bases = [os.environ.get(v) for v in ["ANDROID_NDK_HOME", "ANDROID_NDK", "NDK_HOME", "NDK_ROOT",
                                        "ANDROID_HOME", "ANDROID_SDK_ROOT"]]
    # 常见路径兜底
    bases += [str(Path.home() / "Android/Sdk"), str(Path.home() / "AppData/Local/Android/Sdk")]
    bases += ["D:/android-ndk-r27d-windows", "C:/android-ndk", "D:/android-ndk"]

    for base_str in filter(None, bases):
        for ndk_dir in ndk_candidates(base_str):
            picked = pick_linker(ndk_dir)
            if picked:
                info(f"NDK: {ndk_dir}")
                return ndk_dir, picked[0], picked[1]
    warn("无 NDK"); return None, None, None

def build(ndk_info):
    info("编译...")
    os.chdir(SCRIPT_DIR)
    env = os.environ.copy()
    if ndk_info:
        ndk_dir, host_tag, linker = ndk_info
        if ndk_dir is None:
            die("无 NDK，无法交叉编译 aarch64-linux-android")
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
    ver = now.strftime("%m%d-Release")
    vc = int(now.strftime("%y%m%d"))
    prop = MODULE_DIR / "module.prop"
    prop.write_text(
        f"id=aether-optext\nname=Aether OptExt\nversion={ver}\nversionCode={vc}\nauthor=NekoNemo\n"
        "description=Aether OptExt - Android CPU affinity optimizer\n"
    )

    for f in MODULE_DIR.glob("**/*"):
        if f.suffix in (".sh", ".prop", ".json", ".md") or f.name == "updater-script":
            if fix_line_ending(f): info(f"换行符: {f.name}")
    with zipfile.ZipFile(MODULE_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(MODULE_DIR):
            for f in files:
                full = Path(root) / f; rel = str(full.relative_to(MODULE_DIR)).replace("\\", "/")
                if rel.startswith(".") or "/." in rel: continue
                z.write(binary if rel == "aether-optext" else full, rel)

def main():
    # eBPF 事件驱动默认禁用 (纯 /proc 轮询); 仅当 .o 缺失时用 WSL 重新编译 Rust eBPF
    if not (SCRIPT_DIR / "ebpf_target.o").exists():
        gen_ebpf_bytecode()
    ndk_info = find_ndk()
    build(ndk_info)
    package()
    info(f"完成: {MODULE_ZIP.name} ({MODULE_ZIP.stat().st_size/1024:.0f}KB)")

if __name__ == "__main__":
    main()
