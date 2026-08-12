#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import zipfile
from pathlib import Path
from datetime import datetime

# --- 配置 ---
PROJECT_NAME = "Aether-OptExt"
RUST_TARGET = "aarch64-linux-android"
EBPF_TARGET = "bpfel-unknown-none"
MODULE_DIR = Path("magisk_module")
OUT_DIR = Path("out")
BINARY_NAME = "aether-optext"

def info(msg): print(f"\033[1;32m[INFO]\033[0m {msg}")
def warn(msg): print(f"\033[1;33m[WARN]\033[0m {msg}")
def die(msg):
    print(f"\033[1;31m[ERROR]\033[0m {msg}", file=sys.stderr)
    sys.exit(1)

def gen_ebpf_bytecode():
    """在纯 Linux 下直接调用 cargo +nightly 编译 eBPF"""
    info("Generating eBPF bytecode...")
    ebpf_dir = Path("ebpf")
    output_obj = Path("ebpf_target.o")
    
    if not ebpf_dir.exists():
        warn("eBPF source directory not found, skipping generation.")
        return
        
    try:
        subprocess.run(
            ["cargo", "+nightly", "build", "--release", 
             "--target", EBPF_TARGET, "-Z", "build-std=core"],
            cwd=ebpf_dir, check=True
        )
        src = ebpf_dir / "target" / EBPF_TARGET / "release" / "aether-ebpf"
        if src.exists():
            shutil.copy2(src, output_obj)
            info(f"eBPF object copied to {output_obj}")
        else:
            die(f"eBPF compilation succeeded but output not found at {src}")
    except FileNotFoundError:
        die("cargo +nightly not found. Please install Rust nightly toolchain.")
    except subprocess.CalledProcessError as e:
        die(f"eBPF compilation failed: {e}")

def find_ndk():
    """查找 Android NDK (仅 Linux 路径)"""
    ndk_home = os.environ.get("ANDROID_NDK_HOME") or \
               os.path.join(os.environ.get("ANDROID_HOME", ""), "ndk") or \
               os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "ndk")
    
    if not ndk_home or not Path(ndk_home).exists():
        # 尝试常见 Linux 安装路径
        for p in [Path.home() / "Android/Sdk/ndk", Path("/opt/android-ndk")]:
            if p.exists():
                versions = sorted([d for d in p.iterdir() if d.is_dir()], reverse=True)
                if versions:
                    ndk_home = str(versions[0])
                    break
    
    if not ndk_home or not Path(ndk_home).exists():
        die("Android NDK not found. Set ANDROID_NDK_HOME or install NDK.")
        
    ndk_path = Path(ndk_home)
    host_tag = "linux-x86_64"  # 固定为 Linux
    toolchain = ndk_path / "toolchains/llvm/prebuilt" / host_tag
    linker = toolchain / "bin/aarch64-linux-android24-clang"
    
    if not linker.exists():
        die(f"NDK linker not found at {linker}. Check NDK installation.")
        
    info(f"Using NDK: {ndk_path} ({host_tag})")
    return str(ndk_path), host_tag, str(linker)

def build(ndk_path, linker):
    """编译 Rust 用户态程序"""
    info(f"Building {PROJECT_NAME} for {RUST_TARGET}...")
    
    cargo_config = Path(".cargo/config.toml")
    cargo_config.parent.mkdir(exist_ok=True)
    cargo_config.write_text(f"""\
[target.{RUST_TARGET}]
linker = "{linker}"
ar = "{Path(ndk_path)/'toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar'}"
""")
    
    env = os.environ.copy()
    env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = linker
    
    try:
        subprocess.run(
            ["cargo", "build", "--release", "--target", RUST_TARGET],
            check=True, env=env
        )
    except subprocess.CalledProcessError as e:
        die(f"Rust build failed: {e}")
        
    binary = Path(f"target/{RUST_TARGET}/release/{BINARY_NAME}")
    if not binary.exists():
        die(f"Build artifact not found: {binary}")
    info(f"Build successful: {binary}")
    return binary

def package(binary_path):
    """打包 Magisk 模块"""
    info("Packaging Magisk module...")
    
    # 复制二进制
    dest = MODULE_DIR / "system/bin" / BINARY_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary_path, dest)
    dest.chmod(0o755)
    
    # 更新版本号
    now = datetime.now()
    version = now.strftime("%m%d-Release")
    version_code = now.strftime("%y%m%d")
    
    prop_file = MODULE_DIR / "module.prop"
    if prop_file.exists():
        content = prop_file.read_text()
        import re
        content = re.sub(r'^version=.*$', f'version={version}', content, flags=re.M)
        content = re.sub(r'^versionCode=.*$', f'versionCode={version_code}', content, flags=re.M)
        prop_file.write_text(content)
    
    # 修复换行符
    for ext in ['*.sh', '*.prop', '*.json', '*.md']:
        for f in MODULE_DIR.rglob(ext):
            text = f.read_bytes().replace(b'\r\n', b'\n').replace(b'\r', b'\n')
            f.write_bytes(text)
    updater = MODULE_DIR / "META-INF/com/google/android/updater-script"
    if updater.exists():
        text = updater.read_bytes().replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        updater.write_bytes(text)
    
    # 生成 ZIP
    OUT_DIR.mkdir(exist_ok=True)
    zip_name = f"Aether-OptExt_{now.strftime('%Y%m%d_%H%M%S')}.zip"
    zip_path = OUT_DIR / zip_name
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(MODULE_DIR):
            for file in files:
                fp = Path(root) / file
                arcname = fp.relative_to(MODULE_DIR)
                zf.write(fp, arcname)
                
    info(f"Module packaged: {zip_path}")
    return zip_path

def main():
    ebpf_obj = Path("ebpf_target.o")
    if not ebpf_obj.exists():
        gen_ebpf_bytecode()
    else:
        info(f"Using existing eBPF object: {ebpf_obj}")
        
    ndk_path, _, linker = find_ndk()
    binary = build(ndk_path, linker)
    package(binary)

if __name__ == "__main__":
    main()
