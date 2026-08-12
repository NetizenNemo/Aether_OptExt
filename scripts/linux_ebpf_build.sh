#!/bin/bash
set -euo pipefail

# 设置 Rust/Cargo 环境变量
export PATH="$HOME/.cargo/bin:$PATH"

# 定义项目根目录（根据实际情况修改）
PROJECT_ROOT="${AETHER_PROJECT_ROOT:-$HOME/projects/Aether_OptExt}"
EBPF_SRC="$PROJECT_ROOT/ebpf/target/bpfel-unknown-none/release/aether-ebpf"
EBPF_DST="$PROJECT_ROOT/ebpf_target.o"

# 检查源文件是否存在
if [ ! -f "$EBPF_SRC" ]; then
    echo "错误: eBPF 目标文件不存在: $EBPF_SRC" >&2
    echo "请先运行 cargo build --release --target bpfel-unknown-none" >&2
    exit 1
fi

# 复制并重命名
cp "$EBPF_SRC" "$EBPF_DST"

# 验证结果
ls -la "$EBPF_DST"
echo "✅ eBPF 对象文件已就绪: $EBPF_DST"
