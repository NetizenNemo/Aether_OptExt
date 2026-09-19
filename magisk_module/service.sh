#!/system/bin/sh
MODDIR=${0%/*}
CONFIG="/sdcard/Android/Aether/threads.json"

wait_until_login() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 2.5s
    done
    local test_file="/sdcard/Android/.PERMISSION_TEST_AETHER"
    true >"$test_file"
    while [ ! -f "$test_file" ]; do
        sleep 0.25s
        true >"$test_file"
    done
    rm "$test_file"
}

wait_until_login
rm -f /sdcard/Android/Aether/threads_log.txt 2>/dev/null

# 更新模块描述：先落默认值，再按 Aether 调度器是否在役加前缀
# /data/adb/modules/aether 存在 => 已作为 Aether 的插件协同工作，否则独立运行
update_module_desc() {
    local prop="$MODDIR/module.prop"
    [ -f "$prop" ] || return 0
    local base="一个使用Rust开发的Android 应用/游戏线程 CPU 亲和性优化工具 Feedback: 1028546498"

    # 1. 先写入默认描述（检测失败也有兜底）
    write_desc "$prop" "$base"

    # 2. 按 Aether 调度器是否存在覆盖前缀
    if [ -d "/data/adb/modules/aether" ]; then
        write_desc "$prop" "[已作为插件接入Aether] $base"
        echo "[Aether] 检测到 Aether 调度器，已标记为插件模式"
    else
        write_desc "$prop" "[正在作为独立程序运行] $base"
        echo "[Aether] 未检测到 Aether 调度器，标记为独立模式"
    fi
}

# 仅替换 description 行，保留 id/name/version 等其余字段
write_desc() {
    local prop="$1" desc="$2" tmp="$1.tmp"
    grep -v '^description=' "$prop" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
    printf 'description=%s\n' "$desc" >> "$tmp" || { rm -f "$tmp"; return 0; }
    mv "$tmp" "$prop" 2>/dev/null || { rm -f "$tmp"; return 0; }
    chmod 644 "$prop" 2>/dev/null
}

update_module_desc

pkill "aether-optext" 2>/dev/null
sleep 1

if [ -f "$MODDIR/aether-optext" ]; then
    echo "[Aether] 启动进程..."
    "$MODDIR/aether-optext" -c "$CONFIG" -s 2 &
    echo "[Aether] PID $!"
else
    echo "[Aether] 二进制不存在: $MODDIR/aether-optext"
fi
