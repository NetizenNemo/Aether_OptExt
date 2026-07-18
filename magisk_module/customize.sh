#!/system/bin/sh
# Aether OptExt — Magisk/KernelSU 安装脚本

set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/aether-optext 0 0 0755

# 清除旧缓存
rm -f /sdcard/Android/Aether/threads_cache 2>/dev/null

# 按频率检测 CPU 拓扑
detect_topology() {
    local counts=""
    for policy in /sys/devices/system/cpu/cpufreq/policy[0-9]*; do
        [ -d "$policy" ] || continue
        local cpus=$(cat "$policy/related_cpus" 2>/dev/null)
        [ -z "$cpus" ] && continue
        local count=0
        for c in $(echo "$cpus" | tr ',' ' ' | tr '-' ' '); do
            count=$((count + 1))
        done
        if echo "$cpus" | grep -q '-'; then
            local start=$(echo "$cpus" | cut -d'-' -f1)
            local end=$(echo "$cpus" | cut -d'-' -f2)
            count=$((end - start + 1))
        fi
        counts="$counts $count"
    done
    local topo=$(echo "$counts" | xargs | tr ' ' '\n' | tr '\n' '+' | sed 's/^+//;s/+$//')
    [ -z "$topo" ] && topo="unknown"
    echo "$topo"
}

TARGET="/sdcard/Android/Aether"
mkdir -p "$TARGET" 2>/dev/null

TOPOLOGY=$(detect_topology)
ui_print "- CPU: $TOPOLOGY"

if [ -f "$MODPATH/config/${TOPOLOGY}.json" ]; then
    cp "$MODPATH/config/${TOPOLOGY}.json" "$TARGET/threads.json" 2>/dev/null
    ui_print "- 配置已部署"
else
    [ -f "$TARGET/threads.json" ] || ui_print "- 请手动配置 threads.json"
fi

ui_print "- Aether OptExt 安装完成"
ui_print "- 日志: /sdcard/Android/Aether/threads_log.txt"
