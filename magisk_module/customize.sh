#!/system/bin/sh
# Aether OptExt — Magisk/KernelSU 安装脚本

set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/aether-optext 0 0 0755

# 清除旧缓存
rm -f /sdcard/Android/Aether/threads_cache 2>/dev/null

# 按频率检测 CPU 集群
detect_topology() {
    local freq_list=""
    for policy in /sys/devices/system/cpu/cpufreq/policy[0-9]*; do
        [ -d "$policy" ] || continue
        local cpus=$(cat "$policy/related_cpus" 2>/dev/null)
        local freq=$(cat "$policy/cpuinfo_max_freq" 2>/dev/null)
        [ -z "$cpus" ] && continue
        local count=0
        if echo "$cpus" | grep -q '-'; then
            local s=$(echo "$cpus" | cut -d'-' -f1)
            local e=$(echo "$cpus" | cut -d'-' -f2)
            count=$((e - s + 1))
        else
            for c in $(echo "$cpus" | tr ',' ' '); do count=$((count + 1)); done
        fi
        freq_list="$freq_list $freq:$count"
    done
    # 按频率降序 (高频=大核优先)
    local result=""
    for pair in $freq_list; do
        local best=""
        local best_val=0
        for p in $freq_list; do
            local f=${p%:*}
            local c=${p#*:}
            if [ $f -gt $best_val ] 2>/dev/null; then
                best="$p"
                best_val=$f
            fi
        done
        [ -n "$best" ] && result="$result ${best#*:}" && freq_list=${freq_list/$best/}
    done
    [ -n "$result" ] && echo "$result" | tr ' ' '+' || echo "unknown"
}

TARGET="/sdcard/Android/Aether"
mkdir -p "$TARGET" 2>/dev/null

TOPOLOGY=$(detect_topology)
ui_print "- CPU: $TOPOLOGY"

if [ -f "$MODPATH/config/${TOPOLOGY}.json" ]; then
    cp "$MODPATH/config/${TOPOLOGY}.json" "$TARGET/threads.json" 2>/dev/null
    ui_print "- 配置文件已部署"
fi

ui_print "- Aether OptExt 安装完成"
ui_print "- 日志: /sdcard/Android/Aether/threads_log.txt"
