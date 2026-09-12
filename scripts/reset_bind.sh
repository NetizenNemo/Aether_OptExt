#!/system/bin/sh
# Aether OptExt — 一键重置绑核
# 将 Aether 绑过的进程/线程恢复到系统默认调度状态。
#
# 用法（需 root）:
#   sh reset_bind.sh                停守护 + 迁出 cpuset + 恢复亲和性 + 清理分组
#   sh reset_bind.sh --clear-cache  额外清除自动分配缓存 threads_cache
#   sh reset_bind.sh --restart      重置后重启守护进程
#
# 只影响本模块创建的 BASE_CPUSET(/dev/cpuset/OptExt)，不触碰系统原生分组。

BASE_CPUSET="/dev/cpuset/OptExt"
MODDIR=${0%/*}
BIN="$MODDIR/../magisk_module/aether-optext"
[ -x "$BIN" ] || BIN="/data/adb/modules/aether-optext/aether-optext"
CONFIG="/sdcard/Android/Aether/threads.json"
CACHE="/sdcard/Android/Aether/threads_cache"
LOG="/sdcard/Android/Aether/threads_log.txt"
ONLINE=$(cat /sys/devices/system/cpu/online 2>/dev/null)
TIDLIST="/data/local/tmp/.aether_reset_tids.$$"

CLEAR_CACHE=0
RESTART=0
for a in "$@"; do
    [ "$a" = "--clear-cache" ] && CLEAR_CACHE=1
    [ "$a" = "--restart" ] && RESTART=1
done

ok() { echo "  [OK] $1"; }
no() { echo "  [!!] $1"; }
cleanup() { rm -f "$TIDLIST"; }
trap cleanup EXIT INT TERM

echo "================================"
echo " Aether OptExt 重置绑核"
echo "================================"

# 1. 停止守护进程（先停，防止重置后立即被重新绑定）
echo "--- 1. 停止守护进程 ---"
PID=$(pgrep -f "aether-optext" | head -1)
if [ -n "$PID" ]; then
    pkill -f "aether-optext" 2>/dev/null
    sleep 1
    pgrep -f "aether-optext" >/dev/null 2>&1 && no "未能停止 (PID=$PID)" || ok "已停止 (PID=$PID)"
else
    ok "无运行中的守护进程"
fi

# 2. 收集本模块 cpuset 分组内的全部存活线程（迁出前必须先记录，迁出后 tasks 即空）
echo ""
echo "--- 2. 收集受管线程 ---"
: > "$TIDLIST"
if [ -d "$BASE_CPUSET" ]; then
    for tf in $(find "$BASE_CPUSET" -name tasks 2>/dev/null); do
        [ -r "$tf" ] || continue
        while read -r tid; do
            [ -n "$tid" ] || continue
            kill -0 "$tid" 2>/dev/null && echo "$tid" >> "$TIDLIST"
        done < "$tf"
    done
    # 去重
    sort -u "$TIDLIST" -o "$TIDLIST" 2>/dev/null
    CNT=$(wc -l < "$TIDLIST" | tr -d ' ')
    ok "发现 $CNT 个受管线程"
else
    CNT=0
    ok "无 $BASE_CPUSET 分组（cpuset 未启用或未创建）"
fi

# 迁移目标：优先 foreground，退回 top-app
DST="/dev/cpuset/foreground/tasks"
[ -w "$DST" ] || DST="/dev/cpuset/top-app/tasks"

# 3. 迁出 cpuset 分组
echo ""
echo "--- 3. 迁出 cpuset 分组 ---"
if [ "${CNT:-0}" -gt 0 ]; then
    MIGRATED=0
    while read -r tid; do
        kill -0 "$tid" 2>/dev/null || continue
        echo "$tid" > "$DST" 2>/dev/null && MIGRATED=$((MIGRATED + 1))
    done < "$TIDLIST"
    ok "已迁出 $MIGRATED 个线程 -> $DST"
else
    ok "无需迁出"
fi

# 4. 恢复被 sched_setaffinity 绑定的线程亲和性为全部在线核
echo ""
echo "--- 4. 恢复 CPU 亲和性 ---"
if [ "${CNT:-0}" -gt 0 ] && [ -n "$ONLINE" ] && command -v taskset >/dev/null 2>&1; then
    RESTORED=0
    while read -r tid; do
        kill -0 "$tid" 2>/dev/null || continue
        taskset -pc "$ONLINE" "$tid" >/dev/null 2>&1 && RESTORED=$((RESTORED + 1))
    done < "$TIDLIST"
    ok "已恢复 $RESTORED 个线程 -> 在线核 [$ONLINE]"
elif [ "${CNT:-0}" -gt 0 ]; then
    no "taskset 不可用或无 online 信息，跳过亲和性恢复（cpuset 已迁出，影响可控）"
else
    ok "无需恢复"
fi

# 5. 清理 OptExt 分组目录（仅叶子，自底向上；非空则内核拒绝删除）
echo ""
echo "--- 5. 清理分组目录 ---"
if [ -d "$BASE_CPUSET" ]; then
    find "$BASE_CPUSET" -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
        rmdir "$d" 2>/dev/null
    done
    rmdir "$BASE_CPUSET" 2>/dev/null
    [ -d "$BASE_CPUSET" ] && no "部分分组仍被占用，未完全删除" || ok "已删除 $BASE_CPUSET"
else
    ok "无需清理"
fi

# 6. 可选清除自动分配缓存
echo ""
echo "--- 6. 缓存 ---"
if [ "$CLEAR_CACHE" = "1" ]; then
    [ -f "$CACHE" ] && rm -f "$CACHE" && ok "已清除 threads_cache" || ok "无缓存文件"
else
    ok "保留 threads_cache（--clear-cache 可清除）"
fi

# 7. 可选重启守护进程
echo ""
echo "--- 7. 守护进程 ---"
if [ "$RESTART" = "1" ]; then
    if [ -x "$BIN" ] && [ -f "$CONFIG" ]; then
        "$BIN" -c "$CONFIG" -s 2 >> "$LOG" 2>&1 &
        ok "已重启守护进程 (PID=$!)"
    else
        no "二进制或配置缺失，未能重启"
    fi
else
    ok "保持停止（--restart 可重启）"
fi

echo ""
echo "================================"
echo " 重置完成"
echo "================================"
