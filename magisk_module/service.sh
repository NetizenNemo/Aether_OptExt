#!/system/bin/sh
MODDIR=${0%/*}
CONFIG="/sdcard/Android/Aether/threads.json"

wait_until_login() {
    # 等待开机完成
    local i=0
    while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 60 ]; do
        sleep 1; i=$((i+1))
    done
    # 等待 /sdcard 可写 (最多 30 秒)
    i=0
    while [ $i -lt 30 ]; do
        mkdir -p "/sdcard/Android/Aether" 2>/dev/null && break
        sleep 1; i=$((i+1))
    done
}

wait_until_login
rm -f /sdcard/Android/Aether/threads_log.txt 2>/dev/null
pkill "aether-optext" 2>/dev/null
sleep 1
[ -f "$MODDIR/aether-optext" ] && "$MODDIR/aether-optext" -c "$CONFIG" -s 2 &
