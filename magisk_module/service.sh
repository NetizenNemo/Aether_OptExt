#!/system/bin/sh
MODDIR=${0%/*}
CONFIG="/sdcard/Android/Aether/threads.json"

wait_until_login() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2.5; done
    local f="/sdcard/Android/.PERMISSION_TEST_AETHER"
    true >"$f"; while [ ! -f "$f" ]; do sleep 0.25; true >"$f"; done; rm "$f"
}

wait_until_login
mkdir -p "/sdcard/Android/Aether" 2>/dev/null
rm -f /sdcard/Android/Aether/threads_log.txt 2>/dev/null
pkill "aether-optext" 2>/dev/null; sleep 1
[ -f "$MODDIR/aether-optext" ] && "$MODDIR/aether-optext" -c "$CONFIG" -s 2 &
