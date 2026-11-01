//! 屏幕亮灭检测，用于息屏期间降低亲和性校正频率。
//!
//! 息屏后没有前台应用、没有渲染提交、屏幕不刷新，此时周期性全量重绑
//! 上千个线程几乎没有收益，纯耗电。检测方式取背光亮度：`0` 视为息屏。
//!
//! 读不到亮度时一律按「亮屏」处理，即保持原有校正节奏 —— 宁可不省电，
//! 也不能因为检测失败而让前台应用错过绑核时机。

use std::sync::OnceLock;

/// 缓存可用的 brightness 节点路径。首次探测后固定，避免每轮遍历目录
static BACKLIGHT: OnceLock<Option<String>> = OnceLock::new();

fn backlight_node() -> Option<&'static str> {
    BACKLIGHT
        .get_or_init(|| {
            // 主路径：/sys/class/backlight/<设备>/brightness
            if let Ok(rd) = std::fs::read_dir("/sys/class/backlight") {
                for e in rd.flatten() {
                    let p = e.path().join("brightness");
                    if p.exists() {
                        return Some(p.to_string_lossy().into_owned());
                    }
                }
            }
            // 回退：部分老设备只在 leds 下暴露背光
            let p = "/sys/class/leds/lcd-backlight/brightness";
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
            None
        })
        .as_deref()
}

/// 屏幕是否亮着。无可用节点或读取失败时返回 true（保守按亮屏处理）
pub fn is_on() -> bool {
    let Some(path) = backlight_node() else { return true };
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<u32>().map(|v| v > 0).unwrap_or(true),
        Err(_) => true,
    }
}

/// 是否支持息屏检测（节点存在）。仅供日志说明用
pub fn available() -> bool {
    backlight_node().is_some()
}
