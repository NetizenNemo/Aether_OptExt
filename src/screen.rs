//! 屏幕亮灭检测，用于息屏期间降低亲和性校正频率。
//!
//! 息屏后没有前台应用、没有渲染提交、屏幕不刷新，此时周期性全量重绑
//! 上千个线程几乎没有收益，纯耗电。
//!
//! ## 判据优先级
//!
//! 1. `/sys/class/thermal/thermal_message/screen_state` —— 内核侧屏幕状态，
//!    `1` 亮 / `0` 灭。不受 AOD（息屏显示）影响，是首选。
//! 2. `.../backlight/<dev>/actual_brightness` —— 实际生效亮度，息屏为 0
//! 3. `.../backlight/<dev>/brightness`        —— 用户设定值，**息屏不归零**，
//!    仅在前两者都不可用时兜底
//! 4. `/sys/class/drm/*/dpms`                 —— On/Off
//!
//! 实测（25098PN5AC）：息屏后 `brightness` 仍保留 64~700，只有
//! `screen_state` 与 `actual_brightness` 归零。此前的实现只读 `brightness`，
//! 导致息屏检测永久失效、降频从未生效。
//!
//! `screen_state` 是小米/高通私有节点，其他 ROM 上可能不存在或语义不同，
//! 因此保留多级回退；全部不可用时按「亮屏」处理，保持原有校正节奏 ——
//! 宁可不省电，也不能因为检测失败而让前台应用错过绑核时机。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 内核侧屏幕状态：1 亮 / 0 灭
const SCREEN_STATE_PATH: &str = "/sys/class/thermal/thermal_message/screen_state";

/// 过渡期复核延迟。部分设备在 Dozing 与 Awake 之间该节点更新滞后，
/// 直接采信会把"仍在亮屏"误判为息屏
const CONFIRM_DELAY_MS: u64 = 250;

/// 上一轮判定的屏幕状态。仅用于识别「亮→灭」这一需要复核的方向
static LAST_ON: AtomicBool = AtomicBool::new(true);

/// 缓存的背光节点
struct Nodes {
    actual: Option<&'static str>,
    raw: Option<&'static str>,
    dpms: Option<&'static str>,
}

static NODES: std::sync::OnceLock<Nodes> = std::sync::OnceLock::new();

fn nodes() -> &'static Nodes {
    NODES.get_or_init(|| {
        let mut actual = None;
        let mut raw = None;
        if let Ok(rd) = std::fs::read_dir("/sys/class/backlight") {
            for e in rd.flatten() {
                let dir = e.path();
                let a = dir.join("actual_brightness");
                if actual.is_none() && a.exists() {
                    actual = a.to_str().map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str);
                }
                let b = dir.join("brightness");
                if raw.is_none() && b.exists() {
                    raw = b.to_str().map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str);
                }
                if actual.is_some() || raw.is_some() {
                    break;
                }
            }
        }
        if raw.is_none() {
            let p = "/sys/class/leds/lcd-backlight/brightness";
            if std::path::Path::new(p).exists() {
                raw = Some(p);
            }
        }
        let mut dpms = None;
        if actual.is_none() && raw.is_none() {
            if let Ok(rd) = std::fs::read_dir("/sys/class/drm") {
                for e in rd.flatten() {
                    let p = e.path().join("dpms");
                    if p.exists() {
                        dpms = p.to_str().map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str);
                        break;
                    }
                }
            }
        }
        Nodes { actual, raw, dpms }
    })
}

/// 读取一次原始屏幕状态，不做过渡期复核
fn read_raw() -> bool {
    // 1) 内核侧状态节点：AOD 下依然准确
    if let Ok(s) = std::fs::read_to_string(SCREEN_STATE_PATH) {
        match s.trim() {
            "0" => return false,
            "1" => return true,
            _ => {}
        }
    }
    let n = nodes();
    // 2) 实际生效亮度
    if let Some(p) = n.actual {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(v) = s.trim().parse::<u32>() {
                return v > 0;
            }
        }
    }
    // 3) 用户设定亮度（息屏不归零，仅兜底）
    if let Some(p) = n.raw {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(v) = s.trim().parse::<u32>() {
                return v > 0;
            }
        }
    }
    // 4) DRM 电源状态
    if let Some(p) = n.dpms {
        if let Ok(s) = std::fs::read_to_string(p) {
            return !s.trim().eq_ignore_ascii_case("off");
        }
    }
    // 全部不可用：保守按亮屏
    true
}

/// 带过渡期复核的屏幕状态。
///
/// 仅在「亮 → 灭」方向延迟 `CONFIRM_DELAY_MS` 后复读一次：该方向误判的
/// 代价是把正在亮屏的设备当成息屏、停止校正；反方向误判只是晚一轮降频，
/// 无需复核。稳态下只有一次文件读，零额外开销。
pub fn poll_state() -> bool {
    let raw = read_raw();
    let last = LAST_ON.load(Ordering::Relaxed);
    if last && !raw {
        std::thread::sleep(Duration::from_millis(CONFIRM_DELAY_MS));
        let again = read_raw();
        LAST_ON.store(again, Ordering::Relaxed);
        return again;
    }
    LAST_ON.store(raw, Ordering::Relaxed);
    raw
}

/// 是否有可用的屏幕状态来源。仅供启动日志说明
pub fn available() -> bool {
    std::path::Path::new(SCREEN_STATE_PATH).exists()
        || nodes().actual.is_some()
        || nodes().raw.is_some()
        || nodes().dpms.is_some()
}

/// 当前使用的判据来源，供启动日志说明
pub fn source() -> &'static str {
    if std::path::Path::new(SCREEN_STATE_PATH).exists() {
        "screen_state"
    } else if nodes().actual.is_some() {
        "actual_brightness"
    } else if nodes().raw.is_some() {
        "brightness"
    } else if nodes().dpms.is_some() {
        "dpms"
    } else {
        "unavailable"
    }
}
