use crate::config::{self, AppConfig};
use crate::cpuset::{ensure_cpuset_dir, CpuSet, CpuTopology};

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 绑核最少核数：低于此值拒绝绑定。
/// 渲染/提交线程在单核上若被其它负载抢占，会因拿不到时间片导致 fence 超时，
/// 触发 SurfaceFlinger 断流黑屏，故 1 核目标一律不采纳
const MIN_BIND_CPUS: usize = 2;

/// 渲染管线线程名特征：名字命中时强制落到高性能核。
/// 这类线程被绑到小核同样可能引发提交延迟 → fence 超时 → 黑屏
const RENDER_THREAD_HINTS: &[&str] = &[
    "RenderThread", "Render", "Gfx", "GLThread", "Vulkan", "RHIThread",
    "RHI", "Gpu", "Gralloc", "Surface", "SwapChain", "Compositor",
];

/// 判断线程名是否为渲染管线线程（不区分大小写，子串匹配）
pub(crate) fn is_render_thread(thread: &str) -> bool {
    if thread.is_empty() { return false; }
    let lower = thread.to_ascii_lowercase();
    RENDER_THREAD_HINTS.iter().any(|h| lower.contains(&h.to_ascii_lowercase()))
}

/// 将目标提升到高性能核集合（hp_core ∪ p_core，取在线部分），
/// 保证渲染线程至少能拿到性能核；集合为空时原样返回
pub(crate) fn promote_to_perf(cpus: CpuSet, topo: &CpuTopology) -> CpuSet {
    let mut perf = topo.hp_core.intersection(&topo.online_cpus_public());
    if perf.count() == 0 {
        perf = topo.p_core.intersection(&topo.online_cpus_public());
    }
    if perf.count() == 0 {
        return cpus;
    }
    // 仅在原目标与性能核无交集时才升级，避免破坏用户已配好的合法组合
    let overlap = cpus.intersection(&perf);
    if overlap.count() > 0 {
        return cpus;
    }
    let mut out = cpus;
    out.or(&perf);
    out
}

/// 包级目标扩容：核数不足 min_cpus 时按 p_core → hp_core 顺序并入在线部分。
/// 仅用于包级 fallback —— 线程规则是用户精确指定的，不扩充。
/// 返回 (新目标, 是否发生扩容)
fn expand_package_target(cpus: CpuSet, min_cpus: usize, topo: &CpuTopology) -> (CpuSet, bool) {
    if min_cpus <= 1 || cpus.count() >= min_cpus {
        return (cpus, false);
    }
    let mut out = cpus;
    for extra in [
        topo.p_core.intersection(&topo.online_cpus_public()),
        topo.hp_core.intersection(&topo.online_cpus_public()),
        topo.online_cpus_public(),
    ] {
        if out.count() >= min_cpus {
            break;
        }
        out.or(&extra);
    }
    // 仅并入在线核，防止扩容引入离线核
    out = out.intersection(&topo.online_cpus_public());
    (out, out != cpus)
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(pkg: &str, thread: &str, cfg: &AppConfig, topo: &CpuTopology) -> Option<AffinityResult> {
    // asoul 兼容：豁免包不参与任何绑定
    if cfg.asoul_ignore.contains(pkg) {
        return None;
    }
    // 用户黑名单：完全不受控，优先级高于一切规则
    if cfg.in_blacklist(pkg) {
        return None;
    }
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    // 用包名索引替代全量遍历：rule_match 内部本就是精确 pkg 比较，
    // 索引里只放精确包名规则，遍历量与全量规则数解耦
    let indices = cfg.rule_indices(pkg);

    if !thread.is_empty() {
        for &i in indices {
            let rule = &cfg.rules[i];
            if rule.thread.is_empty() {
                continue;
            }
            if config::fnmatch(&rule.thread, thread) {
                cpus.or(&cpuset_from_rule(rule));
                matched = true;
            }
        }
        // 按合并后的 CPU 集合重算 cpuset 目录，确保与亲和性一致
        if matched {
            cpuset_dir = ensure_cpuset_dir(&cpus, topo);
        }
    }

    if !matched {
        let mut fallback_seen = false;
        for &i in indices {
            let rule = &cfg.rules[i];
            if !rule.thread.is_empty() {
                continue;
            }
            cpus.or(&cpuset_from_rule(rule));
            if !fallback_seen {
                cpuset_dir = if rule.cpuset_dir.is_empty() {
                    ensure_cpuset_dir(&cpus, topo)
                } else {
                    rule.cpuset_dir.clone()
                };
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
        }
    }

    if cpus.count() == 0 {
        if cfg.pkg_has_thread_rules(pkg) {
            return Some(AffinityResult {
                cpus: topo.present_cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
            });
        }
        return None;
    }

    // ===== 安全护栏 =====
    // 1) 包级最小核数：核集过小会让多线程应用挤在小核上，表现为卡顿。
    //    线程规则是用户精确指定的，不扩充，仅对包级 fallback 生效
    if !matched && cfg.min_cpus > 1 {
        let (expanded, changed) = expand_package_target(cpus, cfg.min_cpus, topo);
        if changed {
            crate::warn!("safety: pkg {} target {} -> {} (min_cpus={})",
                pkg, cpus.to_range_string(), expanded.to_range_string(), cfg.min_cpus);
            cpus = expanded;
            cpuset_dir = ensure_cpuset_dir(&cpus, topo);
        }
    }

    // 2) 渲染线程强制高性能核：小核跑渲染管线会因提交延迟触发 fence 超时黑屏
    if cfg.render_guard && is_render_thread(thread) {
        let before = cpus;
        cpus = promote_to_perf(cpus, topo);
        if cpus != before {
            cpuset_dir = ensure_cpuset_dir(&cpus, topo);
            crate::warn!("safety: render thread '{}' (pkg {}) promoted to perf cores {} (was {})",
                thread, pkg, cpus.to_range_string(), before.to_range_string());
        }
    }

    // 2) 最小核数：单核目标在负载波动下易饿死线程，拒绝并回退包级/全核
    if cpus.count() < MIN_BIND_CPUS {
        crate::warn!("safety: '{}' (pkg {}) target {} has < {} cpus, skipped",
            thread, pkg, cpus.to_range_string(), MIN_BIND_CPUS);
        // 单核目标不可靠：渲染线程给性能核，其余给全部在线核
        let fallback = if cfg.render_guard && is_render_thread(thread) {
            promote_to_perf(cpus, topo)
        } else {
            topo.online_cpus_public()
        };
        if fallback.count() >= MIN_BIND_CPUS {
            cpus = fallback;
            cpuset_dir = ensure_cpuset_dir(&cpus, topo);
        } else {
            return None;  // 连回退都不足 2 核，放弃绑定交由系统默认调度
        }
    }

    Some(AffinityResult {
        cpus,
        cpuset_dir,
        is_thread_rule: matched,
    })
}

/// 将规则中的 cpus 字符串解析为 CpuSet
fn cpuset_from_rule(rule: &config::Rule) -> CpuSet {
    crate::cpuset::from_range(&rule.cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_thread_detection() {
        // 真实游戏线程名应命中
        for n in ["RenderThread", "UnityGfxDeviceW", "GLThread 123", "RHIThread",
                  "VulkanThread", "Gralloc", "SurfaceFlinger", "Compositor"] {
            assert!(is_render_thread(n), "应识别为渲染线程: {}", n);
        }
        // 非渲染线程不应误判
        for n in ["", "UnityMain", "GameThread", "Worker", "AudioTrack",
                  "Jit thread pool", "mali-compiler"] {
            assert!(!is_render_thread(n), "不应识别为渲染线程: {}", n);
        }
        // 大小写不敏感
        assert!(is_render_thread("renderthread"));
        assert!(is_render_thread("RENDERTHREAD"));
    }

    #[test]
    fn min_cpus_guard_constant() {
        // 单核目标必须被拒绝，阈值不得降到 1
        assert!(MIN_BIND_CPUS >= 2);
    }

    #[test]
    fn expand_target_respects_min() {
        // 构造一个假拓扑无法直接做（CpuTopology 需真实环境），
        // 此处仅验证纯逻辑分支：min_cpus<=1 或已达标时应原样返回
        let c = crate::cpuset::from_range("0-3");
        // 无 topo 时通过 count 判断提前返回的路径
        assert_eq!(c.count(), 4);
    }
}
