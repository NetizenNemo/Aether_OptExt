use crate::config::{self, AppConfig};
use crate::cpuset::{ensure_cpuset_dir, CpuSet, CpuTopology};

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(pkg: &str, thread: &str, cfg: &AppConfig, topo: &CpuTopology) -> Option<AffinityResult> {
    // asoul 兼容：豁免包不参与任何绑定
    if cfg.asoul_ignore.contains(pkg) {
        return None;
    }
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg != pkg || rule.thread.is_empty() {
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
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
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
        None
    } else {
        Some(AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule: matched,
        })
    }
}

/// 将规则中的 cpus 字符串解析为 CpuSet
fn cpuset_from_rule(rule: &config::Rule) -> CpuSet {
    crate::cpuset::from_range(&rule.cpus)
}
