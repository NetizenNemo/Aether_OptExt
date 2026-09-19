use std::collections::HashMap;
use std::time::Instant;
use crate::config;
use crate::cpuset::{ensure_cpuset_dir, CpuSet};
use crate::process;

/// 线程条目，对应 /proc/[pid]/task/[tid]
pub struct TaskEntry {
    pub pid: i32,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
    /// 上次绑定失败（非 ESRCH），跳过重复尝试避免无效 setaffinity 刷 CPU
    pub failed: bool,
    /// 配置原始目标（前台/负载动态调整后可恢复）
    pub base_cpus: CpuSet,
    /// 上次采样的 utime+stime（动态负载感知用，0=未初始化）
    pub prev_ticks: u64,
    /// 内核实际允许的上限（在线核/cpuset effective 收缩后的生效集）。
    /// 非空时目标向其收敛，避免每周期重复撞 EINVAL；TTL 到期清空以尝试重新扩张。
    cap: CpuSet,
    /// cap 已持续周期数，超过 CAP_TTL 清空重探
    cap_age: u8,
}

/// cap 存活周期数：到期后重探一次，保证核/分组恢复时能扩回配置目标
const CAP_TTL: u8 = 3;

/// 双模式共用进程缓存：eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub pkgs: HashMap<i32, (String, bool)>,
    pub tasks: HashMap<i32, TaskEntry>,
    /// 上次负载采样时间，用于换算 tick 窗口
    last_sample: Option<Instant>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self { pkgs: HashMap::new(), tasks: HashMap::new(), last_sample: None }
    }

    pub fn clear(&mut self) {
        self.pkgs.clear();
        self.tasks.clear();
    }

    /// 删除 tid，若该 pid 下无线程则清理 pkgs[pid]
    pub fn task_del(&mut self, tid: i32) {
        let pid = self.tasks.remove(&tid).map(|t| t.pid);
        if let Some(pid) = pid {
            self.pkgs_purge(pid);
        }
    }

    fn pkgs_purge(&mut self, pid: i32) {
        if !self.tasks.values().any(|t| t.pid == pid) {
            self.pkgs.remove(&pid);
        }
    }

    /// eBPF 专用：pkgs 缓存命中优先，否则 comm_to_pkg 匹配后缓存
    pub fn pkg_lookup_comm(&mut self, pid: i32, comm: &str, cfg: &config::AppConfig) -> Option<(String, bool)> {
        if let Some((pkg, htr)) = self.pkgs.get(&pid).cloned() {
            return Some((pkg, htr));
        }
        let pkg = crate::bpf::comm_to_pkg(comm, cfg)?;
        let has_thread_rules = cfg.pkg_has_thread_rules(&pkg);
        self.pkgs.insert(pid, (pkg.clone(), has_thread_rules));
        Some((pkg, has_thread_rules))
    }

    /// 计算并应用线程亲和性，trust_comm=false 时忽略 comm 走 fallback（FORK 继承场景）
    /// 新结果走 fallback 时保护已有线程规则绑定，防止临时改名降级
    pub fn task_apply<F>(&mut self, tid: i32, pid: i32, pkg: &str, comm: &str,
        has_thread_rules: bool, cfg: &config::AppConfig, trust_comm: bool, apply_fn: F) -> bool
    where F: FnOnce(i32, &CpuSet, &str) -> (bool, Option<CpuSet>)
    {
        let thread_name = if has_thread_rules && trust_comm { comm } else { "" };
        let Some(result) = crate::rule_match::thread_affinity(pkg, thread_name, cfg, &cfg.topo) else {
            return false;
        };

        // fallback 结果不覆盖已有线程规则绑定
        if !result.is_thread_rule {
            if let Some(old) = self.tasks.get(&tid) {
                if old.is_thread_rule {
                    return true;
                }
            }
        }

        // 已绑定但目标被内核限缩时沿用旧 cap，避免反复重探
        let keep_cap = self.tasks.get(&tid).map(|t| t.cap).unwrap_or_default();

        self.tasks.remove(&tid);
        let (dead, eff) = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            return false;
        }

        // eff = 内核实际生效集；与配置目标不同则记为 cap。
        // cpuset_dir 必须与生效集同步重算，否则下周期会把线程迁回原分组再撞 EINVAL。
        let (cpus, cap, dir) = match eff {
            Some(e) => {
                let d = if cfg.topo.cpuset_enabled {
                    crate::cpuset::ensure_cpuset_dir(&e, &cfg.topo)
                } else {
                    String::new()
                };
                (e.clone(), e, d)
            }
            None => (result.cpus, keep_cap, result.cpuset_dir),
        };
        self.tasks.insert(tid, TaskEntry {
            pid,
            cpus,
            cpuset_dir: dir,
            is_thread_rule: result.is_thread_rule,
            failed: false,
            base_cpus: result.cpus,
            prev_ticks: 0,
            cap,
            cap_age: 0,
        });
        true
    }

    /// 前台/负载动态调整：仅作用于包级 fallback 线程（线程规则为用户精确指定不动）。
    /// - 后台进程（oom_score_adj >= 900, cached）收缩到 e_core，回前台恢复配置目标
    /// - load_aware 开启时，按 /proc/{tid}/stat tick 增量分级：高负载 hp_core，空闲 e_core
    fn adjust_target(tid: i32, e: &mut TaskEntry, cfg: &config::AppConfig, elapsed_ticks: u64, is_bg: bool) {
        let topo = &cfg.topo;
        if e.is_thread_rule { return; }

        // 内核限缩过的目标优先（后台降档同样受其约束）
        let clamp = |e: &TaskEntry, want: CpuSet| -> CpuSet {
            if e.cap.count() == 0 { return want; }
            let c = want.intersection(&e.cap);
            if c.count() == 0 { e.cap } else { c }
        };

        // 后台降档
        if cfg.foreground_aware && is_bg {
            let want = clamp(e, topo.e_core);
            if want.count() > 0 && want != e.cpus {
                e.cpus = want;
                e.cpuset_dir = ensure_cpuset_dir(&want, topo);
            }
            return;
        }

        // 前台/负载感知
        let mut desired = e.base_cpus;
        if cfg.load_aware && elapsed_ticks > 0 {
            if let Some(ticks) = process::read_thread_cpu_time(tid) {
                if e.prev_ticks > 0 {
                    let load = process::load_level(ticks, e.prev_ticks, elapsed_ticks);
                    let hp = topo.hp_core.intersection(&topo.present_cpus);
                    if load >= 8 && hp.count() > 0 {
                        // 高负载：并入超大核（保留原目标，避免排除已配置的核）
                        desired = e.base_cpus;
                        desired.or(&hp);
                    } else if load <= 2 && topo.e_core.count() > 0 {
                        // 空闲：收缩到能效核
                        desired = topo.e_core;
                    }
                }
                e.prev_ticks = ticks;
            }
        }

        let desired = clamp(e, desired);
        if desired != e.cpus {
            e.cpus = desired;
            e.cpuset_dir = ensure_cpuset_dir(&desired, topo);
        }
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids
    pub fn affinity_sync(&mut self, cfg: &config::AppConfig) -> Vec<i32> {
        // 采样窗口换算为 tick（USER_HZ=100）
        let now = Instant::now();
        let window_secs = self.last_sample.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
        self.last_sample = Some(now);
        let elapsed_ticks = (window_secs * 100.0) as u64;

        // 按 pid 缓存前后台判定，避免每个线程重复读 /proc
        let bg_cache: HashMap<i32, bool> = if cfg.foreground_aware {
            let mut m = HashMap::new();
            for e in self.tasks.values() {
                m.entry(e.pid).or_insert_with(|| process::is_background(e.pid));
            }
            m
        } else {
            HashMap::new()
        };

        let topo = &cfg.topo;
        let mut dead_tids = Vec::new();
        for (tid, e) in self.tasks.iter_mut() {
            if e.failed { continue; }  // 上次失败（cpuset 限制），跳过无效重试
            let is_bg = bg_cache.get(&e.pid).copied().unwrap_or(false);
            Self::adjust_target(*tid, e, cfg, elapsed_ticks, is_bg);
            let (res, eff) = process::affinity_set_ex(*tid, &e.cpus, &e.cpuset_dir, topo);
            match res {
                process::AffinityResult::Dead => dead_tids.push(*tid),
                process::AffinityResult::Failed => e.failed = true,
                process::AffinityResult::Ok => {}  // 成功，不标记失败
            }
            // 目标被内核限缩：记录 cap 并按生效集更新，后续周期零开销短路
            if let Some(eff) = eff {
                e.cpus = eff.clone();
                e.cpuset_dir = if topo.cpuset_enabled {
                    ensure_cpuset_dir(&eff, topo)
                } else {
                    String::new()
                };
                e.cap = eff;
                e.cap_age = 0;
            } else if e.cap.count() > 0 {
                // 无新的限缩信息：cap 到期则清空重探，使核恢复后能扩回配置目标
                e.cap_age = e.cap_age.saturating_add(1);
                if e.cap_age > CAP_TTL {
                    // 重探：清空 cap 并连同分组一起回到配置目标，
                    // 否则线程会滞留在受限分组内继续撞 EINVAL
                    e.cap = CpuSet::new();
                    e.cap_age = 0;
                    e.cpus = e.base_cpus;
                    e.cpuset_dir = ensure_cpuset_dir(&e.base_cpus, topo);
                }
            }
        }
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        dead_tids
    }
}
