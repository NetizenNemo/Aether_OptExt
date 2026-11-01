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
    /// 上次绑定失败（非 ESRCH），退避期间跳过避免无效 setaffinity 刷 CPU。
    /// 配合 fail_age 使用：退避到期会重试，不能永久跳过 —— 失败原因可能是
    /// 临时性的（cpuset 短暂不可写、内核瞬时拒绝），永久跳过会让线程
    /// 在该进程生命周期内彻底脱离管理。
    pub failed: bool,
    /// 失败后已经历周期数，超过 FAIL_RETRY_TTL 则清除 failed 重试
    fail_age: u8,
    /// 配置原始目标（前台/负载动态调整后可恢复）
    pub base_cpus: CpuSet,
    /// 上次采样的 utime+stime（动态负载感知用，0=未初始化）
    pub prev_ticks: u64,
    /// 内核实际允许的上限（在线核/cpuset effective 收缩后的生效集）。
    /// 非空时目标向其收敛，避免每周期重复撞 EINVAL；TTL 到期清空以尝试重新扩张。
    cap: CpuSet,
    /// cap 已持续周期数，超过 CAP_TTL 清空重探
    cap_age: u8,
    /// 该线程名命中渲染管线特征。渲染线程任何路径下都不得被压到小核，
    /// 否则提交延迟会触发 fence 超时 → BufferQueue 断流黑屏
    is_render: bool,
    /// 距上次实际校验亲和性的周期数。目标未变时跳过 setaffinity，
    /// 但内核可能因外部 cgroup 迁移静默重置亲和性，故仍按 TTL 强制校验
    verified_age: u8,
    /// is_render 的动态探测次数。每周期读一次 /proc/{tid}/comm 代价过高
    /// （千级线程每轮上千次文件读），只在前 RENDER_CHECK_MAX 个周期探测，
    /// 线程改名通常发生在创建后很短的时间窗内
    render_checks: u8,
}

/// cap 存活周期数：到期后重探一次，保证核/分组恢复时能扩回配置目标
const CAP_TTL: u8 = 3;

/// 绑定失败后的退避周期数。到期重试一次，避免临时性失败导致线程永久脱离管理
const FAIL_RETRY_TTL: u8 = 10;

/// is_render 动态探测的周期上限。线程改名发生在创建后早期，
/// 超出该窗口后不再读取 /proc/{tid}/comm
const RENDER_CHECK_MAX: u8 = 5;

/// cpuset 空分组清理间隔（周期数）。20 轮约 2 分钟，足够让线程迁移完成，
/// 避免把瞬时为空的分组误删
const PRUNE_INTERVAL: u8 = 20;

/// λmod 采样降频：每 N 个 affinity_sync 周期推进一次。
/// 取 3 意味着 -s 2（6s/轮）时约 18s 采样一次
const LAGRANGE_TICK_DIV: u8 = 3;

/// 亲和性强制校验周期。目标未变时跳过 sched_setaffinity 以省系统调用，
/// 但外部 cgroup 迁移会静默重置亲和性，故每隔这么多周期强制校验一次
const VERIFY_TTL: u8 = 5;

/// 双模式共用进程缓存：eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub pkgs: HashMap<i32, (String, bool)>,
    pub tasks: HashMap<i32, TaskEntry>,
    /// 上次负载采样时间，用于换算 tick 窗口
    last_sample: Option<Instant>,
    /// cpuset 空分组清理计数：配置切换 cpus 组合后旧分组会空置，
    /// 需定期回收，否则长期运行会在 base_cpuset 下堆积废弃目录
    prune_round: u8,
    /// λmod 采样降频计数。每次采样需读每个线程的 /proc/{tid}/stat
    /// 做免 fd 预筛选（千级线程即千次文件读），而线程负载特征不会在
    /// 秒级内剧变，故每 LAGRANGE_TICK_DIV 个周期推进一次
    lambda_round: u8,
}

impl ProcCache {
    pub fn new() -> Self {
        Self { pkgs: HashMap::new(), tasks: HashMap::new(), last_sample: None, prune_round: 0, lambda_round: 0 }
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
            fail_age: 0,
            base_cpus: result.cpus,
            prev_ticks: 0,
            cap,
            cap_age: 0,
            is_render: crate::rule_match::is_render_thread(comm),
            render_checks: 0,
            // 初始即置为 TTL，表示「需要校验」：新线程虽已在 task_apply 绑过，
            // 但随后的 cpuset 迁移会重置亲和性，首个周期就该校验一次
            verified_age: VERIFY_TTL,
        });
        true
    }

    /// 前台/负载动态调整：仅作用于包级 fallback 线程（线程规则为用户精确指定不动）。
    /// - 后台进程（oom_score_adj >= 900, cached）收缩到 e_core，回前台恢复配置目标
    /// - load_aware 开启时，按 /proc/{tid}/stat tick 增量分级：高负载 hp_core，空闲 e_core
    /// 返回 true 表示目标已变更（调用方需立即重新绑定）
    fn adjust_target(tid: i32, e: &mut TaskEntry, cfg: &config::AppConfig, elapsed_ticks: u64, is_bg: bool) -> bool {
        let topo = &cfg.topo;
        if e.is_thread_rule { return false; }

        // is_render 动态刷新：FORK 时 comm 仍是进程名，线程随后才被改名成
        // RenderThread。eBPF 的 task_rename 是 optional hook（可能 attach 失败），
        // 此时快照不会更新、渲染保护失效。故按需重读 comm，一经确认即永久置位。
        if !e.is_render && e.render_checks < RENDER_CHECK_MAX {
            e.render_checks = e.render_checks.saturating_add(1);
            if let Some(c) = process::tid_comm(tid) {
                if crate::rule_match::is_render_thread(&c) {
                    e.is_render = true;
                    crate::warn!("safety: render thread '{}' detected (tid={}), guard armed", c, tid);
                }
            }
        }

        // 内核限缩过的目标优先（后台降档同样受其约束）
        let clamp = |e: &TaskEntry, want: CpuSet| -> CpuSet {
            if e.cap.count() == 0 { return want; }
            let c = want.intersection(&e.cap);
            if c.count() == 0 { e.cap } else { c }
        };

        // 渲染线程保护：任何路径给出的目标都不得把渲染线程压到小核。
        // λmod / load_aware / 后台降档都可能给出能效核目标，必须统一拦截，
        // 否则 task_apply 阶段的 render_guard 提升会被后续周期覆盖掉。
        //
        // 注意顺序：guard 是软约束（应当用什么核），clamp 是硬约束（内核允许
        // 什么核）。必须先 guard 再 clamp —— promote_to_perf 会并入性能核，
        // 若放在 clamp 之后，并入的核可能落在 cap 之外而再次撞 EINVAL
        let guard = |want: CpuSet| -> CpuSet {
            if e.is_render {
                crate::rule_match::promote_to_perf(want, topo)
            } else {
                want
            }
        };

        // 后台降档（经 guard，避免渲染线程在 cached 瞬间被打进小核）
        if cfg.foreground_aware && is_bg {
            let want = clamp(e, guard(topo.e_core));
            if want.count() > 0 && want != e.cpus {
                e.cpus = want;
                e.cpuset_dir = ensure_cpuset_dir(&want, topo);
                return true;
            }
            return false;
        }

        // λmod 优先：perf_event 实测 + 拉格朗日求解给出的层目标。
        // 未启用/未采样到时回退下方 tick 启发式
        let mut desired = e.base_cpus;
        if crate::lagrange::active() {
            if let Some(t) = crate::lagrange::target_for(tid) {
                if t.count() > 0 {
                    let t = clamp(e, guard(t));
                    if t != e.cpus {
                        e.cpus = t;
                        e.cpuset_dir = ensure_cpuset_dir(&t, topo);
                        return true;
                    }
                    return false;
                }
            }
        }
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

        let desired = clamp(e, guard(desired));
        if desired != e.cpus {
            e.cpus = desired;
            e.cpuset_dir = ensure_cpuset_dir(&desired, topo);
            return true;
        }
        false
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
        // 黑名单包 PID 集合：命中则释放绑定（热加载新增黑名单时兜底）。
        // 注意 bl_pids 须同时覆盖 tasks 记录与 OptExt 分组内实际残留的线程
        let bl_pids: std::collections::HashSet<i32> = if cfg.blacklist.is_empty() {
            std::collections::HashSet::new()
        } else {
            self.tasks.values()
                .map(|e| e.pid)
                .collect::<std::collections::HashSet<i32>>()
                .into_iter()
                .filter(|pid| {
                    let pkg = self.pkgs.get(pid).map(|(p, _)| p.clone())
                        .or_else(|| process::read_cmdline(*pid));
                    pkg.map_or(false, |p| cfg.in_blacklist(&p))
                })
                .collect()
        };

        // λmod 周期推进：采样 → 求解 → 推进 λ → 刷新目标缓存。
        // 降频执行：采样阶段要读每个线程的 /proc/{tid}/stat，是当前最大的
        // 周期性开销；targets 缓存会让降频期间仍沿用上次决策
        if crate::lagrange::active() {
            self.lambda_round = self.lambda_round.wrapping_add(1);
            if self.lambda_round % LAGRANGE_TICK_DIV == 0 {
                let tids: Vec<i32> = self.tasks.keys().copied().collect();
                crate::lagrange::tick(&tids, cfg);
            }
        }

        let mut dead_tids = Vec::new();
        let mut released = 0usize;
        for (tid, e) in self.tasks.iter_mut() {
            // 失败退避：窗口内跳过避免刷 CPU；到期清除 failed 重试一次，
            // 否则临时性失败会让线程永久脱离管理
            if e.failed {
                e.fail_age = e.fail_age.saturating_add(1);
                if e.fail_age <= FAIL_RETRY_TTL {
                    continue;
                }
                e.failed = false;
                e.fail_age = 0;
                // 关键：置为待校验，确保重试不会被 verified_age 短路拦住
                e.verified_age = VERIFY_TTL;
            }
            // 黑名单：解除绑定并回收条目，使其完全不受控
            if bl_pids.contains(&e.pid) {
                process::release_affinity(*tid, topo);
                dead_tids.push(*tid);
                released += 1;
                continue;
            }
            let is_bg = bg_cache.get(&e.pid).copied().unwrap_or(false);
            let changed = Self::adjust_target(*tid, e, cfg, elapsed_ticks, is_bg);
            // 目标未变且未到强制校验周期 → 跳过 sched_setaffinity。
            // 千级线程每轮上千次系统调用，而亲和性在稳态下不会自行漂移
            if !changed && e.verified_age < VERIFY_TTL {
                e.verified_age = e.verified_age.saturating_add(1);
                continue;
            }
            e.verified_age = 0;
            let (res, eff) = process::affinity_set_ex(*tid, &e.cpus, &e.cpuset_dir, topo);
            match res {
                process::AffinityResult::Dead => dead_tids.push(*tid),
                process::AffinityResult::Failed => {
                    e.failed = true;
                    e.fail_age = 0;
                }
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
        if released > 0 {
            crate::info!("blacklist: released {} threads from control", released);
        }

        // 回收废弃的 cpuset 分组：热加载切换 cpus 组合后旧目录会空置残留
        self.prune_round = self.prune_round.wrapping_add(1);
        if self.prune_round % PRUNE_INTERVAL == 0 && topo.cpuset_enabled {
            let keep: std::collections::HashSet<String> = self.tasks
                .values()
                .filter(|e| !e.cpuset_dir.is_empty())
                .map(|e| e.cpuset_dir.clone())
                .collect();
            let n = crate::cpuset::prune_empty_dirs(&keep);
            if n > 0 {
                crate::info!("cpuset: 清理 {} 个废弃分组", n);
            }
        }
        dead_tids
    }

    /// 清扫 OptExt 分组内残留的黑名单线程，返回被释放的 tid 列表。
    /// 热加载新增黑名单时，这些进程早已被 in_blacklist 挡在 tasks 之外，
    /// 无法通过遍历 tasks 发现，必须直接扫描 cpuset 分组内容。
    /// 调用方须用返回的 tid 清理 eBPF APPLIED_MAP，否则其 fork 的后代仍会被上报
    pub fn release_blacklisted_orphans(cfg: &config::AppConfig, topo: &crate::cpuset::CpuTopology) -> Vec<i32> {
        let mut freed = Vec::new();
        if cfg.blacklist.is_empty() || !topo.cpuset_enabled { return freed; }
        let base = crate::common::base_cpuset();
        // 递归收集 BASE_CPUSET 下所有子组的 tasks
        let mut dirs = vec![std::path::PathBuf::from(base)];
        if let Ok(rd) = std::fs::read_dir(base) {
            for e in rd.flatten() {
                if e.path().is_dir() { dirs.push(e.path()); }
            }
        }
        // 按 pid 去重：同进程数十线程只解析一次包名
        let mut checked: HashMap<i32, bool> = HashMap::new();
        for dir in dirs {
            let tasks = dir.join("tasks");
            let Ok(content) = std::fs::read_to_string(&tasks) else { continue };
            for line in content.lines() {
                let Ok(tid) = line.trim().parse::<i32>() else { continue };
                // 线程所属进程（tid 可能非主线程，用 Tgid 反查主进程）
                let pid = process::tid_tgid(tid).unwrap_or(tid);
                let hit = *checked.entry(pid).or_insert_with(|| {
                    process::read_cmdline(pid)
                        .or_else(|| process::tid_comm(pid))
                        .map_or(false, |p| cfg.in_blacklist(&p))
                });
                if hit {
                    process::release_affinity(tid, topo);
                    freed.push(tid);
                }
            }
        }
        if !freed.is_empty() {
            crate::info!("blacklist: swept {} orphan threads out of cpuset", freed.len());
        }
        freed
    }
}
