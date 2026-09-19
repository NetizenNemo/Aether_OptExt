use std::collections::HashSet;
use std::io::Write;

const MIN_USER_PID: i32 = 1000;
use std::fs;
use crate::cpuset::CpuSet;
use crate::config::fnmatch;

/// 绑核结果三态
pub enum AffinityResult {
    /// 成功绑核 或 已处于目标亲和性（短路跳过）
    Ok,
    /// 线程已退出（ESRCH）
    Dead,
    /// 绑核真正失败（非 ESRCH），后续应跳过无效重试
    Failed,
}

/// 记录已报告失败的 (tid, cpus)，同一组合只报一次
static FAILED_ONCE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<(i32, String)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

pub fn scan_unknown(set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String)>)> {
    let mut result = Vec::new();
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return result };
    for entry in dir.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
        if pid < MIN_USER_PID { continue; }
        let cl = match fs::read_to_string(entry.path().join("cmdline")) { Ok(c) => c, Err(_) => continue };
        let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() || pkg.contains('/') || !pkg.contains('.') { continue; }
        if set.contains(&pkg) || wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
        if let Ok(st) = fs::read_to_string(entry.path().join("status")) {
            let mut is_user = false;
            for line in st.lines() {
                if line.starts_with("Uid:") {
                    if let Some(u) = line.split_whitespace().nth(1) {
                        if let Ok(uid) = u.parse::<u32>() { is_user = uid >= 10000; }
                    }
                    break;
                }
            }
            if !is_user { continue; }
        } else { continue; }
        let mut th = Vec::new();
        if let Ok(tk) = fs::read_dir(entry.path().join("task")) {
            for t in tk.flatten() {
                let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
                let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
                th.push((tid, comm));
            }
        }
        if th.is_empty() { continue; }
        result.push((pid, pkg, th));
    }
    result
}

/// 读 /proc/{tid}/status 的 Cpus_allowed_list —— 内核视角该任务真实可用核
/// (= cpu online ∩ 所在各级 cpuset 的 effective_cpus)，thermal 限核时最权威
pub fn read_allowed_cpus(tid: i32) -> Option<CpuSet> {
    let st = fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in st.lines() {
        if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
            let set = crate::cpuset::parse_cpu_ranges(rest.trim(), None);
            if set.count() > 0 { return Some(set); }
        }
    }
    None
}

/// 将 tid 写入 cpuset 分组 tasks（dir 为空写 BASE_CPUSET 根），返回路径
fn write_cpuset_tasks(tid: i32, dir: &str, topo: &crate::cpuset::CpuTopology) -> Option<String> {
    if !topo.cpuset_enabled { return None; }
    let tasks_path = if dir.is_empty() {
        format!("{}/tasks", crate::common::base_cpuset())
    } else {
        format!("{}/{}/tasks", crate::common::base_cpuset(), dir)
    };
    let _ = fs::OpenOptions::new()
        .append(true)
        .open(&tasks_path)
        .and_then(|mut f| f.write_all(format!("{}
", tid).as_bytes()));
    Some(tasks_path)
}

fn log_bind_fail(tid: i32, cpus: &CpuSet, e: &std::io::Error) {
    let mut seen = FAILED_ONCE.lock().unwrap_or_else(|p| p.into_inner());
    if seen.insert((tid, cpus.to_range_string())) {
        crate::info!("绑核失败 tid={} cpus={} ({})", tid, cpus.to_range_string(), e);
    }
}

/// 应用绑核（兼容包装，丢弃有效集回传）
#[allow(dead_code)]
pub fn affinity_set(tid: i32, cpus: &CpuSet, cpuset_dir: &str, topo: &crate::cpuset::CpuTopology) -> AffinityResult {
    affinity_set_ex(tid, cpus, cpuset_dir, topo).0
}

/// 应用绑核并回传实际生效目标。生效集与请求目标不同（在线核裁剪，或 EINVAL 后
/// 按 Cpus_allowed_list 收缩）时返回 Some，供调用方回写缓存，避免每周期重复重试。
pub fn affinity_set_ex(tid: i32, cpus: &CpuSet, cpuset_dir: &str, topo: &crate::cpuset::CpuTopology)
    -> (AffinityResult, Option<CpuSet>)
{
    // 快速路径：目标含离线核则裁剪到在线核，裁剪发生时分组按新集合重算
    let clipped = topo.clip_online(cpus);
    let fast_clip = clipped != *cpus;
    let dir_owned: Option<String> = if fast_clip {
        Some(if topo.cpuset_enabled {
            crate::cpuset::ensure_cpuset_dir(&clipped, topo)
        } else {
            String::new()
        })
    } else {
        None
    };
    let (target, dir): (&CpuSet, &str) = match &dir_owned {
        Some(d) => (&clipped, d),
        None => (cpus, cpuset_dir),
    };
    let report = |eff: &CpuSet| if *eff != *cpus { Some(eff.clone()) } else { None };

    // sched_getaffinity 短路：已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr == *target {
            return (AffinityResult::Ok, report(target));
        }
    }

    write_cpuset_tasks(tid, dir, topo);

    if let Err(e) = target.set_affinity(tid) {
        if e.raw_os_error() == Some(3) { return (AffinityResult::Dead, None); }  // ESRCH: 线程已退出
        if e.raw_os_error() == Some(22) {
            // EINVAL：内核拒绝（核被 hotplug 下线，或 cpuset effective 被 thermal 收缩）。
            // 以该任务真实可用核（Cpus_allowed_list = online ∩ 各级 cpuset effective）收缩后重试。
            if let Some(allowed) = read_allowed_cpus(tid) {
                let mut eff = target.intersection(&allowed);
                if eff.count() == 0 { eff = allowed; }
                let eff_dir = if topo.cpuset_enabled {
                    crate::cpuset::ensure_cpuset_dir(&eff, topo)
                } else {
                    String::new()
                };
                write_cpuset_tasks(tid, &eff_dir, topo);
                let r = report(&eff);
                return match eff.set_affinity(tid) {
                    Ok(()) => (AffinityResult::Ok, r),
                    Err(e2) if e2.raw_os_error() == Some(3) => (AffinityResult::Dead, None),
                    Err(e2) => {
                        log_bind_fail(tid, &eff, &e2);
                        (AffinityResult::Failed, r)
                    }
                };
            }
        }
        log_bind_fail(tid, target, &e);
        return (AffinityResult::Failed, report(target));
    }
    (AffinityResult::Ok, report(target))
}

/// 读 /proc/{pid}/cmdline 取包名
pub fn read_cmdline(pid: i32) -> Option<String> {
    let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() { None } else { Some(pkg) }
}

/// 读 /proc/{pid}/task 全部 tid
pub fn task_tids(pid: i32) -> Option<Vec<i32>> {
    let dir = fs::read_dir(format!("/proc/{}/task", pid)).ok()?;
    Some(dir.flatten().filter_map(|t| t.file_name().to_string_lossy().parse().ok()).collect())
}

/// 读线程 comm
pub fn tid_comm(tid: i32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{}/comm", tid)).ok()?;
    let s = comm.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// 读 /proc/{pid}/oom_score_adj，用于前台感知
/// 返回 Some(oom_score_adj) 或 None
pub fn read_oom_score_adj(pid: i32) -> Option<i32> {
    let s = fs::read_to_string(format!("/proc/{}/oom_score_adj", pid)).ok()?;
    s.trim().parse().ok()
}

/// 判断进程是否处于前台（oom_score_adj <= 0 且非冻结进程）
/// Android 前台进程 oom_adj 通常为 0 或负值，后台为正数
#[allow(dead_code)]
pub fn is_foreground(pid: i32) -> bool {
    read_oom_score_adj(pid).map_or(false, |adj| adj <= 0)
}

/// 判断进程是否为缓存后台（oom_score_adj >= 900，Android cached app 阈值）
pub fn is_background(pid: i32) -> bool {
    read_oom_score_adj(pid).map_or(false, |adj| adj >= 900)
}

/// 读 /proc/{tid}/stat 的 utime+stime，用于动态负载感知
/// 返回 (utime+stime, 上次采集时间点)，None 表示读取失败
#[allow(dead_code)]
pub fn read_thread_cpu_time(tid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", tid)).ok()?;
    // 格式: pid (comm) state ppid ... utime(14) stime(15) ...
    // comm 可能含空格和括号，需跳过第一个 ) 后再 split
    let after_comm = stat.find(')').map(|i| &stat[i + 2..])?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 15 { return None; }
    let utime: u64 = fields[12].parse().ok()?;  // 第14个字段（从state算第13个）
    let stime: u64 = fields[13].parse().ok()?;
    Some(utime + stime)
}

/// 线程 CPU 负载等级（0~10），基于 stat 的 utime+stime 短周期差值
/// 与 config::cache::est_load 的静态名推不同，此处反映真实运行时负载
#[allow(dead_code)]
pub fn load_level(current_cpu_ticks: u64, prev_cpu_ticks: u64, elapsed_ticks: u64) -> i32 {
    if elapsed_ticks == 0 { return 0; }
    let delta = current_cpu_ticks.saturating_sub(prev_cpu_ticks);
    let ratio = (delta * 100) / elapsed_ticks;  // 占用百分比
    match ratio {
        0..=5   => 1,
        6..=15  => 3,
        16..=35 => 5,
        36..=60 => 7,
        _       => 10,
    }
}
