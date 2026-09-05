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

/// 应用绑核：sched_getaffinity 短路 → sched_setaffinity → cpuset 写入
/// 返回 AffinityResult 三态：Ok=成功, Dead=线程退出, Failed=真正失败
pub fn affinity_set(tid: i32, cpus: &CpuSet, cpuset_dir: &str, topo: &crate::cpuset::CpuTopology) -> AffinityResult {
    // sched_getaffinity 短路：已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr == *cpus { return AffinityResult::Ok; }
    }

    let mut tasks_path: Option<String> = None;
    if topo.cpuset_enabled {
        let tid_str = format!("{}\n", tid);
        let tasks_path_str = if cpuset_dir.is_empty() {
            format!("{}/tasks", crate::common::base_cpuset())
        } else {
            format!("{}/{}/tasks", crate::common::base_cpuset(), cpuset_dir)
        };
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(&tasks_path_str)
            .and_then(|mut f| f.write_all(tid_str.as_bytes()));
        tasks_path = Some(tasks_path_str);
    }

    if let Err(e) = cpus.set_affinity(tid) {
        if e.raw_os_error() == Some(3) { return AffinityResult::Dead; }  // ESRCH: 线程已退出
        // EINVAL: 迁移可能未生效，重写 tasks 再重试一次（双保险）
        if e.raw_os_error() == Some(22) && topo.cpuset_enabled {
            if let Some(p) = &tasks_path {
                let _ = fs::OpenOptions::new()
                    .append(true)
                    .open(p)
                    .and_then(|mut f| f.write_all(format!("{}\n", tid).as_bytes()));
            }
            if let Err(e2) = cpus.set_affinity(tid) {
                if e2.raw_os_error() == Some(3) { return AffinityResult::Dead; }
                crate::error!("[E] bind failed (retry) tid={} cpus={} ({})", tid,
                    cpus.to_range_string(), e2);
                return AffinityResult::Failed;
            }
            return AffinityResult::Ok;  // 重试成功
        }
        let mut seen = FAILED_ONCE.lock().unwrap_or_else(|p| p.into_inner());
        if seen.insert((tid, cpus.to_range_string())) {
            crate::info!("绑核失败 tid={} cpus={} ({})", tid, cpus.to_range_string(), e);
        }
        return AffinityResult::Failed;
    }
    AffinityResult::Ok
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
