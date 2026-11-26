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

/// 判断线程是否已在目标 cpuset 分组内。`dir` 为空（未启用 cpuset）时视为匹配。
///
/// 亲和性掩码相同不代表分组正确：例如渲染线程被 render_guard 提升到全核后，
/// 掩码与系统默认值一致，若只看 sched_getaffinity 就会误判「已符合目标」而
/// 从不迁入 OptExt 分组，表现为该线程完全没被接管。
fn in_cpuset_dir(tid: i32, dir: &str) -> bool {
    if dir.is_empty() {
        return true;
    }
    let Ok(c) = fs::read_to_string(format!("/proc/{}/cgroup", tid)) else {
        return false;
    };
    let base = crate::common::base_cpuset();
    let name = base.rsplit('/').next().unwrap_or("OptExt");
    let want = format!("/{}/{}", name, dir);
    c.lines()
        .find(|l| l.contains(":cpuset:"))
        .map(|l| l.trim_end().ends_with(&want))
        .unwrap_or(false)
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

/// 将 tid 写入 cpuset 分组 tasks（dir 为空写 BASE_CPUSET 根）。
/// 返回 true 表示无需写入（cpuset 未启用）或写入成功；false 表示写入失败。
/// 调用方据此决定是否重置 group_ok —— 掩码绑对但分组写入失败时若标记分组已就绪，
/// 稳态将不再复核，线程滞留在系统分组，thermal 收缩时受错误 cpuset 约束。
fn write_cpuset_tasks(tid: i32, dir: &str, topo: &crate::cpuset::CpuTopology) -> bool {
    if !topo.cpuset_enabled { return true; }
    let tasks_path = if dir.is_empty() {
        format!("{}/tasks", crate::common::base_cpuset())
    } else {
        format!("{}/{}/tasks", crate::common::base_cpuset(), dir)
    };
    fs::OpenOptions::new()
        .append(true)
        .open(&tasks_path)
        .and_then(|mut f| f.write_all(format!("{}\n", tid).as_bytes()))
        .is_ok()
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
    affinity_set_ex(tid, cpus, cpuset_dir, topo, true).0
}

/// 应用绑核并回传实际生效目标。生效集与请求目标不同（在线核裁剪，或 EINVAL 后
/// 按 Cpus_allowed_list 收缩）时返回 Some，供调用方回写缓存，避免每周期重复重试。
/// 第三个返回值表示 cpuset 分组是否已就绪：写入失败时调用方不得标记 group_ok，
/// 否则掩码虽对、线程仍滞留系统分组且稳态不再复核。
pub fn affinity_set_ex(tid: i32, cpus: &CpuSet, cpuset_dir: &str, topo: &crate::cpuset::CpuTopology, verify_group: bool)
    -> (AffinityResult, Option<CpuSet>, bool)
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

    // 短路：掩码与分组都符合才算达成目标。
    // 只比对掩码会漏掉「掩码相同但仍在 top-app 等系统分组」的情况。
    // 但 /proc/{tid}/cgroup 在千级线程下会形成读放大，故分组校验按需执行：
    // 调用方仅在「该线程尚未确认过分组」（首次绑定 / 目标变更）时传 verify_group=true，
    // 通过一次后即置标记跳过，稳态零读取
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr == *target && (!verify_group || in_cpuset_dir(tid, dir)) {
            // 短路成立：要么分组本就正确，要么无需校验，均视为分组就绪
            return (AffinityResult::Ok, report(target), true);
        }
    }

    let group_ok = write_cpuset_tasks(tid, dir, topo);

    if let Err(e) = target.set_affinity(tid) {
        if e.raw_os_error() == Some(3) { return (AffinityResult::Dead, None, group_ok); }  // ESRCH: 线程已退出
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
                let eff_group_ok = write_cpuset_tasks(tid, &eff_dir, topo);
                let r = report(&eff);
                return match eff.set_affinity(tid) {
                    Ok(()) => (AffinityResult::Ok, r, eff_group_ok),
                    Err(e2) if e2.raw_os_error() == Some(3) => (AffinityResult::Dead, None, eff_group_ok),
                    Err(e2) => {
                        log_bind_fail(tid, &eff, &e2);
                        (AffinityResult::Failed, r, eff_group_ok)
                    }
                };
            }
        }
        log_bind_fail(tid, target, &e);
        return (AffinityResult::Failed, report(target), group_ok);
    }
    (AffinityResult::Ok, report(target), group_ok)
}

/// 读线程所属进程的 Tgid（主线程 pid），失败返回 None
pub fn tid_tgid(tid: i32) -> Option<i32> {
    let st = fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in st.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// 按 oom_score_adj 判定线程应回归的系统分组后缀（模拟系统原本的归属）
fn release_group_suffix(adj: i32) -> &'static str {
    if adj <= 0 {
        "/top-app/tasks"
    } else if adj >= 900 {
        "/background/tasks"
    } else {
        "/foreground/tasks"
    }
}

/// 解除绑定：把线程恢复到全部在线核，并迁出 BASE_CPUSET 分组。
/// 用于黑名单包——从受控列表移除后须真正放手，否则仍残留在自建 cpuset 内。
/// 目标分组按其 oom 档位还原（top-app / foreground / background），
/// 避免一律塞进 foreground 而被该分组的 cpus 限制二次约束。
pub fn release_affinity(tid: i32, topo: &crate::cpuset::CpuTopology) {
    if topo.cpuset_enabled {
        // 优先按 oom 档位回归；目标不存在时退回 foreground
        let adj = read_oom_score_adj(tid).unwrap_or(0);
        let cpuset_root = "/dev/cpuset";
        let want = format!("{}{}", cpuset_root, release_group_suffix(adj));
        let dst = if std::path::Path::new(&want).exists() {
            want
        } else {
            format!("{}/foreground/tasks", cpuset_root)
        };
        let _ = fs::OpenOptions::new().append(true).open(&dst)
            .and_then(|mut f| f.write_all(format!("{}\n", tid).as_bytes()));
    }
    // cpuset 迁移会重设亲和性；此处兜底覆盖未启用 cpuset 或迁移失败的情况
    let all = topo.clip_online(&topo.present_cpus);
    let _ = all.set_affinity(tid);
}

/// 读 /proc/{pid}/cmdline 取包名
pub fn read_cmdline(pid: i32) -> Option<String> {
    use std::io::Read;
    let mut f = fs::File::open(format!("/proc/{}/cmdline", pid)).ok()?;
    // cmdline 是原始字节流，未必是合法 UTF-8（native 程序可自定义 argv[0]）。
    // 用 read_to_string 会因编码错误整体失败，导致该进程被静默跳过、完全不绑核。
    // 同时只读前 512 字节：包名在第一个 NUL 之前，无需读完整参数列表
    let mut buf = [0u8; 512];
    let n = f.read(&mut buf).ok()?;
    let head = &buf[..n];
    let end = head.iter().position(|&b| b == 0).unwrap_or(n);
    let pkg = String::from_utf8_lossy(&head[..end]).trim().to_string();
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
    use std::io::Read;
    let mut f = fs::File::open(format!("/proc/{}/stat", tid)).ok()?;
    // utime/stime 位于前 512 字节内，无需读全文件。原实现用 read_to_string
    // 读完整内容再收集 Vec<&str>；调用方为避免给空闲线程开 perf fd 会逐线程
    // 轮询，这个读放大正是周期性尖峰的主要来源
    let mut buf = [0u8; 512];
    let n = f.read(&mut buf).ok()?;
    let s = std::str::from_utf8(&buf[..n]).ok()?;
    // comm 可能含空格与括号，从最后一个 ')' 之后开始解析
    let after = s.rfind(')')? + 1;
    let mut it = s[after..].split_whitespace();
    // 从 state 起编号：state(0) ppid(1) ... cmajflt(10) utime(11) stime(12)。
    // 原实现取 fields[12]/[13]，实际读到 stime + cutime，漏掉了 utime ——
    // CPU 密集线程 utime 占大头，会让负载被严重低估
    let utime: u64 = it.nth(11)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
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
