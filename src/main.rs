use std::{
    env, fs, io::Write,
    path::Path,
    sync::mpsc,
    time::{Duration, Instant},
};

#[macro_use]
mod log;
mod config;
mod cpu;
mod process;
mod bpf;
mod cpuset;
mod proccache;
mod common;
mod rule_match;
mod inotify;

use config::*;
use cpuset::CpuSet;

/// 热加载配置：重新解析线程配置、合并缓存
fn hot_reload(config_path: &str, cfg: &mut AppConfig) -> bool {
    if let Some(new_cfg) = AppConfig::load(config_path, &cfg.topo) {
        *cfg = new_cfg;
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("config reloaded, {} rules", cfg.rules.len());
        true
    } else {
        error!("config parse failed, keeping old config");
        false
    }
}

/// comm[16] 截断 NUL 转 String
fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("").trim().to_string()
}

/// 已通知的 pid → 上次通知时刻(ms)。eBPF FORK 会为每个线程触发一次，
/// 按 pid 去重才能压住同进程多线程噪音；不同进程交替出现属正常，各自通知一次。
static FG_HINTED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<i32, u64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 同 pid 通知节流窗口：窗口内重复触发直接跳过
const FG_HINT_TTL_MS: u64 = 10_000;
/// 去重表容量上限，超限时清理过期项
const FG_HINT_CAP: usize = 4096;

/// 通知 Aether Scheduler 可能有前台应用变化（Scheduler 收到后自行 dumpsys 确认）
/// 信号文件: /sdcard/Android/Aether/fg_hint
/// 格式: <pkg>:<pid>:<timestamp_ms>
///
/// OptExt 只发"有变化"的信号，不判断哪个应用在前台——进程被迁入自建 cpuset 子组后
/// 不再出现在 top-app/cgroup.procs，Scheduler 的 inotify 监听会失效，故需此旁路通知。
/// 写盘失败静默忽略，不影响绑核主流程。返回 true 表示实际写入（被节流跳过为 false）
fn notify_fg_change(pkg: &str, pid: i32) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    {
        let mut seen = FG_HINTED.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(&t) = seen.get(&pid) {
            if now.saturating_sub(t) < FG_HINT_TTL_MS {
                return false;
            }
        }
        if seen.len() > FG_HINT_CAP {
            seen.retain(|_, &mut t| now.saturating_sub(t) < FG_HINT_TTL_MS);
        }
        seen.insert(pid, now);
    }
    let _ = std::fs::write(
        "/sdcard/Android/Aether/fg_hint",
        format!("{}:{}:{}", pkg, pid, now),
    );
    info!("fg_hint: {} ({})", pkg, pid);
    true
}

/// eBPF 模式: 应用亲和性并写 APPLIED_MAP，返回 (tid已退出, 生效目标变更)
fn event_affinity_apply(tid: i32, cpus: &CpuSet, cpuset_dir: &str, cfg: &AppConfig, bpf_state: &mut bpf::BpfCtx)
    -> (bool, Option<CpuSet>)
{
    let (res, eff) = process::affinity_set_ex(tid, cpus, cpuset_dir, &cfg.topo);
    match res {
        process::AffinityResult::Dead => (true, None),
        _ => {
            bpf::applied_set(bpf_state, tid, cpus.bits[0]);
            (false, eff)
        }
    }
}

/// eBPF 模式: 统一事件处理 (pkg 反查 → task_apply)
fn event_apply(pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx,
    tid: i32, pid: i32, comm: &str, cfg: &AppConfig, trust_comm: bool) -> bool {
    let Some((pkg, has_thread_rules)) = pc.pkg_lookup_comm(pid, comm, cfg) else {
        return false;
    };
    pc.task_apply(tid, pid, &pkg, comm, has_thread_rules, cfg, trust_comm,
        |t, c, dir| event_affinity_apply(t, c, dir, cfg, bpf_state));
    true
}

/// eBPF 模式: 事件派发
fn event_dispatch(event: &bpf::EbpfProcEvent, cfg: &AppConfig,
    pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        bpf::EVENT_EXIT => {
            if tid == pid { pc.pkgs.remove(&pid); }
            pc.task_del(tid);
            bpf::applied_del(bpf_state, tid);
        }
        bpf::EVENT_FG => {
            // 进程被搬入前台 cgroup：读其包名后通知 Scheduler 重查。
            // 不走 event_apply（前台切换与绑核无关），仅发信号。
            if cfg.notify_scheduler {
                if let Some(pkg) = process::read_cmdline(pid) {
                    let base = pkg.split(':').next().unwrap_or(&pkg);
                    notify_fg_change(base, pid);
                }
            }
        }
        bpf::EVENT_EXEC => {
            pc.pkgs.remove(&pid);
            if !event_apply(pc, bpf_state, tid, pid, &comm, cfg, true) {
                pc.task_del(tid);
                bpf::applied_del(bpf_state, tid);
            }
        }
        bpf::EVENT_FORK => {
            // FORK 子线程继承父 comm 不可信，主线程 tid==pid comm 为自身
            event_apply(pc, bpf_state, tid, pid, &comm, cfg, tid == pid);
        }
        bpf::EVENT_RENAME => {
            event_apply(pc, bpf_state, tid, pid, &comm, cfg, true);
        }
        _ => {}
    }
}

/// eBPF 模式: 全量扫描 /proc (仅启动或配置更新时调用, 日常零 /proc 读)
fn full_scan(cfg: &AppConfig, pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx) {
    pc.clear();
    bpf::applied_clear(bpf_state);

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let targets: Vec<(i32, String, bool)> = proc_dir.flatten().filter_map(|entry| {
        let pid = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
        let pkg = process::read_cmdline(pid).or_else(|| process::tid_comm(pid))?;
        // 包名匹配 (含 :suffix)
        let base_pkg = pkg.split(':').next().unwrap_or(&pkg);
        let interested = cfg.pkg_set.contains(&pkg) || cfg.pkg_set.contains(base_pkg)
            || cfg.wild.iter().any(|w| fnmatch(w, &pkg));
        if !interested { return None; }
        let htr = cfg.pkg_has_thread_rules(base_pkg);
        Some((pid, pkg, htr))
    }).collect();

    for (pid, pkg, htr) in targets {
        let Some(tids) = process::task_tids(pid) else { continue };
        for tid in tids {
            let t_name = if htr { process::tid_comm(tid).unwrap_or_default() } else { String::new() };
            pc.task_apply(tid, pid, &pkg, &t_name, htr, cfg, true,
                |t, c, dir| event_affinity_apply(t, c, dir, cfg, bpf_state));
        }
        pc.pkgs.insert(pid, (pkg, htr));
    }
}

/// proc 模式增量同步状态（仿参考项目 ProcScanState）
struct ProcState {
    cache: proccache::ProcCache,
    last_proc_count: i32,
    scan_all_proc: bool,
    tracked_pids: std::collections::HashSet<i32>,
    last_proc_total: i32,
    force_affinity: bool,
}

impl ProcState {
    fn new() -> Self {
        Self {
            cache: proccache::ProcCache::new(),
            last_proc_count: 0,
            scan_all_proc: true,
            tracked_pids: std::collections::HashSet::new(),
            last_proc_total: 0,
            force_affinity: false,
        }
    }
}

/// 轻量增量同步：sysinfo 进程数变化或已跟踪 pid 消失才全量重建缓存
/// 返回 true 表示发生了全量重扫
fn proc_cache_sync(state: &mut ProcState, cfg: &AppConfig) -> bool {
    let mut need_reload = state.scan_all_proc;

    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        need_reload = true;
    } else {
        let cur = info.procs as i32;
        if cur > state.last_proc_count + 11 {
            need_reload = true;
        } else if cur > state.last_proc_count {
            state.force_affinity = true;
        }
        state.last_proc_count = cur;
    }

    if !need_reload {
        for &pid in state.tracked_pids.iter() {
            if unsafe { libc::kill(pid, 0) } != 0 {
                need_reload = true;
                break;
            }
        }
    }

    if !need_reload { return false; }

    // 全量重建缓存（只填充不绑核，绑核由 affinity_sync 统一做）
    state.cache.clear();
    let mut new_tracked: std::collections::HashSet<i32> = std::collections::HashSet::new();
    let mut current_total = 0i32;

    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            current_total += 1;
            if !state.scan_all_proc && !state.tracked_pids.contains(&pid) { continue; }

            let Some(pkg) = process::read_cmdline(pid).or_else(|| process::tid_comm(pid)) else { continue };
            let base_pkg = pkg.split(':').next().unwrap_or(&pkg);
            if cfg.asoul_ignore.contains(&pkg) || cfg.asoul_ignore.contains(base_pkg) { continue; }
            let interested = cfg.pkg_set.contains(&pkg) || cfg.pkg_set.contains(base_pkg)
                || cfg.wild.iter().any(|w| fnmatch(w, &pkg));
            if !interested { continue; }
            let htr = cfg.pkg_has_thread_rules(base_pkg);
            let Some(tids) = process::task_tids(pid) else { continue };

            let mut any = false;
            for tid in tids {
                let tn = if htr { process::tid_comm(tid).unwrap_or_default() } else { String::new() };
                if state.cache.task_apply(tid, pid, &pkg, &tn, htr, cfg, true, |_, _, _| (false, None)) {
                    any = true;
                }
            }
            if any {
                state.cache.pkgs.insert(pid, (pkg, htr));
                new_tracked.insert(pid);
            }
        }
    }

    state.scan_all_proc = current_total > state.last_proc_total;
    state.last_proc_total = current_total;
    state.tracked_pids = new_tracked;
    state.force_affinity = true;
    true
}

fn main() {
    // 进程锁
    std::panic::set_hook(Box::new(|info| {
        let msg = info.payload().downcast_ref::<&str>().copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("?");
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let _ = fs::OpenOptions::new().create(true).append(true).open(log::PATH)
            .map(|mut f| write!(f, "[PANIC] {} at {}\n", msg, loc));
    }));

    let _ = fs::create_dir_all("/sdcard/Android/Aether");
    fs::write(log::PATH, "").ok();

    let args: Vec<String> = env::args().collect();
    let mut config_path = "/sdcard/Android/Aether/threads.json".to_string();
    let mut interval = 2u64;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => { i += 1; if i < args.len() { config_path = args[i].clone(); } }
            "-s" => { i += 1; if i < args.len() { interval = args[i].parse().unwrap_or(2); } }
            _ => {}
        }
        i += 1;
    }
    if interval < 1 { interval = 1; }

    info!("===Welcome To Aether OptExt===");
    info!("CPU: {} cpuset={}", cpu::present(), Path::new("/dev/cpuset").exists());

    // CPU 拓扑 + BASE_CPUSET（绑核前必须初始化）
    crate::common::set_base_cpuset("OptExt");
    let topo = crate::cpuset::init_cpu_topo();

    let mut cfg = match AppConfig::load(&config_path, &topo) {
        Some(c) => c,
        None => { error!("配置加载失败"); return; }
    };
    info!("rules loaded: {}", cfg.rules.len());

    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
    info!("total rules (with cache): {}", cfg.rules.len());

    let (big, mid1, mid2, little, topo) = cpu::detect();
    let mid_str = if mid1.is_empty() && mid2.is_empty() {
        "无".to_string()
    } else {
        format!("{}{}{}", mid1, if !mid1.is_empty() && !mid2.is_empty() { "+" } else { "" }, mid2)
    };
    info!("topology: {} (big={} mid={} little={})", topo, big, mid_str, little);


    // 自身限定在小核运行
    if !little.is_empty() && little != "0" {
        let self_pid = std::process::id() as i32;
        let set = CpuSet::from_range(&little);
        let r = unsafe { libc::sched_setaffinity(self_pid, std::mem::size_of::<libc::cpu_set_t>(), &set as *const CpuSet as *const libc::cpu_set_t) };
        if r != 0 { warn!("self pin skipped (errno={})", r); }
    }

    // eBPF 初始化
    let mut bpf_state = bpf::probe(cfg.ebpf);
    // 白名单容量须与 ebpf/src/main.rs MAP_CAPACITY 一致 (8192): 668 包 × 前后缀 ≈ 1336 键
    let mut comm_capacity = 8192u32;
    let mut need_full_scan = true;
    let mut affinity_deadline = Instant::now();

    // proc 模式状态
    let mut proc_state = ProcState::new();
    let mut cache_scan = 0i32;

    // 启动时自动分配 (两模式共用)
    let unknown = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
    let new_pkgs: Vec<String> = unknown.iter()
        .filter(|(_, pkg, _)| !config::cache::is_blacklisted(pkg))
        .filter(|(_, pkg, _)| !cfg.asoul_ignore.contains(pkg))
        .map(|(_, pkg, _)| pkg.clone()).collect();
    if !new_pkgs.is_empty() {
        for pkg in &new_pkgs {
            info!("new app detected: {}", pkg);
        }
        let n = cache::save_batch(&new_pkgs, &unknown, &big, &mid1, &mid2, &little);
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("auto-assign done: {} apps (saved {})", new_pkgs.len(), n);
    }

    info!("mode: {}", if bpf_state.ok { "eBPF event-driven" } else { "proc polling" });

    // inotify 配置文件监听
    let mut inotify_fd = inotify::init(&config_path);
    let mut last_reload = Instant::now() - Duration::from_secs(10);

    loop {
        // 配置热加载检测 (每轮, 5s debounce 防重复触发)
        let mut config_changed = false;
        if inotify::check_changed(&config_path, &mut inotify_fd, &mut last_reload, &cfg.mtime) {
            config_changed = hot_reload(&config_path, &mut cfg);
            last_reload = Instant::now();
        }

        if bpf_state.ok {
            // ===== eBPF 事件驱动模式 =====
            if config_changed || need_full_scan {
                // 同步白名单（容量编译期固定, 不足时不重建, 降级为部分匹配）
                if bpf::comm_map_init(&mut bpf_state, &cfg.pkg_set, &mut comm_capacity) {
                    info!("eBPF: 白名单容量不足, 部分包名无法即时发现 (需 {} 键)", cfg.pkg_set.len() * 2);
                }
                full_scan(&cfg, &mut proc_state.cache, &mut bpf_state);
                need_full_scan = false;
                info!("eBPF: 全量扫描完成 ({} 进程)", proc_state.cache.pkgs.len());
            }

            // 收事件 (阻塞 1s, 事件驱动日常零 /proc 读)
            match bpf_state.event_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    event_dispatch(&event, &cfg, &mut proc_state.cache, &mut bpf_state);
                    while let Ok(e) = bpf_state.event_rx.try_recv() {
                        event_dispatch(&e, &cfg, &mut proc_state.cache, &mut bpf_state);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    info!("eBPF: 事件通道断开, 回退 /proc 轮询");
                    bpf_state = bpf::BpfCtx::empty();
                    need_full_scan = true;
                }
            }

            // 定期纠正亲和性 (每 3*interval 秒)
            if affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                let dead_tids = proc_state.cache.affinity_sync(&cfg);
                for tid in dead_tids {
                    bpf::applied_del(&mut bpf_state, tid);
                }
                affinity_deadline = Instant::now();
            }
        } else {
            // ===== proc 轮询模式 (增量维护, 仿参考项目) =====
            if config_changed {
                proc_state.scan_all_proc = true;
            }

            let reloaded = proc_cache_sync(&mut proc_state, &cfg);
            let _ = reloaded;

            // 定期纠正亲和性 (每 3*interval 秒 或 进程数变化时)
            if proc_state.force_affinity || affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                let _dead = proc_state.cache.affinity_sync(&cfg);
                proc_state.force_affinity = false;
                affinity_deadline = Instant::now();
            }

            // 未知应用自动分配：每 120 轮(4 分钟) 或 进程数增长时
            cache_scan += 1;
            let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
            let procs_now = if unsafe { libc::sysinfo(&mut si) } == 0 { si.procs as i32 } else { -1 };
            if cache_scan >= 120 || (procs_now > proc_state.last_proc_count) {
                cache_scan = 0;
                let u = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
                let new_pkgs: Vec<String> = u.iter()
                    .filter(|(_, pkg, _)| !config::cache::is_blacklisted(pkg))
                    .filter(|(_, pkg, _)| !cfg.asoul_ignore.contains(pkg))
                    .map(|(_, pkg, _)| pkg.clone()).collect();
                if !new_pkgs.is_empty() {
                    for pkg in &new_pkgs {
                        info!("new app detected: {}", pkg);
                    }
                    let n = cache::save_batch(&new_pkgs, &u, &big, &mid1, &mid2, &little);
                    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
                    info!("cache updated ({} new apps)", n);
                }
            }

            std::thread::sleep(Duration::from_secs(interval));
        }
    }
}
