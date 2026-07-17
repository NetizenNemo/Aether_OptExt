use std::{collections::HashSet, fs, mem};
use crate::config::{self, Rule, fnmatch};

static CPUSET_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 初始化 cpuset 目录
pub fn init_cpuset() {
    if !std::path::Path::new("/dev/cpuset").exists() { return; }
    let _ = fs::create_dir_all("/dev/cpuset/AppOpt");
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write("/dev/cpuset/AppOpt/mems", mems.trim().as_bytes());
    }
    CPUSET_OK.store(true, std::sync::atomic::Ordering::Release);
}

/// 确保 CPU range 对应的 cpuset 目录存在
fn ensure_cpuset(cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(format!("{}/cpus", &dir), cpus.as_bytes());
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write(format!("{}/mems", &dir), mems.trim().as_bytes());
    }
}

/// 写 TID 到 cpuset tasks
fn cpuset_add(tid: i32, cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let _ = fs::write(format!("{}/tasks", dir), format!("{}\n", tid).as_bytes());
}

pub fn scan(rules: &[Rule], set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String, String)>)> {
    let mut result = Vec::new();
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return result };
    for entry in dir.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
        if pid < 1000 { continue; }
        let cl = fs::read_to_string(entry.path().join("cmdline")).unwrap_or_default();
        let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() { continue; }
        if !set.contains(&pkg) && !wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
        let mut th = Vec::new();
        if let Ok(tk) = fs::read_dir(entry.path().join("task")) {
            for t in tk.flatten() {
                let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
                let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
                let mut best = String::new();
                let mut bp = -1i32;
                for r in rules {
                    let pm = r.pkg == pkg || (r.thread.is_empty() && fnmatch(&r.pkg, &pkg));
                    if !pm { continue; }
                    if r.thread.is_empty() { if 200 > bp { best = r.cpus.clone(); bp = 200; } }
                    else if fnmatch(&r.thread, &comm) && r.prio > bp { best = r.cpus.clone(); bp = r.prio; }
                }
                th.push((tid, comm, best));
            }
        }
        if th.is_empty() { continue; }
        result.push((pid, pkg, th));
    }
    result
}

/// 扫描未配置的用户应用，用于自动分配
pub fn scan_unknown(set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String)>)> {
    let mut result = Vec::new();
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return result };
    for entry in dir.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
        if pid < 1000 { continue; }
        let mut is_user = false;
        if let Ok(st) = fs::read_to_string(entry.path().join("status")) {
            for line in st.lines() {
                if line.starts_with("Uid:") {
                    if let Some(u) = line.split_whitespace().nth(1) {
                        if let Ok(uid) = u.parse::<u32>() { is_user = uid >= 10000; }
                    }
                    break;
                }
            }
        }
        if !is_user { continue; }
        let cl = fs::read_to_string(entry.path().join("cmdline")).unwrap_or_default();
        let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() || pkg.contains('/') || !pkg.contains('.') { continue; }
        if set.contains(&pkg) || wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
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

/// 应用绑核
pub fn apply(procs: &[(i32, String, Vec<(i32, String, String)>)], rescan: &std::sync::atomic::AtomicBool) {
    let mut seen_cpus = std::collections::HashSet::<String>::new();
    let mut n = 0usize;
    for (_, _, th) in procs {
        for (tid, _, cpus) in th {
            if cpus.is_empty() { continue; }
            n += 1;

            // 确保 cpuset 目录存在 (仅首次)
            if seen_cpus.insert(cpus.clone()) {
                ensure_cpuset(cpus);
            }

            // sched_setaffinity
            let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
            unsafe { libc::CPU_ZERO(&mut set); }
            for part in cpus.split(',') {
                let part = part.trim();
                if part.is_empty() { continue; }
                if let Some((s, e)) = part.split_once('-') {
                    let start: usize = match s.parse() { Ok(v) => v, Err(_) => continue };
                    let end: usize = match e.parse() { Ok(v) => v, Err(_) => continue };
                    for cpu in start..=end { unsafe { libc::CPU_SET(cpu, &mut set); } }
                } else if let Ok(cpu) = part.parse::<usize>() {
                    unsafe { libc::CPU_SET(cpu, &mut set); }
                }
            }
            unsafe {
                if libc::sched_setaffinity(*tid, mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                        rescan.store(true, std::sync::atomic::Ordering::Release);
                    }
                }
            }

            // cpuset 写入
            cpuset_add(*tid, cpus);
        }
    }
    info!("已绑核 {} 进程 {} 线程", procs.len(), n);
}
