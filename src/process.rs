use std::{collections::{HashMap, HashSet}, fs, mem, sync::{Mutex, OnceLock}};
use crate::config::{Rule, fnmatch};

static CPUSET_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static LAST_AFFINITY: OnceLock<Mutex<HashMap<i32, String>>> = OnceLock::new();

/// 初始化 cpuset 目录
pub fn init_cpuset() {
    if !std::path::Path::new("/dev/cpuset").exists() { return; }
    let _ = fs::create_dir_all("/dev/cpuset/AppOpt");
    // 写入所有可用 CPU 到根 cpuset
    let present = std::fs::read_to_string("/sys/devices/system/cpu/present").unwrap_or_default();
    let _ = fs::write("/dev/cpuset/AppOpt/cpus", present.trim().as_bytes());
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
    let mut buf = [0u8; 8192];
    let fd = unsafe { libc::open("/proc\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 { return result; }
    loop {
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 { break; }
        let mut off = 0usize;
        while off < n as usize {
            let rec = u16::from_ne_bytes(buf[off+16..off+18].try_into().unwrap_or([0;2])) as usize;
            let ino = u64::from_ne_bytes(buf[off..off+8].try_into().unwrap_or([0;8]));
            if rec < 19 || ino == 0 { off += rec; continue; }
            let name = std::str::from_utf8(&buf[off+19..off+rec-1]).unwrap_or("");
            off += rec;
            let pid: i32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            if pid < 1000 { continue; }
            let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
            let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() { continue; }
        if !set.contains(&pkg) && !wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
        let mut th = Vec::new();
        if let Ok(tk) = fs::read_dir(format!("/proc/{}/task", pid)) {
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
    }
    unsafe { libc::close(fd); }
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
    let mut live_tids: HashSet<i32> = HashSet::new();
    // 复制快照以便在持有锁时不长时间阻塞其他读者
    let mut last = LAST_AFFINITY.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    for (_, _, th) in procs {
        for (tid, _, cpus) in th {
            if cpus.is_empty() { continue; }
            live_tids.insert(*tid);

            // 去重: 上次绑定的 cpus 完全相同则跳过, 不计数, 不打日志
            if last.get(tid).map(|s| s == cpus).unwrap_or(false) {
                continue;
            }
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

            // 记录这次绑定的 cpus
            last.insert(*tid, cpus.clone());
        }
    }

    // 清理已死进程的条目 (避免 Map 无限增长 + PID 复用问题)
    last.retain(|tid, _| live_tids.contains(tid));
    drop(last);

    if n > 0 {
        info!("已绑核 {} 进程 {} 线程", procs.len(), n);
    }
}
