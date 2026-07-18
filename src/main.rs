use std::{
    env, fs, io::Write, mem,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
    collections::HashSet,
};

#[macro_use]
mod log;
mod config;
mod cpu;
mod process;
mod bpf;

use log::*;
use config::*;
use cpu::*;
use process::*;

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

    info!("[1] CPU info");
    info!("CPU: {} cpuset={}", cpu::present(), Path::new("/dev/cpuset").exists());

    let mut cfg = match AppConfig::load(&config_path) {
        Some(c) => c,
        None => { error!("配置加载失败"); return; }
    };
    info!("已加载 {} 条规则", cfg.rules.len());

    // 合并缓存
    let mut all_w = cfg.wild.clone();
    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
    info!("[2] cache merged");
    info!("共 {} 条规则 (含缓存)", cfg.rules.len());

    info!("[3] detect");
    let (big, little, topo) = cpu::detect();
    info!("拓扑: {} (大核={} 小核={})", topo, big, little);

    // 初始化 cpuset
    info!("[4] cpuset init");
    process::init_cpuset();

    // 自身限定在小核运行
    if !little.is_empty() && little != "0" {
        let self_pid = std::process::id() as i32;
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set); }
        for part in little.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }
            if let Some((s, e)) = part.split_once('-') {
                let start: usize = s.parse().unwrap_or(0);
                let end: usize = e.parse().unwrap_or(start);
                for cpu in start..=end { unsafe { libc::CPU_SET(cpu, &mut set); } }
            } else if let Ok(cpu) = part.parse::<usize>() {
                unsafe { libc::CPU_SET(cpu, &mut set); }
            }
        }
        let r = unsafe { libc::sched_setaffinity(self_pid, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        if r != 0 { info!("自身绑核跳过 (errno={})", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)); }
    }

    // eBPF
    info!("[5] bpf probe");
    let bpf = bpf::probe(cfg.ebpf);

    let _ = fs::create_dir_all("/sdcard/Android/Aether");

    // 启动时自动分配
    let unknown = process::scan_unknown(&cfg.pkg_set, &all_w);
    for (pid, pkg, th) in &unknown {
        info!("新应用: {} ({} 线程)", pkg, th.len());
        cache::save(pkg, &unknown, &big, &little);
    }
    if !unknown.is_empty() {
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("自动分配完成: {} 个", unknown.len());
    }

    let mut lc = 0i32;
    let mut cnt = 0i32;
    let mut cache_scan = 0i32;
    let mut cache: Vec<(i32, String, Vec<(i32, String, String)>)> = Vec::new();
    let rf = AtomicBool::new(false);
    info!("[6] loop start");
    info!("启动");

    loop {
        // eBPF map 读取
        if bpf.map_fd >= 0 {
            for pid in bpf::read_map(bpf.map_fd) {
                let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
                let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
                if !pkg.is_empty() && (cfg.pkg_set.contains(&pkg) || all_w.iter().any(|w| fnmatch(w, &pkg))) {
                    info!("eBPF: 新进程 {} ({})", pid, pkg);
                }
            }
        }

        let mut nr = false;

        // 定期扫描新应用
        cache_scan += 1;
        if cache_scan >= 30 {
            cache_scan = 0;
            let u = process::scan_unknown(&cfg.pkg_set, &all_w);
            for (pid, pkg, th) in &u {
                info!("新应用: {} ({} 线程)", pkg, th.len());
                cache::save(pkg, &u, &big, &little);
            }
            if !u.is_empty() {
                cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
                info!("缓存已更新");
            }
        }

        // 进程数检测
        let mut si: libc::sysinfo = unsafe { mem::zeroed() };
        if unsafe { libc::sysinfo(&mut si) } != 0 { nr = true; }
        else {
            let cur = si.procs as i32;
            if cur > lc + 10 { nr = true; }
            else if cur > lc { cnt = 0; }
            lc = cur;
        }

        // kill 检测
        if !nr {
            for (pid, _, _) in &cache {
                if unsafe { libc::kill(*pid, 0) } != 0 { nr = true; break; }
            }
        }

        if nr {
            cache = process::scan(&cfg.rules, &cfg.pkg_set, &all_w);
            rf.store(false, Ordering::Release);
        }

        cnt -= 1;
        if cnt < 1 {
            process::apply(&cache, &rf);
            if rf.load(Ordering::Acquire) {
                cache = process::scan(&cfg.rules, &cfg.pkg_set, &all_w);
                rf.store(false, Ordering::Release);
            }
            cnt = 5;
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}
