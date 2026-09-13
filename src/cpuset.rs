use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

use crate::common::{base_cpuset, CPU_SETSIZE, CPU_WORDS, CPU_WORD_BITS};

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
pub struct CpuSet {
    pub bits: [u64; CPU_WORDS],
}

impl CpuSet {
    pub fn new() -> Self {
        CpuSet::default()
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / CPU_WORD_BITS] |= 1u64 << (cpu % CPU_WORD_BITS);
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        cpu < CPU_SETSIZE && self.bits[cpu / CPU_WORD_BITS] & (1u64 << (cpu % CPU_WORD_BITS)) != 0
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|&b| b.count_ones() as usize).sum()
    }

    pub fn or(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d |= s;
        }
    }

    /// self ∩ other（按位与）
    pub fn intersection(&self, other: &CpuSet) -> CpuSet {
        let mut r = CpuSet::new();
        for (i, (&a, &b)) in self.bits.iter().zip(other.bits.iter()).enumerate() {
            r.bits[i] = a & b;
        }
        r
    }

    /// 从 "0-3,6-7" 解析
    pub fn from_range(spec: &str) -> CpuSet {
        parse_cpu_ranges(spec, None)
    }

    /// 转换为范围字符串
    pub fn to_range_string(&self) -> String {
        let mut result = String::new();
        let mut start: Option<usize> = None;
        let mut end: Option<usize> = None;
        let mut first = true;

        for (word_idx, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                if start.is_some() {
                    push_range(&mut result, start, end, &mut first);
                    start = None;
                    end = None;
                }
                continue;
            }
            let base = word_idx * CPU_WORD_BITS;
            for bit in 0..CPU_WORD_BITS {
                if word & (1u64 << bit) != 0 {
                    let cpu = base + bit;
                    if start.is_none() {
                        start = Some(cpu);
                        end = Some(cpu);
                    } else if end.is_some_and(|e| cpu == e + 1) {
                        end = Some(cpu);
                    } else {
                        push_range(&mut result, start, end, &mut first);
                        start = Some(cpu);
                        end = Some(cpu);
                    }
                }
            }
        }
        push_range(&mut result, start, end, &mut first);
        result
    }

    pub fn get_affinity(tid: i32) -> Option<CpuSet> {
        let mut curr = CpuSet::new();
        let ret = unsafe {
            libc::sched_getaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                &mut curr as *mut CpuSet as *mut libc::cpu_set_t,
            )
        };
        if ret == -1 {
            None
        } else {
            Some(curr)
        }
    }

    pub fn set_affinity(&self, tid: i32) -> io::Result<()> {
        let ret = unsafe {
            libc::sched_setaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                self as *const CpuSet as *const libc::cpu_set_t,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn push_range(s: &mut String, start: Option<usize>, end: Option<usize>, first: &mut bool) {
    if let (Some(lo), Some(hi)) = (start, end) {
        if !*first {
            s.push(',');
        }
        if lo == hi {
            let _ = write!(s, "{}", lo);
        } else {
            let _ = write!(s, "{}-{}", lo, hi);
        }
        *first = false;
    }
}

/// 解析 CPU 范围字符串
pub fn parse_cpu_ranges(spec: &str, present: Option<&CpuSet>) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    // 支持逗号、空格及混合分隔（customize.sh 检测的 related_cpus 可能是 "0 1 2 3 4 5"）
    for part in spec.split(|c: char| c == ',' || c == ' ' || c == '\t') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = if let Some(pos) = part.find('-') {
            let a: usize = part[..pos].parse().ok().unwrap_or(usize::MAX);
            let b: usize = part[pos + 1..].parse().ok().unwrap_or(a);
            if a == usize::MAX {
                continue;
            }
            if a > b {
                (b, a)
            } else {
                (a, b)
            }
        } else {
            let a: usize = part.parse().ok().unwrap_or(usize::MAX);
            if a == usize::MAX {
                continue;
            }
            (a, a)
        };
        for i in lo..=hi.min(CPU_SETSIZE - 1) {
            if let Some(present) = present {
                if !present.is_set(i) {
                    continue;
                }
            }
            set.set(i);
        }
    }
    set
}

/// 兼容旧调用：从 "0-3,6-7" 解析
pub fn from_range(spec: &str) -> CpuSet {
    parse_cpu_ranges(spec, None)
}

/// 创建 cpuset 子目录并写入 cpus 与 mems
pub(crate) fn create_cpuset_dir(path: &str, cpus: &str, mems: &str) -> bool {
    let c_path = CString::new(path).expect("cpuset path 受控输入，无 NUL");
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
    }
    if unsafe { libc::chmod(c_path.as_ptr(), 0o755) } != 0 {
        return false;
    }
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        return false;
    }
    let cpus_path = format!("{}/cpus", path);
    if fs::write(&cpus_path, cpus).is_err() {
        return false;
    }
    let mems_path = format!("{}/mems", path);
    fs::write(&mems_path, mems).is_ok()
}

/// 按合并后的 CPU 集合确保 cpuset 子目录存在，返回目录名（cpuset 未启用或创建失败返回空串）
pub fn ensure_cpuset_dir(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if !topo.cpuset_enabled {
        return String::new();
    }
    let dir_name = cpus.to_range_string();
    let path = format!("{}/{}", base_cpuset(), dir_name);
    if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
        dir_name
    } else {
        String::new()
    }
}

#[derive(Clone)]
pub struct CpuTopology {
    pub present_cpus: CpuSet,
    pub present_str: String,
    /// 当前在线核（present ∩ online），thermal 会临时下线大核，
    /// 绑定前目标掩码必须裁掉离线核，否则 sched_setaffinity 报 EINVAL。
    /// clip_online 内部按 ONLINE_REFRESH_MS 节流刷新。
    online_now: std::cell::Cell<CpuSet>,
    online_at: std::cell::Cell<u64>,
    pub mems_str: String,
    pub cpuset_enabled: bool,
    pub base_cpuset_fd: RawFd,
    /// 语义核心分层：最低频为 e-core，最高频为 hp-core，中间为 p-core
    pub e_core: CpuSet,
    pub p_core: CpuSet,
    pub hp_core: CpuSet,
}

/// 读取在线核集合并与 present 求交，失败返回 None
fn read_online_cpus(present: &CpuSet) -> Option<CpuSet> {
    let s = fs::read_to_string("/sys/devices/system/cpu/online").ok()?;
    let o = parse_cpu_ranges(s.trim(), None);
    if o.count() == 0 { return None; }
    Some(o.intersection(present))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).unwrap_or(0)
}

const ONLINE_REFRESH_MS: u64 = 1000;

impl CpuTopology {
    /// 按在线核裁剪目标掩码（thermal 下线大核时防止 sched_setaffinity EINVAL），
    /// 裁剪后为空则回退全部在线核。内部 1s 节流刷新，自动跟随 thermal 上/下线。
    pub fn clip_online(&self, cpus: &CpuSet) -> CpuSet {
        let now = now_ms();
        if now >= self.online_at.get() + ONLINE_REFRESH_MS {
            if let Some(o) = read_online_cpus(&self.present_cpus) {
                self.online_now.set(o);
            }
            self.online_at.set(now);
        }
        let online = self.online_now.get();
        let c = cpus.intersection(&online);
        if c.count() == 0 { online } else { c }
    }
}

/// 按 cpufreq 策略检测核心分层，按最高频率升序分组：首组为 e-core，末组为 hp-core，中间为 p-core
fn detect_core_types() -> (CpuSet, CpuSet, CpuSet) {
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("policy"))
            {
                continue;
            }
            let freq: u64 = fs::read_to_string(path.join("cpuinfo_max_freq"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if freq == 0 {
                continue;
            }
            let cpus: Vec<usize> = fs::read_to_string(path.join("related_cpus"))
                .ok()
                .map(|s| s.split_whitespace().filter_map(|c| c.parse().ok()).collect())
                .unwrap_or_default();
            if cpus.is_empty() {
                continue;
            }
            if let Some(g) = groups.iter_mut().find(|(f, _)| *f == freq) {
                g.1.extend(cpus);
            } else {
                groups.push((freq, cpus));
            }
        }
    }
    groups.sort_by_key(|(f, _)| *f);
    let mut e = CpuSet::new();
    let mut p = CpuSet::new();
    let mut h = CpuSet::new();
    let n = groups.len();
    for (i, (_, cpus)) in groups.iter().enumerate() {
        let target = if i == 0 {
            &mut e
        } else if i == n - 1 {
            &mut h
        } else {
            &mut p
        };
        for &cpu in cpus {
            target.set(cpu);
        }
    }
    (e, p, h)
}

/// 初始化 CPU 拓扑，检测 cpuset 可用性并创建 BASE_CPUSET 目录
pub fn init_cpu_topo() -> CpuTopology {
    let mut topo = CpuTopology {
        present_cpus: CpuSet::new(),
        present_str: String::new(),
        online_now: std::cell::Cell::new(CpuSet::new()),
        online_at: std::cell::Cell::new(0),
        mems_str: String::new(),
        cpuset_enabled: false,
        base_cpuset_fd: -1,
        e_core: CpuSet::new(),
        p_core: CpuSet::new(),
        hp_core: CpuSet::new(),
    };

    if let Ok(content) = fs::read_to_string("/sys/devices/system/cpu/present") {
        topo.present_str = content.trim().to_string();
    }
    topo.present_cpus = parse_cpu_ranges(&topo.present_str, None);
    let online_str = fs::read_to_string("/sys/devices/system/cpu/online")
        .map(|s| s.trim().to_string()).unwrap_or_default();
    let online = {
        let o = parse_cpu_ranges(&online_str, None);
        if o.count() == 0 { topo.present_cpus } else { o.intersection(&topo.present_cpus) }
    };
    topo.online_now.set(online);
    topo.online_at.set(now_ms());
    let (e, p, h) = detect_core_types();
    // 语义分层保留完整检测结果，绑定时刻由 clip_online 动态裁剪（thermal 上下线自适应）
    topo.e_core = e;
    topo.p_core = p;
    topo.hp_core = h;

    // 诊断：online 与根 cpuset 范围（决定大核是否可绑）
    let online = fs::read_to_string("/sys/devices/system/cpu/online")
        .map(|s| s.trim().to_string()).unwrap_or_default();
    let root_cpus = fs::read_to_string("/dev/cpuset/cpus")
        .map(|s| s.trim().to_string()).unwrap_or_default();
    crate::info!("self-check: present={} online={} root_cpus={}",
        topo.present_str, online, root_cpus);

    let cpuset_path = CString::new("/dev/cpuset").expect("常量字符串无 NUL");
    if unsafe { libc::access(cpuset_path.as_ptr(), libc::F_OK) } != 0 {
        crate::warn!("self-check: /dev/cpuset unavailable, skip BASE_CPUSET");
        return topo;
    }

    if create_cpuset_dir(base_cpuset(), &topo.present_str, "0") {
        let base_path = CString::new(base_cpuset()).expect("常量字符串无 NUL");
        topo.base_cpuset_fd =
            unsafe { libc::open(base_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if topo.base_cpuset_fd != -1 {
            topo.cpuset_enabled = true;
            crate::info!("self-check: {} ready cpus={}", base_cpuset(), topo.present_str);
        } else {
            crate::warn!("self-check: {} open failed errno={}", base_cpuset(), std::io::Error::last_os_error());
        }
    } else {
        crate::warn!("self-check: {} create failed (root cpuset may exclude big cores)", base_cpuset());
    }

    let mems_path = format!("{}/mems", base_cpuset());
    if let Ok(mems) = fs::read_to_string(&mems_path) {
        topo.mems_str = mems.trim().to_string();
    } else {
        topo.mems_str = "0".to_string();
    }

    topo
}
