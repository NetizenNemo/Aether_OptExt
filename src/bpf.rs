use aya::Ebpf;
use aya::EbpfLoader;
use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::TracePoint;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc;
use std::thread;
use crate::config;

pub const EVENT_FORK: u32 = 1;
pub const EVENT_EXEC: u32 = 2;
pub const EVENT_RENAME: u32 = 3;
pub const EVENT_EXIT: u32 = 4;
/// 前台归属变化（进程被搬入 top-app/foreground），用于通知 Aether Scheduler 重查
pub const EVENT_FG: u32 = 5;

/// eBPF 进程事件，布局与内核态 ProcEvent 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

/// 用户态注入内核的 tracepoint 字段偏移，布局需与内核态 TracepointOffsets 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
    /// cgroup_attach_task 的 dst_id / pid 偏移（0 = 该 tracepoint 不可用）
    cg_dst_id: u32,
    cg_pid: u32,
}

// SAFETY: 全部为 u32 POD 字段
unsafe impl aya::Pod for EbpfOffsets {}

pub struct BpfCtx {
    pub ok: bool,
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub bpf: Option<Ebpf>,
    wakeup_fd: i32,
    reader_thread: Option<thread::JoinHandle<()>>,
}

impl BpfCtx {
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel();
        BpfCtx { ok: false, event_rx: rx, bpf: None, wakeup_fd: -1, reader_thread: None }
    }
}

impl Drop for BpfCtx {
    fn drop(&mut self) {
        // 写 eventfd 唤醒 reader 线程的 epoll_wait 后 join 等待退出
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if self.wakeup_fd >= 0 {
            unsafe { libc::close(self.wakeup_fd); }
        }
    }
}

#[cfg(not(target_os = "android"))]
pub fn probe(_enable: bool) -> BpfCtx {
    BpfCtx::empty()
}

#[cfg(target_os = "android")]
pub fn probe(enable: bool) -> BpfCtx {
    if !enable { return BpfCtx::empty(); }

    let elf_data = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf_target.o"));
    crate::info!("[ebpf] loading {} bytes", elf_data.len());

    let mut bpf = match EbpfLoader::new().load(&elf_data[..]) {
        Ok(b) => b,
        Err(e) => { crate::error!("[ebpf] EbpfLoader::load failed ({:?})", e); return BpfCtx::empty(); }
    };

    // tracepoint 偏移注入（必须先于 attach，避免首批事件读到空 map）
    if !offsets_inject(&mut bpf) {
        crate::warn!("[ebpf] offset inject failed, fallback to /proc polling");
        return BpfCtx::empty();
    }

    // attach 4 个 tracepoint
    let attach = |bpf: &mut Ebpf, name: &str, category: &str, required: bool| -> bool {
        let prog = match bpf.program_mut(name) {
            Some(p) => p,
            None => {
                if required { crate::warn!("[ebpf] program '{}' not found", name); }
                return false;
            }
        };
        let tp_prog: &mut TracePoint = match prog.try_into() {
            Ok(t) => t,
            Err(e) => {
                if required { crate::warn!("[ebpf] program '{}' try_into failed ({:?})", name, e); }
                return false;
            }
        };
        if let Err(e) = tp_prog.load() {
            if required { crate::warn!("[ebpf] program '{}' BPF_PROG_LOAD failed ({:?})", name, e); }
            return false;
        }
        if let Err(e) = tp_prog.attach(category, name) {
            if required { crate::warn!("[ebpf] program '{}' attach {}/{} failed ({:?})", name, category, name, e); }
            return false;
        }
        if required { crate::info!("[ebpf] program '{}' attached", name); }
        true
    };

    let fork_ok = attach(&mut bpf, "sched_process_fork", "sched", true);
    let exec_ok = attach(&mut bpf, "sched_process_exec", "sched", true);
    let exit_ok = attach(&mut bpf, "sched_process_exit", "sched", true);
    attach(&mut bpf, "task_rename", "task", false); // rename 可选
    // 前台感知可选：失败仅降级为无 fg_hint 通知，不影响绑核主链路
    let fg_ok = attach(&mut bpf, "cgroup_attach_task", "cgroup", false);

    if !(fork_ok && exec_ok && exit_ok) {
        crate::warn!("[ebpf] required tracepoints failed, fallback to /proc polling");
        return BpfCtx::empty();
    }

    // 创建事件通道 + reader 线程
    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        crate::error!("[ebpf] eventfd creation failed");
        return BpfCtx::empty();
    }

    let ring_buf = match bpf.take_map("EVENTS") {
        Some(map) => match RingBuf::try_from(map) {
            Ok(rb) => rb,
            Err(e) => { crate::error!("[ebpf] EVENTS RingBuf failed ({:?})", e); return BpfCtx::empty(); }
        },
        None => { crate::error!("[ebpf] take_map(EVENTS) failed"); return BpfCtx::empty(); }
    };

    let reader = thread::spawn(move || ebpf_reader(ring_buf, tx, wakeup_fd));

    let mut ctx = BpfCtx { ok: true, event_rx: rx, bpf: Some(bpf), wakeup_fd, reader_thread: Some(reader) };
    // 注入前台 cgroup id（供 cgroup_attach_task hook 判定）；失败仅失去 fg_hint 能力
    let fg_n = if fg_ok { fg_cgroup_init(&mut ctx) } else { 0 };
    if fg_ok && fg_n == 0 {
        crate::warn!("[ebpf] fg cgroup id inject failed, fg_hint disabled");
    }

    crate::info!("[ebpf] ready (exec={} fork={} exit={} fg={})", exec_ok, fork_ok, exit_ok, fg_ok);
    ctx
}

/// RingBuf 读取线程：epoll 阻塞等待事件，wakeup_fd 用于 Drop 唤醒退出
fn ebpf_reader(mut ring_buf: RingBuf<aya::maps::MapData>, tx: mpsc::Sender<EbpfProcEvent>, wakeup_fd: i32) {
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 { return; }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        // wakeup 事件优先退出
        let mut wakeup = false;
        for i in 0..n as usize {
            if events[i].u64 == 1 { wakeup = true; break; }
        }
        if wakeup { break; }

        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd); }
                    return;
                }
            }
        }
    }
    unsafe { libc::close(epfd); }
}

/// 检测 tracefs 根路径
fn tracefs_root() -> Option<&'static str> {
    if std::path::Path::new("/sys/kernel/tracing").exists() {
        return Some("/sys/kernel/tracing");
    }
    if std::path::Path::new("/sys/kernel/debug/tracing").exists() {
        return Some("/sys/kernel/debug/tracing");
    }
    None
}

/// 解析 tracepoint format 文件提取字段偏移
fn tracepoint_parse(root: &str, category: &str, name: &str) -> Option<std::collections::HashMap<String, u32>> {
    let path = format!("{}/events/{}/{}/format", root, category, name);
    let content = std::fs::read_to_string(&path).ok()?;
    let mut offsets = std::collections::HashMap::new();
    for line in content.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else { continue };
        let parts: Vec<&str> = rest.split(';').map(|s| s.trim()).collect();
        if parts.len() < 2 { continue; }
        let field_name = parts[0].split_whitespace().last().unwrap_or("")
            .split('[').next().unwrap_or("");
        if field_name.is_empty() { continue; }
        for part in &parts[1..] {
            if let Some(off_str) = part.strip_prefix("offset:") {
                if let Ok(off) = off_str.trim().parse::<u32>() {
                    offsets.insert(field_name.to_string(), off);
                    break;
                }
            }
        }
    }
    Some(offsets)
}

/// 解析本机 format 文件并注入 OFFSETS_MAP 索引 0
fn offsets_inject(bpf: &mut Ebpf) -> bool {
    let Some(root) = tracefs_root() else {
        crate::warn!("[ebpf] tracefs unavailable");
        return false;
    };

    let offsets = (|| {
        let fork_fields = tracepoint_parse(root, "sched", "sched_process_fork")?;
        let rename_fields = tracepoint_parse(root, "task", "task_rename")?;
        // cgroup_attach_task 缺失时置 0，内核态据此跳过前台 hook（不影响绑核主链路）
        let cg = tracepoint_parse(root, "cgroup", "cgroup_attach_task").unwrap_or_default();
        Some(EbpfOffsets {
            fork_child_pid: *fork_fields.get("child_pid")?,
            fork_child_comm: *fork_fields.get("child_comm")?,
            rename_newcomm: *rename_fields.get("newcomm")?,
            cg_dst_id: cg.get("dst_id").copied().unwrap_or(0),
            cg_pid: cg.get("pid").copied().unwrap_or(0),
        })
    })();
    let Some(offsets) = offsets else {
        crate::error!("[ebpf] tracepoint format parse failed [{}]", root);
        return false;
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        crate::error!("[ebpf] OFFSETS_MAP not found");
        return false;
    };
    let Ok(mut offsets_map) = Array::<_, EbpfOffsets>::try_from(map) else {
        crate::error!("[ebpf] OFFSETS_MAP type conversion failed");
        return false;
    };
    if offsets_map.set(0, &offsets, 0).is_err() {
        crate::error!("[ebpf] OFFSETS_MAP inject failed");
        return false;
    }

    crate::info!("[ebpf] offsets [{}] fork[child_pid={}, child_comm={}] rename[newcomm={}] cg[dst_id={}, pid={}]",
        root, offsets.fork_child_pid, offsets.fork_child_comm, offsets.rename_newcomm,
        offsets.cg_dst_id, offsets.cg_pid);
    true
}

/// 构建白名单键：每个包名生成前 8 字节与末 8 字节键
pub fn comm_keys_build<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 8]> {
    let mut entries: Vec<[u8; 8]> = Vec::new();
    for pkg in pkgs {
        let bytes = pkg.as_bytes();
        if bytes.is_empty() { continue; }
        let mut prefix_key = [0u8; 8];
        let prefix_len = bytes.len().min(8);
        prefix_key[..prefix_len].copy_from_slice(&bytes[..prefix_len]);
        entries.push(prefix_key);
        if bytes.len() > 8 {
            let mut suffix_key = [0u8; 8];
            let start = bytes.len() - 8;
            suffix_key.copy_from_slice(&bytes[start..]);
            entries.push(suffix_key);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// 同步白名单到 BPF map，返回 true 表示容量不足需重载
pub fn comm_map_init(ctx: &mut BpfCtx, pkgs: &std::collections::HashSet<String>, comm_capacity: &mut u32) -> bool {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return false };
    let entries = comm_keys_build(pkgs.iter());

    if entries.len() > *comm_capacity as usize {
        crate::warn!("[ebpf] whitelist capacity insufficient ({} > {})", entries.len(), comm_capacity);
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        crate::error!("[ebpf] TARGET_COMM_MAP not found");
        return false;
    };
    let Ok(mut target_map) = BpfHashMap::<_, [u8; 8], u32>::try_from(map) else {
        crate::error!("[ebpf] TARGET_COMM_MAP type conversion failed");
        return false;
    };

    let old_keys: Vec<[u8; 8]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let mut count = 0;
    for key in &entries {
        if target_map.insert(key, 1, 0).is_ok() { count += 1; }
    }

    crate::info!("[ebpf] whitelist configured: {} pkgs, {} keys", pkgs.len(), count);
    false
}

/// 写入 APPLIED_MAP tid → CPU mask
pub fn applied_set(ctx: &mut BpfCtx, tid: i32, cpus_bits0: u64) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut applied) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let _ = applied.insert(&(tid as u32), cpus_bits0, 0);
}

/// 从 APPLIED_MAP 删除 tid
pub fn applied_del(ctx: &mut BpfCtx, tid: i32) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut applied) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let _ = applied.remove(&(tid as u32));
}

/// 清空 APPLIED_MAP
pub fn applied_clear(ctx: &mut BpfCtx) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut m) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let keys: Vec<u32> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &keys {
        let _ = m.remove(k);
    }
}

/// 前台 cgroup 目录：进程被 Android OomAdjuster 搬入此分组即视为前台切换。
/// 只监听 top-app —— 它是 Android 认定的真正前台（顶层窗口所在）。
/// foreground 含大量"可见但非顶层"进程（实测切一次设置就产生 4 条无关事件：
/// ui.cloudservice / com.xiaomi.ab / htmlviewer / coolapk），会淹没真实信号。
const FG_CGROUP_DIRS: &[&str] = &[
    "/dev/cpuset/top-app",
];

/// 注入前台 cgroup kernfs id 到 FG_CGROUP_MAP。
/// tracepoint 的 dst_id 即 cgroup 目录 inode（实测 /dev/cpuset/top-app inode == dst_id），
/// 故用户态 stat 一次目录即可，内核态无需解析路径字符串。
pub fn fg_cgroup_init(ctx: &mut BpfCtx) -> usize {
    use std::os::unix::fs::MetadataExt;
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return 0 };
    let Some(map) = bpf.map_mut("FG_CGROUP_MAP") else { return 0 };
    let Ok(mut m) = BpfHashMap::<_, u64, u32>::try_from(map) else { return 0 };

    let old: Vec<u64> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &old { let _ = m.remove(k); }

    let mut n = 0;
    for dir in FG_CGROUP_DIRS {
        if let Ok(md) = std::fs::metadata(dir) {
            let ino = md.ino();
            if m.insert(&ino, 1, 0).is_ok() {
                crate::info!("[ebpf] fg cgroup: {} -> {}", dir, ino);
                n += 1;
            }
        }
    }
    n
}

/// 从 comm 16 字节反查包名（与 BPF 双键逻辑一致：精确优先，其次前缀/后缀）
pub fn comm_to_pkg(comm: &str, cfg: &config::AppConfig) -> Option<String> {
    if cfg.pkg_set.contains(comm) {
        return Some(comm.to_string());
    }
    if comm.len() >= 15 {
        for pkg in &cfg.pkg_set {
            if pkg.starts_with(comm) { return Some(pkg.clone()); }
        }
        for pkg in &cfg.pkg_set {
            if pkg.ends_with(comm) { return Some(pkg.clone()); }
        }
    }
    None
}
