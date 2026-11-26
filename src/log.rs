use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    mem::MaybeUninit,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

pub const PATH: &str = "/sdcard/Android/Aether/threads_log.txt";
const MAX_SIZE: u64 = 512 * 1024;
const CHECK_EVERY: usize = 512;

/// 持久日志 fd。原实现每行 open/close 一次文件，safety 警告或绑核失败集中爆发时
/// 是系统调用热点。改为持有一个 fd，仅轮转时 reopen。Mutex 保证多线程
/// （eBPF reader 线程、主线程）写入串行，避免行交错。
/// Option 处理目录不可写的情况：写日志失败不应 panic 影响绑核主流程。
static LOG_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn open_log() -> Option<File> {
    OpenOptions::new().create(true).append(true).open(PATH).ok()
}

/// 写入计数，每 CHECK_EVERY 行检查一次文件大小（避免每行 stat）
static WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 统一日志格式: [I] MM-DD HH:MM:SS: message
pub fn write(level: char, msg: &str) {
    let mut now: libc::time_t = 0;
    let mut tm: libc::tm = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        libc::time(&mut now);
        libc::localtime_r(&now, &mut tm);
    }
    let line = format!(
        "[{}] {:02}-{:02} {:02}:{:02}:{:02}: {}\n",
        level, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, msg
    );

    let _ = std::io::stderr().write_all(line.as_bytes());

    // 每 CHECK_EVERY 行检查一次大小，超限轮转（保留最近一份 .old）。
    // 轮转必须在持锁状态下完成：rename 后旧 fd 仍指向旧 inode，需替换整个 File。
    let n = WRITE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let rotate = n % CHECK_EVERY == 0
        && fs::metadata(PATH).map(|m| m.len() > MAX_SIZE).unwrap_or(false);

    let cell = LOG_FILE.get_or_init(|| Mutex::new(open_log()));
    let mut guard = cell.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        *guard = open_log();
    }
    if rotate {
        let _ = fs::rename(PATH, format!("{}.old", PATH));
        // drop 旧 fd 后重开，确保后续写入落到新文件而非已 rename 的旧 inode
        *guard = open_log();
    }
    if let Some(f) = guard.as_mut() {
        let _ = f.write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! info  { ($($a:tt)*) => { $crate::log::write('I', &format!($($a)*)) }; }
#[macro_export]
macro_rules! warn  { ($($a:tt)*) => { $crate::log::write('W', &format!($($a)*)) }; }
#[macro_export]
macro_rules! error { ($($a:tt)*) => { $crate::log::write('E', &format!($($a)*)) }; }
