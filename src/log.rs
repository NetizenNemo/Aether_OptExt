use std::{fs, io::Write, mem::MaybeUninit, sync::atomic::{AtomicUsize, Ordering}};

pub const PATH: &str = "/sdcard/Android/Aether/threads_log.txt";
const MAX_SIZE: u64 = 512 * 1024;
const CHECK_EVERY: usize = 512;

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

    // 每 CHECK_EVERY 行检查一次文件大小，超限轮转（保留最近一份 .old）
    let n = WRITE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n % CHECK_EVERY == 0 {
        if let Ok(m) = fs::metadata(PATH) {
            if m.len() > MAX_SIZE {
                let _ = fs::rename(PATH, format!("{}.old", PATH));
            }
        }
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(PATH) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! info  { ($($a:tt)*) => { $crate::log::write('I', &format!($($a)*)) }; }
#[macro_export]
macro_rules! warn  { ($($a:tt)*) => { $crate::log::write('W', &format!($($a)*)) }; }
#[macro_export]
macro_rules! error { ($($a:tt)*) => { $crate::log::write('E', &format!($($a)*)) }; }
