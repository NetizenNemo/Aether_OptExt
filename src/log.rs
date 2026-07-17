use std::{fs, io::Write};

pub const PATH: &str = "/sdcard/Android/Aether/threads_log.txt";

pub fn write(level: &str, msg: &str) {
    let mut now: libc::time_t = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::time(&mut now);
        libc::localtime_r(&now, &mut tm);
    }
    let line = format!("[{:02}:{:02}:{:02}][{}] {}\n", tm.tm_hour, tm.tm_min, tm.tm_sec, level, msg);
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Ok(m) = fs::metadata(PATH) {
        if m.len() > 524288 { let _ = fs::write(PATH, ""); }
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(PATH) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! info  { ($($a:tt)*) => { $crate::log::write("INFO", &format!($($a)*)) }; }
#[macro_export]
macro_rules! error { ($($a:tt)*) => { $crate::log::write("ERROR", &format!($($a)*)) }; }
