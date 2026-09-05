use std::ffi::CString;
use std::fs;
use std::time::{Duration, Instant};

/// 初始化 inotify 监听配置文件，失败返回 -1
pub fn init(path: &str) -> i32 {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 { return -1; }
    let cpath = match CString::new(path) {
        Ok(c) => c,
        Err(_) => { unsafe { libc::close(fd); } return -1; }
    };
    let wd = unsafe {
        libc::inotify_add_watch(fd, cpath.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
    };
    if wd < 0 { unsafe { libc::close(fd); } return -1; }
    crate::info!("inotify: watching config (fd={})", fd);
    fd
}

/// 读取 inotify 事件：Some(1)=重载, Some(2)=重载+重注册, None=无事件
pub fn read(fd: i32) -> Option<u8> {
    if fd < 0 { return None; }
    let mut buf = [0u8; 1024];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n <= 0 { return None; }
    let hdr = std::mem::size_of::<libc::inotify_event>();
    let mut off = 0usize;
    let mut reload = false;
    let mut rewatch = false;
    while off + hdr <= n as usize {
        let ev = unsafe { &*(buf.as_ptr().add(off) as *const libc::inotify_event) };
        if ev.mask & libc::IN_CLOSE_WRITE != 0 { reload = true; }
        if ev.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 { reload = true; rewatch = true; }
        off += hdr + ev.len as usize;
    }
    if reload { Some(if rewatch { 2 } else { 1 }) } else { None }
}

/// 重新注册 inotify watch（文件被删除/移动后）
pub fn rewatch(path: &str, fd: &mut i32) {
    if *fd < 0 { return; }
    let cpath = match CString::new(path) {
        Ok(c) => c, Err(_) => return,
    };
    let wd = unsafe {
        libc::inotify_add_watch(*fd, cpath.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
    };
    if wd < 0 {
        unsafe { libc::close(*fd); }
        *fd = -1;
        crate::warn!("inotify: register failed, fallback to mtime polling");
    } else {
        crate::info!("inotify: re-registered");
    }
}

/// 检测配置变更（inotify 优先，fallback 到 mtime）
pub fn check_changed(path: &str, inotify_fd: &mut i32, last_reload: &mut Instant, cfg_mtime: &std::time::SystemTime) -> bool {
    if last_reload.elapsed() < Duration::from_secs(5) {
        return false;
    }
    if let Some(ev) = read(*inotify_fd) {
        if ev == 2 { rewatch(path, inotify_fd); }
        return true;
    }
    if *inotify_fd < 0 {
        if let Ok(mt) = fs::metadata(path).and_then(|m| m.modified()) {
            if mt > *cfg_mtime {
                return true;
            }
        }
    }
    false
}