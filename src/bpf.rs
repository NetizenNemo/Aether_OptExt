use std::mem;

pub struct BpfCtx {
    pub ok: bool,
    pub map_fd: i32,
    pub prog_fd: i32,
}

impl Drop for BpfCtx {
    fn drop(&mut self) {
        if self.prog_fd >= 0 { unsafe { libc::close(self.prog_fd); } }
        if self.map_fd >= 0 { unsafe { libc::close(self.map_fd); } }
    }
}

pub fn probe(enable: bool) -> BpfCtx {
    if !enable { return BpfCtx { ok: false, map_fd: -1, prog_fd: -1 }; }

    #[repr(C, packed)]
    struct M { mt: u32, ks: u32, vs: u32, me: u32, mf: u32, pad: [u32;6] }
    #[repr(C, packed)]
    struct P { pt: u32, ic: u32, ins: u64, lic: u64, ll: u32, ls: u32, lb: u64, kv: u32, pad: u32 }

    unsafe {
        let ma = M { mt: 1, ks: 4, vs: 4, me: 256, mf: 0, pad: [0;6] };
        let mfd = libc::syscall(280, 0, &ma as *const _, mem::size_of::<M>()) as i32;
        if mfd < 0 { return BpfCtx { ok: false, map_fd: -1, prog_fd: -1 }; }

        let mut ins: [u64; 17] = [
            0x00000000000016bf, 0x0000000e00000085, 0x00000000000007bf,
            0x0000002000000077, 0x00000000fffc0a63, 0x0000000000001118,
            0x0000000000000000, 0x000000000000a2bf, 0xfffffffc00000207,
            0x00000001000000b7, 0x00000000fff80a63, 0x000000000000a3bf,
            0xfffffff800000307, 0x00000000000004b7, 0x0000000200000085,
            0x00000000000000b7, 0x0000000000000095,
        ];
        ins[5] = 0x18u64 | (1u64 << 8) | (1u64 << 12) | ((mfd as u64 & 0xFFFFFFFF) << 32);

        let lic: [u8; 4] = [71, 80, 76, 0];
        let mut vlog = [0u8; 4096];
        let pa = P { pt: 5, ic: 17, ins: &ins as *const _ as u64, lic: lic.as_ptr() as u64, ll: 1, ls: 4096, lb: &mut vlog as *mut _ as u64, kv: 0, pad: 0 };
        let pfd = libc::syscall(280, 5, &pa as *const _, mem::size_of::<P>()) as i32;
        if pfd < 0 {
            let vs = std::str::from_utf8(&vlog).unwrap_or("");
            info!("eBPF: PROG_LOAD 失败 (errno={})", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
            if vs.len() > 2 { info!("eBPF 日志: {}", vs.trim_end_matches(char::from(0))); }
            libc::close(mfd);
            return BpfCtx { ok: false, map_fd: -1, prog_fd: -1 };
        }
        info!("eBPF: 已加载");
        BpfCtx { ok: true, map_fd: mfd, prog_fd: pfd }
    }
}

pub fn read_map(map_fd: i32) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut key: u32 = 0;
    loop {
        let mut nk: u32 = 0;
        let attr: [u64; 4] = [map_fd as u64, &key as *const _ as u64, &mut nk as *mut _ as u64, 0];
        if unsafe { libc::syscall(280, 3, &attr as *const _, mem::size_of::<[u64;4]>()) as i32 } != 0 { break; }
        pids.push(nk);
        key = nk;
    }
    for pid in &pids {
        let a: [u64; 3] = [map_fd as u64, pid as *const u32 as u64, 0];
        unsafe { libc::syscall(280, 4, &a as *const _, mem::size_of::<[u64;3]>()); }
    }
    pids
}
