/// 读取 CPU present 掩码字符串
pub fn present() -> String {
    std::fs::read_to_string("/sys/devices/system/cpu/present")
        .unwrap_or_default().trim().to_string()
}

/// 检测 CPU 集群，返回 (大核列表, 小核列表, 拓扑描述)
pub fn detect() -> (String, String, String) {
    let mut cls: Vec<(u64, Vec<usize>)> = Vec::new();
    // 方法1: cpufreq policy 目录
    if let Ok(dir) = std::fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("policy") { continue; }
            let rel = match std::fs::read_to_string(e.path().join("related_cpus")) {
                Ok(x) => x.trim().to_string(), Err(_) => continue
            };
            let f_str = match std::fs::read_to_string(e.path().join("cpuinfo_max_freq")) {
                Ok(x) => x.trim().to_string(), Err(_) => continue
            };
            let freq: u64 = match f_str.parse() { Ok(f) => f, Err(_) => continue };
            let mut cpus = Vec::new();
            for part in rel.split(|c: char| c == ',' || c == ' ') {
                let part = part.trim();
                if part.is_empty() { continue; }
                if let Some((a, b)) = part.split_once('-') {
                    let s: usize = a.parse().unwrap_or(0);
                    let e: usize = b.parse().unwrap_or(s);
                    for cpu in s..=e { cpus.push(cpu); }
                } else if let Ok(c) = part.parse::<usize>() { cpus.push(c); }
            }
            if !cpus.is_empty() { cls.push((freq, cpus)); }
        }
    }
    // 方法2: 逐个读 CPU 频率 (策略1失败时)
    if cls.len() < 2 {
        cls.clear();
        for cpu in 0..128 {
            let fp = format!("/sys/devices/system/cpu/cpu{}/cpufreq/cpuinfo_max_freq", cpu);
            let f_str = match std::fs::read_to_string(&fp) { Ok(x) => x.trim().to_string(), Err(_) => break };
            let freq: u64 = match f_str.parse() { Ok(f) => f, Err(_) => continue };
            let mut found = false;
            for (f, cpus) in &mut cls {
                if *f == freq { cpus.push(cpu); found = true; break; }
            }
            if !found { cls.push((freq, vec![cpu])); }
        }
    }
    cls.sort_by(|a, b| b.0.cmp(&a.0)); // 按频率降序
    if cls.is_empty() { return ("0".into(), "0".into(), "1".into()); }
    let big = fmt_cpus(&cls[0].1);
    let little = fmt_cpus(&cls.last().unwrap().1);
    let topo = cls.iter().map(|(_, c)| c.len().to_string()).collect::<Vec<_>>().join("+");
    (big, little, topo)
}

fn fmt_cpus(cpus: &[usize]) -> String {
    if cpus.is_empty() { return "0".into(); }
    let mut parts = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        let mut end = start;
        while i + 1 < cpus.len() && cpus[i+1] == end + 1 { i += 1; end = cpus[i]; }
        if start == end { parts.push(start.to_string()); } else { parts.push(format!("{}-{}", start, end)); }
        i += 1;
    }
    parts.join(",")
}
