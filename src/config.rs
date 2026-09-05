use std::{collections::HashSet, fs, time::SystemTime};

pub fn fnmatch(pat: &str, name: &str) -> bool {
    if pat.is_empty() { return false; }
    match pat.find('*') {
        None => pat == name,
        Some(pos) => name.starts_with(&pat[..pos])
            && (pat[pos+1..].is_empty() || name[pos..].ends_with(&pat[pos+1..]))
    }
}

fn rule_prio(pat: &str) -> i32 {
    if pat.is_empty() { return 200; }
    if !pat.contains('*') && !pat.contains('?') { return 1000 + pat.len() as i32; }
    let nw = pat.chars().filter(|c| !matches!(c, '*' | '?' | '[' | ']')).count() as i32;
    if pat.contains('[') { 500 + nw } else if pat.contains('?') { 300 + nw } else { 100 + nw }
}

#[derive(Clone)]
pub struct Rule {
    pub pkg: String,
    pub thread: String,
    pub cpus: String,
    #[allow(dead_code)]
    pub prio: i32,
    /// 包级规则的 cpuset 子目录（load 时预生成）；线程规则为空，匹配时按合并集合创建
    pub cpuset_dir: String,
}

/// 解析单个 JSON 条目的结构化结果
pub struct ParsedEntry {
    pub packages: Vec<String>,
    pub other_cpus: String,
    /// (cpus, thread_name, prio)
    pub thread_rules: Vec<(String, String, i32)>,
}

/// 从 JSON 条目中提取 packages / other_cpus / thread_rules
pub fn parse_entry(entry: &json::JsonValue) -> Option<ParsedEntry> {
    let pl: Vec<String> = entry["packages"].members()
        .filter_map(|v| v.as_str().map(String::from)).collect();
    if pl.is_empty() { return None; }
    let other = entry["cpuset"]["other"].as_str().unwrap_or("0").to_string();
    let mut thread_rules = Vec::new();
    if entry["cpuset"]["comm"].is_object() {
        for (cpus, names) in entry["cpuset"]["comm"].entries() {
            for nv in names.members() {
                if let Some(name) = nv.as_str() {
                    thread_rules.push((cpus.to_string(), name.to_string(), rule_prio(name)));
                }
            }
        }
    }
    Some(ParsedEntry { packages: pl, other_cpus: other, thread_rules })
}

#[derive(Clone)]
pub struct AppConfig {
    pub rules: Vec<Rule>,
    pub pkg_set: HashSet<String>,
    pub wild: Vec<String>,
    pub mtime: SystemTime,
    pub ebpf: bool,
    pub topo: crate::cpuset::CpuTopology,
    /// asoul 兼容豁免集合：检测到 asoul 模块时，名单内包名完全不干扰
    pub asoul_ignore: HashSet<String>,
}

/// 检测 asoul 模块是否安装（其守护进程以 /data/adb/asoul_affinity_opt 为根）
pub fn asoul_detected() -> bool {
    std::path::Path::new("/data/adb/asoul_affinity_opt").exists()
}

/// 读取 asoul 兼容名单（每行一个包名，# 开头为注释），仅在 asoul 模块存在时读取
pub fn asoul_gamelist() -> HashSet<String> {
    if !asoul_detected() {
        return HashSet::new();
    }
    std::fs::read_to_string("/sdcard/Android/Aether/gamelist")
        .map(|s| {
            s.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

impl AppConfig {
    pub fn load(path: &str, topo: &crate::cpuset::CpuTopology) -> Option<Self> {
        let data = fs::read_to_string(path).ok()?;
        let root = json::parse(&data).ok()?;

        // 彩蛋
        if root["nekonemo"].as_str() == Some("meow") {
            let count = if root.is_object() { root.entries().count() } else { 0 };
            if count <= 1 {
                info!("嗷呜~💗艇长才不是猫娘喵！！！");
                return None;
            }
        }

        let ebpf = root["features"]["ebpf"].as_bool().unwrap_or(false);
        let entries = if root.is_array() { &root } else { &root["rules"] };
        if !entries.is_array() { return None; }

        let mut rules = Vec::new();
        let mut pkg_set = HashSet::new();
        let mut wild = Vec::new();

        for e in entries.members() {
            let Some(pe) = parse_entry(e) else { continue };
            let def = pe.packages[0].clone();

            for pk in &pe.packages {
                pkg_set.insert(pk.clone());
                if pk.contains('*') || pk.contains('?') { wild.push(pk.clone()); }
            }

            let other_set = crate::cpuset::from_range(&pe.other_cpus);
            let other_dir = other_set.to_range_string();
            let other_cpuset_dir = if topo.cpuset_enabled {
                crate::cpuset::create_cpuset_dir(
                    &format!("{}/{}", crate::common::base_cpuset(), other_dir),
                    &other_dir, &topo.mems_str,
                ).then_some(other_dir).unwrap_or_default()
            } else {
                String::new()
            };
            rules.push(Rule { pkg: def.clone(), thread: String::new(), cpus: pe.other_cpus, prio: 200, cpuset_dir: other_cpuset_dir });

            for (cpus, name, prio) in &pe.thread_rules {
                rules.push(Rule {
                    pkg: def.clone(),
                    thread: name.clone(),
                    cpus: cpus.clone(),
                    prio: *prio,
                    cpuset_dir: String::new(),
                });
            }
        }

        let mt = fs::metadata(path).ok()?.modified().ok()?;
        let mut cfg = AppConfig {
            rules, pkg_set, wild, mtime: mt, ebpf, topo: topo.clone(),
            asoul_ignore: HashSet::new(),
        };
        cfg.apply_asoul_ignore();
        Some(cfg)
    }

    /// 该包是否存在线程级规则
    pub fn pkg_has_thread_rules(&self, pkg: &str) -> bool {
        self.rules.iter().any(|r| !r.thread.is_empty() && fnmatch(&r.pkg, pkg))
    }

    /// 应用 asoul 豁免：过滤规则/包名/通配，返回是否发生豁免
    pub fn apply_asoul_ignore(&mut self) -> bool {
        let ignore = asoul_gamelist();
        if ignore.is_empty() { return false; }
        let n_before = self.rules.len();
        self.rules.retain(|r| !ignore.contains(&r.pkg));
        self.pkg_set.retain(|p| !ignore.contains(p));
        self.wild.retain(|w| !ignore.contains(w));
        self.asoul_ignore = ignore;
        crate::info!("asoul compat: ignoring {} pkgs (filtered {} rules)",
            self.asoul_ignore.len(), n_before - self.rules.len());
        true
    }
}

pub mod cache {
    use std::{collections::HashSet, fs};
    use super::Rule;

    const FILE: &str = "/sdcard/Android/Aether/threads_cache";

    pub fn merge(set: &mut HashSet<String>, rules: &mut Vec<Rule>) {
        let data = match fs::read_to_string(FILE) { Ok(x) => x, Err(_) => return };
        let root = match json::parse(&data) { Ok(x) => x, Err(_) => return };
        if !root.is_array() { return; }
        let mut seen_pkgs = HashSet::new();
        for entry in root.members() {
            let Some(pe) = super::parse_entry(entry) else { continue };
            let def = pe.packages[0].clone();
            // 去重：同名包只保留最后一条（最新）
            if !seen_pkgs.insert(def.clone()) { continue; }
            for pk in &pe.packages { set.insert(pk.clone()); }
            rules.push(Rule { pkg: def.clone(), thread: String::new(), cpus: pe.other_cpus, prio: 200, cpuset_dir: String::new() });
            for (cpus, name, prio) in &pe.thread_rules {
                rules.push(Rule { pkg: def.clone(), thread: name.clone(), cpus: cpus.clone(), prio: *prio, cpuset_dir: String::new() });
            }
        }
        info!("cache entries loaded: {}", seen_pkgs.len());
    }

    /// 用 JSON 库读写 cache，按包名去重覆盖（避免无限膨胀）
    /// 黑名单: 已知无需记忆的系统服务
    pub fn is_blacklisted(pkg: &str) -> bool {
        if pkg.ends_with(":widgetProvider") || pkg.ends_with(":searchDataService")
            || pkg.ends_with(":coreService") || pkg.ends_with(":cognitionService")
            || pkg.ends_with(":bert") || pkg.ends_with(":bertAlgo")
            || pkg.ends_with(":privacy") || pkg.ends_with(":kit7")
            || pkg.ends_with(":services") || pkg.ends_with(":daemon")
            || pkg == "android.process.media" || pkg == "android.process.acore"
            || pkg.starts_with("com.qualcomm.") || pkg.starts_with(".qti")
            || pkg.starts_with(".qms") || pkg.starts_with(".cacert")
            || pkg.starts_with(".dataservices")
        {
            return true;
        }
        // 系统应用前缀（各厂商系统组件，不参与自动分配）
        pkg.starts_with("com.android.") || pkg.starts_with("android.")
            || pkg.starts_with("com.google.android.") || pkg.starts_with("com.miui.")
            || pkg.starts_with("com.xiaomi.") || pkg.starts_with("com.qti.")
            || pkg.starts_with("com.qualcomm.") || pkg.starts_with("vendor.")
            || pkg.starts_with("com.oplus.") || pkg.starts_with("com.oneplus.")
            || pkg.starts_with("com.coloros.") || pkg.starts_with("com.heytap.")
            || pkg.starts_with("com.vivo.") || pkg.starts_with("com.huawei.")
            || pkg.starts_with("com.honor.") || pkg.starts_with("com.samsung.")
            || pkg.starts_with("com.sec.android.") || pkg.starts_with("com.meizu.")
            || pkg.starts_with("org.codeaurora.") || pkg.starts_with("com.miui.securitycenter")
            || pkg.starts_with("com.lbe.") || pkg.starts_with("com.miui.powerkeeper")
    }

    /// 构建单条缓存条目（线程按负载分级到 big/mid1/mid2/little）
    fn build_entry(pkg: &str, all: &[(i32, String, Vec<(i32, String)>)], big: &str, mid1: &str, mid2: &str, little: &str) -> Option<json::JsonValue> {
        let mut big_names = Vec::new();
        let mut mid1_names = Vec::new();
        let mut mid2_names = Vec::new();
        let mut lil_names = Vec::new();
        let has_mid = !mid1.is_empty() || !mid2.is_empty();
        for (_, _, th) in all.iter().filter(|(_, n, _)| n == pkg) {
            for (_, comm) in th {
                let load = est_load(comm);
                if load >= 8 { big_names.push(comm.clone()); }
                else if load >= 6 && !mid1.is_empty() { mid1_names.push(comm.clone()); }
                else if load >= 5 && has_mid { mid2_names.push(comm.clone()); }
                else { lil_names.push(comm.clone()); }

            }
        }

        let mut comm_map: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
        for n in &big_names { comm_map.entry(big).or_default().push(n); }
        for n in &mid1_names { comm_map.entry(mid1).or_default().push(n); }
        for n in &mid2_names { comm_map.entry(mid2).or_default().push(n); }

        let mut entry = json::JsonValue::new_object();
        entry["friendly"] = json::JsonValue::String(format!("[auto] {}", pkg));
        let mut pkgs = json::JsonValue::new_array();
        let _ = pkgs.push(pkg);
        entry["packages"] = pkgs;
        let mut cs = json::JsonValue::new_object();
        cs["other"] = json::JsonValue::String(little.to_string());
        if !big_names.is_empty() || !mid1_names.is_empty() || !mid2_names.is_empty() {
            let mut cm = json::JsonValue::new_object();
            for (cpus, ns) in &comm_map {
                let mut arr = json::JsonValue::new_array();
                for n in ns { let _ = arr.push(*n); }
                cm[*cpus] = arr;
            }
            cs["comm"] = cm;
        }
        entry["cpuset"] = cs;
        Some(entry)
    }

    /// 批量保存：一次读-去重-写，避免多个新应用时循环全量读写
    pub fn save_batch(pkgs: &[String], all: &[(i32, String, Vec<(i32, String)>)], big: &str, mid1: &str, mid2: &str, little: &str) -> usize {
        let mut entries = Vec::new();
        for pkg in pkgs {
            if is_blacklisted(pkg) { continue; }
            if let Some(entry) = build_entry(pkg, all, big, mid1, mid2, little) {
                entries.push(entry);
            }
        }
        if entries.is_empty() { return 0; }
        save_batch_entries(&mut entries);
        entries.len()
    }

    fn save_batch_entries(entries: &mut Vec<json::JsonValue>) {
        let _ = fs::create_dir_all("/sdcard/Android/Aether");
        // 用 JSON 库读写，按包名去重
        let old = fs::read_to_string(FILE).unwrap_or_default();
        let arr: json::JsonValue = if old.trim().is_empty() || !old.trim_start().starts_with('[') {
            json::JsonValue::new_array()
        } else {
            json::parse(&old).unwrap_or(json::JsonValue::new_array())
        };
        let new_pkgs: std::collections::HashSet<String> = entries.iter()
            .filter_map(|e| e["packages"][0].as_str().map(String::from)).collect();
        // 去重：过滤掉与新增包同名的老条目
        let mut deduped = json::JsonValue::new_array();
        for e in arr.members() {
            let keep = match e["packages"][0].as_str() {
                Some(old_pkg) => !new_pkgs.contains(old_pkg),
                None => true,
            };
            if keep {
                let _ = deduped.push(e.clone());
            }
        }
        for e in entries.drain(..) {
            let _ = deduped.push(e);
        }
        let _ = fs::write(FILE, json::stringify_pretty(deduped, 2).as_bytes());
    }

    fn est_load(name: &str) -> i32 {
        if name.contains("Render") || name.contains("Gfx") || name.contains("GL") || name.contains("Vulkan") { return 10; }
        if name.contains("Decode") || name.contains("Codec") || name.contains("Video") || name.contains("Audio") { return 8; }
        if name.contains("Main") || name.contains("Unity") || name.contains("Game")
            || name.contains("Native") || name.contains("RHI") || name.contains("TaskGraph") { return 9; }
        if name.contains("Worker") || name.contains("Thread") || name.contains("Job") { return 5; }
        if name.contains("Io") || name.contains("Network") || name.contains("Http") { return 3; }
        if name.contains("Background") || name.contains("Idle") || name.contains("Pool") { return 1; }
        5
    }
}
