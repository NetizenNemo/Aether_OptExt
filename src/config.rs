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
    pub prio: i32,
}

#[derive(Clone)]
pub struct AppConfig {
    pub rules: Vec<Rule>,
    pub pkg_set: HashSet<String>,
    pub wild: Vec<String>,
    pub mtime: SystemTime,
    pub ebpf: bool,
}

impl AppConfig {
    pub fn load(path: &str) -> Option<Self> {
        let data = fs::read_to_string(path).ok()?;
        let root = json::parse(&data).ok()?;
        let ebpf = root["features"]["ebpf"].as_bool().unwrap_or(true);
        let entries = if root.is_array() { &root } else { &root["rules"] };
        if !entries.is_array() { return None; }

        let mut rules = Vec::new();
        let mut pkg_set = HashSet::new();
        let mut wild = Vec::new();

        for e in entries.members() {
            let pl: Vec<String> = e["packages"].members()
                .filter_map(|v| v.as_str().map(String::from)).collect();
            if pl.is_empty() { continue; }
            let other = e["cpuset"]["other"].as_str().unwrap_or("0");
            let def = pl[0].clone();

            for pk in &pl {
                pkg_set.insert(pk.clone());
                if pk.contains('*') || pk.contains('?') { wild.push(pk.clone()); }
            }

            rules.push(Rule { pkg: def.clone(), thread: String::new(), cpus: other.to_string(), prio: 200 });

            if e["cpuset"]["comm"].is_object() {
                for (cpus, names) in e["cpuset"]["comm"].entries() {
                    for nv in names.members() {
                        if let Some(name) = nv.as_str() {
                            rules.push(Rule {
                                pkg: def.clone(),
                                thread: name.to_string(),
                                cpus: cpus.to_string(),
                                prio: rule_prio(name),
                            });
                        }
                    }
                }
            }
        }

        let mt = fs::metadata(path).ok()?.modified().ok()?;
        Some(AppConfig { rules, pkg_set, wild, mtime: mt, ebpf })
    }
}

pub mod cache {
    use std::{collections::HashSet, fs};
    use super::{Rule, fnmatch};

    const FILE: &str = "/sdcard/Android/Aether/threads_cache";

    pub fn merge(set: &mut HashSet<String>, rules: &mut Vec<Rule>) {
        let data = match fs::read_to_string(FILE) { Ok(x) => x, Err(_) => return };
        let root = match json::parse(&data) { Ok(x) => x, Err(_) => return };
        if !root.is_array() { return; }
        for entry in root.members() {
            let pl: Vec<String> = entry["packages"].members()
                .filter_map(|v| v.as_str().map(String::from)).collect();
            if pl.is_empty() { continue; }
            let other = entry["cpuset"]["other"].as_str().unwrap_or("0");
            for pk in &pl { set.insert(pk.clone()); }
            rules.push(Rule { pkg: pl[0].clone(), thread: String::new(), cpus: other.to_string(), prio: 200 });
            if entry["cpuset"]["comm"].is_object() {
                for (cpus, names) in entry["cpuset"]["comm"].entries() {
                    for nv in names.members() {
                        if let Some(name) = nv.as_str() {
                            let p = if !name.contains('*') && !name.contains('?') { 1000 + name.len() as i32 }
                                    else { 100 + name.chars().filter(|c| *c != '*').count() as i32 };
                            rules.push(Rule { pkg: pl[0].clone(), thread: name.to_string(), cpus: cpus.to_string(), prio: p });
                        }
                    }
                }
            }
        }
        info!("已加载 {} 条缓存", root.members().count());
    }

    pub fn save(pkg: &str, all: &[(i32, String, Vec<(i32, String)>)], big: &str, little: &str) {
        // 只过滤特定系统服务，不过滤全部 MIUI/Xiaomi
        if pkg.ends_with(":widgetProvider") || pkg.ends_with(":searchDataService")
            || pkg.ends_with(":coreService") || pkg.ends_with(":cognitionService")
            || pkg.ends_with(":bert") || pkg.ends_with(":bertAlgo")
            || pkg.ends_with(":privacy") || pkg.ends_with(":kit7")
            || pkg.ends_with(":services") || pkg.ends_with(":daemon")
            || pkg == "android.process.media" || pkg == "android.process.acore"
            || pkg.starts_with("com.qualcomm.") || pkg.starts_with(".qti")
            || pkg.starts_with(".qms") || pkg.starts_with(".cacert")
            || pkg.starts_with(".dataservices") { return; }
        let mut big_names = Vec::new();
        let mut lil_names = Vec::new();
        for (_, n, th) in all.iter().filter(|(_, n, _)| n == pkg) {
            for (_, comm) in th {
                let load = est_load(comm);
                if load >= 8 { big_names.push(comm.clone()); }
                else { lil_names.push(comm.clone()); }
                if comm.contains("Render") || comm.contains("Codec") || comm.contains("Audio") {
                    info!("save: {} load={} -> {} (big={} little={})", comm, load,
                        if load>=8{"big"}else{"lil"}, big, little);
                }
            }
        }

        let mut comm_map: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
        for n in &big_names { comm_map.entry(big).or_default().push(n); }

        let comm_json = if big_names.is_empty() { String::new() } else {
            let parts: Vec<String> = comm_map.iter().map(|(c, ns)| {
                let arr = ns.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(",\n        ");
                format!("        \"{}\": [\n        {}\n        ]", c, arr)
            }).collect();
            format!(",\n      \"comm\": {{\n{}\n      }}", parts.join(",\n"))
        };

        let entry = format!(
            "  {{\n    \"friendly\": \"[auto] {}\",\n    \"packages\": [\"{}\"],\n    \"cpuset\": {{\n      \"other\": \"{}\"{}\n    }}\n  }}",
            pkg, pkg, little, comm_json
        );

        let _ = fs::create_dir_all("/sdcard/Android/Aether");
        let old = fs::read_to_string(FILE).unwrap_or_default();
        let new = if old.trim().is_empty() || !old.trim_start().starts_with('[') {
            format!("[\n{}\n]\n", entry)
        } else {
            let t = old.trim_end();
            let ins = if t.ends_with(']') { &t[..t.len()-1] } else { t };
            format!("{},\n{}\n]\n", ins.trim_end(), entry)
        };
        let _ = fs::write(FILE, new.as_bytes());
    }

    fn est_load(name: &str) -> i32 {
        info!("est_load: {} -> {}", name, if name.contains("Render")||name.contains("Gfx")||name.contains("GL")||name.contains("Vulkan") {10} else if name.contains("Decode")||name.contains("Codec")||name.contains("Video")||name.contains("Audio") {8} else if name.contains("Main")||name.contains("Unity")||name.contains("Game") {9} else if name.contains("Worker")||name.contains("Thread")||name.contains("Job") {5} else if name.contains("Io")||name.contains("Network")||name.contains("Http") {3} else if name.contains("Background")||name.contains("Idle")||name.contains("Pool") {1} else {4});
        if name.contains("Render") || name.contains("Gfx") || name.contains("GL") || name.contains("Vulkan") { return 10; }
        if name.contains("Decode") || name.contains("Codec") || name.contains("Video") || name.contains("Audio") { return 8; }
        if name.contains("Main") || name.contains("Unity") || name.contains("Game") { return 9; }
        if name.contains("Worker") || name.contains("Thread") || name.contains("Job") { return 5; }
        if name.contains("Io") || name.contains("Network") || name.contains("Http") { return 3; }
        if name.contains("Background") || name.contains("Idle") || name.contains("Pool") { return 1; }
        4
    }
}
