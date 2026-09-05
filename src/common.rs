use std::sync::OnceLock;

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// BASE_CPUSET 运行时路径，未设置时默认 /dev/cpuset/OptExt
static BASE_CPUSET_PATH: OnceLock<String> = OnceLock::new();

/// 设置 BASE_CPUSET 目录名，name 为空或含 / 时使用默认值
pub fn set_base_cpuset(name: &str) {
    if name.is_empty() || name.contains('/') {
        return;
    }
    let path = format!("/dev/cpuset/{}", name);
    if BASE_CPUSET_PATH.set(path).is_err() {
        crate::warn!("BASE_CPUSET 已设置，忽略重复调用 ({})", name);
    }
}

/// 获取 BASE_CPUSET 路径，未设置返回默认值
pub fn base_cpuset() -> &'static str {
    BASE_CPUSET_PATH
        .get()
        .map(|s| s.as_str())
        .unwrap_or("/dev/cpuset/OptExt")
}

