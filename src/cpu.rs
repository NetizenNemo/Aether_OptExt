/// 读取 CPU present 掩码字符串
pub fn present() -> String {
    std::fs::read_to_string("/sys/devices/system/cpu/present")
        .unwrap_or_default().trim().to_string()
}

/// 从唯一的拓扑源 CpuTopology 派生 (大核, 中核高, 中核低, 小核, 拓扑描述)。
/// 此前本函数独立读 sysfs，与 cpuset::detect_core_types() 各写一套逻辑且兜底策略不同：
/// cpufreq 不可用时这里还能给出 big/little 分级、那边却返回空层，导致 auto 分配与
/// 实际绑核行为分叉。现在统一以 init_cpu_topo() 的检测结果为准，消除双份实现。
/// all_tiers 按频率升序（e → … → hp），故最高层是 hp、最低层是 e。
pub fn detect(topo: &crate::cpuset::CpuTopology) -> (String, String, String, String, String) {
    let tiers = &topo.all_tiers;
    if tiers.is_empty() {
        return (topo.present_str.clone(), String::new(), String::new(), topo.present_str.clone(), "1".into());
    }
    let big = tiers.last().unwrap().to_range_string();
    let little = tiers.first().unwrap().to_range_string();
    // 4 层示例 1+2+2+3（升序 e=[0], p1=[1-2], p2=[3-4], hp=[5-7]）：
    // mid1 = 第二层 [1-2]，mid2 = 第三层 [3-4]，与 p_core 合并顺序一致
    let mid1 = if tiers.len() >= 3 { tiers[1].to_range_string() } else { String::new() };
    let mid2 = if tiers.len() >= 4 { tiers[2].to_range_string() } else { String::new() };
    let topo_str = tiers.iter().map(|c| c.count().to_string()).collect::<Vec<_>>().join("+");
    (big, mid1, mid2, little, topo_str)
}

