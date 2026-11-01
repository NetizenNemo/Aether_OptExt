//! λmod —— 基于拉格朗日乘子的绑核目标求解
//!
//! 思路：把"线程分配到哪一层核"建模为带容量约束的效用最大化问题，
//! 用梯度法迭代 λ（各约束的乘子），再由 λ 导出每线程各层的权重与最优层。
//!
//! 与参考实现的关键差异（三处防护，均为踩过的坑）：
//!   1. 拓扑实测：层划分取自 OptExt 的 cpufreq 探测结果，不硬编码 TIER_CORES
//!   2. 在线核裁剪：绑定前经 clip_online()，避免 thermal 下线核导致 EINVAL
//!   3. 最小核数：目标少于 min_cpus 时按 p_core → hp_core 并入，防小核堵死
//!
//! perf_event 不可用（权限/内核不支持）时采集返回 None，调用方维持原目标。

use dashmap::DashMap;
use rayon::prelude::*;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};

// ---- 代价模型常数 ----



const ETA_TIER: f64 = 0.1;


/// LLC / 内存约束的目标值。s[1]/s[2] 归一化为加权平均后量纲为 O(0.1)，
/// 与原 C_LLC=0.05*C_CPU=0.5 不再可比——量纲不匹配会让误差恒为正、
/// λ 单调漂移而无法收敛（实测 λ[1] 两小时从 0.55 涨到 6.6）。

const REF_MISS: f64 = 0.05;
const REF_L2_KB: f64 = 1024.0;
const TEMP: f64 = 0.1;
const FLOAT_EPS: f64 = 1e-12;

/// 观测窗口的兜底上限：单核 L2 未知时按 512KB 估
const DEFAULT_L2_KB: f64 = 512.0;

static PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_RAW: u32 = 4;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 1;
/// x86 Intel 的 LLC 事件编码（PERF_TYPE_RAW）
const X86_LL_CACHE_RD: u64 = 0x0036;
const X86_LL_CACHE_MISS_RD: u64 = 0x0037;
/// aarch64 标准事件号（armv8_pmuv3）
const ARM_L2D_CACHE: u64 = 0x0016;
const ARM_L2D_CACHE_REFILL: u64 = 0x0017;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct perf_event_attr {
    type_: u32, size: u32, config: u64, sample_period: u64, sample_type: u64,
    read_format: u64, disabled: u64, inherit: u64, pinned: u64, exclusive: u64,
    exclude_user: u64, exclude_kernel: u64, exclude_hv: u64, exclude_idle: u64,
    mmap: u64, comm: u64, freq: u64, inherit_stat: u64, enable_on_exec: u64,
    task: u64, watermark: u64, precise_ip: u64, mmap_data: u64, sample_id_all: u64,
    exclude_host: u64, exclude_guest: u64, exclude_callchain_kernel: u64,
    exclude_callchain_user: u64, mmap2: u64, comm_exec: u64, use_clockid: u64,
    context_switch: u64, write_backward: u64, namespaces: u64, ksymbol: u64,
    bpf_event: u64, aux_output: u64, cgroup: u64, text_poke: u64, build_id: u64,
    __reserved_1: u64, __reserved_2: u64, __reserved_3: u64, __reserved_4: u64,
    __reserved_5: u64,
}

fn perf_event_open(attr: &mut perf_event_attr, tid: i32) -> i32 {
    unsafe {
        libc::syscall(libc::SYS_perf_event_open, attr, tid, -1, -1, 0) as i32
    }
}

/// 一层核的静态属性
#[derive(Clone)]
pub struct TierInfo {
    pub cpus: CpuSet,
    pub l2_kb: f64,
    /// 该层占总核数的比例，作为 λ 的容量约束
    pub rho: f64,
}

/// λmod 运行状态
pub struct Lambda {
    tiers: Vec<TierInfo>,
    /// 乘子：0=CPU 总量, 1=LLC, 2=内存, 3..=各层容量
    lambda: Vec<AtomicU64>,
    gamma: AtomicU64,
    nodes: DashMap<i32, Arc<NodeData>>,
    /// 求解结果缓存：tid → 该线程应绑的核集
    targets: DashMap<i32, CpuSet>,
    /// 拥塞感知阻尼状态（跨周期）
    congestion: std::sync::Mutex<Congestion>,
}

/// 跨周期的拥塞度量。signal 越大 → cone 越小 → γ 越小
struct Congestion {
    /// 权重的相对变化率 EWMA
    v_fr: f64,
    /// 约束量与线程数的变化 EWMA
    dz: f64,
    /// 拥塞缩放因子 EWMA
    cone: f64,
    /// 上轮的层分配分布，用于算 v_fr
    prev_tier: Vec<f64>,
    n: usize,
    init: bool,
}

impl Default for Congestion {
    fn default() -> Self {
        Self {
            v_fr: 0.0, dz: 0.0, cone: 1.0,
            prev_tier: Vec::new(),
            n: 0, init: false,
        }
    }
}

struct NodeData {
    c_llc: AtomicU64,
    m_mem: AtomicU64,
    insn_share: AtomicU64,
}

impl NodeData {
    fn new() -> Self {
        Self {
            c_llc: AtomicU64::new(0.001f64.to_bits()),
            m_mem: AtomicU64::new(0.001f64.to_bits()),
            insn_share: AtomicU64::new(0f64.to_bits()),
        }
    }
    fn read(&self) -> (f64, f64, f64) {
        (
            f64::from_bits(self.c_llc.load(Ordering::Relaxed)),
            f64::from_bits(self.m_mem.load(Ordering::Relaxed)),
            f64::from_bits(self.insn_share.load(Ordering::Relaxed)),
        )
    }
}

impl Lambda {
    /// 依据实测拓扑构建层信息。层序：e_core → p_core → hp_core（低性能在前）
    pub fn new(topo: &CpuTopology) -> Option<Self> {
        let online = topo.online_cpus_public();
        // 按实测的完整频率层构建（2+2+4 等 4 层架构不被压成 3 层）。
        // 顶层给更大 L2 估值，使 sens 项对高性能层形成正确偏好
        let n_tiers = topo.all_tiers.len();
        let mut raw: Vec<(CpuSet, f64)> = Vec::new();
        for (i, set) in topo.all_tiers.iter().enumerate() {
            let c = set.intersection(&online);
            if c.count() == 0 { continue; }
            let l2 = if n_tiers > 1 && i == n_tiers - 1 { 1024.0 } else { DEFAULT_L2_KB };
            raw.push((c, l2));
        }
        if raw.len() < 2 { return None; } // 单层设备无分配意义

        let total: f64 = raw.iter().map(|(c, _)| c.count() as f64).sum();
        if total <= 0.0 { return None; }

        let tiers: Vec<TierInfo> = raw.into_iter().map(|(cpus, l2)| {
            let rho = cpus.count() as f64 / total;
            TierInfo { cpus, l2_kb: l2, rho }
        }).collect();

        let m = tiers.len();
        // 层容量乘子给非零初值：λ 全零会使各层 π 相等、softmax 退化为均匀分布。
        // 初值使 sens 项生效 —— 高层 L2 大 → pressure 小 → sens 小 → π 小 →
        // 对重线程形成正确偏好，随后由梯度法自行校正
        let lambda = (0..m).map(|_| AtomicU64::new(1.0_f64.to_bits())).collect();
        Some(Self {
            tiers,
            lambda,
            gamma: AtomicU64::new(1.0f64.to_bits()),
            nodes: DashMap::new(),
            targets: DashMap::new(),
            congestion: std::sync::Mutex::new(Congestion::default()),
        })
    }

    pub fn num_tiers(&self) -> usize { self.tiers.len() }
    fn m(&self) -> usize { self.tiers.len() }

    fn read_lambda(&self, r: usize) -> f64 { f64::from_bits(self.lambda[r].load(Ordering::Relaxed)) }
    fn write_lambda(&self, r: usize, v: f64) { self.lambda[r].store(v.to_bits(), Ordering::Release); }

    /// 各层的容量配额 = 该层核数占总核数的比例
    fn capacity(&self, r: usize) -> f64 {
        self.tiers.get(r).map(|t| t.rho).unwrap_or(0.0)
    }

    fn eta(&self, _r: usize) -> f64 { ETA_TIER }

    /// 迭代一次 λ 并返回各约束的当前累积量
    fn step_lambdas(&self, s: &[f64]) {
        let gamma = f64::from_bits(self.gamma.load(Ordering::Acquire));
        (0..self.m()).into_par_iter().for_each(|r| {
            let cap = self.capacity(r);
            let err = s[r] - cap;
            let new = (self.read_lambda(r) + gamma * self.eta(r) * err).max(0.0);
            self.write_lambda(r, new);
        });
    }

    /// 单线程：各层权重与最优层
    fn thread_w(&self, lambdas: &[f64], c_llc: f64, m_mem: f64, insn_share: f64)
        -> (f64, Vec<f64>, usize)
    {
        let k = self.tiers.len();
        let mut pi = Vec::with_capacity(k);
        // π 只保留「随层变化」的项。λ[0] + λ[1]·c_llc + λ[2]·m_mem 对所有层是
        // 同一个常数，而 softmax 具有平移不变性 —— 它们对层选择零影响，却因
        // 约束量 s 与层分配解耦而无反馈地单调漂移（实测 λ[1] 1h23min 从 0.002
        // 涨到 0.663 且无回落）。只有 λ[kk]·sens_kk 因 cap_kb 随层变化而真正驱动分配。
        let _ = m_mem;
        for (kk, t) in self.tiers.iter().enumerate() {
            let cap_kb = t.l2_kb.max(64.0);
            let pressure = (insn_share * c_llc) / cap_kb;
            let ref_pressure = REF_MISS / REF_L2_KB;
            let sens = (1.0 + pressure / ref_pressure).max(1.0);
            pi.push(lambdas[kk] * sens);
        }
        let min_pi = pi.iter().cloned().fold(f64::MAX, f64::min);
        let t_safe = TEMP.max(1e-6);
        let mut probs = Vec::with_capacity(k);
        let mut exp_sum = 0.0;
        let mut best_k = 0usize;
        let mut best_p = -1.0f64;
        for (kk, &p) in pi.iter().enumerate() {
            let e = (-(p - min_pi) / t_safe).exp();
            probs.push(e);
            exp_sum += e;
            if e > best_p { best_p = e; best_k = kk; }
        }
        for p in probs.iter_mut() { *p /= exp_sum; }
        // free energy：LSE 形式为 -T·ln(Σexp(-π/T))，其负值即 log-sum-exp 下界。
        // 权重取 w = exp(-pi_lse) —— 负号不可省：漏掉会写成 exp(+pi_lse)，
        // π 为大正数时指数爆炸，s[0]=Σw 发散并正反馈到 λ[0]，最终 inf/NaN。
        // （原先因 s[0]≡1.0 恒小于 cap[0]、λ[0] 被永久钳零而掩盖了此错误）
        let pi_lse = min_pi - t_safe * exp_sum.ln();
        let w = (-pi_lse).exp();
        (w, probs, best_k)
    }

    /// 全网求解：返回 (每 tid 的最优层, 各约束累积量)
    /// 累积量按 argmax 累加 —— 与实际分配一致，避免 λ 依据错误分布收敛
    pub fn solve(&self) -> (Vec<(i32, usize)>, Vec<f64>) {
        let k = self.tiers.len();
        let m = self.m();
        let lambdas: Vec<f64> = (0..m).map(|r| self.read_lambda(r)).collect();

        let snap: Vec<(i32, f64, f64, f64)> = self.nodes.iter()
            .map(|e| { let (c, mm, ins) = e.value().read(); (*e.key(), c, mm, ins) })
            .collect();

        // 采样轮次作 salt：每轮重新采样，使时间平均收敛到 probs
        static SALT: AtomicU64 = AtomicU64::new(0);
        let salt = SALT.fetch_add(1, Ordering::Relaxed).wrapping_mul(0x2545F4914F6CDD1D);

        let (mut s, assign): (Vec<f64>, Vec<(i32, usize)>) = snap.par_iter()
            .fold(
                || (vec![0.0f64; m], Vec::new()),
                |(mut s, mut a), &(tid, c, mm, ins)| {
                    let (_w, probs, _best) = self.thread_w(&lambdas, c, mm, ins);
                    // s[kk] 是各层的「线程数占比」，与 rho[k] 同量纲。
                    // 它不能按指令量加权 —— cap 定义为核心数比例，按线程数配平才可收敛
                    for kk in 0..k {
                        s[kk] += probs[kk];
                    }
                    let tier = pick_tier(tid, &probs, salt);
                    a.push((tid, tier));
                    (s, a)
                },
            )
            .reduce(
                || (vec![0.0f64; m], Vec::new()),
                |(mut a, mut la), (b, mut lb)| {
                    for i in 0..m { a[i] += b[i]; }
                    la.append(&mut lb);
                    (a, la)
                },
            );

        // 归一化为占比，消去线程数带来的线性增长（否则 s 随 N 线性增长，
        // 误差恒为正、λ 只能单调上升）
        let n = snap.len().max(1) as f64;
        for kk in 0..k {
            s[kk] /= n;
        }
        let _ = k;
        (assign, s)
    }

    /// 用 solve 的累积量推进 λ 与 gamma
    pub fn advance(&self, s: &[f64]) -> f64 {
        // 误差统计（先算，供 boost 使用）。
        // 只统计层容量约束 s[3..]/rho —— 三者已统一为「占比」量纲。
        // s[0] 是权重和（量级随线程数变化），纳入会让 err 被常数偏差主导
        let mut max_rel = 0.0f64;
        for kk in 0..self.tiers.len() {
            let cap = self.capacity(kk).max(FLOAT_EPS);
            let rel = (s[kk] - cap).abs() / cap;
            if rel > max_rel { max_rel = rel; }
        }

        // 拥塞感知阻尼：系统变化剧烈时压低学习率。
        // 缺失时 γ 峰值达 8（误差 26 时单步 Δλ≈21）→ 必然过冲，
        // 表现为 λ 在约束间反复拉扯、长时间不收敛。
        let gamma = {
            let mut cg = self.congestion.lock().unwrap_or_else(|p| p.into_inner());
            // v_fr：层分配分布的相对变化率（相邻周期 s[3..] 的归一化变化）。
            // 原参考实现用权重向量的变化率，等价性上此处用分配分布更直接，
            // 且无需跨周期保存每线程权重
            let v_fr = if cg.prev_tier.len() == self.tiers.len() {
                let mut sq = 0.0f64;
                for kk in 0..self.tiers.len() {
                    let a = s[kk];
                    let b = cg.prev_tier[kk];
                    let avg = ((a + b) / 2.0).max(FLOAT_EPS);
                    let d = a - b;
                    sq += d * d / avg;
                }
                sq.sqrt()
            } else { 0.0 };
            cg.prev_tier = s.to_vec();
            // dz：约束量变化 + 线程数变化率
            let dn = if cg.init && cg.n > 0 {
                (self.nodes.len() as f64 - cg.n as f64).abs() / cg.n as f64
            } else { 0.0 };
            let dz = if cg.init {
                v_fr + DN_WEIGHT * dn
            } else { 0.0 };
            cg.n = self.nodes.len();
            cg.init = true;

            cg.v_fr = (1.0 - V_FR_EWMA) * cg.v_fr + V_FR_EWMA * v_fr;
            cg.dz = (1.0 - DZ_EWMA) * cg.dz + DZ_EWMA * dz;

            let signal = cg.v_fr.max(cg.dz * DZ_WEIGHT);
            let cone_base = (1.0 / (1.0 + CONGESTION_BETA * signal))
                .clamp(CONE_SCALE_MIN, CONE_SCALE_MAX);
            cg.cone = (1.0 - CONE_EWMA) * cg.cone + CONE_EWMA * cone_base;

            // cone ≤ 1 起阻尼作用；boost 提供有限加速；总上限 2.0 防过冲
            let boost = 1.0 + max_rel.min(1.0);
            (cg.cone * boost).clamp(0.05, 2.0)
        };

        self.step_lambdas(s);
        self.gamma.store(gamma.to_bits(), Ordering::Release);
        max_rel
    }

    /// 层 → 绑核目标。
    /// 防护：按在线核裁剪；核数不足 min_cpus 时并入更高层（不越过目标层向上扩）
    pub fn tier_target(&self, tier: usize, topo: &CpuTopology, min_cpus: usize) -> CpuSet {
        let online = topo.online_cpus_public();
        let mut out = self.tiers
            .get(tier)
            .map(|t| t.cpus.intersection(&online))
            .unwrap_or_default();
        // 仅当存在更高层可并入时才做 min_cpus 扩容。
        // 最高性能层通常只有 2 核（如 2+2+4 的 6-7、6+2 的 6-7），若强扩到
        // min_cpus 会并成全核，等于放弃绑定；且该层是性能核，2 核本身合理。
        let is_top = tier + 1 >= self.tiers.len();
        if !is_top {
            let mut idx = tier;
            while out.count() < min_cpus && idx + 1 < self.tiers.len() {
                idx += 1;
                out.or(&self.tiers[idx].cpus.intersection(&online));
            }
            if out.count() < min_cpus {
                out.or(&online);
            }
        }
        out.intersection(&online)
    }

    /// 采样并写入线程指标。insn 为窗口内新增指令数
    pub fn observe(&self, tid: i32, c_llc: f64, m_mem: f64, insn_share: f64) {
        let nd = self.nodes.entry(tid).or_insert_with(|| Arc::new(NodeData::new()));
        nd.c_llc.store(c_llc.to_bits(), Ordering::Relaxed);
        nd.m_mem.store(m_mem.to_bits(), Ordering::Relaxed);
        nd.insn_share.store(insn_share.to_bits(), Ordering::Relaxed);
    }

    /// 清理非活跃线程的采样数据。
    /// 必须与 targets 同步清理：insn_share 按每批采样归一化（Σ=1），
    /// 若 nodes 累积多批，solve() 的 s 会叠加成 >1，λ 收到虚高误差而震荡不收敛
    pub fn retain_nodes(&self, keep: &std::collections::HashSet<i32>) {
        self.nodes.retain(|k, _| keep.contains(k));
    }

    pub fn set_target(&self, tid: i32, t: CpuSet) { self.targets.insert(tid, t); }
    pub fn get_target(&self, tid: i32) -> Option<CpuSet> { self.targets.get(&tid).map(|v| *v) }
    pub fn retain_targets(&self, keep: &std::collections::HashSet<i32>) {
        self.targets.retain(|k, _| keep.contains(k));
    }

}

/// 按 probs 随机选层（Monte Carlo）。
/// 硬 argmax 只能整层选一个，无法表达 rho=0.75/0.25 这类中间分布，
/// 会导致 λ 在两极间过冲震荡；按概率采样则时间平均等于 probs，可收敛。
/// 用 tid + salt 派生的 splitmix 序列，避免引入额外随机数依赖。
fn pick_tier(tid: i32, probs: &[f64], salt: u64) -> usize {
    if probs.is_empty() { return 0; }
    let mut x = (tid as u64).wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(salt);
    x ^= x >> 30; x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27; x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    let r = (x >> 11) as f64 / ((1u64 << 53) as f64);
    let mut acc = 0.0;
    for (i, p) in probs.iter().enumerate() {
        acc += p;
        if r < acc { return i; }
    }
    probs.len() - 1
}

// ============================================================
// perf_event 采集
// ============================================================
/// 每线程的 perf 计数器句柄。
/// 只保留 4 个真正参与计算的计数器——原先还有一个 CONTEXT_SWITCHES，
/// 但它的增量算出后即被丢弃（`let _ =`），纯粹浪费一个 fd。
pub(crate) struct Handles {
    insn: i32, cycles: i32, llc: i32, miss: i32,
    last_insn: u64, last_cycles: u64, last_llc: u64, last_miss: u64,
    /// /proc/{tid}/stat 的 utime+stime，用于免 fd 预筛选
    last_ticks: u64,
    /// ticks 基准是否已建立
    ticks_valid: bool,
    /// 连续空闲（tick 无增量）轮次
    idle_rounds: u8,
}

/// 每线程占用的 fd 数，用于 fd 预算估算
pub(crate) const FDS_PER_THREAD: usize = 4;

// ---- 拥塞感知阻尼：抑制 λ 振荡 ----
// 系统变化剧烈时降低学习率 γ，避免过冲。缺失时 λ 会随线程数/负载波动
// 无界漂移（实测 λ[1] 两小时 0.55→6.6 未收敛）。
const CONGESTION_BETA: f64 = 1.0;
const V_FR_EWMA: f64 = 0.3;
const DZ_EWMA: f64 = 0.3;
const CONE_EWMA: f64 = 0.4;
const CONE_SCALE_MIN: f64 = 0.15;
const CONE_SCALE_MAX: f64 = 1.00;
const DZ_WEIGHT: f64 = 5.0;
/// 线程数变化在 dz 中的权重
const DN_WEIGHT: f64 = 1.0;

/// 连续空闲多少轮后回收 fd。
/// /proc/{tid}/stat 的 tick 粒度是 10ms，而采样间隔约 33s，中等活跃线程
/// 常有整轮无 tick 增量的情况。阈值取 2 时实测 2 小时回收 56432 次
/// （held 仅数百），fd 反复 open/close，每次最多 7 次 perf_event_open，
/// 系统调用开销远超收益。取 6 轮（约 3 分钟）可显著抑制抖动。
/// 实测受控 2730 线程时 perf_fd 达 13268（软上限 32768 的 41%），
/// 线程数再增长会逼近上限。取 10 轮（λmod 已降频到 3 轮采样，约 3 分钟空闲）
/// 在「fd 峰值」与「open/close 抖动」之间折中
const IDLE_RECLAIM_ROUNDS: u8 = 10;

impl Handles {
    pub(crate) fn new() -> Self {
        Self {
            insn: -1, cycles: -1, llc: -1, miss: -1,
            last_insn: 0, last_cycles: 0, last_llc: 0, last_miss: 0,
            last_ticks: 0, ticks_valid: false, idle_rounds: 0,
        }
    }

    fn is_open(&self) -> bool { self.insn >= 0 }

    /// 打开 4 个计数器。首轮只校准基准，避免把历史累计值当成增量
    fn open_fds(&mut self, tid: i32) {
        self.insn = open_hw(tid, PERF_COUNT_HW_INSTRUCTIONS);
        self.cycles = open_hw(tid, PERF_COUNT_HW_CPU_CYCLES);
        let (l, m) = open_llc(tid);
        self.llc = l; self.miss = m;
        if self.insn >= 0 { self.last_insn = read_u64(self.insn).unwrap_or(0); }
        if self.cycles >= 0 { self.last_cycles = read_u64(self.cycles).unwrap_or(0); }
        if let Some((l, m)) = read_pair(self.llc, self.miss) { self.last_llc = l; self.last_miss = m; }
        self.idle_rounds = 0;
    }

    fn close_fds(&mut self) {
        for fd in [self.insn, self.cycles, self.llc, self.miss] {
            if fd >= 0 { unsafe { libc::close(fd); } }
        }
        self.insn = -1; self.cycles = -1; self.llc = -1; self.miss = -1;
    }

    /// 标记本轮空闲；连续 IDLE_RECLAIM_ROUNDS 轮后回收 fd
    fn mark_idle(&mut self, ticks: u64) {
        self.last_ticks = ticks;
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if self.idle_rounds >= IDLE_RECLAIM_ROUNDS && self.is_open() {
            self.close_fds();
        }
    }

    /// 返回 (c_llc, m_mem, delta_insn)；指令计数不可用返回 None
    fn sample(&mut self) -> Option<(f64, f64, u64)> {
        if self.insn < 0 { return None; }
        let insn = read_u64(self.insn)?;
        let cycles = read_u64(self.cycles).unwrap_or(0);
        let (llc, miss) = read_pair(self.llc, self.miss).unwrap_or((0, 0));

        let d_insn = insn.saturating_sub(self.last_insn);
        let d_cycles = cycles.saturating_sub(self.last_cycles);
        let d_llc = llc.saturating_sub(self.last_llc);
        let d_miss = miss.saturating_sub(self.last_miss);

        self.last_insn = insn; self.last_cycles = cycles;
        self.last_llc = llc; self.last_miss = miss;

        if d_insn == 0 { return None; }
        // c_llc = LLC 访问中的 miss 率；m_mem = miss 率 × CPI，反映内存墙程度
        let c_llc = if d_llc > 0 { (d_miss as f64 / d_llc as f64).min(1.0) } else { 0.001 };
        let cpi = if d_insn > 0 { (d_cycles as f64 / d_insn as f64).max(0.1) } else { 1.0 };
        let m_mem = (c_llc * cpi).max(0.001);
        Some((c_llc, m_mem, d_insn))
    }
}

fn open_hw(tid: i32, config: u64) -> i32 {
    let mut attr: perf_event_attr = unsafe { mem::zeroed() };
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_HARDWARE; attr.config = config; attr.exclude_hv = 1;
    let fd = perf_event_open(&mut attr, tid);
    if fd >= 0 { unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE as i32, 0); } return fd; }
    // 权限受限时退回仅统计用户态
    attr.exclude_kernel = 1;
    let fd2 = perf_event_open(&mut attr, tid);
    if fd2 >= 0 { unsafe { libc::ioctl(fd2, PERF_EVENT_IOC_ENABLE as i32, 0); } }
    fd2
}

fn open_llc(tid: i32) -> (i32, i32) {
    let ty = pmu_type();
    let (ev_rd, ev_miss) = cache_events();
    let one = |config: u64, ex_k: u64| -> i32 {
        let mut attr: perf_event_attr = unsafe { mem::zeroed() };
        attr.size = mem::size_of::<perf_event_attr>() as u32;
        attr.type_ = ty; attr.config = config; attr.disabled = 1;
        attr.exclude_hv = 1; attr.exclude_kernel = ex_k;
        let fd = perf_event_open(&mut attr, tid);
        if fd < 0 { return -1; }
        if unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE as i32, 0) } == -1 {
            unsafe { libc::close(fd); }
            return -1;
        }
        fd
    };
    let a = one(ev_rd, 0);
    let m = one(ev_miss, 0);
    if a >= 0 && m >= 0 { return (a, m); }
    if a >= 0 { unsafe { libc::close(a); } }
    if m >= 0 { unsafe { libc::close(m); } }
    let a2 = one(ev_rd, 1);
    let m2 = one(ev_miss, 1);
    if a2 >= 0 && m2 >= 0 { return (a2, m2); }
    if a2 >= 0 { unsafe { libc::close(a2); } }
    if m2 >= 0 { unsafe { libc::close(m2); } }
    (-1, -1)
}

fn read_u64(fd: i32) -> Option<u64> {
    if fd < 0 { return None; }
    let mut v: u64 = 0;
    let r = unsafe { libc::read(fd, &mut v as *mut u64 as *mut libc::c_void, 8) };
    if r == 8 { Some(v) } else { None }
}

fn read_pair(a: i32, m: i32) -> Option<(u64, u64)> {
    if a < 0 || m < 0 { return None; }
    let mut va: u64 = 0;
    let mut vm: u64 = 0;
    unsafe {
        if libc::read(a, &mut va as *mut u64 as *mut libc::c_void, 8) != 8 { return None; }
        if libc::read(m, &mut vm as *mut u64 as *mut libc::c_void, 8) != 8 { return None; }
    }
    Some((va, vm))
}

/// 缓存事件源类型。aarch64 走 armv8_pmuv3（type 通常为 10），x86 走
/// PERF_TYPE_RAW。读不到时回退 RAW —— 原先固定用 PERF_TYPE_RAW + 0x36/0x37
/// 是 x86 编码，在 aarch64 上 open 必然失败，导致 c_llc 恒为 fallback 常量、
/// λ[1]/λ[2] 永久钳零，λmod 丢失全部缓存感知能力。
static PMU_TYPE: AtomicU64 = AtomicU64::new(0);

fn pmu_type() -> u32 {
    let cached = PMU_TYPE.load(Ordering::Relaxed);
    if cached != 0 { return cached as u32; }
    let t = std::fs::read_to_string("/sys/bus/event_source/devices/armv8_pmuv3/type")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(PERF_TYPE_RAW as u64);
    PMU_TYPE.store(t, Ordering::Relaxed);
    t as u32
}

/// 从 sysfs 读事件编码（如 l2d_cache -> event=0x0016），读不到用默认值
fn pmu_event(name: &str, fallback: u64) -> u64 {
    let path = format!("/sys/bus/event_source/devices/armv8_pmuv3/events/{}", name);
    std::fs::read_to_string(path).ok()
        .and_then(|s| {
            s.split_whitespace()
                .find_map(|kv| kv.strip_prefix("event=").map(|v| v.to_string()))
        })
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(fallback)
}

/// 缓存事件对 (访问, miss)。按事件源类型选 ARM 或 x86 编码
fn cache_events() -> (u64, u64) {
    if pmu_type() == PERF_TYPE_RAW {
        (X86_LL_CACHE_RD, X86_LL_CACHE_MISS_RD)
    } else {
        (pmu_event("l2d_cache", ARM_L2D_CACHE),
         pmu_event("l2d_cache_refill", ARM_L2D_CACHE_REFILL))
    }
}

/// perf_event 是否可用于本进程（快速探测，避免每周期无效开 fd）。
/// 同时检查 fd 软上限：每线程 FDS_PER_THREAD 个 fd，大核数设备上
/// 线程多时可能逼近 RLIMIT_NOFILE（实测 2541 线程 → 11520 fd，
/// 软上限 32768 的 35%），余量不足时直接不启用，避免中途 EMFILE
pub fn perf_available() -> bool {
    let tid = unsafe { libc::getpid() } as i32;
    let fd = open_hw(tid, PERF_COUNT_HW_INSTRUCTIONS);
    if fd < 0 { return false; }
    unsafe { libc::close(fd); }

    // fd 预算：预留 1/4 给其它用途
    let mut lim: libc::rlimit = unsafe { mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        let budget = (lim.rlim_cur as usize).saturating_mul(3) / 4;
        if budget < FDS_PER_THREAD * 64 {
            crate::warn!("λmod: fd budget too small ({}), skipped", budget);
            return false;
        }
    }
    true
}

/// 采集一批线程的指标并写入 λmod。
/// 返回**成功采样**的 tid 列表；空表示 perf 不可用或全部无增量，调用方应维持原状
pub fn sample_tids(lm: &Lambda, tids: &[i32], handles: &mut std::collections::HashMap<i32, Handles>) -> Vec<i32> {
    // 清理已退出线程的 fd。用集合查找，避免 retain 内线性 contains 的 O(n*m)
    let alive: std::collections::HashSet<i32> = tids.iter().copied().collect();
    handles.retain(|tid, h| {
        if alive.contains(tid) { true } else { h.close_fds(); false }
    });

    let mut measured: Vec<(i32, f64, f64, u64)> = Vec::new();
    let mut total_insn: u64 = 0;
    for &tid in tids {
        let h = handles.entry(tid).or_insert_with(Handles::new);
        // 免 fd 预筛选：用 /proc/{tid}/stat 的 tick 判断本轮是否消耗过 CPU。
        // 空闲线程不开 perf fd —— 实测 903 个持句柄线程中仅 56 个有指令增量，
        // fd 几乎全被空闲线程占着（3612 个中约 94% 属白占）。
        match crate::process::read_thread_cpu_time(tid) {
            Some(t) if h.ticks_valid && t == h.last_ticks => {
                h.mark_idle(t);
                continue;
            }
            Some(t) => {
                h.last_ticks = t;
                h.ticks_valid = true;
                h.idle_rounds = 0;
            }
            None => {
                // 线程退出或不可读，释放 fd 并等待上层清理条目
                h.close_fds();
                continue;
            }
        }
        if !h.is_open() { h.open_fds(tid); }
        if let Some((c, m, d)) = h.sample() {
            total_insn = total_insn.saturating_add(d);
            measured.push((tid, c, m, d));
        }
    }
    if measured.is_empty() { return Vec::new(); }
    let inv = if total_insn > 0 { 1.0 / total_insn as f64 } else { 0.0 };
    for (tid, c, m, d) in &measured {
        lm.observe(*tid, *c, *m, (*d as f64) * inv);
    }
    measured.into_iter().map(|(t, _, _, _)| t).collect()
}

// ============================================================
// 全局入口：主循环周期性 tick，adjust_target 查询结果
// ============================================================
static GLOBAL: std::sync::OnceLock<Lambda> = std::sync::OnceLock::new();
static SAMPLER: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<i32, Handles>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 初始化。返回 false 表示未启用或 perf_event 不可用（调用方回退既有策略）
pub fn init(topo: &CpuTopology, enable: bool) -> bool {
    if !enable { return false; }
    if !perf_available() {
        crate::warn!("λmod: perf_event unavailable, fallback to tick heuristic");
        return false;
    }
    match Lambda::new(topo) {
        Some(lm) => {
            let k = lm.num_tiers();
            let ok = GLOBAL.set(lm).is_ok();
            if ok { crate::info!("λmod: enabled, {} tiers", k); }
            ok
        }
        None => {
            crate::warn!("λmod: topology has <2 tiers, skipped");
            false
        }
    }
}

pub fn active() -> bool { GLOBAL.get().is_some() }

/// 周期性推进：采样 → 求解 → 推进 λ → 刷新目标缓存。返回采样到的线程数
pub fn tick(tids: &[i32], cfg: &AppConfig) -> usize {
    let Some(lm) = GLOBAL.get() else { return 0 };
    let sampled = {
        let mut h = SAMPLER.lock().unwrap_or_else(|p| p.into_inner());
        sample_tids(lm, tids, &mut h)
    };
    let n = sampled.len();
    if n == 0 { return 0; }

    // 只保留本轮成功采样的线程：nodes 与 targets 必须同步清理，
    // 否则 insn_share 的多批归一化值会叠加，破坏 λ 的约束量语义
    let keep: std::collections::HashSet<i32> = sampled.iter().copied().collect();
    lm.retain_nodes(&keep);
    lm.retain_targets(&keep);

    let (assign, _s) = lm.solve();
    lm.advance(&_s);

    // 目标缓存同步
    for (tid, tier) in &assign {
        let t = lm.tier_target(*tier, &cfg.topo, cfg.min_cpus);
        lm.set_target(*tid, t);
    }
    n
}

/// 查询某线程的 λ 求解目标
pub fn target_for(tid: i32) -> Option<CpuSet> {
    GLOBAL.get()?.get_target(tid)
}
