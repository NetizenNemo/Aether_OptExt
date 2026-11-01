# Aether OptExt

Android 应用/游戏线程 CPU 亲和性优化工具，以 Magisk/KernelSU 模块形式运行。

## 作者OS
总的来说，这是本人的第二个开源的RUST作品吧，也是一个极具我个人风格的作品呢
emm...艇长猫猫还是很喜欢大家的使用哒～使用艇长是俺的荣幸哦～
项目会不断更新，有啥问题可以去issues(虽然猫猫不咋看啦)提交，不过最好的方法还是直接去俺群里把俺艾特出来～千万不要直接骂艇长唔，猫猫很怕凶的(哭哭)
猫猫虽然平时很深情，但代码是认真的！请见俺的README～

=======
## 环境要求

### 设备端

| 要求 | 说明 |
|:---|:---|
| 系统 | Android 8.0+（内核需支持 cpuset，一般均满足） |
| 权限 | Magisk 或 KernelSU root |
| 内核（可选） | eBPF 加速需 `CONFIG_BPF_SYSCALL` / `CONFIG_BPF_EVENTS`，tracefs 需挂载；不支持自动回退 proc 轮询。λmod 求解器需 `CONFIG_PERF_EVENTS` 且 `perf_event_paranoid` 允许访问，不可用自动回退 `load_aware` |

### 构建端（Windows 示例）

| 依赖 | 用途 | 说明 |
|:---|:---|:---|
| Python 3 | 构建脚本 | `python build.py` 一键编译打包 |
| Rust stable | 主程序编译 | 需 `rustup target add aarch64-linux-android` |
| Android NDK | 交叉链接 | 自动检测 `$ANDROID_NDK_HOME` / `$ANDROID_HOME` |
| WSL (Ubuntu) + Rust nightly | 仅当需重编译 eBPF 程序 | 见下方"重编译 eBPF" |
| Android clang19 | 仅当需重编译 eBPF 程序 | 提供 LLVM 库给 aya-ebpf 编译 |

> 预打包的 `out/*.zip` 已内置编译好的 eBPF 程序（`ebpf_target.o`），普通用户刷入即可，无需构建环境。

### 重编译 eBPF 程序

修改 `ebpf/` 下的 BPF 源码后需在 WSL（Ubuntu 发行版）中重编译：

- WSL 内安装 Rust nightly：`rustup toolchain install nightly`（建议配置国内镜像 `RUSTUP_DIST_SERVER=https://rsproxy.cn`）
- 需要 Android clang（如 `~/kernel/bin/clang19`，提供 LLVM 库），或安装 `llvm` 系统包

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export LLVM_SYS_190_PREFIX="$HOME/kernel/bin/clang19"
cd ebpf
cargo +nightly build --target bpfel-unknown-none --release -Zbuild-std=core
cp target/bpfel-unknown-none/release/aether-ebpf ../ebpf_target.o
```

或直接运行 `scripts/wsl_ebpf_build.sh`。

## 构建

```bash
# 一键编译 + 打包
python build.py

# 输出
out/Aether-OptExt_YYYYMMDD_HHMMSS.zip
```

### 前置条件

- [Rust](https://rustup.rs)
- Android NDK（自动检测 `$ANDROID_NDK_HOME`）
- 编译目标: `rustup target add aarch64-linux-android`

## 安装

Magisk / KernelSU 中刷入 `out/Aether-OptExt_*.zip` 即可。

### 运行时路径

| 项目 | 路径 |
|:---|:---|
| 配置文件 | `/sdcard/Android/Aether/threads.json` |
| 日志文件 | `/sdcard/Android/Aether/threads_log.txt` |
| 自动分配缓存 | `/sdcard/Android/Aether/threads_cache` |
| 前台变化信号 | `/sdcard/Android/Aether/fg_hint`（供 Aether Scheduler 读取） |

## 配置文件格式

```json
{
  "features": {
    "ebpf": true,
    "auto-for-none": true,
    "foreground": true,
    "load_aware": true,
    "notify_scheduler": true,
    "blacklist": [],
    "render_guard": true,
    "min_cpus": 4,
    "lagrange": { "enable": true }
  },
  "rules": [
    {
      "friendly": "原神",
      "packages": ["com.miHoYo.Yuanshen"],
      "cpuset": {
        "other": "0-5",
        "comm": {
          "6-7": ["UnityMain", "UnityGfxDeviceW"],
          "0-5": ["NativeThread"]
        }
      }
    }
  ]
}
```

- `features.ebpf` — 启用 eBPF 加速（需内核支持）
- `features.auto-for-none` — 启用自动分配缓存
- `features.foreground` — 前台感知（默认 true）：缓存后台进程（`oom_score_adj >= 900`）自动收缩到能效核，回前台恢复配置目标；仅作用于包级 `other`，线程规则不受影响
- `features.load_aware` — 动态负载感知（默认 true）：按 `/proc/{tid}/stat` 的 tick 增量实测线程占用率，高负载并入超大核、空闲收缩到能效核，仅作用于包级 `other`
- `features.blacklist` — 用户黑名单（默认空数组）：列入的包名**完全不受控**，不绑核、不纳入自动分配缓存、不注入 eBPF 白名单、不发 fg_hint 信号，优先级高于一切规则；含 `:suffix` 的进程按其基础包名判定
- `features.render_guard` — 渲染安全护栏（默认 true）：① 渲染管线线程（`RenderThread`/`Gfx`/`Vulkan`/`RHI`/`Surface` 等）若被配到与性能核无交集的集合，自动升档到 `{hp_core}`/`{p_core}`；② 绑核目标少于 2 核时拒绝并回退（单核在负载波动下易饿死线程，触发 fence 超时黑屏）。降级动作会写入 `safety:` 日志
- `features.min_cpus` — 包级最小核数（默认 4）：包级 `other` 目标核数不足时，按 `{p_core}` → `{hp_core}` → 全在线核顺序并入，避免多线程应用全挤在小核上导致卡顿；设为 `1` 禁用。**仅作用于包级 `other`，用户手写的线程规则不扩充**
- `features.notify_scheduler` — 前台变化通知（默认 true）：检测到应用进程需要应用 cgroup 策略时，向 `/sdcard/Android/Aether/fg_hint` 写入 `<pkg>:<pid>:<timestamp_ms>`，供 Aether Scheduler 感知前台切换。仅发「有变化」信号、由 Scheduler 自行 `dumpsys` 判定；按 pid（10s）与包名（60s）双重节流防刷屏
- `features.lagrange` — λmod 求解器（默认 `{ "enable": true }`）：基于 perf_event 实测（指令数/周期数/LLC 访问与 miss）构建线程指纹，以带容量约束的效用最大化模型求解各层配额，比 tick 启发式更能表达「6 小核 : 2 大核」这类中间分布。性能计数器不可用时自动回退 `load_aware`；仅作用于包级 `other`
- `other` — 该应用所有线程的默认绑核
- `comm` — 按线程名匹配的绑核规则（支持 `*` 通配符）

## 特性

### eBPF 加速

挂载 5 个 tracepoint，事件经 ringbuf 实时上报，**先于 /proc 扫描发现**新进程/线程：

| tracepoint | 类别 | 必需 | 用途 |
|:---|:---|:---|:---|
| `sched_process_fork` | sched | 是 | 新线程创建（毫秒级发现） |
| `sched_process_exec` | sched | 是 | 进程 exec |
| `sched_process_exit` | sched | 是 | 进程/线程退出，回收跟踪 |
| `task_rename` | task | 否 | 线程改名后重新匹配规则 |
| `cgroup_attach_task` | cgroup | 否 | 进程被移入 `top-app` cgroup → 前台变化信号 |

任一必需 tracepoint 挂载失败则整体回退 `/proc` 轮询；可选 tracepoint 失败不影响主链路（缺失时相应功能降级，如无 `task_rename` 时靠周期性重读 `comm` 兜底）。

需内核支持以下配置：

```
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBE_EVENTS=y
CONFIG_PERF_EVENTS=y
```

通过 `features.ebpf: true/false` 控制。

> 注：tracepoint 字段偏移（`child_pid`/`newcomm`/`dst_id` 等）在运行时从 tracefs 的 `format` 文件解析，不同内核版本无需改动代码。若内核使用 Android Vendor Hooks（`CONFIG_ANDROID_VENDOR_HOOKS=y`），BPF map 创建可正常进行，但 `bpf_perf_event_output` 等高级功能受限，程序自动回退 `/proc` 轮询。

### 自动分配缓存

当配置文件中未收录某个用户应用时，自动扫描其线程，按线程名估算负载后分配核心，保存到 `/sdcard/Android/Aether/threads_cache`，下次启动自动合并到规则集。

**负载分级：**

| 级别 | 线程名特征 | 目标核心 |
|:---|:---|:---|
| 高负载 | `RenderThread` / `UnityMain` / `GLThread*` / `Vulkan*` | 大核集群 |
| 较高负载 | `CodecLooper` / `Video*` / `Audio*` | 大核集群 |
| 中等负载 | `Worker*` / `Job*` / `Thread-*` | 小核集群 |
| 低负载 | `Io*` / `Network*` / `Http*` | 小核集群 |
| 极低负载 | `Background*` / `Idle*` / `Pool*` | 小核集群 |
| 默认 | 其他未匹配线程 | 小核集群 |

通过 `features.auto-for-none: true/false` 控制。

### λmod 求解器

`features.lagrange` 开启时，以 perf_event 实测数据替代线程名启发式来分配核心：

- **线程指纹**：perf 计数器读取每线程的指令数、CPU 周期数、LLC 访问与 LLC miss，得到缓存 miss 率与 CPI
- **求解模型**：把绑核建模为带容量约束的效用最大化，各层容量配额 `rho` = 该层核数 / 总核数，用梯度法迭代拉格朗日乘子；层概率取 softmax，实际绑定按概率采样，使长期分布收敛到配额
- **软分配**：按概率软累加而非硬取 argmax —— 硬分配只能整层取一，永远表达不了「75% : 25%」这类中间分布
- **自动降级**：perf_event 不可用（内核不支持或权限不足）时回退 `load_aware`；探测到的有效层数 < 2 时跳过（单层设备无分配意义）
- **开销控制**：先用 `/proc/{tid}/stat` 的 tick 增量做免 fd 预筛选，仅活跃线程才开 perf 计数器；连续空闲约 11 分钟才回收句柄。计数器的 fd 用量在启动时按 `RLIMIT_NOFILE` 预检，余量不足则不启用

> 与 `load_aware` 的区别：`load_aware` 按 tick 增量分高/中/低三档，粒度粗；λmod 依据缓存行为与指令量求解配额，能区分同为「高负载」但缓存特征迥异的线程。

### 语义占位符（多拓扑自适应）

规则中的 cpus 使用语义占位符，安装时按设备拓扑自动展开为实际核号，无需为每种 CPU 规格单独写配置：

| 占位符 | 语义 | 4 层 SOC 示例（1+2+2+3） |
|:---|:---|:---|
| `{e_core}` | 最低频层（小核） | `0` |
| `{p1_core}` | 中核 | `1-2` |
| `{p2_core}` | 大核（仅 4 层存在） | `3-4` |
| `{p_core}` | 中核 ∪ 大核 | `1-2,3-4` |
| `{hp_core}` | 最高频层（超大核） | `5-7` |
| `{all_core}` | 全部 CPU | `0-7` |

层级命名惯例大核在前：`1+3+4` = 超大核 1 + 大核 3 + 小核 4。2 层 SOC 时 `{p_core}` 展开为空（无中核可绑），1 层时 `{hp_core}` 回退到 `{e_core}`。


> 缓存按包名去重，已知系统包名（`com.miui.*`、`com.xiaomi.*`、`vendor.*` 等）被自动过滤。模块更新时清除旧缓存。

### asoul 兼容

设备安装 asoul 模块（`/data/adb/asoul_affinity_opt` 存在）时，自动读取 `/sdcard/Android/Aether/gamelist`（默认 316 个游戏包），名单内包名完全豁免：不匹配规则、不自动分配、不绑核，与 asoul 互不干扰。gamelist 可直接编辑增删。


### 优先级匹配

绑核规则按 `calculate_rule_priority` 算法排序，每个线程取优先级最高的匹配：

| 匹配方式 | 权重基准 | 示例 |
|:---|:---|:---|
| 精确匹配 | 1000 + 模式长度 | `UnityMain` |
| 范围匹配 `[a-z]` | 500 + 非通配符数 | `Thread-[0-9]` |
| 单通配符 `?` | 300 + 非通配符数 | `Thread-???` |
| 星通配符 `*` | 100 + 非通配符数 | `Render*` |
| 进程级兜底 | 固定 200 | 空匹配字符串 |

### 多拓扑适配

安装时通过 cpufreq policy 目录自动检测 CPU 集群分布（支持 1/2/3/4 层 SOC），将 `threads.json` 中的语义占位符展开为实际核号，生成 `/sdcard/Android/Aether/threads.json`：

- 最低频组 → `{e_core}`（小核）
- 中间组 → `{p1_core}` / `{p2_core}`（中核/大核，2/3 层时相应为空）
- 最高频组 → `{hp_core}`（超大核）

同一套模板自适应任意 CPU 规格，无需按拓扑维护多份配置文件。auto-for-none 自动分配同样按 4 层分级（big/mid1/mid2/little）绑定。

运行时（λmod）同样按 cpufreq 实测分层，并保留**未经合并的完整层列表**：`2+2+4` 这类四层架构会得到 4 个独立层，不会被压成 3 层，从而保留完整的分配粒度。语义占位符中的 `{p_core}` 仍按「中间层合并」给出（绑核用），两者互不影响。

支持的拓扑形态：

| 架构 | 检测层数 | e | p | hp |
|:---|:---|:---|:---|:---|
| `2+2+4` | 3 层 | 4 核 | 2 核 | 2 核 |
| `1+2+2+3` | 4 层 | 3 核 | 4 核（中间两层合并） | 1 核 |
| `6+2` | 2 层 | 6 核 | — | 2 核 |
| 单簇 | 1 层 | 全部 | — | — |


## 许可证

GPL-3.0
