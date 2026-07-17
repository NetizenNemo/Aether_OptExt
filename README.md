# Aether OptExt

Android 应用/游戏线程 CPU 亲和性优化工具，以 Magisk/KernelSU 模块形式运行。

## 作者OS
总的来说，这是本人的第二个开源的RUST作品吧，也是一个极具我个人风格的作品呢
emm...艇长猫猫还是很喜欢大家的使用哒～使用艇长是俺的荣幸哦～
项目会不断更新，有啥问题可以去issues(虽然猫猫不咋看啦)提交，不过最好的方法还是直接去俺群里把俺艾特出来～千万不要直接骂艇长唔，猫猫很怕凶的(哭哭)
猫猫虽然平时很深情，但代码是认真的！请见俺的README～

## 事先说明
本项目由于社区环境原因，仅允许诸君学习参考，不允许二改，若发现则究查到底

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

## 配置文件格式

```json
{
  "features": { "ebpf": true, "auto-for-none": true },
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
- `other` — 该应用所有线程的默认绑核
- `comm` — 按线程名匹配的绑核规则（支持 `*` 通配符）

## 特性

### eBPF 加速

挂载 `sched/sched_process_exec` tracepoint，新进程执行时 BPF 程序在纳秒级将 PID 写入 HASH map。主循环每轮读取 map 获取新进程，**先于 /proc 扫描发现**。需内核支持以下配置：

```
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBE_EVENTS=y
CONFIG_PERF_EVENTS=y
```

通过 `features.ebpf: true/false` 控制。

> 注：若内核使用 Android Vendor Hooks（`CONFIG_ANDROID_VENDOR_HOOKS=y`），BPF map 创建可正常进行，但 `bpf_perf_event_output` 等高级功能受限，程序自动回退 `/proc` 轮询。

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

> 缓存按包名去重，已知系统包名（`com.miui.*`、`com.xiaomi.*`、`vendor.*` 等）被自动过滤。模块更新时清除旧缓存。

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

安装时通过 cpufreq policy 目录自动检测 CPU 集群分布，选择对应的配置文件：

- `4+3+1`（默认）
- `3+4+1`
- `4+4`
- `6+2` / `2+6`
- `4+2+2`
- `4+3+2+1`

每种拓扑预先计算核心分配方案，非游戏应用自动绑定到效率核，游戏应用保留完整 comm 规则。


## 许可证

GPL-3.0
