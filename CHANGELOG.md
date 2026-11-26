# 更新日志

## 1127-Release

本轮是全面加固：修掉三处会静默失效或泄漏资源的缺陷，统一了拓扑检测 source，并把规则匹配、日志写入、λmod 单线程路径的开销压下去。交叉编译与完整打包均通过。

### 修复

- 通配符规则静默失效
  `fnmatch` 原来只取第一个 `*` 当「前缀+后缀」，`?` 与 `[0-9]`/`[a-z]` 被当字面字符，但 `rule_prio` 与文档都给它们排了高优先级——结果是这类规则抢到最高优先级却一个线程都匹配不上。改为 token + DP 实现，完整支持 `*` / `?` / `[range]` / `[!neg]`，含未闭合 `[` 的降级处理；补 5 组单元测试覆盖全部语法。

- eBPF 初始化失败路径 fd 泄漏
  `wakeup_fd` 创建后、`EVENTS` map 转换失败时直接 `return BpfCtx::empty()`，fd 无人接管，回退 /proc 轮询后永久泄漏。失败 return 前显式关闭。

- cpuset 写入失败仍标记分组就绪
  `affinity_set_ex` 原来丢弃 `write_cpuset_tasks` 返回值，只要 `sched_setaffinity` 成功就返回 `Ok`，调用方随即把 `group_ok` 置位。掩码绑对但 tasks 写入失败时，线程滞留在系统分组且稳态不再复核，thermal 收缩下受错误 cpuset 约束。新增分组就绪返回值，写入失败时保持 `group_ok=false` 继续重试。

### 优化

- flock 进程独占锁
  `service.sh` 的 `pkill + sleep 1` 无法保证旧实例已退出（D 态杀不干净），双开会同时绑核、写 `fg_hint`、改 cpuset 互相踩。主程序启动时取 `flock(LOCK_EX|LOCK_NB)`，拿不到锁直接退出；`/data/adb` 不可写时（本地调试）不阻断。

- 统一 CPU 拓扑检测
  `cpu::detect()` 原本独立读 sysfs、带两级兜底，与 `cpuset::detect_core_types()` 各写一套且行为分叉：cpufreq 不可用时前者仍给出 big/little 供 auto 分配，后者返回空层导致绑核全回退全核。改为从唯一的 `init_cpu_topo()` 结果派生，消除双份实现。

- 规则匹配加包名索引
  `AppConfig` 新增精确包名 → rules 下标的索引，线程规则匹配从「每线程遍历全部规则」降为「只看本包规则」；在 load / merge_cache 的 retain 之后重建，避免下标失效。

- 日志持久 fd
  由「每行 open/close」改为 `OnceLock<Mutex<Option<File>>>` 持有单个 fd，消除 safety 警告/绑核失败集中爆发时的系统调用热点与多线程行交错；轮转时替换整个 File，避免写进已 rename 的旧 inode。

- λmod 单活跃线程锁定层
  `solve()` 的 salt 每轮递增、按概率重采样，单个活跃线程会被随机甩到不同层，导致每轮 `setaffinity`。单线程且已有目标时沿用旧目标、不推进 λ；多线程恢复后正常收敛。

- 其他
  `ProcCache::clear()` 补清采样时钟与前后台缓存，全量重建不再跨扫描残留旧状态；`inotify` 事件读取改用 `read_unaligned`，消除 1 字节对齐缓冲区解引用 4 字节结构的未定义行为。

## 1115-Release

本轮聚焦周期性开销与实现缺陷：修复两处会让功能静默失效的读接口 BUG，并把亲和性校正热路径上的读放大降到稳态零读取。

真机实测（8 核 6+2，2730 线程负载），lagrange 采样尖峰由 +76 tick / 18s 降至 +57 tick / 60s，折算 CPU 占用 4.2% → 0.95%。

### 修复

- 读线程 CPU 时间漏掉 utime
  `/proc/{tid}/stat` 从 state 起算，utime 是第 12 项、stime 第 13 项；原实现取第 13/14 项，实际读到 stime + cutime。
  CPU 密集线程 utime 占绝对大头，load_aware 分级与 λmod 采样长期严重低估负载，高负载线程被误判为空闲压进小核。

- 非 UTF-8 cmdline 使进程被静默丢弃
  `read_to_string().ok()?` 遇非法 UTF-8 直接返回 None，该进程不绑核、不进缓存、不打任何日志，完全脱离管理。
  native 程序自定义 argv[0] 即可触发。改用 `fs::read` + `from_utf8_lossy`。

### 优化

- lagrange 采样加空闲门控，息屏直接跳过
- LAGRANGE_TICK_DIV 3 → 10，采样周期 18s → 60s
- 前后台判定加 25s TTL 缓存，消除 6 秒周期抖动
- 线程 CPU 时间与 cmdline 改 512 字节定长读
- cpuset 分组校验改为一次性确认（group_ok），稳态零读取

### 升级说明

直接在 KernelSU / Magisk 中刷入覆盖安装，无需清除数据，重启后生效。

## 1108-Release

- 修复空 cpus 键导致整条规则失效（应用完全不被分配）
- 修复亲和性短路只比对掩码、漏判 cpuset 分组归属
- 新增息屏降频（screen_state 判据）
- 新增 cpuset 分组回收
- 线程失败后支持退避重试
