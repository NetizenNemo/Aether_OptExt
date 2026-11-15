# 更新日志

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
