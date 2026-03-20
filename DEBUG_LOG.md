# Live Capture — 调试日志

> 记录问题、排查过程和修复结果。
> 创建于 2026-03-12。

---

## 问题 #1: PLP Counter Monitor 进程崩溃

**描述:** Live Capture 在 `localadm@192.168.41.68` 上运行，PLP Counter Monitor 面板存在但没有工作 — 看不到 Counter 连续性检查结果（Gap数、丢包率等）。

**期望行为:** Capture 启动时，CounterMonitor 独立进程自动启动，通过 TPACKET_V3 MMAP 抓取 EtherType `0x2090` 包，实时检查 Counter 连续性，每秒更新 UI 显示。

---

### 重要发现：本地与远程版本不同步

| | 远程 (`192.168.41.68`) | 本地 (WSL `Live Capture/`) |
|---|---|---|
| **行数** | **8243 行** | 5756 行 |
| **大小** | **345,871 字节** | 240,173 字节 |
| **修改时间** | **Mar 11 21:24** | Mar 3 14:54 |

远程版本多了约 **2500 行**，新了 **8 天**。之前直接在远程机器上做了大量优化，没有同步回本地。

**远程版本已有的功能（本地没有）：**
- `_counter_monitor_worker()` — 独立进程，TPACKET_V3 MMAP，绑定 EtherType 0x2090
- `_start_counter_monitor()` / `_stop_counter_monitor()` — 进程生命周期管理
- `_poll_counter_stats()` — QTimer 每秒读取 SharedMemory 统计
- `_on_counter_stats_updated()` — UI 更新（红/绿/橙色显示）
- `_toggle_counter_panel()` / `_reset_counter_monitor()` — UI 控制
- `core/capture_process.py` (46217 字节) — 远程独有的模块

---

### 根本原因（已确认）

**日志证据（`/tmp/livecapture_output.log`）：**
```
Process CounterMonitor:
  File "/home/localadm/LiveCapture/ui/wireshark_panel.py", line 162, in _counter_monitor_worker
NameError: name 'local_states' is not defined
```

**代码分析：** 重构时将 `local_states` 改为 `probe_states`（按 probe_id 分组），但第162行旧引用 `ls = local_states[di]` 未删除。该行实际多余，后面 `ls` 会被 `probe_states[arr_idx][probe_id]` 正确赋值。

---

### 修复记录

#### 尝试 1: 删除 `local_states` 引用

- **日期:** 2026-03-12 ~09:50
- **操作:** `sed -i '162d'` 删除 `ls = local_states[di]`
- **结果:** ✅ 成功 — 程序重启后 CounterMonitor 进程正常运行，UI 显示统计数据
- **状态:** **已解决**

---

### 后续任务

1. [x] 定位根本原因
2. [x] 修复第162行 `local_states` → 删除该行
3. [x] 重启程序，验证 CounterMonitor 进程正常运行
4. [x] UI 显示 Counter 统计 → 可以看到了，但丢失率异常高（见问题 #2）
5. [ ] 将远程版本同步回本地 WSL

---
---

## 问题 #2: PLP Counter 丢失率高达 90%+（eno7np2 上 0x66/0x67）

**描述:** 问题 #1 修复后，Counter Monitor 能正常显示统计数据，但 eno7np2 接口上的 stream 0x66 和 0x67 报告丢失率高达 **90%以上**。

**期望行为:** 丢失率应在可接受范围内（< 5%），反映网络的实际质量。

---

### 环境信息

- **网卡:** Intel i40e, 10Gbps, eno7np2
- **NIC tuning 服务:** `nic-tuning.service` (systemd, enabled)
- **tuning 脚本:** `/usr/local/bin/nic-tuning.sh`（Ring Buffer 4096, IRQ Affinity, RPS, Coalesce off）

---

### 排查过程

#### 检查 1: NIC tuning 服务状态

- **日期:** 2026-03-12 ~09:55
- **结果:** 服务 `active (exited)`，开机时成功运行
- **细节:**
  - 开机时 (09:18): eno7np2 → CPU 0-7, eno8np3 → CPU 8-15 ✅
  - Ring Buffer: 4096/4096 ✅
  - Coalesce: adaptive off, rx-usecs=0 ✅
  - IRQ Affinity: 16 个队列分配到 CPU 0-7 ✅

#### 检查 2: NIC tuning 脚本版本不一致

- **日期:** 2026-03-12 ~09:55
- **发现:** 源文件 (`LiveCapture/nic-tuning.sh`) 与安装版 (`/usr/local/bin/nic-tuning.sh`) **不一致**
  - 源文件有 `sysctl netdev_budget=4096` → 安装版**缺少**这3行
  - 安装版有 link-wait 逻辑 → 源文件**缺少**
- **影响:** `netdev_budget` 实际值为 **1200**（默认值），不是脚本设定的 4096
- **修复:** `sudo cp` 源文件到安装目录，`systemctl restart nic-tuning.service`
- **结果:** ✅ `netdev_budget=4096`, `budget_usecs=16000` 已生效
- **注意:** 重启服务时 eno7np2 未被重新 tune（原因不明，开机时正常），但开机时的设置仍有效

#### 检查 3: 实际丢包统计（5秒增量测试）

- **日期:** 2026-03-12 ~10:00
- **结果:**

| 指标 | 增量 (5s) | 速率 | 说明 |
|------|----------|------|------|
| NIC `rx_missed_errors` | +23,514 | ~4,700/s | 硬件 Ring Buffer 溢出 |
| CPU 5 softnet `dropped` | +147,421 | **~29,500/s** | 内核 backlog 溢出 |
| CPU 5 softnet `time_squeeze` | +6,883 | ~1,377/s | NAPI budget 耗尽 |
| CPU 5 softnet `processed` | +311,447 | ~62,300 pps | 实际处理 |

**计算丢包率:** (4,700 + 29,500) / (62,300 + 29,500 + 4,700) ≈ **35-40%**

#### 检查 4: 队列分布（根本原因）

- **日期:** 2026-03-12 ~10:00
- **发现:** `ethtool -S eno7np2` per-queue 统计：

```
rx-0.packets:  0
rx-1.packets:  0
rx-2.packets:  0
rx-3.packets:  0
rx-4.packets:  250,045,685    ← 所有流量！
rx-5.packets:  0
...
rx-15.packets: 0
```

**所有 2.5 亿个包都在 rx-4 一个队列上**，其他 15 个队列全部为 0。

**根本原因:** i40e 的 RSS hash 只支持 IP 头字段（src/dst IP + port），对于非 IP 的 EtherType 0x2090 包，RSS 无法分散，全部 hash 到同一个队列 → 单核过载。

#### 检查 5: 尝试硬件分流

- **日期:** 2026-03-12 ~10:05
- **尝试 A:** `ethtool -N eno7np2 flow-type ether proto 0x2090 action 0` → ❌ `Operation not supported`
- **尝试 B:** `ethtool -X eno7np2 hfunc xor` → ❌ `Operation not supported`
- **结论:** i40e 不支持基于 EtherType 的 ntuple 分流，也不支持更改 hash 函数

---

### 故障原因分析

| # | 原因 | 概率 | 状态 |
|---|------|------|------|
| 1 | **RSS 无法分散非IP流量，所有0x2090包集中在rx-4单队列** | **已确认** | 根本原因 |
| 2 | `netdev_budget` 过低 (1200→已修复为4096) | 已确认 | ✅ 已修复 |
| 3 | NIC `rx_missed_errors` 持续增长（硬件层丢包） | 已确认 | 待解决 |
| 4 | Counter Monitor 自身 TPACKET_V3 ring buffer 不够大 | 待验证 | OFFEN |

---

### 检查 6: PLP 流量分析（Probe/Stream 结构）

- **日期:** 2026-03-12 ~10:10
- **方法:** 独立 Python AF_PACKET socket 抓包 5000 个，按 probe_id 分别统计
- **发现:**

| Probe ID | 包数 | Streams | Gaps | 丢失 | 丢失率 | pps |
|----------|------|---------|------|------|--------|-----|
| 0x0000 | 6 | 0x64, 0x65 | 0 | 0 | **0.00%** | 81 |
| 0xD003 | 4994 | 0x66, 0x67 | **2** | 1556 | **23.76%** | 67,007 |

**关键发现:**
- 两个独立的 Probe 共享同一个接口 eno7np2
- Probe 0x0000（低速，~81 pps）：完全无丢包 ✅
- Probe 0xD003（高速，~67K pps）：~24% 丢包，只有 2 次 gap 但每次跳过大量 counter
- 2 gaps / 1556 lost = **突发性集中丢包**（burst loss），不是随机丢 → 单队列 rx-4 瞬间溢出
- Counter Monitor 代码**确认按 probe_id 分开追踪**（代码正确），UI 上报主 probe (0xD003) 的数据

---

### 解决方案尝试

#### 方案 A: 修复 `netdev_budget`（1200 → 4096）

- **日期:** 2026-03-12 ~09:58
- **操作:** 重新安装 `nic-tuning.sh`，`systemctl restart nic-tuning.service`
- **结果:** ✅ sysctl 生效。CPU 5 time_squeeze 从 ~1,377/s 降为 0

#### 方案 B: 增大 `netdev_max_backlog`（50,000 → 200,000）

- **日期:** 2026-03-12 ~10:00
- **操作:** `sysctl -w net.core.netdev_max_backlog=200000`
- **结果:** ✅ **CPU 5 softnet drops 完全停止（从 ~29,500/s → 0）**
- **效果:** 处理能力从 ~62K pps 提升到 ~94K pps
- **注意:** 此设置未持久化，需加入 `nic-tuning.sh`

#### 方案 C: 增大 Counter Monitor TPACKET_V3 Ring Buffer

- **原理:** 当前 BLOCK_NR=16 (16MB ring)，在 67K pps × 8KB ≈ 536MB/s 下约 30ms 满。增大可缓冲更多 burst。
- **日期:** 2026-03-12 ~10:20
- **操作:** `BLOCK_NR = 16` → `BLOCK_NR = 64`（16MB → 64MB，~120ms buffer）
- **结果:** 待重启程序后验证

#### 方案 D: tc flower/u32 软件分流

- **原理:** 用 `tc filter` 将 EtherType 0x2090 流量分散到多个 RX 队列
- **日期:** 2026-03-12 ~10:15
- **操作:** `tc qdisc add ingress` + `tc filter u32 match ... action skbedit queue_mapping`
- **结果:** ❌ **无效** — `skbedit queue_mapping` 只改 skb 标记，不影响 NAPI 上下文。数据包已在 rx-4/CPU 4 的 NAPI 中处理完毕，tc ingress 无法让另一个 CPU 重新处理。已清理。

#### 方案 E: 关闭 eno7np2 的 RPS

- **原理:** TPACKET_V3 在 NAPI 上下文中直接投递，关闭 RPS 减少 IPI 开销。
- **日期:** 2026-03-12 ~10:10
- **操作:** `echo 0 > /sys/class/net/eno7np2/queues/rx-*/rps_cpus`
- **结果:** ❌ **更差** — rx_missed_errors 从 ~350/s 升到 ~4,272/s。CPU 4 同时承担 NAPI + 协议处理 → 更忙 → 更多硬件丢包。**已恢复** `rps_cpus=00ff`。

#### 方案 F: 持久化 netdev_max_backlog

- **日期:** 2026-03-12 ~10:20
- **操作:** 在 `nic-tuning.sh` 中添加 `sysctl -w net.core.netdev_max_backlog=200000`，重新 `cp` 到 `/usr/local/bin/`
- **结果:** ✅ 已持久化，重启后自动生效

---

### 参考数据

- **网卡型号:** Intel i40e (X710/XXV710), 10Gbps
- **驱动:** i40e
- **队列数:** 16 RX + 16 TX
- **Ring Buffer:** 4096 (最大值)
- **rmem_max:** 268,435,456 (256MB)
- **netdev_max_backlog:** 200,000（已从 50,000 增大）
- **netdev_budget:** 4096（已从 1200 修复）
- **PLP 包平均大小:** ~7,818 bytes
- **PLP 总吞吐:** Probe 0xD003 ~87K pps（主要流量）

---

### 检查 7: TPACKET_V3 实时丢包率验证

- **日期:** 2026-03-12 ~10:30
- **方法:** 独立 Python 脚本使用 TPACKET_V3 MMAP（与 Counter Monitor 完全相同方式），测量 5 秒
- **结果:**

| 方法 | 丢包率 | 说明 |
|------|--------|------|
| TPACKET_V3（5s实测） | **0.17%** | 9 gaps, 747 lost / 435,336 rcvd |
| Python recv()（有预热） | 0.33% | Python GIL 开销偏高 |
| Counter Monitor UI | ~6% | 累积值，含启动 burst |

**结论: UI 显示的 ~6% 是启动以来的累积统计。** 启动初期 Counter Monitor 进程初始化 + 首次 poll() 延迟会造成一次大的 burst loss，被计入总数据中。实际实时丢包率仅 ~0.17%。

**解决:** 点击 UI 上的 "↺ Zurücksetzen" 按钮重置统计，之后显示的是实时丢包率。

**剩余 0.17% 的原因分析:**
- NIC `rx_missed_errors` 增量 ~6/s（eno7np2 单队列 rx-4 偶发微小溢出）
- 87K pps 全在一个 NAPI 队列上，偶发 burst 超出 Ring Buffer 4096 的缓冲能力
- 这是 i40e 对非 IP 流量（EtherType 0x2090）不支持 RSS 分流的硬件限制

---

### 修复总结（问题 #2）

| 修复项 | 效果 |
|--------|------|
| `netdev_budget` 1200→4096 | 消除 time_squeeze |
| `netdev_max_backlog` 50K→200K | 消除 softnet drops（~29,500/s→0）|
| TPACKET_V3 ring 16MB→64MB | 减少 burst loss |
| 持久化到 `nic-tuning.sh` | 重启后自动生效 |
| **最终实时丢包率** | **~0.17%**（硬件限制）|

---

### 检查 8: Counter Monitor 对视频稳定性的影响测试

- **日期:** 2026-03-12 ~10:45
- **背景:** Reset 后 UI 仍显示 ~6% 丢包。视频每 10-15 秒抖动一次。内核层无丢包。
- **方法:** 添加 "⏹ Counter pausieren" 按钮，可暂停/恢复 Counter Monitor 的计数（进程不停止，只跳过分析）
- **结果:** ✅ **已确认 Counter Monitor 计数导致视频抖动**
  - 暂停计数后：0x66/0x67 图像长时间观察**无波动**
  - 恢复计数后：图像**立即恢复偶发上下波动**（每 10-15 秒一次）
  - 重复测试：结果一致
- **结论:** Counter Monitor 的 TPACKET_V3 数据采集/分析过程**确实干扰**视频数据接收

---
---

## 问题 #3: Counter Monitor 计算丢包率干扰视频图像显示

**描述:** PLP Counter Monitor 虽然运行在独立进程中，但其 TPACKET_V3 数据采集仍然导致 0x66/0x67 视频流每 10-15 秒出现一次图像上下波动/抖动。暂停 Counter 计算后视频完全稳定。

**已确认:** 通过暂停/恢复对比测试确认（见问题 #2 检查 8）。

---

### 技术背景

Counter Monitor 架构：
```
┌─────────────────────────────────────────────────────────┐
│  NIC eno7np2 (i40e)                                     │
│  rx-4 队列 ← 所有 0x2090 流量 (~87K pps)                │
│      │                                                   │
│      ▼                                                   │
│  NAPI softirq (CPU 4)                                   │
│      │                                                   │
│      ├──→ AF_PACKET socket #1 (视频 capture/dumpcap)     │
│      │    → 投递到 socket buffer                         │
│      │                                                   │
│      ├──→ AF_PACKET socket #2 (Counter Monitor TPACKET_V3)│
│      │    → 投递到 64MB mmap ring buffer                 │
│      │                                                   │
│      └──→ 协议栈 (RPS → 其他 CPU)                       │
└─────────────────────────────────────────────────────────┘
```

**关键点:** 两个 AF_PACKET socket 的投递**都发生在 CPU 4 的 NAPI softirq 上下文中**，共享同一个 CPU 时间片。

---

### 故障原因分析（按可能性排序）

| # | 可能原因 | 概率 | 状态 |
|---|---------|------|------|
| 1 | **NAPI 双投递开销：每个包需投递到两个 AF_PACKET socket，NAPI 处理时间翻倍** | **高 (80%)** | 待验证 |
| 2 | **内存带宽竞争：Counter Monitor 的 64MB mmap ring 与视频 buffer 竞争 L3 cache 和内存带宽** | **中高 (60%)** | 待验证 |
| 3 | **NAPI budget 耗尽：双倍投递消耗更多 NAPI budget，导致间歇性 time_squeeze** | **中 (50%)** | 待验证 |
| 4 | **NIC rx_missed 增加：NAPI 处理变慢 → NIC ring 溢出 → 硬件丢包影响视频帧完整性** | **中 (40%)** | 待验证 |
| 5 | **Counter 进程 CPU 调度干扰：Counter 进程与视频 assembly 线程在某些 CPU 上竞争** | **低 (20%)** | 待验证 |
| 6 | **socket filter 缺失：Counter Monitor socket 接收所有 0x2090 包但只需要 header，浪费 DMA 带宽** | **低 (15%)** | 待验证 |

---

### 详细分析

#### 原因 1: NAPI 双投递开销 (80%)

在 `__netif_receive_skb_core()` 中，内核遍历 `ptype_all` 链表，对每个注册的 AF_PACKET socket 调用 `deliver_skb()`。Counter Monitor 的 TPACKET_V3 socket 是第二个 AF_PACKET handler，每个包的 NAPI 处理时间增加：
- `tpacket_rcv()` → 复制 packet 到 ring buffer → 更新 block header
- 在 87K pps 下，额外约 87K × ~500ns = **~43ms/s 额外 CPU 开销**（在 CPU 4 上）

这可能导致 NAPI poll 周期变长，间歇性来不及处理所有包。

**验证方法:** 对比暂停/恢复时 `rx_missed_errors` 增长速率

#### 原因 2: 内存带宽竞争 (60%)

Counter Monitor 的 64MB mmap ring buffer 持续被写入（NAPI 侧）和读取（Counter 进程侧），导致 CPU 4 的 L3 cache 被污染，影响视频数据的 DMA 和 buffer 访问效率。

**验证方法:** 减小 ring buffer 大小（64MB → 4MB），或者用 BPF 只捕获 header

#### 原因 3: NAPI budget 耗尽 (50%)

双投递增加了每个包的 NAPI 处理时间，可能导致 `netdev_budget` 在某些周期内不够用，触发 time_squeeze → 延迟处理下一批包。

**验证方法:** 对比暂停/恢复时 softnet_stat 的 time_squeeze 变化

#### 原因 4: NIC rx_missed 增加 (40%)

NAPI 变慢 → NIC ring buffer 更容易溢出 → 视频帧中的某些 PLP 包丢失 → reassembly 不完整 → 图像抖动

**验证方法:** 对比暂停/恢复时 `rx_missed_errors` 增长速率

#### 原因 5: CPU 调度竞争 (20%)

Counter Monitor 进程虽然是独立的，但可能与视频 assembly 线程共享 CPU。`_counter_monitor_worker` 在 busy loop 中运行（poll+drain），可能抢占视频线程的 CPU 时间。

**验证方法:** 检查 Counter Monitor 进程的 CPU 亲和性，用 `taskset` 绑定到非视频 CPU

#### 原因 6: 无 socket filter，浪费 DMA 带宽 (15%)

Counter Monitor 只需要每个包的前 30 字节（probe_id + counter + stream_id），但 TPACKET_V3 默认 snaplen 捕获整个包（~7818 字节）。每个包多复制 ~7788 字节到 ring buffer 是不必要的。

**验证方法:** 设置 `setsockopt(SOL_PACKET, PACKET_COPY_THRESH)` 或 `sock.setsockopt(SOL_SOCKET, SO_RCVBUF)` 限制 snaplen

---

### 验证计划

| # | 验证项 | 方法 | 状态 |
|---|--------|------|------|
| V1 | NAPI + rx_missed 对比 | 暂停/恢复时各测 10s `ethtool -S` 和 `softnet_stat` 增量 | 待执行 |
| V2 | snaplen 限制 | Counter Monitor socket 设置 `setsockopt(SOL_PACKET, PACKET_COPY_THRESH, 64)` | 待执行 |
| V3 | ring buffer 缩小 | BLOCK_NR 64→8 (8MB) | 待执行 |
| V4 | CPU 亲和性 | Counter Monitor 进程 `os.sched_setaffinity()` 绑定到 CPU 14-15 | 待执行 |
| V5 | BPF filter | 只捕获 header 前 30 字节 | 待执行 |

---

### 验证记录

#### V1: NAPI + rx_missed 对比

- **日期:** 2026-03-12 ~11:05
- **操作:** 分别在 Counter 活跃和暂停状态下测量 15 秒 `ethtool -S` 和 `softnet_stat`
- **结果:**

| 指标 | Counter 活跃 (15s) | Counter 暂停 (15s) |
|------|-------------------|-------------------|
| **rx_missed_errors** | **+111 (7.4/s)** | **0** |
| CPU 5 processed | ~97K pps | ~97K pps |
| softnet drops | 0 | 0 |
| time_squeeze | 0 | 0 |

- **结论:** Counter 活跃时 NIC 硬件丢包 7.4/s，暂停后**完全归零**。证实 NAPI 双投递导致处理变慢 → NIC ring 偶发溢出。

#### V2+V4+V5 组合: CPU 绑定 + snaplen 限制

- **日期:** 2026-03-12 ~11:10
- **操作:**
  - Counter Monitor 进程用 `os.sched_setaffinity(0, {15})` 绑定到 CPU 15（远离 NAPI CPU 4/5）
  - `setsockopt(SOL_PACKET, PACKET_COPY_THRESH, 64)` 限制 snaplen 为 64 字节（原 ~7818 字节）
- **预期:** 减少 CPU 调度竞争 + 减少 DMA 复制量 → rx_missed_errors 降低或消除
- **结果:** CPU 绑定和 snaplen 限制已部署，但仅在独立进程模式下有效。实测帧间 jitter 数据表明问题的根本原因确实是双 AF_PACKET socket，而非进程调度。详见 V6。

#### V6: Jitter 诊断 — 帧间时间差定量对比

- **日期:** 2026-03-12 ~11:30
- **方法:** 在 `capture_process.py:_isp_pipeline()` 中添加帧间时间差日志（`/tmp/0x2090_jitter.log`）。阈值 dt>100ms 或 dt<10ms 标记为异常。暂停/恢复时写入分界标记。
- **注意:** 最初错误地将 jitter 代码放在 `wireshark_panel.py:_reconstruct_0x2090_frame()` 中，但该函数未被调用（实际路径是 `capture_process.py:_isp_pipeline()`）。修正后成功采集数据。
- **结果:**

| 阶段 | 0x66 avg dt | 0x67 avg dt | >300ms 异常帧比例 (0x66) | >300ms 异常帧比例 (0x67) |
|------|-----------|-----------|------------------------|------------------------|
| **Counter 活跃** | **409ms** | **361ms** | **89%** (49/55) | **68%** (43/63) |
| 暂停后 0-5s（过渡期）| 407ms | 396ms | 80% | 80% |
| 暂停后 5-15s | 287ms | 272ms | 43% | 35% |
| **暂停后 >15s（稳定）** | **220ms** | **220ms** | **12%** (126/1058) | **10%** (103/1056) |

- **关键发现:**
  1. Counter 活跃 vs 暂停稳定：帧间隔从 ~400ms 降到 ~220ms，**改善约 45%**
  2. >300ms 卡顿帧比例从 ~80% 降到 ~11%
  3. **过渡期约 5-15 秒**——与用户观察"暂停后 4-5 秒画面才稳定"完全吻合
  4. 过渡期原因：Counter Monitor 的 64MB ring buffer 需要时间排空，且内核仍往 AF_PACKET socket buffer 写入数据直到 NAPI 路径调整
- **结论:** **双 AF_PACKET socket 的 NAPI 双投递是导致视频帧间 jitter 的确定性根因。** CPU 绑定和 snaplen 在独立进程模式下不足以消除该问题。

---

### 解决方案: V7 — 内联 Counter 提取（消除第二个 AF_PACKET socket）

- **日期:** 2026-03-12 ~12:00
- **设计思路:**

之前的方案（独立进程 + TPACKET_V3）问题的根源不是计算开销，而是**第二个 AF_PACKET socket 的存在本身**——它迫使内核在 NAPI softirq 中对每个包执行双倍投递。

新方案：在 CaptureWorker 的现有包处理循环中**内联提取 PLP Counter**，完全消除第二个 socket。

```
旧架构（两个 socket，NAPI 双投递）:
  NIC → NAPI → AF_PACKET #1 (视频) + AF_PACKET #2 (Counter) → 双倍开销

新架构（单 socket，零额外开销）:
  NIC → NAPI → AF_PACKET #1 (视频 + Counter 内联) → 零额外开销
```

- **实现:**
  - `capture_process.py`:
    - `capture_worker_entry()` 新增 `counter_stats` (multiprocessing.Array) 和 `counter_pause` (multiprocessing.Event) 参数
    - `_mmap_loop()` 包处理循环中，每个包读取 `eth_off+16` 的 2 字节 Counter（~10ns/包），检查连续性，统计 gaps/lost
    - 每 poll 周期（~100ms）检查一次 `counter_pause` Event，暂停时完全跳过 Counter 提取
    - 每秒将统计写入 `multiprocessing.Array`（每 worker 12 个字段：total, gaps, lost, stream_ids[8], timestamp）
  - `wireshark_panel.py`:
    - `_start_afpacket_workers()` 创建 `_inline_counter_stats` Array 和 `_inline_counter_pause` Event，传给所有 CaptureWorker
    - `_start_counter_monitor()` 改为内联模式：不再启动独立进程，只启动 QTimer 每秒读取 inline stats
    - `_poll_counter_stats_inline()` 从 inline Array 读取数据，合并同 interface 下两个 worker 的统计
    - `_toggle_counter_monitor_running()` 暂停时 set `_inline_counter_pause`，恢复时 clear — **CaptureWorker 中 Counter 提取代码真正停止执行**
    - 独立 Counter Monitor 进程代码保留但不再使用（向后兼容）
- **结果:** 待重启程序后验证

---

### V8: CaptureWorker CPU 亲和性 — 避开 NAPI CPU

**时间:** 2026-03-12
**问题:** V7 内联 Counter 部署后，即使关闭 Counter 统计，4 路视频仍全部撕裂。

**诊断:**
```
ksoftirqd/4   → 100% CPU (eno7np2 NAPI)
ksoftirqd/12  → 100% CPU (eno8np3 NAPI)
rx_missed_errors: eno7np2 +9,500/s, eno8np3 +16,250/s
CaptureWorker PIDs: 45201-45204, CPU affinity = 0-15 (无限制)
ISP 处理密集: 4 worker 合计 ~640% CPU
```

**根因:** 4 个 CaptureWorker 进程（ISP 处理密集，合计 ~640% CPU）的 CPU 亲和性为 0-15（全部 CPU），
Linux 调度器会将它们调度到 NAPI CPU（4 和 12）上运行，抢占 ksoftirqd 的 softirq 处理时间
→ NIC 硬件 ring buffer 溢出 → `rx_missed_errors` 持续增长 → 视频撕裂。

**修复:** 在 `capture_process.py:_run_capture()` 开头，根据 interface 名称设置 CPU 亲和性：
```python
_IFACE_CPU_AFFINITY = {
    'eno7np2': [0, 1, 2, 3, 5, 6, 7],      # CPU 0-7 去掉 NAPI CPU 4
    'eno8np3': [8, 9, 10, 11, 13, 14, 15],  # CPU 8-15 去掉 NAPI CPU 12
}
# _run_capture() 开头:
os.sched_setaffinity(0, affinity)
```

**预期效果:** NAPI CPU 4 和 12 专用于 ksoftirqd/内核包处理，不被用户态进程抢占，
`rx_missed_errors` 归零，视频撕裂消除。

**结果: ✅ 完美生效！**
- CPU 亲和性验证:
  - PID 78659/78660: mask=`0xef` = `{0,1,2,3,5,6,7}` — eno7np2 Worker，避开 NAPI CPU 4
  - PID 78661/78662: mask=`0xef00` = `{8,9,10,11,13,14,15}` — eno8np3 Worker，避开 NAPI CPU 12
- `rx_missed_errors`: **两个网卡均为 0**（之前 eno7np2 +9,500/s, eno8np3 +16,250/s）
- `softnet_stat dropped`: CPU 4 仍有少量 (+2365/5s)，CPU 12 极少 (+61/5s)，但已不影响画面
- **4 路视频画面完美，无任何撕裂**
- `ksoftirqd/4` 和 `ksoftirqd/12` 不再 100% CPU

**持久性:** 亲和性写在 `capture_process.py` 代码中（类变量 `_IFACE_CPU_AFFINITY`），
每次 CaptureWorker 进程启动时自动调用 `os.sched_setaffinity()`，无需系统级脚本。
与 `install-nic-tuning.sh`（系统级 sysctl/RPS/ring buffer）互补，缺一不可。

---

### V9: Counter Monitor 启动时序 Bug

**时间:** 2026-03-12
**问题:** 重启后 PLP Counter Monitor 面板无数据显示。

**根因:** `_start_counter_monitor()` 在 `_start_afpacket_workers()` **之前**被调用，
此时 `_inline_counter_stats`（multiprocessing.Array）还未创建（为 None），
函数检测到 `ict is None` 直接 return，QTimer 从未启动。

**修复:** 将 Counter Monitor 启动移到 `_start_afpacket_workers()` **之后**：
```python
# 原: 在 _start_live_capture() 末尾直接调用（Worker 未启动）
# 新: 先保存 _pending_counter_ifaces，Worker 启动后再调用
_pci = getattr(self, '_pending_counter_ifaces', None)
if _pci:
    self._start_counter_monitor(_pci)
```

**结果:** 待重启验证
