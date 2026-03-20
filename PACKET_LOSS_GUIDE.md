# Live Capture — 丢包问题排查手册

> 从项目开始就反复出现的问题。本文档汇总所有已知原因、排查步骤和解决方案。
> 创建于 2026-03-12。

---

## 系统架构概览

```
NIC (i40e 10Gbps)
  └─ 16 RX 队列，但 EtherType 0x2090 (非IP) 无法 RSS 分散
     └─ 所有 0x2090 包集中在 **1 个队列** (如 rx-4)
        └─ 1 个 NAPI CPU 处理所有包 (如 CPU 4)
           └─ ksoftirqd + AF_PACKET 投递
              └─ CaptureWorker 进程 (TPACKET_V3 MMAP 接收)

eno7np2: streams 0x66, 0x67 (Probe 0xD003, ~87K pps) → NAPI CPU 4, RPS → CPU 0-7
eno8np3: streams 0x64, 0x65 (Probe 0x0000, ~87K pps) → NAPI CPU 12, RPS → CPU 8-15
```

**关键限制:** i40e 的 RSS hash 只支持 IP 头字段。EtherType 0x2090 是非 IP 协议，所有包 hash 到同一队列 → 单核瓶颈。

---

## 丢包层级模型

丢包可能发生在 4 个层级，需要**从底向上**逐层排查：

| 层级 | 指标 | 查看命令 | 正常值 |
|------|------|---------|--------|
| **L1: NIC 硬件** | `rx_missed_errors` | `ethtool -S <iface> \| grep rx_missed` | 增量 0/s |
| **L2: 内核 backlog** | softnet `dropped` | `cat /proc/net/softnet_stat` (第2列) | 增量 0 |
| **L3: 内核 budget** | softnet `time_squeeze` | `cat /proc/net/softnet_stat` (第3列) | 增量 0 |
| **L4: AF_PACKET ring** | `tp_drops` | `getsockopt(SOL_PACKET, PACKET_STATISTICS)` | `kern_drops=0` |

### 快速诊断脚本（5 秒增量测试）

```bash
# 在远程机器上运行
M1=$(ethtool -S eno7np2 | grep rx_missed | awk '{print $2}')
S1=$(cat /proc/net/softnet_stat)
sleep 5
M2=$(ethtool -S eno7np2 | grep rx_missed | awk '{print $2}')
S2=$(cat /proc/net/softnet_stat)
echo "rx_missed delta: $((M2-M1))"
# softnet_stat 第1列=processed, 第2列=dropped, 第3列=time_squeeze
```

---

## 已知问题与解决方案

### 问题 1: RSS 单队列瓶颈

- **症状:** `ethtool -S` 显示只有 1 个 rx-N 队列有 packets，其余全 0
- **原因:** i40e RSS 不支持非 IP 流量的 hash 分散
- **尝试过的无效方案:**
  - `ethtool -N flow-type ether proto 0x2090 action N` → `Operation not supported`
  - `ethtool -X hfunc xor` → `Operation not supported`
  - `tc filter u32 skbedit queue_mapping` → 只改 skb 标记，不影响 NAPI 上下文
- **结论:** **硬件限制，无法解决。** 必须从软件层面优化单核处理效率。

### 问题 2: netdev_budget 不足

- **症状:** `softnet_stat` 第3列 (time_squeeze) 持续增长
- **原因:** 默认 `netdev_budget=300`，87K pps 下每个 NAPI poll 周期处理不完
- **解决:** `sysctl -w net.core.netdev_budget=4096`
- **验证:** time_squeeze 增量归零
- **持久化:** 写入 `nic-tuning.sh`

### 问题 3: netdev_max_backlog 溢出

- **症状:** `softnet_stat` 第2列 (dropped) 持续增长，可达 ~29,500/s
- **原因:** RPS 将包从 NAPI CPU 转发到其他 CPU 的 backlog 队列，默认 1000 太小
- **解决:** `sysctl -w net.core.netdev_max_backlog=200000`
- **验证:** dropped 增量归零
- **持久化:** 写入 `nic-tuning.sh`

### 问题 4: 双 AF_PACKET socket NAPI 倍增

- **症状:** Counter Monitor 运行时视频抖动，暂停后稳定（4-5秒过渡期）
- **原因:** Counter Monitor 开启第二个 AF_PACKET socket，内核在 NAPI 中对每个包双倍投递
- **数据:**
  - Counter 活跃: 帧间隔 avg=409ms, >300ms 比例 89%
  - Counter 暂停: 帧间隔 avg=220ms, >300ms 比例 12%
  - `rx_missed_errors`: 活跃时 +7.4/s，暂停时 0/s
- **解决:** 内联 Counter 提取到 CaptureWorker（消除第二个 socket）
- **教训:** **绝对不要**在同一个 NIC 上开两个 AF_PACKET socket 监听同一 EtherType。

### 问题 5: CaptureWorker CPU 抢占 NAPI CPU

- **症状:** 所有 4 路视频撕裂，`ksoftirqd/4` 和 `ksoftirqd/12` 100% CPU
- **原因:** 4 个 CaptureWorker（ISP 处理密集，合计 ~640% CPU）亲和性 0-15（全部 CPU），
  会被调度到 NAPI CPU（4 和 12）上运行，抢占 softirq 处理时间 → NIC ring 溢出
- **解决:** `capture_process.py:_run_capture()` 开头用 `os.sched_setaffinity()` 设置 CPU 亲和性，**避开 NAPI CPU**
  - eno7np2 worker: `{0,1,2,3,5,6,7}` — 避开 CPU 4（NAPI）
  - eno8np3 worker: `{8,9,10,11,13,14,15}` — 避开 CPU 12（NAPI）
- **代码:**
  ```python
  _IFACE_CPU_AFFINITY = {
      'eno7np2': [0, 1, 2, 3, 5, 6, 7],
      'eno8np3': [8, 9, 10, 11, 13, 14, 15],
  }
  # in _run_capture():
  os.sched_setaffinity(0, affinity)
  ```
- **验证结果 (2026-03-12): ✅ 完美生效**
  - PID 78659/78660: mask=`0xef` → eno7np2 Worker 避开 NAPI CPU 4
  - PID 78661/78662: mask=`0xef00` → eno8np3 Worker 避开 NAPI CPU 12
  - `rx_missed_errors`: **两个网卡均为 0**（修复前: eno7np2 +9,500/s, eno8np3 +16,250/s）
  - 4 路视频画面完美，无撕裂
- **持久性:** 写在代码中（类变量 `_IFACE_CPU_AFFINITY`），每次 Worker 启动自动生效，无需系统脚本

### 问题 6: 关闭 RPS 适得其反

- **症状:** 关闭 RPS 后 `rx_missed_errors` 从 ~350/s 升到 ~4,272/s
- **原因:** 关闭 RPS 后 NAPI CPU 同时承担包接收 + 协议处理，更忙
- **教训:** 对于单队列高速流量，RPS **必须开启**，将协议处理分散到其他 CPU

---

## nic-tuning.sh 配置清单

| 配置项 | 值 | 作用 |
|--------|------|------|
| Ring Buffer RX/TX | 4096 (最大) | 增大 NIC 硬件缓冲 |
| Adaptive Coalesce | off | 最低延迟，立即触发 IRQ |
| rx-usecs | 0 | 不等待，立即中断 |
| IRQ Affinity | eno7np2→CPU 0-7, eno8np3→CPU 8-15 | 每个 NIC 独占一组 CPU |
| RPS | eno7np2→0x00ff, eno8np3→0xff00 | softirq 分散到对应 CPU 组 |
| rps_flow_cnt | 32768 | RPS flow table 大小 |
| rps_sock_flow_entries | 65536 | 全局 RPS flow table |
| netdev_budget | 4096 | NAPI poll 每周期处理上限 |
| netdev_budget_usecs | 16000 | NAPI poll 时间上限 |
| netdev_max_backlog | 200000 | RPS 每 CPU backlog 队列大小 |

### 验证清单（重启后必须检查）

```bash
# 1. sysctl
sysctl net.core.netdev_budget net.core.netdev_max_backlog

# 2. Ring buffer
ethtool -g eno7np2 | grep "Current" -A4

# 3. Coalesce
ethtool -c eno7np2 | grep -E "Adaptive|rx-usecs"

# 4. IRQ affinity
for irq in $(grep i40e-eno7np2 /proc/interrupts | awk '{print $1}' | tr -d ':'); do
    echo "IRQ $irq: $(cat /proc/irq/$irq/smp_affinity_list)"
done

# 5. RPS
cat /sys/class/net/eno7np2/queues/rx-0/rps_cpus

# 6. rx_missed 增量 (应为 0)
M1=$(ethtool -S eno7np2 | grep rx_missed | awk '{print $2}'); sleep 5
M2=$(ethtool -S eno7np2 | grep rx_missed | awk '{print $2}')
echo "delta: $((M2-M1))"
```

---

## PLP 协议参考

- **EtherType:** 0x2090
- **Counter 位置:** Ethernet Header (14B) + PLP offset 2-3 = 包偏移 **16-17 字节** (16-bit big-endian)
- **Probe ID:** 包偏移 14-15 字节 (16-bit big-endian)
- **Stream ID:** 包偏移 26-29 字节 (32-bit big-endian)
- **Packet Type:** 包偏移 22-25 字节 (0x04=数据, 0x05=帧结束, 0x06=帧开始)
- **VLAN (0x8100):** 若有 VLAN tag，所有偏移 +4 字节

---

## 排查流程图

```
视频撕裂/丢包？
  │
  ├─ 检查 rx_missed_errors 增量
  │   ├─ > 0 → L1 NIC 硬件丢包
  │   │   ├─ ksoftirqd 100%？→ CaptureWorker 抢占 NAPI CPU → 设 CPU 亲和性
  │   │   ├─ Ring buffer < 4096？→ ethtool -G 增大
  │   │   └─ 只有单队列有包？→ RSS 限制，无法硬件解决
  │   └─ = 0 → 非 NIC 层问题
  │
  ├─ 检查 softnet_stat dropped 增量
  │   ├─ > 0 → L2 backlog 溢出 → 增大 netdev_max_backlog
  │   └─ = 0 → 非 backlog 问题
  │
  ├─ 检查 softnet_stat time_squeeze 增量
  │   ├─ > 0 → L3 budget 不足 → 增大 netdev_budget
  │   └─ = 0 → 非 budget 问题
  │
  ├─ 检查 CaptureWorker kern_drops
  │   ├─ > 0 → L4 AF_PACKET ring 溢出 → 增大 BLOCK_NR
  │   └─ = 0 → 非 socket 层问题
  │
  └─ 以上都正常？→ 检查是否有第二个 AF_PACKET socket (双投递问题)
      └─ ss -f link | grep 0x2090 | wc -l → 应为 2 (每 interface 1 个)
```

---

## 修改历史

| 日期 | 变更 | 效果 |
|------|------|------|
| 2026-03-12 | 创建本文档 | — |
| 2026-03-12 | netdev_budget 1200→4096 | 消除 time_squeeze |
| 2026-03-12 | netdev_max_backlog 50K→200K | 消除 softnet drops (~29,500/s→0) |
| 2026-03-12 | Counter Monitor 改为内联模式 | 消除双 AF_PACKET socket 的 NAPI 倍增 |
| 2026-03-12 | CaptureWorker CPU 亲和性 | ✅ rx_missed 从 25,750/s → 0，4路视频完美 |
| 2026-03-12 | Counter Monitor 启动时序修复 | _start_counter_monitor 移到 Worker 启动之后 |
