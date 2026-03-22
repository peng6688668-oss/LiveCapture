# CM CAN Combo Simulator — 协议分析与模拟方案

## 1. 抓包发现 (2026-03-22)

### 1.1 CM CAN Combo 使用 PLP (0x2090)，不是 TECMP (0x99FE)

所有帧 EtherType = 0x2090。CM CAN Combo 手册第15页图3-2虽然标注"TECMP/Legacy: 0x99FE"，
但实际抓包全部是 0x2090。可能是通过 CCA 中转后变为 PLP 封装。

### 1.2 CM CAN Combo 关键参数

| 参数 | 值 | 位置 |
|------|-----|------|
| MAC | `38:2a:19:80:78:56` | Ethernet Src |
| DeviceID | `0x0041` | PLP Header [0:2] |
| Version | `3` | PLP Header [4] |
| CM_ID | `0x000F` | Entry Header [0:2] |

### 1.3 三种消息类型

#### Status Device (MsgType=0x01) — 每秒1次

```
PLP Header:
  DeviceID = 0x0041
  Counter  = 递增
  Version  = 3
  MsgType  = 0x01 (Status Device)
  DataType = 0x0000
  Flags    = 0x00000007

Entry Header:
  CM_ID        = 0x000F
  InterfaceID  = 0xFF02
  DataLen      = 46 (0x2E)
  DataFlags    = 0x0F00

Payload (46 bytes) — 设备信息:
  [0000] 0C 01 04 00 00 18 00 41 01 66 47 05 00 15 07 82
  [0016] 03 03 00 00 00 00 00 02 00 00 1D 82 ...
  包含: 硬件版本、固件版本、序列号等
```

#### Status Bus (MsgType=0x02) — 每秒1次

```
PLP Header:
  DeviceID = 0x0041
  Counter  = 递增
  Version  = 3
  MsgType  = 0x02 (Status Bus)
  DataType = 0x0000
  Flags    = 0x00000007

Entry Header:
  CM_ID        = 0x000F
  InterfaceID  = 0xFF00
  DataLen      = 120 (0x78)
  DataFlags    = 0x0000

Payload (120 bytes) — 总线列表:
  [0016] 0C 01 04 00 00 00 00 41 01 66 47 05 00 00
  [0030] 00 11 00 00 3D DE 00 00 00 04   → bus 0x11 (CAN Ch.1), type=0x3DDE, flags=0x04
  [0038] 00 00 00 12 00 00 3D DE 00 00 00 04   → bus 0x12 (CAN Ch.2)
  [0046] 00 00 00 13 00 00 3D DE 00 00 00 04   → bus 0x13 (CAN Ch.3) ← plp stream用的就是这个
  [0054] 00 00 00 14 00 00 3D DE 00 00 00 04   → bus 0x14 (CAN Ch.4)
  [0062] 00 00 00 15 00 00 3D DE 00 00 00 04   → bus 0x15 (CAN Ch.5)
  [0070] 00 00 00 16 00 00 3D DE 00 00 00 04   → bus 0x16 (CAN Ch.6)
  后续全0填充

总线列表结构 (每个 8 bytes):
  [0:4] InterfaceID (big-endian uint32)
  [4:6] BusType (0x3DDE = CAN?)
  [6:8] Flags (0x0004)

6个CAN通道: 0x11=17, 0x12=18, 0x13=19, 0x14=20, 0x15=21, 0x16=22
```

#### Log Stream (MsgType=0x03) — CAN 数据帧

目前抓到的 Log Stream 帧全部来自 CCA (DevID=0xD003)，DataType=0x0101 (CAN PHY)。
CM CAN Combo 的 CAN 数据帧 (DataType=0x0002) 需要在 CAN 总线上有实际流量时才会产生。

预期格式:
```
PLP Header:
  DeviceID = 0x0041
  MsgType  = 0x03 (Log Stream)
  DataType = 0x0002 (CAN Data)
  Version  = 3

Entry Header:
  CM_ID       = 0x000F
  InterfaceID = 0x0013 (对应 CAN Ch.3)
  Timestamp   = 纳秒时间戳
  DataLen     = 5 + DLC (CAN payload)
  DataFlags   = 0x0000

CAN Payload:
  [0:4] CAN_ID (big-endian, bit31=extended flag)
  [4]   DLC
  [5:]  Data bytes
```

## 2. 0x13 的来源

`0x13` (decimal 19) 是 CM CAN Combo 的**第3个CAN通道的 InterfaceID**。
- CM CAN Combo 在 Status Bus 消息中报告 6 个 CAN 通道: 0x11-0x16
- CCA 收到 Status Bus 后自动创建 PLP 接口
- 用户在 CCA 的 plp stream 配置中选择 bus_id=0x13
- CCA 将 InterfaceID=0x13 的 CAN 数据转发到指定网口

## 3. 模拟方案

### 3.1 Simulator 需要发送的消息

1. **Status Device** (MsgType=0x01): 注册设备，每秒1次
2. **Status Bus** (MsgType=0x02): 注册总线列表，每秒1次
3. **Log Stream** (MsgType=0x03): CAN 数据帧，按用户设定的间隔

### 3.2 Simulator 可配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| DeviceID | 0x0041 | 模拟设备ID |
| CM_ID | 0x000F | Capture Module ID |
| InterfaceID | 0x0013 | CAN通道ID (对应CCA的bus_id) |
| CAN ID | 0x069 | CAN帧ID |
| 网口 | eno3 | 发送接口 |

### 3.3 关键发现

- CM CAN Combo 使用 PLP V3 (不是 V2)
- EtherType = 0x2090 (不是 0x99FE)
- 目标 MAC = 01:00:5e:00:00:00 (组播)
- CCA 必须先收到 Status Device + Status Bus 才能识别数据帧
- Flags 字段在 Status 消息中 = 0x00000007

## 4. CCA 侧配置要求

1. 接收端口 (E23): `plp_enabled = true`
2. `plp_processing 1`: `plp_processing_enable = true`
3. `plp_processing 1` → `plp_bus_ids`: 选择 Simulator 注册的 bus
4. `plp stream 0`: `bus_ids` = 同一个 bus, `eth_port` = 输出端口

## 5. Log Stream CAN 数据帧 — 真实抓包 (2026-03-22 第二次抓包)

### 5.1 抓包结果

10秒内从 CM CAN Combo (MAC 38:2a:19:80:78:56) 抓到 166 帧:
- Status Device (0x01): 2 帧 (每秒1次)
- Status Bus (0x02): 2 帧 (每秒1次)
- **Log Stream CAN Data (0x03, 0x0002): 162 帧** ← 关键数据！

### 5.2 Log Stream CAN Data 精确格式

```
帧总大小: 60 bytes (Ethernet 14 + PLP Header 12 + Entry 16 + CAN 15 + padding 3)

PLP Header (12 bytes):
  [0:2]  DeviceID    = 0x0041
  [2:4]  Counter     = 递增 (如 41676, 41677, ...)
  [4]    Version     = 3
  [5]    MsgType     = 0x03 (Log Stream)
  [6:8]  DataType    = 0x0002 (CAN Data)
  [8:12] Flags       = 0x00000007

Entry Header (16 bytes):
  [0:2]  CM_ID       = 0x0000  ← 注意! 数据帧中CM_ID=0, 不是0x000F
  [2:4]  InterfaceID = 0x0013 (19)  ← 对应CAN通道
  [4:12] Timestamp   = 纳秒时间戳
  [12:14] DataLen    = 15 (= 4 + 1 + 8 = CAN_ID + DLC + 8字节数据 + 2字节padding?)
  [14:16] DataFlags  = 0x0001

CAN Payload (15 bytes):
  [0:4]  CAN_ID      = 0x00000123 (STD, 0x123)
  [4]    DLC         = 8
  [5:13] Data        = 00 11 22 33 44 55 66 77
  [13:15] (padding)  = 2 bytes
```

### 5.3 关键差异: Status消息 vs Log Stream

| 字段 | Status Device/Bus | Log Stream CAN |
|------|------------------|----------------|
| CM_ID | 0x000F | **0x0000** |
| InterfaceID | 0xFF02 / 0xFF00 | **0x0013** (通道号) |
| DataFlags | 0x0F00 / 0x0000 | **0x0001** |
| Flags (Header) | 0x00000007 | 0x00000007 |
| DataLen | 46 / 120 | **15** (CAN帧大小) |

### 5.4 InterfaceID 分布 (6个CAN通道均匀分布)

```
InterfaceID=0x0011 (dec=17): 27 frames  → CAN Ch.1
InterfaceID=0x0012 (dec=18): 27 frames  → CAN Ch.2
InterfaceID=0x0013 (dec=19): 27 frames  → CAN Ch.3
InterfaceID=0x0014 (dec=20): 27 frames  → CAN Ch.4
InterfaceID=0x0015 (dec=21): 27 frames  → CAN Ch.5
InterfaceID=0x0016 (dec=22): 27 frames  → CAN Ch.6
```

CAN数据 (CAN_ID=0x123, Data=00 11 22 33 44 55 66 77) 在6个通道上同时出现。

### 5.5 Status Bus Payload 修正

之前 BusType 字段误读为 0x3DDE，实际第二次抓包显示:
```
  00 00 00 11 00 00 43 02 00 00 00 04  → bus 0x11, type=0x4302, flags=0x04
  00 00 00 12 00 00 43 02 00 00 00 04  → bus 0x12
  00 00 00 13 00 00 43 02 00 00 00 04  → bus 0x13
  ...
```
BusType = 0x4302 (可能随CAN配置变化，之前是0x3DDE)

## 6. 完整模拟方案 (更新)

### 6.1 Simulator Start 流程

```
1. 打开 Raw Socket (AF_PACKET, eno3, 0x2090)
2. 启动 Status Timer (每秒):
   - 发送 Status Device (MsgType=0x01)
   - 发送 Status Bus (MsgType=0x02, 包含 InterfaceID 列表)
3. 启动 Data Timer (按用户间隔):
   - 发送 Log Stream CAN Data (MsgType=0x03, DataType=0x0002)
   - Entry中 CM_ID=0x0000, InterfaceID=用户设置的通道号
   - DataFlags=0x0001
```

### 6.2 Simulator Stop 流程

```
1. 停止 Data Timer
2. 停止 Status Timer
3. 关闭 Raw Socket
```

## 7. 实现的 UI 布局

### 7.1 CAN Simulator 界面

```
Row 0: [DBC] | Pattern:[▼] | Protokoll:[PLP▼] | Netzwerk:[eno3▼] | ☑Echo-Filter | RTT:---
Row 1: Modus:[Zyklisch▼] | Intervall:[100ms] | Anzahl:[Endlos]
Row 2: DevID:[0x0041] | CM:[0x000F] | IF:[0x0013] | CAN ID:[0x069] | Ext | DLC:[8] | Daten:[...] | [▶ Generieren] | [▶ Start] | [⬛ Stop]
```

### 7.2 控件说明

| 控件 | 默认值 | 来源 | 说明 |
|------|--------|------|------|
| DevID | 0x0041 | PLP Header [0:2] | 设备标识 (CM CAN Combo = 0x0041) |
| CM | 0x000F | Entry Header [0:2] | Capture Module ID (Status消息中使用) |
| IF | 0x0013 | Entry Header [2:4] | Interface ID = CAN通道号 (= CCA bus_id) |
| CAN ID | 0x069 | CAN Payload [0:4] | CAN帧的Arbitration ID |
| Protokoll | PLP | — | PLP(0x2090) / TECMP(0x99FE) / CMP(0x99FE) |
| Netzwerk | eno3 | — | 发送用的网口 |
| Echo-Filter | ☑ | — | 过滤RX中自发帧 (Src MAC = 本机) |

## 8. Start/Stop 完整流程

### 8.1 Start 流程

```
用户点击 [▶ Start]:
  │
  ├── 1. 打开 Raw Socket (AF_PACKET, eno3, EtherType=0x2090)
  │
  ├── 2. 启动 Status Timer (每1秒):
  │     ├── 发送 Status Device (MsgType=0x01)
  │     │     DevID=0x0041, CM_ID=0x000F, InterfaceID=0xFF02
  │     │     DataLen=46, DataFlags=0x0F00
  │     │     → CCA 识别设备
  │     │
  │     └── 发送 Status Bus (MsgType=0x02)
  │           DevID=0x0041, CM_ID=0x000F, InterfaceID=0xFF00
  │           DataLen=120, DataFlags=0x0000
  │           Payload 包含 Bus 列表: IF=0x0013, BusType=0x4302
  │           → CCA 创建 PLP 接口, bus 出现在 Interfaces > PLP
  │
  ├── 3. 立即发送第一组 Status (不等1秒)
  │
  └── 4. 启动 Data Timer (按用户设定的间隔):
        └── 每N ms 发送 Log Stream (MsgType=0x03)
              DevID=0x0041, DataType=0x0002 (CAN Data)
              CM_ID=0x0000, InterfaceID=0x0013
              DataFlags=0x0001, Flags=0x00000007
              CAN Payload: CAN_ID + DLC + Data
              目标 MAC: 01:00:5e:00:00:00 (组播)
```

### 8.2 Stop 流程

```
用户点击 [⬛ Stop]:
  │
  ├── 1. 停止 Data Timer
  ├── 2. 停止 Status Timer
  └── 3. 关闭 Raw Socket
```

### 8.3 Generieren (单次发送)

```
用户点击 [▶ Generieren]:
  │
  ├── 1. 临时打开 Raw Socket
  ├── 2. 发送一帧 Log Stream CAN Data
  └── 3. 关闭 Raw Socket
  注: 单次发送不发 Status 消息
```

## 9. 数据流全链路

### 9.1 发送链路 (Simulator → CCA)

```
LiveCapture CAN Simulator
  │ [Start]
  ▼
eno3 (Raw Socket, AF_PACKET, 0x2090)
  │ PLP Status Device + Status Bus (每秒)
  │ PLP Log Stream CAN Data (每N ms)
  ▼
CCA E23 (plp_enabled=true)
  │
  ├── plp_processing 1 (解析PLP帧)
  │     plp_bus_ids 包含 Simulator 注册的 bus (IF=0x0013)
  │
  └── plp stream 0 (转发)
        bus_ids = 0x0013
        eth_port = E22
  │
  ▼
CCA E22 (输出)
  │
  ▼
eno4 (接收)
  │ dumpcap 抓包
  ▼
LiveCapture RX 表格 (Live CAN)
  显示 CCA 回传的 CAN 数据帧
```

### 9.2 对比视图

```
┌─────────────────────────────┐
│ SIM — Simulierte CAN-Frames │  ← 本地生成的帧 (淡紫/白 交替行)
│ Nr.  Zeit    CAN ID  Data   │
│ 1    0.100   0x069   ...    │
│ 2    0.200   0x069   ...    │
├─────────────────────────────┤
│ RX — Empfangene Daten       │  ← CCA 回传的帧 (从 eno4 接收)
│ Nr.  Zeit    IF-19   0x069  │
│ 1    0.105   IF-19   ...    │  ← RTT ≈ 5ms
│ 2    0.205   IF-19   ...    │
└─────────────────────────────┘
```

## 10. CCA 侧配置清单

### 10.1 接收端口 (E23)

```
Konfiguration > Schnittstellen > E23 > Port:
  enable = ✓
  plp_enabled = ✓

Konfiguration > Schnittstellen > E23 > Raw Eth (Sniffer):
  (可选, 用于调试)
```

### 10.2 PLP Processing

```
Konfiguration > Verarbeitung > plp_processing 1:
  plp_processing_enable = ✓
  plp_bus_ids = [Simulator注册的bus]  ← Start后出现在列表中
```

### 10.3 PLP Stream

```
Konfiguration > Verarbeitung > plp stream 0:
  enable = ✓
  bus_ids = [同一个bus]
  eth_port = E22 (1G)
```

### 10.4 输出端口 (E22)

```
Konfiguration > Schnittstellen > E22 > Port:
  enable = ✓
  (plp_enabled 可以关闭, E22 只做输出)
```

## 11. 待验证

- [ ] 模拟的 Status Device/Bus 发送后 CCA 是否创建 PLP 接口
- [ ] Status Bus Payload 前14字节的精确结构 (当前简化实现)
- [ ] Log Stream 帧 DataLen=15 中是否有padding
- [ ] DataFlags=0x0001 的含义
- [ ] BusType 0x4302 vs 0x3DDE 的区别 (CAN配置相关?)
- [ ] 单次 Generieren 不发 Status 消息时 CCA 能否处理
- [ ] CCA REST API 是否可以自动查询 PLP 接口注册状态
