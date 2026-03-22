# USB Video Display — 问题排查记录

## 目标
在 LiveCapture 的 Live Video 面板中显示来自 USB 摄像头 (LI-GW5200 + IMX490) 的实时视频。

## 硬件
- **USB BOX:** LI-GMSL2-FP-USB-BOX (设备名 LI-GW5200)
- **摄像头:** LI-IMX490-GW5400-GMSL2
- **固件:** 2024_06_07，支持 2880×1860 @ 25fps YUYV
- **连接:** GMSL2 Fakra → USB 3.0 (SuperSpeed 5Gbps)

## 参考实现
Messtechnik `video_player.py` 在 WSL2 上流畅运行：
- `ffmpeg.exe -f dshow -video_size 2880x1860 -i "video=LI-GW5200"` (Windows DirectShow)
- H.264 编码 → UDP → OpenCV 读取
- 实际帧率: ~13 fps (截图显示)

## 远程机器环境
- **系统:** Ubuntu 24.04 原生 Linux (非 WSL2)
- **内核:** 6.8.0-106-generic
- **UVC驱动:** uvcvideo, UVC 1.10
- **V4L2报告:** YUYV 2880×1860 @ 60fps (与固件标称25fps不符)

---

## 尝试记录

### 尝试 1: OpenCV V4L2 直读 (QThread)
**方法:** `USBCameraCaptureThread(QThread)` 中 `cv2.VideoCapture(0, cv2.CAP_V4L2)`
**结果:** ❌ `select() timeout` 每10秒一次，几乎无帧输出
**原因:** Qt Event-Loop 干扰 V4L2 的 select() 系统调用

### 尝试 2: ffmpeg (Linux) V4L2 → H.264 → UDP → OpenCV
**方法:** `ffmpeg -f v4l2 -i /dev/video0 -c:v libx264 -f mpegts udp://127.0.0.1:5004`
**结果:** ❌ ffmpeg 报告 `Dequeued v4l2 buffer contains corrupted data (0 bytes)`，几乎无UDP输出
**原因:** ffmpeg 内部也遇到 V4L2 空帧问题；UDP 连接需要长时间等待

### 尝试 3: ffmpeg (Windows) DirectShow → UDP (WSL2 方案)
**方法:** `ffmpeg.exe -f dshow -i "video=LI-GW5200"` (仅适用于WSL2)
**结果:** ❌ 远程机器是原生Linux，无Windows，方案不适用
**原因:** 远程机器无 ffmpeg.exe / DirectShow

### 尝试 4: OpenCV V4L2 直读 (multiprocessing.Process)
**方法:** V4L2 采集放入独立进程，通过 Queue 传帧给 QThread
**结果:** ❌ 仍然 `select() timeout`，子进程 fork 继承了父进程状态
**原因:** 可能是 fork 方式继承了 Qt 的文件描述符/信号处理器

### 关键发现: 独立 Python 脚本测试
**方法:** `python3 -c "import cv2; cap=cv2.VideoCapture(0, cv2.CAP_V4L2); ..."`
**结果:** ✅ **22fps 稳定，3956帧/180秒，首帧0.2秒，97%帧连续**
**结论:** V4L2 硬件完全正常！问题 100% 在 LiveCapture 进程环境

---

## 关键对比

| 条件 | 结果 | 帧率 |
|------|------|------|
| 独立 python3 脚本 | ✅ 流畅 | 22 fps |
| LiveCapture QThread | ❌ timeout | ~0 fps |
| LiveCapture multiprocessing (fork) | ❌ timeout | ~0 fps |
| Messtechnik WSL2 DirectShow | ✅ 流畅 | 13 fps |

## 待尝试

### 尝试 5: 确认 sudo / venv 无关
**方法:** 分别用 普通用户、sudo、sudo+venv 运行独立脚本
**结果:** ✅ 全部 20fps，sudo 和 venv 不影响
**结论:** 排除权限/环境问题

### 尝试 6: multiprocessing spawn 模式 (独立脚本)
**方法:** `multiprocessing.get_context('spawn').Process(target=worker)`
**结果:** ✅ **22.5fps，113帧/5秒**
**结论:** spawn 模式完全隔离 Qt 状态，V4L2 正常工作

### 尝试 7: 修改 LiveCapture 用 spawn 替代 fork
**方法:** `ctx = multiprocessing.get_context('spawn')` 创建 Process/Queue/Event
**结果:** ❌ 仍然 `select() timeout` @11s, @21s, @42s。/dev/video0 最终消失。
**原因:** spawn 子进程的 stderr 中仍有 V4L2 timeout，UVC 驱动再次进入坏状态。
spawn 虽然不继承 Qt 状态，但可能继承了某些内核层面的 socket/fd 状态。

### 尝试 8: subprocess.Popen 完全独立脚本 (计划中)
**方法:** 用 subprocess.Popen 启动独立 Python 脚本，通过 Unix socket 传帧。
完全独立的进程，无任何继承关系。
独立脚本测试已确认 22fps 可用。

---

## 根因分析

**fork vs spawn:**
- `fork`: 子进程继承父进程的所有状态（文件描述符、信号处理器、线程）
  → Qt 的 Event-Loop / XCB 连接 / 信号处理器被复制到子进程
  → V4L2 的 select() 被 Qt 继承的 fd/signal 干扰 → timeout
- `spawn`: 启动全新 Python 解释器，不继承任何父进程状态
  → V4L2 在干净环境中运行 → 22fps 正常

**UVC 驱动坏状态:**
- V4L2 `select() timeout` 后，UVC 驱动进入异常状态 (dmesg: -71 EPROTO)
- 必须 `modprobe -r uvcvideo && modprobe uvcvideo` 恢复
- 后续任何进程（包括独立脚本）都无法打开摄像头，直到驱动重载

## 待尝试

### 尝试 8: subprocess.Popen + Unix Socket (完全独立进程)
**方法:** `core/usb_capture_worker.py` 独立脚本，通过 Unix Domain Socket 传 JPEG 帧
**结果:** ⚠️ 部分成功 — subprocess 正确隔离(无 select timeout 错误)，帧到达 RenderThread
但 UVC 驱动仍在数秒后崩溃，/dev/video0 消失。subprocess CPU 65.7% (空转)。

### 发现: UVC 驱动崩溃是硬件/固件层面问题
- USB 重置 + 模块重载后仍然 0 帧 select timeout
- 摄像头可能进入了需要完整电源循环才能恢复的坏状态
- Leopard 文档要求: **12V 电源必须在 USB 之前连接** (步骤不可逆)
- 之前 22fps 的独立测试是在摄像头新鲜连接时进行的

### 待尝试: 完整电源循环后重新测试
1. 拔 USB → 拔 12V → 等 5 秒 → 接 12V → 接 USB
2. 验证独立脚本是否仍能 22fps
3. 如果是，用 subprocess 方案在 LiveCapture 中测试

### 尝试 9: CPU 绑定 (taskset)
**方法:** 把 worker 绑定到 USB 中断所在的 CPU 10
**结果:** ❌ 无效

### 尝试 10: 决定性测试 — LiveCapture 运行时独立脚本
**方法:** 杀掉 worker 后手动运行独立 Python 脚本（LiveCapture 主进程仍在运行）
**结果:** ❌ 独立脚本也超时！证明主进程在系统层面干扰 USB

### 根因确认: llvmpipe 软件渲染吃光 CPU
**发现:** `top -H` 显示 12 个 `llvmpipe` 线程各占 10% CPU = 120% 总 CPU
- llvmpipe = Mesa 软件 OpenGL（远程机器没有 GPU）
- Qt WebEngine 的 Chromium 渲染器触发了软件 OpenGL
- 系统负载 11.0（16 核机器），USB 中断无法及时处理

### 修复: LP_NUM_THREADS=2
**方法:** 在 `run.py` 中设置 `os.environ.setdefault('LP_NUM_THREADS', '2')`
**预期:** llvmpipe 从 12 线程降到 2 线程，释放 ~100% CPU，USB 中断恢复正常
