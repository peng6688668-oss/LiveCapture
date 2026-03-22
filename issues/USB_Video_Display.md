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
**结果:** 🔄 部署中...

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

### 尝试 8: guvcview / leopard_cam (备选)
Leopard 文档推荐的 Linux 工具，如果 spawn 方案失败可以分析其 V4L2 配置。
