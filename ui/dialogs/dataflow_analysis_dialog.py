"""数据流全链路分析 — CAN帧 -> TECMP/PLP 以太网帧 数据封装流程."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import Qt


# ── HTML Template ─────────────────────────────────────────────────────

_CSS = """
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
          --blue: #58a6ff; --green: #3fb950; --orange: #d29922; --red: #f85149;
          --purple: #bc8cff; --cyan: #39d2c0; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg);
         color: var(--text); padding: 24px; line-height: 1.7; }
  h1 { font-size: 22px; color: var(--blue); border-bottom: 2px solid var(--blue);
       padding-bottom: 8px; margin-bottom: 20px; }
  h2 { font-size: 17px; color: var(--cyan); margin: 28px 0 14px 0; }
  h3 { font-size: 14px; color: var(--purple); margin: 20px 0 10px 0; }
  p { margin: 10px 0; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
          padding: 18px; margin: 14px 0; }
  .highlight { background: #1a2332; border-left: 4px solid var(--blue);
               padding: 14px 18px; margin: 14px 0; border-radius: 0 6px 6px 0; }
  .warn { background: #2a1f0d; border-left: 4px solid var(--orange);
          padding: 14px 18px; margin: 14px 0; border-radius: 0 6px 6px 0; }
  .success { background: #0d2818; border-left: 4px solid var(--green);
             padding: 14px 18px; margin: 14px 0; border-radius: 0 6px 6px 0; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; }
  th { background: #21262d; color: var(--blue); text-align: left; padding: 10px 14px;
       border: 1px solid var(--border); font-size: 13px; }
  td { padding: 8px 14px; border: 1px solid var(--border); font-size: 13px; }
  tr:hover { background: #1c2128; }
  code { background: #1c2128; color: var(--orange); padding: 2px 6px; border-radius: 3px;
         font-family: 'Consolas', 'Fira Code', monospace; font-size: 12px; }
  .mono { font-family: 'Consolas', monospace; font-size: 12px; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
         font-weight: 600; margin: 0 2px; }
  .tag-blue { background: #1a3a5c; color: var(--blue); }
  .tag-green { background: #0d2818; color: var(--green); }
  .tag-orange { background: #2a1f0d; color: var(--orange); }
  .tag-red { background: #2d1117; color: var(--red); }
  .tag-purple { background: #231a3a; color: var(--purple); }
  /* Flow diagram */
  .flow { display: flex; align-items: stretch; gap: 0; margin: 20px 0; flex-wrap: nowrap; }
  .flow-node { background: var(--card); border: 2px solid var(--border); border-radius: 10px;
               padding: 14px; text-align: center; min-width: 180px; flex: 1; }
  .flow-node h4 { color: var(--blue); font-size: 13px; margin-bottom: 6px; }
  .flow-node p { font-size: 11px; color: #8b949e; margin: 2px 0; }
  .flow-node.active { border-color: var(--green); box-shadow: 0 0 12px rgba(63,185,80,0.2); }
  .flow-node.device { border-color: var(--orange); }
  .flow-node.software { border-color: var(--purple); }
  .flow-arrow { display: flex; align-items: center; justify-content: center;
                color: var(--cyan); font-size: 22px; padding: 0 4px; min-width: 36px; }
  .flow-arrow span { font-size: 10px; color: #8b949e; display: block; }
  /* Byte map */
  .byte-map { display: flex; flex-wrap: wrap; gap: 2px; margin: 10px 0; }
  .byte { display: inline-flex; align-items: center; justify-content: center;
          width: 36px; height: 28px; font-family: 'Consolas', monospace; font-size: 11px;
          border-radius: 3px; font-weight: 600; }
  .b-eth { background: #1a3a5c; color: var(--blue); }
  .b-tecmp { background: #2a1f0d; color: var(--orange); }
  .b-entry { background: #231a3a; color: var(--purple); }
  .b-can { background: #0d2818; color: var(--green); }
  .b-data { background: #2d1117; color: var(--red); }
  .legend { display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0; }
  .legend-item { display: flex; align-items: center; gap: 6px; font-size: 12px; }
  .legend-color { width: 14px; height: 14px; border-radius: 3px; }
  /* Decision tree */
  .decision { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
              padding: 16px; margin: 10px 0; }
  .decision-node { margin: 6px 0 6px 20px; padding: 8px 14px; border-radius: 6px;
                   border-left: 3px solid var(--border); }
  .decision-q { background: #1a2332; border-left-color: var(--blue); font-weight: 600; }
  .decision-yes { background: #0d2818; border-left-color: var(--green); margin-left: 44px; }
  .decision-no { background: #2d1117; border-left-color: var(--red); margin-left: 44px; }
  .decision-action { background: #231a3a; border-left-color: var(--purple); margin-left: 68px; }
  svg text { font-family: 'Segoe UI', sans-serif; }
</style>
"""


def _page(title, html):
    return _CSS + "<h1>" + title + "</h1>" + html


_CONTENT = {}
_PAGE_ORDER = []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Page 1: 全链路总览
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('全链路总览')
_CONTENT['全链路总览'] = _page('CAN 帧 → TECMP/PLP 以太网帧 — 全链路总览', """
<p>CAN 帧从 PCAN USB Pro FD 发出，经过 Technica CAN COMBO 设备封装为 TECMP 以太网帧，
最终被 Live Capture 程序接收和解析。</p>

<div class="flow">
  <div class="flow-node active">
    <h4>🔧 PCAN USB Pro FD</h4>
    <p>CAN 总线接口</p>
    <p><code>ID=0x123</code></p>
    <p><code>DLC=8</code></p>
    <p class="mono">00 11 22 33 44 55 66 77</p>
  </div>
  <div class="flow-arrow">→<br><span>CAN<br>Bus</span></div>
  <div class="flow-node device">
    <h4>📡 Technica CAN COMBO</h4>
    <p>CAN → TECMP 转换</p>
    <p>Interface ID: <code>0x0013</code></p>
    <p>33 帧/包 批量封装</p>
    <p>纳秒级时间戳</p>
  </div>
  <div class="flow-arrow">→<br><span>Ethernet<br>0x2090</span></div>
  <div class="flow-node software">
    <h4>💻 Live Capture (eno4)</h4>
    <p>TECMP 解码器</p>
    <p>还原 CAN ID: <code>0x123</code></p>
    <p>还原数据: <code>00 11 22...</code></p>
    <p>显示在 RX 表格</p>
  </div>
</div>

<h2>关键结论</h2>
<div class="success">
  <b>✅ CAN ID 全程保持不变。</b><br>
  <code>0x0013</code> 不是 CAN ID！它是 Technica CAN COMBO 的 <b>Interface ID</b>（接口/通道编号 = 19），
  是 TECMP 协议 Entry Header 中的一个字段。真正的 CAN ID <code>0x0123</code> 被完整保存在
  TECMP Entry 的 CAN Payload 内部（4 字节大端序：<code>00 00 01 23</code>）。
</div>

<div class="highlight">
  <b>💡 性能优化：批量封装</b><br>
  Technica CAN COMBO 将多个 CAN 帧（约 33 帧 ≈ 10ms 数据量）打包到一个 983 字节的以太网帧中，
  大幅降低了以太网帧的开销。每个 CAN 帧仅占用 29 字节（16 字节 Entry Header + 13 字节 CAN Payload）。
</div>

<h2>协议层次对比</h2>
<table>
  <tr><th>层次</th><th>协议</th><th>关键字段</th><th>说明</th></tr>
  <tr><td><span class="tag tag-blue">L2</span></td><td>Ethernet</td>
      <td><code>EtherType=0x2090</code></td><td>TECMP/PLP 专用 EtherType</td></tr>
  <tr><td><span class="tag tag-orange">L3</span></td><td>TECMP Header</td>
      <td><code>Data Type=0x0002</code></td><td>标识载荷为 CAN Data</td></tr>
  <tr><td><span class="tag tag-purple">L4</span></td><td>TECMP Entry</td>
      <td><code>Interface ID=0x0013</code></td><td>Technica 设备的 CAN 通道号</td></tr>
  <tr><td><span class="tag tag-green">L5</span></td><td>CAN Frame</td>
      <td><code>CAN ID=0x0123</code></td><td>原始 CAN 帧 ID，完整保留</td></tr>
</table>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Page 2: TECMP 帧结构
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('TECMP 帧结构')
_CONTENT['TECMP 帧结构'] = _page('TECMP/PLP 以太网帧结构 (EtherType 0x2090)', """
<p>一个完整的 TECMP 以太网帧包含三个层次：</p>

<h2>字节级结构 (前 60 字节示例)</h2>
<div class="card">
<div class="legend">
  <div class="legend-item"><div class="legend-color" style="background:#1a3a5c"></div> Ethernet Header</div>
  <div class="legend-item"><div class="legend-color" style="background:#2a1f0d"></div> TECMP Header</div>
  <div class="legend-item"><div class="legend-color" style="background:#231a3a"></div> Entry Header</div>
  <div class="legend-item"><div class="legend-color" style="background:#0d2818"></div> CAN ID</div>
  <div class="legend-item"><div class="legend-color" style="background:#2d1117"></div> CAN Data</div>
</div>
<div class="byte-map">
  <div class="byte b-eth">01</div><div class="byte b-eth">00</div>
  <div class="byte b-eth">5E</div><div class="byte b-eth">00</div>
  <div class="byte b-eth">00</div><div class="byte b-eth">00</div>
  <div class="byte b-eth">42</div><div class="byte b-eth">7A</div>
  <div class="byte b-eth">2E</div><div class="byte b-eth">8E</div>
  <div class="byte b-eth">D6</div><div class="byte b-eth">A3</div>
  <div class="byte b-eth">20</div><div class="byte b-eth">90</div>
  <div class="byte b-tecmp">00</div><div class="byte b-tecmp">00</div>
  <div class="byte b-tecmp">00</div><div class="byte b-tecmp">52</div>
  <div class="byte b-tecmp">02</div><div class="byte b-tecmp">03</div>
  <div class="byte b-tecmp">00</div><div class="byte b-tecmp">02</div>
  <div class="byte b-tecmp">00</div><div class="byte b-tecmp">00</div>
  <div class="byte b-tecmp">00</div><div class="byte b-tecmp">0F</div>
  <div class="byte b-entry">00</div><div class="byte b-entry">00</div>
  <div class="byte b-entry">00</div><div class="byte b-entry">13</div>
  <div class="byte b-entry">18</div><div class="byte b-entry">9E</div>
  <div class="byte b-entry">33</div><div class="byte b-entry">5B</div>
  <div class="byte b-entry">1C</div><div class="byte b-entry">03</div>
  <div class="byte b-entry">53</div><div class="byte b-entry">27</div>
  <div class="byte b-entry">00</div><div class="byte b-entry">0D</div>
  <div class="byte b-entry">00</div><div class="byte b-entry">01</div>
  <div class="byte b-can">00</div><div class="byte b-can">00</div>
  <div class="byte b-can">01</div><div class="byte b-can">23</div>
  <div class="byte b-data">08</div>
  <div class="byte b-data">00</div><div class="byte b-data">11</div>
  <div class="byte b-data">22</div><div class="byte b-data">33</div>
  <div class="byte b-data">44</div><div class="byte b-data">55</div>
  <div class="byte b-data">66</div><div class="byte b-data">77</div>
</div>
</div>

<h2>Ethernet Header (14 字节)</h2>
<table>
  <tr><th>偏移</th><th>字段</th><th>值</th><th>说明</th></tr>
  <tr><td><code>0-5</code></td><td>Dst MAC</td><td class="mono">01:00:5E:00:00:00</td><td>IPv4 组播地址</td></tr>
  <tr><td><code>6-11</code></td><td>Src MAC</td><td class="mono">42:7A:2E:8E:D6:A3</td><td>Technica CAN COMBO</td></tr>
  <tr><td><code>12-13</code></td><td>EtherType</td><td><code>0x2090</code></td><td>TECMP/PLP 标识</td></tr>
</table>

<h2>TECMP Header (12 字节)</h2>
<table>
  <tr><th>偏移</th><th>字段</th><th>长度</th><th>示例值</th><th>说明</th></tr>
  <tr><td><code>+0</code></td><td>Device ID</td><td>2B</td><td><code>0x0000</code></td><td>Capture Module 设备 ID</td></tr>
  <tr><td><code>+2</code></td><td>Counter</td><td>2B</td><td><code>0x0052</code></td><td>帧序列号 (82)</td></tr>
  <tr><td><code>+4</code></td><td>Version</td><td>1B</td><td><code>0x02</code></td><td>TECMP 版本 2</td></tr>
  <tr><td><code>+5</code></td><td>Msg Type</td><td>1B</td><td><code>0x03</code></td><td>Log Stream</td></tr>
  <tr><td><code>+6</code></td><td>Data Type</td><td>2B</td><td><code>0x0002</code></td><td><b>CAN Data</b></td></tr>
  <tr><td><code>+8</code></td><td>Flags</td><td>4B</td><td><code>0x0000000F</code></td><td>传输标志</td></tr>
</table>

<h2>Entry Header (16 字节 × N)</h2>
<table>
  <tr><th>偏移</th><th>字段</th><th>长度</th><th>示例值</th><th>说明</th></tr>
  <tr><td><code>+0</code></td><td>CM ID</td><td>2B</td><td><code>0x0000</code></td><td>Capture Module 子 ID</td></tr>
  <tr><td><code>+2</code></td><td><b>Interface ID</b></td><td>2B</td>
      <td><code style="color:#f85149">0x0013</code></td>
      <td>⚠️ <b>这就是你看到的 "0x13"！</b><br>CAN 通道编号 = 19</td></tr>
  <tr><td><code>+4</code></td><td>Timestamp</td><td>8B</td><td class="mono">18 9E 33 5B...</td><td>纳秒级硬件时间戳</td></tr>
  <tr><td><code>+12</code></td><td>Data Length</td><td>2B</td><td><code>0x000D</code></td><td>CAN Payload 长度 = 13</td></tr>
  <tr><td><code>+14</code></td><td>Data Flags</td><td>2B</td><td><code>0x0001</code></td><td>数据状态标志</td></tr>
</table>

<h2>CAN Payload (13 字节)</h2>
<table>
  <tr><th>偏移</th><th>字段</th><th>长度</th><th>示例值</th><th>说明</th></tr>
  <tr><td><code>+0</code></td><td><b>CAN ID</b></td><td>4B</td>
      <td><code style="color:#3fb950">0x00000123</code></td>
      <td>✅ <b>真正的 CAN ID = 0x123</b><br>bit31=0 → Standard Frame</td></tr>
  <tr><td><code>+4</code></td><td>DLC</td><td>1B</td><td><code>0x08</code></td><td>数据长度 = 8 字节</td></tr>
  <tr><td><code>+5</code></td><td>Data</td><td>8B</td><td class="mono">00 11 22 33 44 55 66 77</td><td>CAN 帧原始数据</td></tr>
</table>

<div class="warn">
  <b>⚠️ 易混淆点：</b> <code>0x0013</code> (Interface ID) 和 <code>0x0123</code> (CAN ID) 在原始十六进制中
  视觉上容易混淆。关键区别是它们在帧中的<b>位置</b>不同：<br>
  • <code>0x0013</code> 在 Entry Header 偏移 +2（通道号）<br>
  • <code>0x0123</code> 在 CAN Payload 偏移 +0（帧 ID）
</div>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Page 3: EtherType 处理决策树
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('EtherType 决策树')
_CONTENT['EtherType 决策树'] = _page('Live Capture — EtherType 处理决策树', """
<p>当 Live Capture 从网卡接收到一个以太网帧时，首先检查 EtherType 来决定如何处理。</p>

<h2>决策流程</h2>
<div class="decision">
  <div class="decision-node decision-q">📥 收到以太网帧 → 读取 EtherType (字节 12-13)</div>

  <div class="decision-node decision-q" style="margin-top:16px">
    EtherType == <code>0x2090</code> ? &nbsp; <span class="tag tag-orange">TECMP/PLP</span>
  </div>
  <div class="decision-node decision-yes">
    ✅ YES → 读取 TECMP Header 的 Data Type (字节 20-21)
  </div>
  <div class="decision-node decision-action">
    Data Type = <code>0x0002</code> → <span class="tag tag-green">CAN Data</span> → 提取 CAN 帧 → 送入 CAN Bus 表格
  </div>
  <div class="decision-node decision-action">
    Data Type = <code>0x0003</code> → <span class="tag tag-green">CAN FD</span> → 提取 CAN FD 帧 → 送入 CAN Bus 表格
  </div>
  <div class="decision-node decision-action">
    Data Type = <code>0x0004</code> → <span class="tag tag-blue">LIN</span> → 提取 LIN 帧 → 送入 LIN Bus 表格
  </div>
  <div class="decision-node decision-action">
    Data Type = <code>0x0008</code> → <span class="tag tag-purple">FlexRay</span> → 提取 FlexRay 帧 → 送入 FlexRay 表格
  </div>
  <div class="decision-node decision-action">
    Data Type = <code>0x0080/81</code> → <span class="tag tag-blue">Ethernet</span> → 提取嵌套以太网帧 → 送入 Ethernet 表格
  </div>
  <div class="decision-node decision-action">
    其他 Data Type → <b>Video 数据</b> (GMSL/CSI-2) → 送入视频解码队列
  </div>

  <div class="decision-node decision-no" style="margin-top:12px">
    ❌ NO → 不是 0x2090
  </div>

  <div class="decision-node decision-q" style="margin-left:44px">
    EtherType == <code>0x99FE</code> ? &nbsp; <span class="tag tag-orange">PLP/TECMP (旧)</span>
  </div>
  <div class="decision-node decision-yes" style="margin-left:68px">
    ✅ → 同上流程，解析 TECMP Header → 分发到对应 Bus 表格
  </div>

  <div class="decision-node decision-q" style="margin-left:44px">
    EtherType == <code>0x88F7</code> ? &nbsp; <span class="tag tag-blue">PTPv2</span>
  </div>
  <div class="decision-node decision-yes" style="margin-left:68px">
    ✅ → 解析 IEEE 1588 时间同步报文 → 显示在 Ethernet 表格
  </div>

  <div class="decision-node decision-q" style="margin-left:44px">
    EtherType == <code>0x0800</code> ? &nbsp; <span class="tag tag-green">IPv4</span>
  </div>
  <div class="decision-node decision-yes" style="margin-left:68px">
    ✅ → 解析 IP → TCP/UDP → 上层协议 (SOME/IP, DoIP, HTTP...) → Ethernet 表格
  </div>

  <div class="decision-node decision-q" style="margin-left:44px">
    EtherType == <code>0x86DD</code> ? &nbsp; <span class="tag tag-purple">IPv6</span>
  </div>
  <div class="decision-node decision-yes" style="margin-left:68px">
    ✅ → 同 IPv4 流程
  </div>

  <div class="decision-node decision-q" style="margin-left:44px">
    EtherType == <code>0x8100</code> ? &nbsp; <span class="tag tag-blue">VLAN</span>
  </div>
  <div class="decision-node decision-yes" style="margin-left:68px">
    ✅ → 剥离 VLAN Tag → 递归处理内层 EtherType
  </div>

  <div class="decision-node decision-no" style="margin-left:44px; margin-top:8px">
    ❓ 其他 → 作为通用以太网帧显示在 Ethernet 表格 (显示 EtherType 值)
  </div>
</div>

<h2>Data Type 完整映射表</h2>
<table>
  <tr><th>Data Type</th><th>名称</th><th>目标</th><th>解码方式</th></tr>
  <tr><td><code>0x0001</code></td><td>CAN Raw</td><td>CAN 表格</td><td>4B ID + 1B DLC + NB Data</td></tr>
  <tr><td><code>0x0002</code></td><td>CAN Data</td><td>CAN 表格</td><td>4B ID + 1B DLC + NB Data</td></tr>
  <tr><td><code>0x0003</code></td><td>CAN FD</td><td>CAN 表格</td><td>4B ID + 1B DLC + NB Data + Flags</td></tr>
  <tr><td><code>0x0004</code></td><td>LIN</td><td>LIN 表格</td><td>1B ID + 1B DLC + NB Data + Checksum</td></tr>
  <tr><td><code>0x0008</code></td><td>FlexRay</td><td>FlexRay 表格</td><td>Slot + Cycle + Data</td></tr>
  <tr><td><code>0x0080</code></td><td>Ethernet</td><td>Ethernet 表格</td><td>嵌套的完整以太网帧</td></tr>
  <tr><td><code>0x0081</code></td><td>Ethernet Raw</td><td>Ethernet 表格</td><td>原始以太网帧数据</td></tr>
  <tr><td>其他</td><td>Video/Sensor</td><td>视频解码队列</td><td>GMSL/CSI-2 像素流</td></tr>
</table>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Page 4: Live Capture 处理流水线
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PAGE_ORDER.append('处理流水线')
_CONTENT['处理流水线'] = _page('Live Capture 内部处理流水线', """
<p>从网卡收到 TECMP 帧到在 UI 上显示 CAN 数据，经过以下流水线：</p>

<div class="flow">
  <div class="flow-node">
    <h4>① 网卡抓包</h4>
    <p>Raw Socket</p>
    <p><code>AF_PACKET</code></p>
    <p><code>htons(0x2090)</code></p>
  </div>
  <div class="flow-arrow">→</div>
  <div class="flow-node">
    <h4>② 快速路径</h4>
    <p>检查 EtherType</p>
    <p>0x2090 → 读 Data Type</p>
    <p>Bus Data? → Scapy</p>
    <p>Video? → Queue</p>
  </div>
  <div class="flow-arrow">→</div>
  <div class="flow-node">
    <h4>③ TECMP 解码</h4>
    <p>TECMPDecoder</p>
    <p>解析 Entry Headers</p>
    <p>提取 CAN Payload</p>
    <p>还原 CAN ID</p>
  </div>
  <div class="flow-arrow">→</div>
  <div class="flow-node">
    <h4>④ Bus Queue</h4>
    <p>_add_bus_data()</p>
    <p>添加序号 Nr.</p>
    <p>Recording 备份</p>
  </div>
  <div class="flow-arrow">→</div>
  <div class="flow-node active">
    <h4>⑤ UI 刷新</h4>
    <p>BusTableModel</p>
    <p>flush_batch()</p>
    <p>FilterHeaderView</p>
    <p>显示在 CAN 表格</p>
  </div>
</div>

<h2>CAN ID 还原算法</h2>
<div class="card">
<pre style="color: var(--green); font-family: Consolas; font-size: 13px; line-height: 1.8;">
<span style="color:#8b949e"># core/protocol_decoders.py — _decode_can()</span>

can_id_raw = int.from_bytes(payload[0:4], <span style="color:#f0883e">'big'</span>)

<span style="color:#8b949e"># bit 31 = Extended Frame 标志</span>
extended = bool(can_id_raw & <span style="color:#79c0ff">0x80000000</span>)

<span style="color:#8b949e"># 低 29 位 = 实际 CAN ID</span>
can_id = can_id_raw & <span style="color:#79c0ff">0x1FFFFFFF</span>

<span style="color:#8b949e"># 示例: 0x00000123 & 0x1FFFFFFF = 0x123</span>
dlc = payload[4]
data = payload[5 : 5 + dlc]
</pre>
</div>

<div class="highlight">
  <b>💡 Standard vs Extended Frame</b><br>
  • bit 31 = 0 → <b>Standard Frame</b> (11-bit ID, 0x000–0x7FF)<br>
  • bit 31 = 1 → <b>Extended Frame</b> (29-bit ID, 0x00000000–0x1FFFFFFF)<br>
  Live Capture 通过 <code>can_id_raw & 0x80000000</code> 自动判断帧类型。
</div>

<h2>为什么 0x0013 ≠ CAN ID？</h2>
<table>
  <tr><th>字段</th><th>值</th><th>位置</th><th>含义</th></tr>
  <tr><td><code>0x0013</code></td><td>19</td><td>Entry Header 偏移 +2</td>
      <td>Technica 设备的 CAN <b>接口编号</b></td></tr>
  <tr><td><code>0x0123</code></td><td>291</td><td>CAN Payload 偏移 +0</td>
      <td>原始 CAN <b>帧 ID</b></td></tr>
</table>
<p>两者在字节流中仅相隔 14 字节，且十六进制视觉相似（<code>13</code> vs <code>123</code>），
这就是为什么查看 Wireshark/tcpdump 原始输出时容易混淆。</p>
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dialog
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DataFlowAnalysisDialog(QDialog):
    """数据流全链路分析 — CAN → TECMP/PLP 以太网帧."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("数据流全链路分析 — CAN帧 → TECMP/PLP 以太网帧")
        self.resize(1200, 800)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Tree navigation
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMaximumWidth(260)
        self._tree.setMinimumWidth(180)
        self._tree.setStyleSheet("""
            QTreeWidget {
                background: #0d1117; color: #c9d1d9; border: none;
                font-size: 13px; padding: 8px;
            }
            QTreeWidget::item {
                padding: 6px 10px; border-radius: 6px; margin: 2px 4px;
            }
            QTreeWidget::item:selected {
                background: #1a3a5c; color: #58a6ff;
            }
            QTreeWidget::item:hover {
                background: #161b22;
            }
        """)
        splitter.addWidget(self._tree)

        # Right: WebEngine view
        self._web = QWebEngineView()
        splitter.addWidget(self._web)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([220, 980])
        layout.addWidget(splitter)

        # Populate tree
        self._items = {}
        for name in _PAGE_ORDER:
            item = QTreeWidgetItem([name])
            self._tree.addTopLevelItem(item)
            self._items[name] = item

        self._tree.currentItemChanged.connect(self._on_item_changed)

        if _PAGE_ORDER:
            self._tree.setCurrentItem(self._items[_PAGE_ORDER[0]])

    def _on_item_changed(self, current, _previous):
        if current is None:
            return
        name = current.text(0)
        html = _CONTENT.get(name, '')
        self._web.setHtml(html)
