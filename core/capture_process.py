"""Unabhaengiger Capture-Prozess fuer 0x2090 CSI-2 Video-Streams.

Eigener Prozess → kein GIL-Konflikt mit Qt/UI.
AF_PACKET + PACKET_MMAP (TPACKET_V3) → Zero-Copy Paketempfang.
ISP inline → fertiger BGR-Frame in SharedMemory.

Architektur:
  CaptureWorker (Process)          Main Process (Qt)
  ┌──────────────────┐             ┌──────────────┐
  │ AF_PACKET/MMAP   │             │              │
  │ → Frame Assembly │             │ QSocketNotif │
  │ → RAW12 Unpack   │──SharedMem──│ → QLabel     │
  │ → ISP Pipeline   │   + pipe    │   setPixmap  │
  │ → BGR Output     │             │              │
  └──────────────────┘             └──────────────┘
"""
import multiprocessing
import os
import struct
import time
import socket
import mmap
import traceback
import ctypes
import ctypes.util
import numpy as np
import cv2

# ── Linux AF_PACKET / TPACKET_V3 Konstanten ──
SOL_PACKET = 263
PACKET_VERSION = 10
PACKET_RX_RING = 5
TPACKET_V3 = 2
TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1 << 0

# Block-Descriptor Offsets (tpacket_block_desc → tpacket_hdr_v1)
#   [0:4] version, [4:8] offset_to_priv,
#   [8:12] block_status, [12:16] num_pkts,
#   [16:20] offset_to_first_pkt, [20:24] blk_len
BD_BLOCK_STATUS = 8
BD_NUM_PKTS = 12
BD_OFFSET_FIRST_PKT = 16

# Packet Header Offsets (tpacket3_hdr)
#   [0:4] tp_next_offset, [4:8] tp_sec, [8:12] tp_nsec,
#   [12:16] tp_snaplen, [16:20] tp_len, [20:24] tp_status,
#   [24:26] tp_mac, [26:28] tp_net
PH_NEXT_OFFSET = 0
PH_SNAPLEN = 12
PH_STATUS = 20
PH_MAC = 24


def capture_worker_entry(interface, shm_name, notify_conn, stop_event,
                         worker_index=0, num_workers=1,
                         claimed_streams=None,
                         gain_mode=None,
                         counter_stats=None,
                         counter_pause=None):
    """Einstiegspunkt fuer den CaptureWorker-Prozess (spawn-kompatibel).

    Args:
        worker_index: Index dieses Workers (0, 1, 2, ...)
        num_workers: Gesamtzahl der Worker
        claimed_streams: multiprocessing.Array — jeder Worker schreibt
                         seine stream_id, andere pruefen auf Duplikate
        gain_mode: multiprocessing.Value('i') — 0=Auto/LCG, 1=HCG
        counter_stats: multiprocessing.Array('l') — Counter-Statistik
        counter_pause: multiprocessing.Event — wenn gesetzt, Counter-
                       Extraktion wird uebersprungen (A/B-Test)
    """
    worker = CaptureWorker.__new__(CaptureWorker)
    worker.interface = interface
    worker.shm_name = shm_name
    worker.notify_conn = notify_conn
    worker.stop_event = stop_event
    worker.target_stream_id = None
    worker.worker_index = worker_index
    worker.num_workers = num_workers
    worker.claimed_streams = claimed_streams
    worker.gain_mode = gain_mode
    worker.counter_stats = counter_stats
    worker.counter_pause = counter_pause
    worker._run_capture()


class CaptureWorker(multiprocessing.Process):
    """Capture-Prozess fuer einen 0x2090 Video-Stream.

    - Eigener Prozess → kein GIL-Konflikt
    - AF_PACKET + PACKET_MMAP → Zero-Copy
    - ISP inline → fertiger BGR-Frame
    - SharedMemory → Transfer zum Hauptprozess
    """

    # SharedMemory Layout (Double-Buffer, tear-free):
    #   [0:4]   active_slot    (uint32 LE, 0 oder 1)
    #   --- Slot 0 ---
    #   [4:8]   frame_counter  (uint32 LE)
    #   [8:12]  bgr_height     (uint32 LE)
    #   [12:16] bgr_width      (uint32 LE)
    #   [16:16+MAX_BGR] BGR pixel data
    #   --- Slot 1 ---
    #   [4+SLOT_SIZE:...]  gleiche Struktur
    #
    # Writer schreibt immer in den INAKTIVEN Slot,
    # dann flippt active_slot atomar → Reader liest immer komplette Frames.
    SLOT_HEADER = 16   # frame_counter(4) + h(4) + w(4) + stream_id(4)
    MAX_DISPLAY_W = 1920
    MAX_DISPLAY_H = 1080
    MAX_BGR_BYTES = MAX_DISPLAY_W * MAX_DISPLAY_H * 3  # ~6.2 MB
    SLOT_SIZE = SLOT_HEADER + MAX_BGR_BYTES
    SHM_HEADER = 4     # active_slot(4)
    SHM_SIZE = SHM_HEADER + 2 * SLOT_SIZE              # ~12.4 MB

    # Sensor-Parameter (0x2090 CSI-2 RAW12)
    TARGET_H = 2166

    def __init__(self, interface: str, shm_name: str,
                 notify_conn,
                 stop_event,
                 stream_id: int = None):
        super().__init__(daemon=True)
        self.interface = interface
        self.shm_name = shm_name
        self.notify_conn = notify_conn   # multiprocessing.Connection
        self.stop_event = stop_event
        self.target_stream_id = stream_id
        self.counter_stats = None  # multiprocessing.Array (optional)

    # ════════════════════════════════════════════════════════════════
    #  Prozess-Einstiegspunkt
    # ════════════════════════════════════════════════════════════════

    def run(self):
        try:
            self._run_capture()
        except Exception as e:
            self._log(f"FATAL: {e}\n{traceback.format_exc()}")

    # ── CPU-Affinity: NAPI-CPU je Interface ──
    # i40e RSS fuer EtherType 0x2090 → alle Pakete in 1 Queue → 1 NAPI-CPU.
    # CaptureWorker darf NICHT auf der NAPI-CPU laufen, sonst verhungert
    # ksoftirqd und NIC-Ring laeuft ueber (rx_missed_errors).
    _IFACE_CPU_AFFINITY = {
        'eno7np2': list({0, 1, 2, 3, 5, 6, 7}),      # CPU 0-7 ohne NAPI-CPU 4
        'eno8np3': list({8, 9, 10, 11, 13, 14, 15}),  # CPU 8-15 ohne NAPI-CPU 12
    }

    def _run_capture(self):
        from multiprocessing.shared_memory import SharedMemory

        # ── CPU-Affinity setzen (vor allem anderen) ──
        iface = self.interface
        affinity = self._IFACE_CPU_AFFINITY.get(iface)
        if affinity:
            try:
                os.sched_setaffinity(0, affinity)
                self._log(f"CPU affinity set: {sorted(affinity)} "
                          f"(avoiding NAPI CPU for {iface})")
            except OSError as e:
                self._log(f"CPU affinity FAILED: {e}")
        else:
            self._log(f"No CPU affinity rule for {iface}, using default")

        shm = SharedMemory(name=self.shm_name)

        use_mmap = False
        sock = ring = None
        block_size = block_nr = 0

        try:
            sock, ring, block_size, block_nr = self._setup_mmap_socket()
            use_mmap = True
            self._log(f"PACKET_MMAP OK: {block_nr} blocks x "
                       f"{block_size // 1048576}MB = "
                       f"{block_size * block_nr // 1048576}MB ring")
        except Exception as e:
            self._log(f"MMAP failed ({e}), fallback recv()")
            sock = self._setup_recv_socket()

        self._log(f"started: iface={self.interface} mmap={use_mmap} "
                   f"pid={os.getpid()}")

        try:
            if use_mmap:
                self._mmap_loop(sock, ring, block_size, block_nr, shm)
            else:
                self._recv_loop(sock, shm)
        finally:
            shm.close()
            if ring:
                ring.close()
            sock.close()
            try:
                self.notify_conn.close()
            except Exception:
                pass

    # ════════════════════════════════════════════════════════════════
    #  BPF-Filter: Kernel filtert nicht-passende Pakete vor Zustellung
    # ════════════════════════════════════════════════════════════════

    def _attach_stream_filter(self, sock, stream_id):
        """BPF-Filter anbringen: nur Pakete mit stream_id durchlassen.

        Ohne Filter kopiert der Kernel jedes Paket an ALLE Sockets
        auf dem Interface → doppelte Speicherbandbreite bei 2 Workern.
        Mit BPF filtert der Kernel im Netzwerk-Stack (nahezu kostenlos)
        und liefert nur passende Pakete → kein Duplikat-Overhead.
        """
        try:
            class BpfInsn(ctypes.Structure):
                _fields_ = [("code", ctypes.c_ushort),
                             ("jt", ctypes.c_ubyte),
                             ("jf", ctypes.c_ubyte),
                             ("k", ctypes.c_uint)]

            class BpfProg(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ushort),
                             ("filter", ctypes.POINTER(BpfInsn))]

            # BPF: ldw [26] → stream_id laden (4 Bytes ab Ethernet+26)
            #      jeq #sid → akzeptieren / ablehnen
            insns = (BpfInsn * 4)(
                BpfInsn(0x20, 0, 0, 26),            # ld [26]
                BpfInsn(0x15, 0, 1, stream_id),      # jeq #stream_id
                BpfInsn(0x06, 0, 0, 0xFFFF),         # ret accept
                BpfInsn(0x06, 0, 0, 0),              # ret reject
            )
            prog = BpfProg(4, ctypes.cast(insns,
                                          ctypes.POINTER(BpfInsn)))

            libc = ctypes.CDLL(
                ctypes.util.find_library('c') or 'libc.so.6',
                use_errno=True)
            _SOL_SOCKET = 1
            _SO_ATTACH_FILTER = 26
            ret = libc.setsockopt(
                sock.fileno(), _SOL_SOCKET, _SO_ATTACH_FILTER,
                ctypes.byref(prog), ctypes.sizeof(prog))

            if ret == 0:
                self._log(
                    f"BPF-Filter fuer 0x{stream_id:04X} aktiviert "
                    f"→ Kernel filtert nicht-passende Pakete")
            else:
                eno = ctypes.get_errno()
                self._log(f"BPF-Filter fehlgeschlagen: errno={eno}")
        except Exception as e:
            self._log(f"BPF-Filter Fehler: {e}")

    # ════════════════════════════════════════════════════════════════
    #  Socket Setup
    # ════════════════════════════════════════════════════════════════

    def _setup_mmap_socket(self):
        """AF_PACKET + TPACKET_V3 MMAP Ring-Buffer."""
        ETH_P_2090 = 0x2090
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW,
            socket.htons(ETH_P_2090))
        sock.bind((self.interface, 0))

        # ── FANOUT entfernt (V3): LB verteilt Pakete 50/50 → Worker ──
        # ── bekommt nur ~25% nuetzliche Daten. Ohne FANOUT: 50%. ──

        # TPACKET_V3
        ver = struct.pack('i', TPACKET_V3)
        sock.setsockopt(SOL_PACKET, PACKET_VERSION, ver)

        # Ring-Buffer: 4MB x 64 Blocks = 256 MB (fuer 10 Gbit/s)
        BLOCK_SIZE = 1 << 22    # 4 MB
        BLOCK_NR = 64           # 256 MB total
        FRAME_SIZE = 1 << 14   # 16 KB (> 9000 MTU jumbo)
        FRAME_NR = (BLOCK_SIZE * BLOCK_NR) // FRAME_SIZE

        # tpacket_req3: 7 x uint32 = 28 bytes
        req = struct.pack('IIIIIII',
                          BLOCK_SIZE, BLOCK_NR, FRAME_SIZE, FRAME_NR,
                          32,   # tp_retire_blk_tov: 32ms block timeout
                          0,    # tp_sizeof_priv
                          0)    # tp_feature_req_word
        sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)

        ring_size = BLOCK_SIZE * BLOCK_NR
        ring = mmap.mmap(sock.fileno(), ring_size,
                         mmap.MAP_SHARED,
                         mmap.PROT_READ | mmap.PROT_WRITE)

        return sock, ring, BLOCK_SIZE, BLOCK_NR

    def _setup_recv_socket(self):
        """Fallback: Normaler AF_PACKET recv()."""
        ETH_P_2090 = 0x2090
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW,
            socket.htons(ETH_P_2090))
        sock.bind((self.interface, 0))

        for bufsz in (536_870_912, 268_435_456, 67_108_864):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsz)
                break
            except Exception:
                continue

        sock.setblocking(False)
        return sock

    # ════════════════════════════════════════════════════════════════
    #  PACKET_MMAP Hauptschleife (Zero-Copy)
    # ════════════════════════════════════════════════════════════════

    def _mmap_loop(self, sock, ring, block_size, block_nr, shm):
        """MMAP-Hauptschleife: Packet-Read und ISP in getrennten Threads.

        - Recv-Thread: Draent MMAP-Ring so schnell wie moeglich
        - ISP-Thread:  Verarbeitet den neuesten Frame asynchron
        → Keine Blockierung des Packet-Empfangs durch ISP (~20ms/Frame)
        """
        import select
        import threading
        import queue

        state = self._init_state()
        frame_num = 0
        diag_n = 0

        # ── ISP-Thread: Verarbeitet Frames asynchron ──
        isp_queue = queue.Queue(maxsize=2)

        def _isp_worker():
            isp_cache = {}
            while True:
                item = isp_queue.get()
                if item is None:
                    break
                raw_buf, frame_info, fn, dn = item
                try:
                    # _extract_lines jetzt hier im ISP-Thread
                    # statt im Capture-Loop (~10ms Blockierung eliminiert)
                    lines = self._extract_lines_from_buf(
                        raw_buf, frame_info['stride'])
                    if not lines or len(lines) < 100:
                        continue
                    bgr = self._process_frame(
                        lines, frame_info, isp_cache, fn)
                    if bgr is not None:
                        sid = frame_info.get('active_stream', 0)
                        self._write_frame(shm, bgr, fn, sid)
                    if dn <= 30 or dn % 100 == 0:
                        self._log(
                            f"F{dn} lines={len(lines)} "
                            f"frame={fn} mode=mmap")
                except Exception:
                    self._log(f"ISP error F{fn}: "
                              f"{traceback.format_exc()}")

        isp_thread = threading.Thread(
            target=_isp_worker, daemon=True)
        isp_thread.start()

        # ── Recv-Schleife: Draent MMAP-Ring mit voller Geschwindigkeit ──
        block_idx = 0
        poller = select.poll()
        poller.register(sock, select.POLLIN)

        _up_I = struct.Struct('>I').unpack_from
        _up_H = struct.Struct('>H').unpack_from
        _le_I = struct.Struct('<I').unpack_from
        _le_H = struct.Struct('<H').unpack_from

        # ── Diagnose: PACKET_STATISTICS alle 5s loggen ──
        PACKET_STATISTICS = 6
        _diag_time = time.monotonic()
        _diag_pkts = 0
        _diag_blocks = 0

        # ── PLP Counter 连续性检查 (内联, 零开销) ──
        _ct_stats = self.counter_stats  # multiprocessing.Array or None
        _ct_pause_ev = self.counter_pause  # multiprocessing.Event or None
        _ct_active = (_ct_stats is not None)  # 本周期是否执行检查
        _ct_prev = -1          # 上一个 counter 值
        _ct_total = 0          # 总包数
        _ct_gaps = 0           # 跳跃次数
        _ct_lost = 0           # 丢失 counter 数
        _ct_streams = set()    # 已见的 stream_id
        _ct_last_write = time.monotonic()

        try:
            while not self.stop_event.is_set():
                events = poller.poll(100)
                if not events:
                    continue

                # ── Counter Pause 状态更新 (每 poll 周期, ~100ms) ──
                if _ct_pause_ev is not None:
                    _ct_active = (_ct_stats is not None
                                  and not _ct_pause_ev.is_set())

                # ── Periodische Diagnose (alle 5s) ──
                now = time.monotonic()
                if now - _diag_time >= 5.0:
                    elapsed = now - _diag_time
                    try:
                        stats_raw = sock.getsockopt(
                            SOL_PACKET, PACKET_STATISTICS, 12)
                        tp_pkts, tp_drops = struct.unpack('II',
                                                          stats_raw[:8])
                        sid = state.get('active_stream', 0)
                        self._log(
                            f"[STATS] S0x{sid:04x} "
                            f"recv={_diag_pkts} "
                            f"blocks={_diag_blocks} "
                            f"kern_drops={tp_drops} "
                            f"in {elapsed:.1f}s")
                    except Exception:
                        pass
                    _diag_time = now
                    _diag_pkts = 0
                    _diag_blocks = 0

                # ── Counter 统计写入 Shared Array (每秒) ──
                if _ct_active and now - _ct_last_write >= 1.0:
                    _ct_last_write = now
                    widx = getattr(self, 'worker_index', 0)
                    _CT_FIELDS = 12
                    base = widx * _CT_FIELDS
                    try:
                        _ct_stats[base + 0] = _ct_total
                        _ct_stats[base + 1] = _ct_gaps
                        _ct_stats[base + 2] = _ct_lost
                        sids = sorted(_ct_streams)
                        for si in range(8):
                            _ct_stats[base + 3 + si] = (
                                sids[si] if si < len(sids) else 0)
                        _ct_stats[base + 11] = int(now)
                    except (IndexError, Exception):
                        pass

                while not self.stop_event.is_set():
                    offset = block_idx * block_size
                    block_status = _le_I(
                        ring, offset + BD_BLOCK_STATUS)[0]
                    if not (block_status & TP_STATUS_USER):
                        break

                    num_pkts = _le_I(ring, offset + BD_NUM_PKTS)[0]
                    first_off = _le_I(
                        ring, offset + BD_OFFSET_FIRST_PKT)[0]

                    pkt_pos = offset + first_off
                    for _ in range(num_pkts):
                        tp_next = _le_I(
                            ring, pkt_pos + PH_NEXT_OFFSET)[0]
                        tp_snaplen = _le_I(
                            ring, pkt_pos + PH_SNAPLEN)[0]
                        tp_mac = _le_H(ring, pkt_pos + PH_MAC)[0]

                        if tp_snaplen >= 42:
                            eth_off = pkt_pos + tp_mac
                            pkt_type = _up_I(
                                ring, eth_off + 22)[0]
                            stream_id = _up_I(
                                ring, eth_off + 26)[0]

                            # ── PLP Counter 内联提取 (~10ns) ──
                            if _ct_active:
                                _ct_val = _up_H(
                                    ring, eth_off + 16)[0]
                                _ct_total += 1
                                _ct_streams.add(stream_id)
                                if _ct_prev >= 0:
                                    _ct_exp = (_ct_prev + 1) & 0xFFFF
                                    if _ct_val != _ct_exp:
                                        if _ct_val > _ct_prev:
                                            _ct_g = _ct_val - _ct_prev
                                        else:
                                            _ct_g = (65536 - _ct_prev) + _ct_val
                                        _ct_gaps += 1
                                        _ct_lost += _ct_g - 1
                                _ct_prev = _ct_val

                            if state['active_stream'] is None:
                                if pkt_type == 0x06:
                                    # Duplikat-Check via shared Array (atomar mit Lock)
                                    cs = getattr(self, 'claimed_streams', None)
                                    idx = getattr(self, 'worker_index', 0)
                                    if cs is not None:
                                        with cs.get_lock():
                                            taken = False
                                            for k in range(len(cs)):
                                                if k != idx and cs[k] == stream_id:
                                                    taken = True
                                                    break
                                            if taken:
                                                pkt_pos += tp_next
                                                continue
                                            # Diesen Stream beanspruchen
                                            cs[idx] = stream_id
                                    state['active_stream'] = stream_id
                                    self._log(
                                        f"Stream 0x{stream_id:04X} erkannt "
                                        f"(worker={idx})")
                                    # BPF-Filter: Kernel nur passende
                                    # Pakete zustellen (kein Duplikat)
                                    self._attach_stream_filter(
                                        sock, stream_id)
                                else:
                                    pkt_pos += tp_next
                                    continue
                            elif stream_id != state['active_stream']:
                                pkt_pos += tp_next
                                continue

                            raw_buf = self._handle_pkt_mmap(
                                ring, eth_off, tp_snaplen,
                                pkt_type, state, _up_I, _up_H)

                            if raw_buf is not None:
                                frame_num += 1
                                diag_n += 1
                                # Frame-Info Snapshot (fuer ISP Thread)
                                frame_info = {
                                    'stride': state['stride'],
                                    'fs_ts': state.get('fs_ts', 0),
                                    'active_stream': state.get(
                                        'active_stream', 0),
                                }
                                # Alten Frame verwerfen, neuesten behalten
                                while not isp_queue.empty():
                                    try:
                                        isp_queue.get_nowait()
                                    except queue.Empty:
                                        break
                                isp_queue.put((
                                    raw_buf, frame_info,
                                    frame_num, diag_n))

                        pkt_pos += tp_next
                        _diag_pkts += 1

                    # Block an Kernel zurueckgeben
                    struct.pack_into(
                        '<I', ring, offset + BD_BLOCK_STATUS,
                        TP_STATUS_KERNEL)
                    block_idx = (block_idx + 1) % block_nr
                    _diag_blocks += 1
        finally:
            isp_queue.put(None)
            isp_thread.join(timeout=3)

    # ════════════════════════════════════════════════════════════════
    #  Fallback recv() Hauptschleife
    # ════════════════════════════════════════════════════════════════

    def _recv_loop(self, sock, shm):
        _recv = sock.recv
        _up_I = struct.Struct('>I').unpack_from
        _up_H = struct.Struct('>H').unpack_from

        state = self._init_state()
        isp_cache = {}
        frame_num = 0
        diag_n = 0

        while not self.stop_event.is_set():
            burst = 0
            try:
                while True:
                    data = _recv(65535)
                    burst += 1
                    if len(data) < 42 or data[12] != 0x20 or data[13] != 0x90:
                        continue

                    pkt_type = _up_I(data, 22)[0]
                    stream_id = _up_I(data, 26)[0]

                    if state['active_stream'] is None:
                        if pkt_type != 0x06:
                            continue
                        cs = getattr(self, 'claimed_streams', None)
                        idx = getattr(self, 'worker_index', 0)
                        if cs is not None:
                            with cs.get_lock():
                                taken = any(cs[k] == stream_id
                                            for k in range(len(cs)) if k != idx)
                                if taken:
                                    continue
                                cs[idx] = stream_id
                        state['active_stream'] = stream_id
                        self._log(
                            f"Stream 0x{stream_id:04X} erkannt "
                            f"(worker={idx})")
                    elif stream_id != state['active_stream']:
                        continue

                    lines = self._handle_pkt_bytes(
                        data, pkt_type, state, _up_I, _up_H)

                    if lines is not None:
                        frame_num += 1
                        bgr = self._process_frame(
                            lines, state, isp_cache, frame_num)
                        if bgr is not None:
                            self._write_frame(shm, bgr, frame_num)

                        diag_n += 1
                        if diag_n <= 30 or diag_n % 100 == 0:
                            self._log(
                                f"F{diag_n} lines={len(lines)} "
                                f"frame={frame_num} mode=recv")

            except BlockingIOError:
                pass
            except OSError:
                break

            if burst == 0:
                time.sleep(0.0001)

    # ════════════════════════════════════════════════════════════════
    #  Frame Assembly
    # ════════════════════════════════════════════════════════════════

    def _init_state(self):
        return {
            'active_stream': self.target_stream_id,
            'parse_buf': bytearray(),
            'frame_started': False,
            'stride': 0,
            'width': 0,
            'fs_ts': 0,
        }

    def _parse_stride(self, state, raw, offset, datalen):
        """Stride aus Frame-Start Sub-Header lesen (einmalig)."""
        if state['stride'] > 0:
            return
        if datalen < 74 - offset:
            return
        stride_val = int.from_bytes(raw[offset + 60 - 14:offset + 62 - 14]
                                    if isinstance(raw, (bytes, bytearray))
                                    else raw[offset + 46:offset + 48], 'big')
        # Fuer mmap: eth_off + 60 - eth_off = absolute position
        # Wir bekommen stride_val direkt
        if stride_val <= 0:
            return
        pixel_bpl = stride_val - 16
        if pixel_bpl > 0 and pixel_bpl % 3 == 0:
            w = pixel_bpl * 2 // 3
            if w > 640:
                state['stride'] = stride_val
                state['width'] = w
                return
        for pad in (0, 2, 4):
            pix_bpl = stride_val - pad
            if pix_bpl > 0 and pix_bpl % 3 == 0:
                w2 = pix_bpl * 2 // 3
                if w2 > 640:
                    state['stride'] = stride_val
                    state['width'] = w2
                    return

    def _handle_pkt_mmap(self, ring, eth_off, snaplen, pkt_type,
                         state, _up_I, _up_H):
        """Verarbeitet ein Paket aus dem MMAP Ring-Buffer.

        Returns: list[(ts, bytes)] bei Frame-Abschluss, sonst None.
        """
        if pkt_type == 0x06:
            # ── Frame-Start ──
            state['parse_buf'] = bytearray()
            state['frame_started'] = True
            state['fs_ts'] = int.from_bytes(
                ring[eth_off + 30:eth_off + 38], 'big')

            if state['stride'] == 0 and snaplen >= 74:
                stride_val = int.from_bytes(
                    ring[eth_off + 60:eth_off + 62], 'big')
                self._try_set_stride(state, stride_val)

            data_len = _up_H(ring, eth_off + 38)[0]
            pixel_data = ring[eth_off + 74:eth_off + 42 + data_len]
            if pixel_data:
                state['parse_buf'].extend(pixel_data)

        elif pkt_type == 0x04 and state['frame_started']:
            # ── Auto-Submit bei Buffer-Ueberlauf ──
            # Verhindert Frame-Merge wenn 0x05+0x06 Pakete verloren
            stride = state['stride']
            if stride > 0 and len(state['parse_buf']) > stride * 2300:
                # Rohen Buffer kopieren (~0.3ms statt ~10ms _extract_lines)
                # Line-Extraktion passiert im ISP-Thread
                raw_buf = bytes(state['parse_buf'])
                state['parse_buf'] = bytearray()
                state['fs_ts'] = 0
                data_len = _up_H(ring, eth_off + 38)[0]
                state['parse_buf'].extend(
                    ring[eth_off + 42:eth_off + 42 + data_len])
                return raw_buf

            data_len = _up_H(ring, eth_off + 38)[0]
            state['parse_buf'].extend(
                ring[eth_off + 42:eth_off + 42 + data_len])

        elif pkt_type == 0x05 and state['frame_started']:
            # ── Frame-Ende ──
            data_len = _up_H(ring, eth_off + 38)[0]
            state['parse_buf'].extend(
                ring[eth_off + 42:eth_off + 42 + data_len])
            state['frame_started'] = False

            # Rohen Buffer kopieren (~0.3ms statt ~10ms _extract_lines)
            # Line-Extraktion passiert im ISP-Thread
            stride = state['stride']
            if stride > 0 and len(state['parse_buf']) > stride * 100:
                raw_buf = bytes(state['parse_buf'])
                state['parse_buf'] = bytearray()
                return raw_buf
            state['parse_buf'] = bytearray()

        return None

    def _handle_pkt_bytes(self, data, pkt_type, state, _up_I, _up_H):
        """Verarbeitet ein Paket (bytes, fuer recv()-Fallback).

        Returns: list[(ts, bytes)] bei Frame-Abschluss, sonst None.
        """
        if pkt_type == 0x06:
            state['parse_buf'] = bytearray()
            state['frame_started'] = True
            state['fs_ts'] = int.from_bytes(data[30:38], 'big')

            if state['stride'] == 0 and len(data) >= 74:
                stride_val = int.from_bytes(data[60:62], 'big')
                self._try_set_stride(state, stride_val)

            data_len = _up_H(data, 38)[0]
            pixel_data = data[74:42 + data_len]
            if pixel_data:
                state['parse_buf'].extend(pixel_data)

        elif pkt_type == 0x04 and state['frame_started']:
            stride = state['stride']
            if stride > 0 and len(state['parse_buf']) > stride * 2300:
                lines = self._extract_lines(state)
                if lines and len(lines) >= 100:
                    state['parse_buf'] = bytearray()
                    state['fs_ts'] = 0
                    data_len = _up_H(data, 38)[0]
                    state['parse_buf'].extend(data[42:42 + data_len])
                    return lines
                state['parse_buf'] = bytearray()

            data_len = _up_H(data, 38)[0]
            state['parse_buf'].extend(data[42:42 + data_len])

        elif pkt_type == 0x05 and state['frame_started']:
            data_len = _up_H(data, 38)[0]
            state['parse_buf'].extend(data[42:42 + data_len])
            state['frame_started'] = False

            lines = self._extract_lines(state)
            state['parse_buf'] = bytearray()
            if lines and len(lines) >= 100:
                return lines

        return None

    def _try_set_stride(self, state, stride_val):
        """Stride + Width aus Sub-Header berechnen."""
        if stride_val <= 0:
            return
        pixel_bpl = stride_val - 16
        if pixel_bpl > 0 and pixel_bpl % 3 == 0:
            w = pixel_bpl * 2 // 3
            if w > 640:
                state['stride'] = stride_val
                state['width'] = w
                return
        for pad in (0, 2, 4):
            pix_bpl = stride_val - pad
            if pix_bpl > 0 and pix_bpl % 3 == 0:
                w2 = pix_bpl * 2 // 3
                if w2 > 640:
                    state['stride'] = stride_val
                    state['width'] = w2
                    return

    def _extract_lines(self, state):
        """CSI-2 Zeilen via Magic-Pattern-Suche extrahieren (fuer recv-Fallback)."""
        return self._extract_lines_from_buf(
            state['parse_buf'], state['stride'])

    def _extract_lines_from_buf(self, parse_buf, stride):
        """CSI-2 Zeilen via Magic-Pattern-Suche extrahieren.

        Ausgelagerte Kernlogik — kann im ISP-Thread laufen,
        ohne den Capture-Loop zu blockieren.
        """
        if stride <= 0:
            return None

        magic = b'\x00\x00' + stride.to_bytes(2, 'big') + b'\x00\x2c'
        buf_len = len(parse_buf)
        wc = stride
        lines = []
        pos = 0

        while pos + wc <= buf_len:
            idx = parse_buf.find(magic, pos)
            if idx < 0 or idx + wc > buf_len:
                break
            nxt = idx + wc
            if nxt + 6 <= buf_len:
                if parse_buf[nxt:nxt + 6] != magic:
                    pos = idx + 1
                    continue
            ts = int.from_bytes(parse_buf[idx + 6:idx + 14], 'big')
            hdr14 = int.from_bytes(parse_buf[idx + 14:idx + 16], 'big')
            lines.append((ts, bytes(parse_buf[idx + 16:idx + wc]), hdr14))
            pos = nxt

        return lines

    # ════════════════════════════════════════════════════════════════
    #  Frame-Verarbeitung: RAW12 → LCG → ISP → BGR
    # ════════════════════════════════════════════════════════════════

    def _process_frame(self, lines, state, isp_cache, frame_num):
        """Komplette Frame-Pipeline: Lines → BGR.

        Verwendet Timestamp-basierte Positionsberechnung (wie Hauptprozess)
        und Bayer-Paritaetskorrektur fuer RCCB-Sensor.
        """
        stride = state['stride']
        if stride <= 0:
            return None

        pixel_bpl = stride - 16
        if pixel_bpl <= 0 or pixel_bpl % 3 != 0:
            return None
        n_groups = pixel_bpl // 3
        lcg_w = n_groups

        # ── Timestamps + Line-Counter extrahieren ──
        timestamps = [ts for ts, _, _ in lines]
        if len(timestamps) < 50:
            return None

        # ── avg_dt berechnen (Median der aufeinanderfolgenden Deltas) ──
        deltas = sorted([timestamps[i + 1] - timestamps[i]
                         for i in range(min(len(timestamps) - 1, 500))
                         if 0 < timestamps[i + 1] - timestamps[i] < 100000])
        if not deltas:
            return None
        avg_dt = deltas[len(deltas) // 2]
        if avg_dt <= 0:
            return None

        # ── Multi-Frame-Erkennung via Timestamp-Luecken ──
        # Bei verlorenen 0x05+0x06 Paketen enthaelt der Buffer
        # Zeilen aus ZWEI Frames. Die groessere Haelfte behalten.
        gap_thresh = avg_dt * 150
        gap_pos = -1
        for i in range(len(timestamps) - 1):
            if timestamps[i + 1] - timestamps[i] > gap_thresh:
                gap_pos = i + 1
        if gap_pos > 0:
            first_half = gap_pos
            second_half = len(lines) - gap_pos
            sid = state.get('active_stream', 0)
            self._log(f"[SPLIT] S0x{sid:x} F{frame_num}: gap@{gap_pos} "
                      f"first={first_half} second={second_half}")
            # Groessere Haelfte behalten (vollstaendigerer Frame)
            if first_half >= second_half:
                lines = lines[:gap_pos]
            else:
                lines = lines[gap_pos:]
            timestamps = [ts for ts, _, _ in lines]
            # Zu wenige Zeilen → Frame verwerfen statt Tearing
            if len(lines) < self.TARGET_H * 0.8:
                return None

        # ── Stabile Bildhoehe ──
        expected_h = isp_cache.get('expected_h', 0)
        if expected_h < 2000:
            expected_h = self.TARGET_H
        expected_h = min(expected_h, 2168) & ~1
        isp_cache['expected_h'] = expected_h

        # ── Sequenzielle Positionierung ──
        # Zeilen sind bereits in Empfangsreihenfolge (= Sensor-Reihenfolge).
        # Timestamp-basierte Positionierung verursacht Drift bei ungenauen
        # avg_dt → Bayer-Parity kippt in der unteren Bildhaelfte.
        # Sequenzielle Platzierung eliminiert dieses Problem.
        raw_data = bytearray()
        valid_indices = []
        seq_pos = 0
        hdr14_list = []
        for i, (ts, data, hdr14) in enumerate(lines):
            if seq_pos < expected_h and len(data) >= pixel_bpl:
                raw_data.extend(data[:pixel_bpl])
                valid_indices.append(seq_pos)
                hdr14_list.append(hdr14)
                seq_pos += 1

        n_new = len(valid_indices)
        if n_new < 50:
            return None

        # ── RAW12 Entpackung ──
        expected_bytes = n_new * n_groups * 3
        if len(raw_data) < expected_bytes:
            return None

        raw_buf = np.frombuffer(
            bytes(raw_data[:expected_bytes]),
            dtype=np.uint8).reshape(n_new, n_groups, 3)
        b1 = raw_buf[:, :, 1].astype(np.uint16)
        # Gain-Modus lesen (0=Auto/LCG, 1=HCG)
        _gm = getattr(self, 'gain_mode', None)
        _use_hcg = (_gm is not None and _gm.value == 1)
        if _use_hcg:
            b0 = raw_buf[:, :, 0].astype(np.uint16)
            new_lcg = (b0 << 4) | (b1 & 0x0F)
            del b0
        else:
            b2 = raw_buf[:, :, 2].astype(np.uint16)
            new_lcg = (b2 << 4) | (b1 >> 4)
            del b2
        del raw_buf, b1, raw_data

        # Mode-Wechsel erkennen → ISP-Cache zuruecksetzen
        _prev_mode = isp_cache.get('_gain_mode_prev')
        _cur_mode = 1 if _use_hcg else 0
        if _prev_mode is not None and _prev_mode != _cur_mode:
            isp_cache.pop('_lcg_persistent', None)
            isp_cache.pop('bl_lcg', None)
            isp_cache.pop('_wp_lcg', None)
            isp_cache.pop('_bl_wp_lut8', None)
            isp_cache.pop('wb_gains', None)
            isp_cache.pop('_wb_lut_bgr', None)
        isp_cache['_gain_mode_prev'] = _cur_mode

        idx_arr = np.array(valid_indices, dtype=np.intp)

        # ── Bayer-Paritaets-Korrektur (RCCB-Sensor) ──
        # Sequenzielle Platzierung: Zeile 0 → Position 0.
        # RCCB: Clear (hell) muss an gerader Position (0, 2, 4, ...) stehen.
        # Wenn Zeile 0 dunkler als Zeile 1 → Zeile 0 ist Blue → shift +1.
        if n_new >= 4:
            m0 = float(new_lcg[0, ::8].mean())
            m1 = float(new_lcg[1, ::8].mean())
            shift = 1 if m1 > m0 else 0
            if m1 > m0:
                idx_arr = idx_arr + 1
                mask = idx_arr < expected_h
                idx_arr = idx_arr[mask]
                new_lcg = new_lcg[mask]

            # ── V1 Diagnose: Parity + Line-Header + Pixelwerte ──
            sid = state.get('active_stream', 0)
            if frame_num <= 50 or frame_num % 200 == 0:
                # Zeile 0-3: Mean + erste 6 LCG-Werte
                r0 = new_lcg[0, :6].tolist() if n_new > 0 else []
                r1 = new_lcg[1, :6].tolist() if n_new > 1 else []
                r2 = new_lcg[2, :6].tolist() if n_new > 2 else []
                r3 = new_lcg[3, :6].tolist() if n_new > 3 else []
                # Line-Counter (hdr14) der ersten 5 Zeilen
                h14 = hdr14_list[:5]
                # Zeilenmittelwerte (::2 Subsampling: gerade/ungerade getrennt)
                m0_even = float(new_lcg[0, ::2].mean()) if n_new > 0 else 0
                m0_odd = float(new_lcg[0, 1::2].mean()) if n_new > 0 else 0
                m1_even = float(new_lcg[1, ::2].mean()) if n_new > 1 else 0
                m1_odd = float(new_lcg[1, 1::2].mean()) if n_new > 1 else 0
                self._log(
                    f"[DIAG] S0x{sid:x} F{frame_num}: "
                    f"shift={shift} m0={m0:.0f} m1={m1:.0f} | "
                    f"hdr14={h14} | "
                    f"r0_ev={m0_even:.0f} r0_od={m0_odd:.0f} "
                    f"r1_ev={m1_even:.0f} r1_od={m1_odd:.0f} | "
                    f"row0={r0} row1={r1}")

        # ── Index-basierte Platzierung im persistenten Buffer ──
        persistent = isp_cache.get('_lcg_persistent')
        if persistent is None or persistent.shape != (expected_h, lcg_w):
            persistent = np.zeros((expected_h, lcg_w), dtype=np.uint16)

        persistent[idx_arr] = new_lcg
        isp_cache['_lcg_persistent'] = persistent
        del new_lcg

        return self._isp_pipeline(persistent.copy(), isp_cache, frame_num,
                                  state.get('active_stream', 0))

    # ════════════════════════════════════════════════════════════════
    #  ISP Pipeline: LCG → Binning → Demosaic → WB/Gamma → BGR
    # ════════════════════════════════════════════════════════════════

    def _isp_pipeline(self, lcg, isp_cache, frame_num, stream_id):
        """Vereinfachte ISP-Pipeline (identisch zu wireshark_panel)."""
        bh, bw = lcg.shape

        # ── 1. Bayer 2x2 Binning ──
        if bh >= 50 and bw >= 50:
            bh4 = (bh // 4) * 4
            bw4 = (bw // 4) * 4
            src = lcg[:bh4, :bw4]
            binned = np.empty((bh4 // 2, bw4 // 2), dtype=np.uint16)
            binned[0::2, 0::2] = (src[0::4, 0::4].astype(np.uint32) +
                                  src[0::4, 2::4] + src[2::4, 0::4] +
                                  src[2::4, 2::4]) >> 2
            binned[0::2, 1::2] = (src[0::4, 1::4].astype(np.uint32) +
                                  src[0::4, 3::4] + src[2::4, 1::4] +
                                  src[2::4, 3::4]) >> 2
            binned[1::2, 0::2] = (src[1::4, 0::4].astype(np.uint32) +
                                  src[1::4, 2::4] + src[3::4, 0::4] +
                                  src[3::4, 2::4]) >> 2
            binned[1::2, 1::2] = (src[1::4, 1::4].astype(np.uint32) +
                                  src[1::4, 3::4] + src[3::4, 1::4] +
                                  src[3::4, 3::4]) >> 2
            lcg = binned
            del binned, src

        # ── 2. Black-Level + White-Point via uint16→uint8 LUT ──
        bl_cnt = isp_cache.get('_bl_cnt', 0) + 1
        isp_cache['_bl_cnt'] = bl_cnt

        if bl_cnt % 5 == 1 or '_bl_wp_lut8' not in isp_cache:
            sub = lcg[::4, ::4]
            sub_pos = sub[sub > 0]
            if len(sub_pos) > 100:
                bl_new = float(np.percentile(sub_pos, 1))
                wp_new = max(float(np.percentile(sub_pos, 99.5)) - bl_new, 1.0)
            else:
                bl_new, wp_new = 0.0, 65535.0
            bl_old = isp_cache.get('bl_lcg')
            bl = bl_old * 0.8 + bl_new * 0.2 if bl_old is not None else bl_new
            wp_old = isp_cache.get('_wp_lcg')
            wp = wp_old * 0.8 + wp_new * 0.2 if wp_old is not None else wp_new
            isp_cache['bl_lcg'] = bl
            isp_cache['_wp_lcg'] = max(wp, 1.0)
            x = np.arange(65536, dtype=np.float32)
            np.clip((x - bl) * (255.0 / max(wp, 1.0)), 0, 255, out=x)
            isp_cache['_bl_wp_lut8'] = x.astype(np.uint8)

        bayer_8 = isp_cache['_bl_wp_lut8'][lcg]
        del lcg

        # ── 3. Bayer RG Demosaic (RCCB: R bei [0,0]) ──
        bgr_8 = cv2.cvtColor(bayer_8, cv2.COLOR_BayerRG2BGR)
        del bayer_8

        # ── 4. White Balance + Gamma ──
        wb_sub = bgr_8[::4, ::4]
        gm = float(np.mean(wb_sub[:, :, 1]))
        bm = float(np.mean(wb_sub[:, :, 0]))
        rm = float(np.mean(wb_sub[:, :, 2]))
        gain_b = (gm / bm) if bm > 0 else 1.0
        gain_r = (gm / rm) if rm > 0 else 1.0

        prev = isp_cache.get('wb_gains')
        rebuild = True
        if prev is not None:
            if (abs(gain_b - prev[0]) / max(prev[0], 1e-6) < 0.05
                    and abs(gain_r - prev[1]) / max(prev[1], 1e-6) < 0.05):
                rebuild = False
        if rebuild:
            def _make_lut8(gain):
                x = np.arange(256, dtype=np.float32) / 255.0
                x = np.clip(x * gain, 0, 1)
                return (np.power(x, 1.0 / 2.2) * 255).astype(np.uint8)

            lut_b = _make_lut8(gain_b)
            lut_g = _make_lut8(1.0)
            lut_r = _make_lut8(gain_r)
            lut_bgr = np.zeros((256, 1, 3), dtype=np.uint8)
            lut_bgr[:, 0, 0] = lut_b
            lut_bgr[:, 0, 1] = lut_g
            lut_bgr[:, 0, 2] = lut_r
            isp_cache['wb_gains'] = (gain_b, gain_r)
            isp_cache['_wb_lut_bgr'] = lut_bgr

        bgr = cv2.LUT(bgr_8, isp_cache['_wb_lut_bgr'])
        del bgr_8

        # ── 5. Resize auf Vorschau-Groesse (480x540 statt 1920x1080) ──
        # Display ist nur ~800x420 → groessere Frames verschwenden CPU+RAM
        tw, th = 480, 540
        src_h, src_w = bgr.shape[:2]
        scale = min(tw / src_w, th / src_h)
        out_w = int(src_w * scale) & ~1
        out_h = int(src_h * scale) & ~1
        if out_w < 2 or out_h < 2:
            out_w, out_h = tw, th
        bgr = cv2.resize(bgr, (out_w, out_h), interpolation=cv2.INTER_LINEAR)

        # Farb-Diagnose (erste 10 Frames + jeder 50.)
        if frame_num <= 10 or frame_num % 50 == 0:
            try:
                _cs = bgr[::4, ::4]
                _bm = float(np.mean(_cs[:, :, 0]))
                _gm = float(np.mean(_cs[:, :, 1]))
                _rm = float(np.mean(_cs[:, :, 2]))
                with open('/tmp/0x2090_isp.log', 'a') as _f:
                    _f.write(f"[AF] F{frame_num} S0x{stream_id:x}: "
                             f"{src_h}x{src_w}→{out_h}x{out_w}, "
                             f"preWB B={bm:.0f} G={gm:.0f} R={rm:.0f}, "
                             f"gain_b={gain_b:.2f} gain_r={gain_r:.2f}, "
                             f"out B={_bm:.0f} G={_gm:.0f} R={_rm:.0f}\n")
            except Exception:
                pass

        # ── 帧抖动诊断 (帧间时间差 + coverage) ──
        try:
            import time as _time
            _jt_key = f'_jitter_{stream_id}'
            _jt = isp_cache.get(_jt_key)
            _now = _time.monotonic()
            if _jt is None:
                _jt = {'prev_time': _now, 'events': 0, 'total': 0,
                       'log_f': open('/tmp/0x2090_jitter.log', 'a')}
                isp_cache[_jt_key] = _jt
                _jt['log_f'].write(
                    f"\n=== Jitter-Diagnose gestartet S0x{stream_id:x} "
                    f"{_time.strftime('%H:%M:%S')} ===\n")
                _jt['log_f'].flush()
            else:
                _dt = (_now - _jt['prev_time']) * 1000  # ms
                _jt['total'] += 1
                # 正常帧间隔约 33ms (30fps) 或 66ms (15fps)
                # 异常: dt > 100ms (丢帧/卡顿) 或 dt < 10ms (突发)
                _is_anomaly = (_dt > 100) or (_dt < 10)
                if _is_anomaly:
                    _jt['events'] += 1
                    _jt['log_f'].write(
                        f"[JITTER] F{frame_num} S0x{stream_id:x} "
                        f"t={_time.strftime('%H:%M:%S')} "
                        f"dt={_dt:.0f}ms "
                        f"events={_jt['events']}/{_jt['total']}\n")
                    _jt['log_f'].flush()
                elif frame_num % 300 == 0:
                    _jt['log_f'].write(
                        f"[OK]     F{frame_num} S0x{stream_id:x} "
                        f"t={_time.strftime('%H:%M:%S')} "
                        f"dt={_dt:.0f}ms "
                        f"events={_jt['events']}/{_jt['total']}\n")
                    _jt['log_f'].flush()
            _jt['prev_time'] = _now
        except Exception:
            pass

        return bgr

    # ════════════════════════════════════════════════════════════════
    #  SharedMemory Output
    # ════════════════════════════════════════════════════════════════

    def _write_frame(self, shm, bgr, frame_num, stream_id=0):
        """BGR-Frame in SharedMemory schreiben (Double-Buffer, tear-free)."""
        h, w = bgr.shape[:2]
        nbytes = h * w * 3
        if nbytes > self.MAX_BGR_BYTES:
            return

        buf = shm.buf

        # In den INAKTIVEN Slot schreiben
        active = struct.unpack_from('<I', buf, 0)[0]
        target = 1 - active
        off = self.SHM_HEADER + target * self.SLOT_SIZE

        # Erst Daten, dann Header (inkl. stream_id)
        buf[off + self.SLOT_HEADER:off + self.SLOT_HEADER + nbytes] = \
            bgr.tobytes()
        struct.pack_into('<IIII', buf, off, frame_num, h, w, stream_id)

        # Atomar Slot flippen (4-Byte-Write ist auf x86 atomar)
        struct.pack_into('<I', buf, 0, target)

        # Hauptprozess benachrichtigen via Connection
        try:
            self.notify_conn.send_bytes(b'\x01')
        except (OSError, BrokenPipeError):
            pass

    # ════════════════════════════════════════════════════════════════
    #  Hilfsfunktionen
    # ════════════════════════════════════════════════════════════════

    def _log(self, msg):
        try:
            with open('/tmp/capture_process.log', 'a') as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        except Exception:
            pass
