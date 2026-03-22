#!/usr/bin/env python3
"""Testskript: Verifiziert PLP/TECMP/CMP Paketformate fuer CAN Simulator.

Verwendung:
  1. Terminal 1: Wireshark starten auf dem Ziel-Interface
       sudo wireshark -i eth0 -k -f "ether proto 0x2090 or ether proto 0x99fe"

  2. Terminal 2: Dieses Skript ausfuehren
       sudo python3 tests/test_sim_protocols.py --iface eth0

  3. In Wireshark pruefen:
     - Frame 1-3: PLP  (EtherType 0x2090) mit CAN ID 0x100, 0x200, 0x7FF
     - Frame 4-6: TECMP (EtherType 0x99FE) mit CAN ID 0x100, 0x200, 0x7FF
     - Frame 7-9: CMP   (EtherType 0x99FE) mit CAN ID 0x100, 0x200, 0x7FF

  Ohne --send: Nur Hex-Dump der Pakete (kein Root noetig).
  Mit  --send: Tatsaechlich ueber Raw-Socket senden (Root noetig).
"""

import argparse
import os
import socket
import struct
import time


# ── CAN Payload Builder ──────────────────────────────────────────────

def build_can_payload(can_id: int, dlc: int, data: bytes,
                      is_ext: bool = False) -> bytes:
    """CAN Frame Payload: CAN_ID(4) + DLC(1) + Data(DLC)"""
    id_raw = can_id | (0x80000000 if is_ext else 0)
    return struct.pack('>IB', id_raw, dlc) + data[:dlc]


# ── PLP / TECMP Packet Builder ───────────────────────────────────────

def build_plp_tecmp(can_payload: bytes, counter: int) -> bytes:
    """PLP/TECMP: Header(12B) + Entry(16B) + CAN Payload.

    Header:
      DeviceID(2) + Counter(2) + Version(1)=3 + MsgType(1)=0x0A
      + DataType(2)=0x0002 + Flags(4)=0

    Entry:
      CM_ID(2)=0 + InterfaceID(2)=1 + Timestamp(8)
      + DataLength(2) + DataFlags(2)=0
    """
    device_id = 0xFFFF
    version = 3
    msg_type = 0x0A      # Replay Data
    data_type = 0x0002   # CAN Data

    header = struct.pack('>HH BB HI',
                         device_id, counter & 0xFFFF,
                         version, msg_type,
                         data_type, 0)

    ts_ns = int(time.time() * 1_000_000_000) & 0xFFFFFFFFFFFFFFFF
    entry = struct.pack('>HH QH H',
                        0x0000,              # CM_ID
                        0x0001,              # InterfaceID
                        ts_ns,
                        len(can_payload),    # DataLength
                        0x0000)              # DataFlags

    return header + entry + can_payload


# ── ASAM CMP Packet Builder ──────────────────────────────────────────

def build_cmp(can_payload: bytes, counter: int) -> bytes:
    """ASAM CMP: Header(8B) + CAN Payload.

    Header:
      CmpVersion(1)=0x01 + Reserved(1)=0x00 + DeviceId(2)=0xFFFF
      + MessageType(1)=0x01 + StreamId(1)=0x01 + SeqCounter(2)
    """
    header = struct.pack('>BB HB BH',
                         0x01,    # CmpVersion
                         0x00,    # Reserved
                         0xFFFF,  # DeviceId (Simulator)
                         0x01,    # MessageType = Data
                         0x01,    # StreamId
                         counter & 0xFFFF)
    return header + can_payload


# ── Ethernet Frame Builder ───────────────────────────────────────────

def build_eth_frame(payload: bytes, ether_type: int,
                    src_mac: bytes) -> bytes:
    """Ethernet Frame: Dst(6) + Src(6) + EtherType(2) + Payload"""
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
    return dst_mac + src_mac + struct.pack('>H', ether_type) + payload


def get_mac(iface: str) -> bytes:
    """Liest MAC-Adresse eines Interfaces."""
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return bytes.fromhex(f.read().strip().replace(':', ''))
    except Exception:
        return b'\x02\x00\x00\x00\x00\x01'


# ── Hex Dump ─────────────────────────────────────────────────────────

def hex_dump(data: bytes, label: str):
    """Gibt einen formatierten Hex-Dump aus."""
    print(f"\n{'=' * 60}")
    print(f" {label}")
    print(f" Laenge: {len(data)} Bytes")
    print(f"{'=' * 60}")

    # Ethernet Header
    print(f"  Dst MAC:    {data[0:6].hex(':')}")
    print(f"  Src MAC:    {data[6:12].hex(':')}")
    etype = int.from_bytes(data[12:14], 'big')
    print(f"  EtherType:  0x{etype:04X}", end="")
    if etype == 0x2090:
        print(" (PLP)")
    elif etype == 0x99FE:
        print(" (TECMP/CMP)")
    else:
        print()

    payload = data[14:]
    print(f"  Payload ({len(payload)} Bytes):")

    # Protocol Header
    if etype == 0x2090 or (etype == 0x99FE and len(payload) >= 12
                           and payload[4] == 3):
        # PLP/TECMP
        if len(payload) >= 12:
            dev = int.from_bytes(payload[0:2], 'big')
            cnt = int.from_bytes(payload[2:4], 'big')
            ver = payload[4]
            mtype = payload[5]
            dtype = int.from_bytes(payload[6:8], 'big')
            flags = int.from_bytes(payload[8:12], 'big')
            proto_name = "PLP" if etype == 0x2090 else "TECMP"
            print(f"    [{proto_name} Header]"
                  f" DevID=0x{dev:04X} Cnt={cnt}"
                  f" Ver={ver} MsgType=0x{mtype:02X}"
                  f" DataType=0x{dtype:04X} Flags=0x{flags:08X}")

        if len(payload) >= 28:
            cm = int.from_bytes(payload[12:14], 'big')
            iid = int.from_bytes(payload[14:16], 'big')
            ts = int.from_bytes(payload[16:24], 'big')
            dlen = int.from_bytes(payload[24:26], 'big')
            dflags = int.from_bytes(payload[26:28], 'big')
            print(f"    [Entry Header]"
                  f" CM_ID=0x{cm:04X} IfaceID=0x{iid:04X}"
                  f" Timestamp={ts} DataLen={dlen}"
                  f" DataFlags=0x{dflags:04X}")

            can_data = payload[28:]
            _dump_can(can_data)
    else:
        # ASAM CMP
        if len(payload) >= 8:
            cver = payload[0]
            dev = int.from_bytes(payload[2:4], 'big')
            mtype = payload[4]
            sid = payload[5]
            seq = int.from_bytes(payload[6:8], 'big')
            print(f"    [ASAM CMP Header]"
                  f" Version=0x{cver:02X} DevID=0x{dev:04X}"
                  f" MsgType=0x{mtype:02X} StreamID={sid}"
                  f" SeqCnt={seq}")

            can_data = payload[8:]
            _dump_can(can_data)


def _dump_can(can_data: bytes):
    """Gibt CAN-Payload Details aus."""
    if len(can_data) >= 5:
        cid_raw = int.from_bytes(can_data[0:4], 'big')
        ext = bool(cid_raw & 0x80000000)
        cid = cid_raw & 0x1FFFFFFF
        dlc = can_data[4]
        data = can_data[5:5 + dlc]
        data_hex = ' '.join(f'{b:02X}' for b in data)
        id_type = "EXT" if ext else "STD"
        print(f"    [CAN Payload]"
              f" ID=0x{cid:03X} ({id_type})"
              f" DLC={dlc}"
              f" Data=[{data_hex}]")


# ── Testfaelle ───────────────────────────────────────────────────────

TEST_FRAMES = [
    # (can_id, dlc, data, is_ext, beschreibung)
    (0x100, 8, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
     False, "Standard CAN 0x100"),
    (0x200, 4, bytes([0xDE, 0xAD, 0xBE, 0xEF]),
     False, "Standard CAN 0x200 (4 Bytes)"),
    (0x7FF, 8, bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]),
     False, "Standard CAN 0x7FF (max ID)"),
]


def run_tests(iface: str, do_send: bool):
    src_mac = get_mac(iface)
    print(f"Interface: {iface}")
    print(f"MAC:       {src_mac.hex(':')}")

    sock = None
    if do_send:
        print("\nSende-Modus aktiv — Pakete werden tatsaechlich gesendet!")
    else:
        print("\nNur Hex-Dump (kein Senden). "
              "Fuer tatsaechliches Senden: --send")

    counter = 0
    all_frames = []

    for proto, etype, builder in [
        ("PLP",   0x2090, build_plp_tecmp),
        ("TECMP", 0x99FE, build_plp_tecmp),
        ("CMP",   0x99FE, build_cmp),
    ]:
        for can_id, dlc, data, is_ext, desc in TEST_FRAMES:
            counter += 1
            can_payload = build_can_payload(can_id, dlc, data, is_ext)
            proto_payload = builder(can_payload, counter)
            eth_frame = build_eth_frame(proto_payload, etype, src_mac)

            label = f"[{counter}] {proto} — {desc}"
            hex_dump(eth_frame, label)
            all_frames.append((eth_frame, etype, label))

    if do_send:
        print(f"\n{'*' * 60}")
        print(f" Sende {len(all_frames)} Frames ueber {iface}...")
        print(f"{'*' * 60}")

        for eth_frame, etype, label in all_frames:
            try:
                sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW,
                    socket.htons(etype))
                sock.bind((iface, 0))
                sock.send(eth_frame)
                print(f"  OK: {label}")
                sock.close()
            except PermissionError:
                print(f"  FEHLER: Root-Rechte benoetigt! "
                      f"(sudo python3 {__file__})")
                return
            except Exception as e:
                print(f"  FEHLER: {e}")
            time.sleep(0.1)  # 100ms zwischen Frames

        print(f"\nAlle {len(all_frames)} Frames gesendet.")
        print(f"Pruefen Sie Wireshark auf {iface}:")
        print(f"  Filter: eth.type == 0x2090 || eth.type == 0x99fe")

    print("\n--- Erwartete Ergebnisse in Wireshark ---")
    print("Frame 1-3:  EtherType 0x2090 (PLP)")
    print("  Header: DevID=0xFFFF, Ver=3, MsgType=0x0A, "
          "DataType=0x0002")
    print("  Entry:  CM_ID=0, IfaceID=1, DataFlags=0")
    print("  CAN:    ID=0x100/0x200/0x7FF, DLC=8/4/8")
    print()
    print("Frame 4-6:  EtherType 0x99FE (TECMP)")
    print("  Gleicher Header wie PLP, nur anderer EtherType")
    print()
    print("Frame 7-9:  EtherType 0x99FE (ASAM CMP)")
    print("  Header: CmpVer=0x01, DevID=0xFFFF, "
          "MsgType=0x01, StreamID=1")
    print("  CAN Payload direkt nach 8-Byte Header")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='CAN Simulator Protokoll-Test '
                    '(PLP/TECMP/CMP)')
    parser.add_argument('--iface', default='eth0',
                        help='Netzwerk-Interface (default: eth0)')
    parser.add_argument('--send', action='store_true',
                        help='Tatsaechlich senden (benoetigt root)')
    args = parser.parse_args()

    run_tests(args.iface, args.send)
