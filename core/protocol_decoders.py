"""Gemeinsame Protokoll-Decoder für automotive Ethernet-Protokolle.

Verwendet von wireshark_panel.py und logger_panel.py.
Unterstützte Protokolle:
  - TECMP (Technica Engineering Capture Module Protocol)
  - IEEE 1722 (AVTP - Audio Video Transport Protocol)
  - PLP (Physical Layer Protocol)
  - GMSL2/3 (Maxim SerDes, via AED GmbH SLA-Module)
  - FPD-Link III/IV (TI SerDes, via AED GmbH SLA-Module)
"""

from typing import Optional, List, Dict, Any


# ---------------------------------------------------------------------------
# TECMPDecoder — Extrahiert aus wireshark_panel.py
# ---------------------------------------------------------------------------

class TECMPDecoder:
    """Decoder für PLP/TECMP (Technically Enhanced Capture Module Protocol)."""

    TECMP_ETHERTYPE = 0x99FE
    TECMP_DEFAULT_UDP_PORT = 50000

    MESSAGE_TYPES = {
        0x00: "Control",
        0x01: "Status Device",
        0x02: "Status Bus",
        0x03: "Log Stream",
        0x04: "Config",
        0x0A: "Replay Data",
        0x0B: "Counter Event",
        0x0C: "Timesync Event",
    }

    DATA_TYPES = {
        0x0001: "CAN Raw",
        0x0002: "CAN Data",
        0x0003: "CAN FD",
        0x0004: "LIN",
        0x0008: "FlexRay",
        0x000A: "GPIO",
        0x0010: "RS232",
        0x0020: "Analog",
        0x0080: "Ethernet",
        0x0081: "Ethernet Raw",
        0x0104: "I2C",
    }

    # Technica GmbH Capture-Module Geräteliste
    DEVICES = {
        "CM 1000 High": "Technica CM 1000 High – Automotive Ethernet 1000BASE-T1",
        "CM 100 High": "Technica CM 100 High – Automotive Ethernet 100BASE-T1",
        "CM 10Base-T1S": "Technica CM 10Base-T1S – 10BASE-T1S Multidrop",
        "CM SerDes": "Technica CM SerDes – SerDes (GMSL/FPD-Link) Capture",
        "CM MultiGigabit": "Technica CM MultiGigabit – Multi-Gigabit Ethernet",
        "CM Ethernet Combo": "Technica CM Ethernet Combo – Multi-Speed Ethernet",
        "CM ILaS Combo": "Technica CM ILaS Combo – ILaS + Ethernet",
        "CM CAN Combo": "Technica CM CAN Combo – CAN/CAN-FD + Ethernet",
        "CM LIN Combo": "Technica CM LIN Combo – LIN + Ethernet",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert TECMP-Header (12 Bytes)."""
        result = {"protocol": "PLP/TECMP", "fields": []}

        if len(data) < 12:
            result["error"] = "TECMP header too short"
            return result

        device_id = int.from_bytes(data[0:2], 'big')
        counter = int.from_bytes(data[2:4], 'big')
        version = data[4]
        msg_type = data[5]
        data_type = int.from_bytes(data[6:8], 'big')
        flags = int.from_bytes(data[8:12], 'big')

        result["device_id"] = device_id
        result["counter"] = counter
        result["version"] = version
        result["msg_type"] = msg_type
        result["data_type"] = data_type
        result["flags"] = flags

        result["fields"].append(("Device ID", f"0x{device_id:04X}"))
        result["fields"].append(("Counter", str(counter)))
        result["fields"].append(("Version", str(version)))
        result["fields"].append(("Message Type", f"0x{msg_type:02X} ({cls.MESSAGE_TYPES.get(msg_type, 'Unknown')})"))
        result["fields"].append(("Data Type", f"0x{data_type:04X} ({cls.DATA_TYPES.get(data_type, 'Unknown')})"))
        result["fields"].append(("Flags", f"0x{flags:08X}"))

        # Payload Entries dekodieren
        if len(data) > 12:
            entries = cls._decode_entry_header(data[12:], data_type)
            if entries:
                result["entries"] = entries

        return result

    @classmethod
    def _decode_entry_header(cls, data: bytes, data_type: int = 0) -> List[Dict[str, Any]]:
        """Dekodiert TECMP Payload Entry Header (16 Bytes pro Entry).

        Format: CM_ID(2) + InterfaceID(2) + Timestamp(8) + DataLength(2) + DataFlags(2)
        """
        entries = []
        offset = 0

        while offset + 16 <= len(data):
            entry = {}
            cm_id = int.from_bytes(data[offset:offset+2], 'big')
            interface_id = int.from_bytes(data[offset+2:offset+4], 'big')
            timestamp_ns = int.from_bytes(data[offset+4:offset+12], 'big')
            data_length = int.from_bytes(data[offset+12:offset+14], 'big')
            data_flags = int.from_bytes(data[offset+14:offset+16], 'big')

            entry["cm_id"] = cm_id
            entry["interface_id"] = interface_id
            entry["timestamp_ns"] = timestamp_ns
            entry["data_length"] = data_length

            entry["fields"] = [
                ("CM ID", f"0x{cm_id:04X}"),
                ("Interface ID", f"0x{interface_id:04X}"),
                ("Timestamp (ns)", str(timestamp_ns)),
                ("Data Length", str(data_length)),
                ("Data Flags", f"0x{data_flags:04X}"),
            ]

            # Sub-Protokoll-Payload
            payload_start = offset + 16
            payload_end = payload_start + data_length
            if payload_end <= len(data):
                payload_bytes = data[payload_start:payload_end]
            else:
                payload_bytes = data[payload_start:]

            bus_info = cls._decode_bus_payload(data_type, payload_bytes)
            if bus_info:
                entry["bus_data"] = bus_info
            entry["payload"] = payload_bytes.hex().upper()

            entries.append(entry)
            offset = payload_end if payload_end <= len(data) else len(data)

        return entries

    @classmethod
    def _decode_bus_payload(cls, data_type: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Dispatcher: Ruft je nach data_type den passenden Sub-Protokoll-Decoder auf."""
        if data_type in (0x0001, 0x0002):
            return cls._decode_can(data)
        elif data_type == 0x0003:
            return cls._decode_can_fd(data)
        elif data_type == 0x0004:
            return cls._decode_lin(data)
        elif data_type == 0x0008:
            return cls._decode_flexray(data)
        elif data_type in (0x0080, 0x0081):
            return cls._decode_ethernet(data)
        elif data_type == 0x0020:
            return cls._decode_analog(data)
        elif data_type == 0x000A:
            return cls._decode_gpio(data)
        return None

    @classmethod
    def _decode_can(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert CAN Raw (0x0001) / CAN Data (0x0002) Frames."""
        if len(data) < 5:
            return None
        can_id_raw = int.from_bytes(data[0:4], 'big')
        extended = bool(can_id_raw & 0x80000000)
        can_id = can_id_raw & 0x1FFFFFFF
        dlc = data[4]
        payload = data[5:5 + dlc]
        data_hex = " ".join(f"{b:02X}" for b in payload)
        id_type = "Extended" if extended else "Standard"
        return {
            "protocol": "CAN Data Frame",
            "fields": [
                ("CAN ID", f"0x{can_id:03X} ({id_type})"),
                ("DLC", str(dlc)),
                ("Data", data_hex),
            ],
        }

    @classmethod
    def _decode_can_fd(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert CAN FD (0x0003) Frames."""
        if len(data) < 6:
            return None
        can_id_raw = int.from_bytes(data[0:4], 'big')
        extended = bool(can_id_raw & 0x80000000)
        can_id = can_id_raw & 0x1FFFFFFF
        flags = data[4]
        brs = bool(flags & 0x01)
        esi = bool(flags & 0x02)
        dlc = data[5]
        payload = data[6:6 + dlc]
        data_hex = " ".join(f"{b:02X}" for b in payload)
        id_type = "Extended" if extended else "Standard"
        fd_flags = []
        if brs:
            fd_flags.append("BRS")
        if esi:
            fd_flags.append("ESI")
        return {
            "protocol": "CAN FD Frame",
            "fields": [
                ("CAN ID", f"0x{can_id:03X} ({id_type})"),
                ("FD Flags", ", ".join(fd_flags) if fd_flags else "None"),
                ("DLC", str(dlc)),
                ("Data", data_hex),
            ],
        }

    @classmethod
    def _decode_lin(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert LIN (0x0004) Frames."""
        if len(data) < 3:
            return None
        lin_id = data[0] & 0x3F
        dlc = data[1]
        payload = data[2:2 + dlc]
        data_hex = " ".join(f"{b:02X}" for b in payload)
        checksum_offset = 2 + dlc
        checksum = data[checksum_offset] if checksum_offset < len(data) else None
        fields = [
            ("LIN ID", f"0x{lin_id:02X}"),
            ("DLC", str(dlc)),
            ("Data", data_hex),
        ]
        if checksum is not None:
            fields.append(("Checksum", f"0x{checksum:02X}"))
        return {
            "protocol": "LIN Frame",
            "fields": fields,
        }

    @classmethod
    def _decode_flexray(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert FlexRay (0x0008) Frames."""
        if len(data) < 4:
            return None
        channel_byte = data[0]
        channel = "A" if channel_byte == 0 else "B" if channel_byte == 1 else f"0x{channel_byte:02X}"
        slot_id = int.from_bytes(data[1:3], 'big')
        cycle = data[3]
        payload = data[4:]
        data_hex = " ".join(f"{b:02X}" for b in payload)
        return {
            "protocol": "FlexRay Frame",
            "fields": [
                ("Channel", channel),
                ("Slot ID", str(slot_id)),
                ("Cycle", str(cycle)),
                ("Data", data_hex),
            ],
        }

    @classmethod
    def _decode_ethernet(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert Ethernet (0x0080) / Ethernet Raw (0x0081) Frames."""
        if len(data) < 14:
            return None
        dst_mac = ":".join(f"{b:02X}" for b in data[0:6])
        src_mac = ":".join(f"{b:02X}" for b in data[6:12])
        ethertype = int.from_bytes(data[12:14], 'big')
        payload = data[14:]
        return {
            "protocol": "Ethernet Frame",
            "fields": [
                ("Destination MAC", dst_mac),
                ("Source MAC", src_mac),
                ("EtherType", f"0x{ethertype:04X}"),
                ("Payload Length", str(len(payload))),
            ],
        }

    @classmethod
    def _decode_analog(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert Analog (0x0020) Messdaten."""
        if len(data) < 2:
            return None
        raw_value = int.from_bytes(data[0:2], 'big')
        voltage = raw_value * 5.0 / 4095  # 12-bit ADC, 0-5V Referenz
        fields = [
            ("Raw Value", str(raw_value)),
            ("Voltage", f"{voltage:.3f} V"),
        ]
        if len(data) >= 4:
            sample_rate = int.from_bytes(data[2:4], 'big')
            fields.append(("Sample Rate", f"{sample_rate} Hz"))
        return {"protocol": "Analog Sample", "fields": fields}

    @classmethod
    def _decode_gpio(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert GPIO (0x000A) Digitale I/O Daten."""
        if len(data) < 1:
            return None
        gpio_byte = data[0]
        level = "HIGH" if gpio_byte & 0x01 else "LOW"
        edge_bits = (gpio_byte >> 1) & 0x03
        edge = {0: "None", 1: "Rising", 2: "Falling", 3: "Both"}.get(
            edge_bits, "Unknown")
        fields = [
            ("Level", level),
            ("Edge", edge),
            ("Raw", f"0x{gpio_byte:02X}"),
        ]
        if len(data) >= 5:
            pulse_width_us = int.from_bytes(data[1:5], 'big')
            fields.append(("Pulse Width", f"{pulse_width_us} µs"))
        return {"protocol": "GPIO Event", "fields": fields}


# ---------------------------------------------------------------------------
# IEEE1722Decoder — IEEE 1722 (AVTP) Audio Video Transport Protocol
# ---------------------------------------------------------------------------

class IEEE1722Decoder:
    """Decoder für IEEE 1722 (AVTP - Audio Video Transport Protocol).

    EtherType: 0x22F0
    Verwendet für automotive Kamera-/Sensordatenübertragung.
    """

    AVTP_ETHERTYPE = 0x22F0

    SUBTYPES = {
        0x00: "IEC 61883/IIDC",
        0x01: "MMA Stream",
        0x02: "CVF (Compressed Video Format)",
        0x03: "CRF (Clock Reference Format)",
        0x04: "TSCF (Time-Synchronous Control Format)",
        0x05: "NTSCF (Non-Time-Synchronous Control Format)",
        0x6E: "EF (Experimental Format)",
        0x7E: "VSF (Vendor-Specific Format)",
        0x7F: "AEF (AVTP Encapsulation Format)",
    }

    # CVF Format Subtypes
    CVF_FORMATS = {
        0x00: "RFC Payload Type",
        0x01: "Reserved",
        0x02: "MJPEG",
        0x03: "H.264",
        0x04: "JPEG 2000",
    }

    # ACF (AVTP Control Format) Nachrichtentypen
    ACF_MSG_TYPES = {
        0x00: "FlexRay",
        0x01: "CAN",
        0x02: "CAN Brief",
        0x03: "LIN",
        0x04: "MOST",
        0x05: "GPC (General Purpose Control)",
        0x06: "Sensor",
        0x07: "Sensor Brief",
        0x08: "AECP",
        0x09: "Ancillary Data",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert AVTP Common Header.

        Byte 0: subtype (8 bits)
        Byte 1: sv (1 bit), version (3 bits), subtype_specific (4 bits)
        Bytes 4-11: stream_id (64 bits) - bei den meisten Subtypes
        """
        result = {"protocol": "IEEE 1722 (AVTP)", "fields": []}

        if len(data) < 4:
            result["error"] = "AVTP header too short"
            return result

        subtype = data[0]
        sv_ver_flags = data[1]
        sv = bool(sv_ver_flags & 0x80)
        version = (sv_ver_flags >> 4) & 0x07

        result["subtype"] = subtype
        result["version"] = version

        subtype_name = cls.SUBTYPES.get(subtype, f"Unknown (0x{subtype:02X})")
        result["fields"].append(("Subtype", f"0x{subtype:02X} ({subtype_name})"))
        result["fields"].append(("Stream Valid", str(sv)))
        result["fields"].append(("Version", str(version)))

        # Stream ID (Bytes 4-11) bei den meisten Subtypes
        if len(data) >= 12 and sv:
            stream_id = int.from_bytes(data[4:12], 'big')
            result["stream_id"] = stream_id
            result["fields"].append(("Stream ID", f"0x{stream_id:016X}"))

        # Subtype-spezifische Dekodierung
        if subtype == 0x02:  # CVF
            cvf_info = cls._decode_cvf(data)
            if cvf_info:
                result["subtype_data"] = cvf_info
                result["fields"].extend(cvf_info.get("fields", []))
        elif subtype in (0x04, 0x05):  # TSCF / NTSCF (ACF Container)
            acf_info = cls._decode_acf(data)
            if acf_info:
                result["subtype_data"] = acf_info
                result["fields"].extend(acf_info.get("fields", []))
        elif subtype == 0x03:  # CRF
            crf_info = cls._decode_crf(data)
            if crf_info:
                result["subtype_data"] = crf_info
                result["fields"].extend(crf_info.get("fields", []))

        return result

    @classmethod
    def _decode_cvf(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert CVF (Compressed Video Format).

        Verwendet für H.264/MJPEG Kamera-Streams.
        """
        if len(data) < 24:
            return None

        # CVF-spezifische Felder
        format_subtype = data[2] & 0x1F
        # Byte 3: reserved/M-bit
        m_bit = bool(data[3] & 0x10)
        # Bytes 12-15: avtp_timestamp
        avtp_timestamp = int.from_bytes(data[12:16], 'big')
        # Bytes 16-17: format specific
        format_info = data[2]
        # Bytes 20-21: stream_data_length
        stream_data_length = int.from_bytes(data[20:22], 'big')
        # Byte 22-23: tag/channel/etc
        cvf_format = (data[22] >> 4) & 0x0F

        format_name = cls.CVF_FORMATS.get(cvf_format, f"Unknown (0x{cvf_format:X})")

        fields = [
            ("CVF Format", format_name),
            ("Marker Bit", str(m_bit)),
            ("AVTP Timestamp", f"0x{avtp_timestamp:08X}"),
            ("Stream Data Length", str(stream_data_length)),
        ]

        return {"protocol": "CVF", "fields": fields}

    @classmethod
    def _decode_acf(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert ACF (AVTP Control Format) Container.

        Transportiert CAN, LIN, FlexRay, Sensor-Daten über AVTP.
        TSCF (subtype 0x04): mit Timestamp
        NTSCF (subtype 0x05): ohne Timestamp
        """
        if len(data) < 12:
            return None

        subtype = data[0]
        fields = []

        if subtype == 0x04:  # TSCF
            # Bytes 12-15: avtp_timestamp
            if len(data) >= 16:
                avtp_timestamp = int.from_bytes(data[12:16], 'big')
                fields.append(("AVTP Timestamp", f"0x{avtp_timestamp:08X}"))
            # Bytes 2-3: sequence_num + tu
            sequence_num = data[2]
            fields.append(("Sequence Num", str(sequence_num)))
            acf_offset = 16
        else:  # NTSCF
            # Bytes 2-3: sequence_num + length
            sequence_num = data[2]
            ntscf_length = int.from_bytes(data[2:4], 'big') & 0x07FF
            fields.append(("Sequence Num", str(sequence_num >> 3)))
            fields.append(("NTSCF Data Length", str(ntscf_length)))
            acf_offset = 12

        # ACF Messages dekodieren
        acf_messages = []
        offset = acf_offset
        while offset + 4 <= len(data):
            acf_msg_type = (data[offset] >> 1) & 0x7F
            acf_msg_length = int.from_bytes(data[offset + 2:offset + 4], 'big') & 0x01FF
            acf_msg_length_bytes = acf_msg_length * 4  # Quadlets

            msg_type_name = cls.ACF_MSG_TYPES.get(acf_msg_type, f"Unknown (0x{acf_msg_type:02X})")
            acf_messages.append({
                "type": acf_msg_type,
                "type_name": msg_type_name,
                "length": acf_msg_length_bytes,
            })

            offset += 4 + acf_msg_length_bytes
            if acf_msg_length_bytes == 0:
                break

        if acf_messages:
            fields.append(("ACF Messages", str(len(acf_messages))))
            for i, msg in enumerate(acf_messages):
                fields.append((f"  ACF[{i}] Type", msg["type_name"]))
                fields.append((f"  ACF[{i}] Length", f"{msg['length']} bytes"))

        return {"protocol": "ACF Container", "fields": fields, "messages": acf_messages}

    @classmethod
    def _decode_crf(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Dekodiert CRF (Clock Reference Format).

        Enthält Timestamp-Intervall und Referenz-Timestamps.
        """
        if len(data) < 20:
            return None

        # Byte 2: pull/type
        crf_type = data[2] & 0x03
        type_names = {0: "User", 1: "Audio Sample", 2: "Video Frame", 3: "Video Line"}
        # Bytes 12-15: base_frequency
        base_frequency = int.from_bytes(data[12:16], 'big')
        # Bytes 16-17: timestamp_interval + multiplier
        timestamp_interval = int.from_bytes(data[16:18], 'big')
        # Bytes 20+: CRF timestamps (8 bytes each)
        crf_data_length = int.from_bytes(data[18:20], 'big')

        fields = [
            ("CRF Type", type_names.get(crf_type, f"Unknown ({crf_type})")),
            ("Base Frequency", f"{base_frequency} Hz"),
            ("Timestamp Interval", str(timestamp_interval)),
            ("CRF Data Length", str(crf_data_length)),
        ]

        # Timestamps extrahieren
        ts_offset = 20
        ts_count = 0
        while ts_offset + 8 <= len(data) and ts_count < 5:
            ts = int.from_bytes(data[ts_offset:ts_offset + 8], 'big')
            fields.append((f"  CRF Timestamp[{ts_count}]", f"0x{ts:016X}"))
            ts_offset += 8
            ts_count += 1

        return {"protocol": "CRF", "fields": fields}


# ---------------------------------------------------------------------------
# ASAMCMPDecoder — ASAM Capture Module Protocol
# ---------------------------------------------------------------------------

class ASAMCMPDecoder:
    """Decoder fuer ASAM CMP (Capture Module Protocol).

    ASAM CMP teilt EtherType 0x99FE mit TECMP, hat aber ein anderes
    Header-Format (8 Bytes statt 12).

    Header:
      [0]    CmpVersion   (0x01 = V1.0)
      [1]    Reserved     (0x00)
      [2-3]  DeviceId
      [4]    MessageType
      [5]    StreamId
      [6-7]  StreamSequenceCounter
    """

    MESSAGE_TYPES = {
        0x01: "Data",
        0x02: "Status",
        0x03: "Control",
        0xFE: "Vendor Defined",
        0xFF: "Vendor Reserved",
    }

    # Bekannte Vendor-IDs
    VENDOR_IDS = {
        0x019C: "Technica Engineering",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert ASAM CMP Header (8 Bytes)."""
        result = {"protocol": "ASAM CMP", "fields": []}

        if len(data) < 8:
            result["error"] = "ASAM CMP header too short"
            return result

        cmp_version = data[0]
        reserved = data[1]
        device_id = int.from_bytes(data[2:4], 'big')
        msg_type = data[4]
        stream_id = data[5]
        seq_counter = int.from_bytes(data[6:8], 'big')

        result["cmp_version"] = cmp_version
        result["device_id"] = device_id
        result["msg_type"] = msg_type
        result["stream_id"] = stream_id
        result["seq_counter"] = seq_counter

        msg_type_name = cls.MESSAGE_TYPES.get(msg_type, f"Unknown (0x{msg_type:02X})")

        result["fields"].append(("CMP Version", f"0x{cmp_version:02X}"))
        result["fields"].append(("Device ID", f"0x{device_id:04X}"))
        result["fields"].append(("Message Type",
                                 f"0x{msg_type:02X} ({msg_type_name})"))
        result["fields"].append(("Stream ID", str(stream_id)))
        result["fields"].append(("Sequence Counter", str(seq_counter)))

        # Payload nach Header
        if len(data) > 8:
            payload_len = len(data) - 8
            result["fields"].append(("Payload Length", f"{payload_len} bytes"))

        return result


# ---------------------------------------------------------------------------
# PLPDecoder — Physical Layer Protocol
# ---------------------------------------------------------------------------

class PLPDecoder:
    """Decoder für PLP (Physical Layer Protocol) im TECMP-Ökosystem.

    PLP transportiert Physical-Layer-Metriken neben TECMP-Captures:
    - Spannungspegel, Flanken-Timing
    - Error-Frames, Bitfehler
    - PHY-Statistiken
    """

    # PLP-spezifische Datentypen innerhalb TECMP
    PLP_DATA_TYPES = {
        0x0100: "Ethernet PHY",
        0x0101: "CAN PHY",
        0x0102: "LIN PHY",
        0x0103: "FlexRay PHY",
    }

    # PLP Event Types
    EVENT_TYPES = {
        0x00: "No Event",
        0x01: "Voltage Level",
        0x02: "Bit Error",
        0x03: "PHY Error",
        0x04: "Wake Up",
        0x05: "Sleep",
        0x10: "Link Up",
        0x11: "Link Down",
        0x20: "PHY Statistics",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert PLP-Header und Payload."""
        result = {"protocol": "PLP", "fields": []}

        if len(data) < 8:
            result["error"] = "PLP data too short"
            return result

        # PLP Header
        phy_type = int.from_bytes(data[0:2], 'big')
        event_type = data[2]
        channel_id = data[3]
        timestamp_offset = int.from_bytes(data[4:8], 'big')

        result["phy_type"] = phy_type
        result["event_type"] = event_type

        phy_name = cls.PLP_DATA_TYPES.get(phy_type, f"Unknown (0x{phy_type:04X})")
        event_name = cls.EVENT_TYPES.get(event_type, f"Unknown (0x{event_type:02X})")

        result["fields"].append(("PHY Type", phy_name))
        result["fields"].append(("Event Type", event_name))
        result["fields"].append(("Channel ID", str(channel_id)))
        result["fields"].append(("Timestamp Offset", f"{timestamp_offset} ns"))

        # Event-spezifische Daten
        if len(data) > 8:
            if event_type == 0x01:  # Voltage Level
                cls._decode_voltage(data[8:], result)
            elif event_type in (0x02, 0x03):  # Bit/PHY Error
                cls._decode_error(data[8:], result)
            elif event_type == 0x20:  # PHY Statistics
                cls._decode_phy_stats(data[8:], result)

        return result

    @classmethod
    def _decode_voltage(cls, data: bytes, result: Dict[str, Any]):
        """Dekodiert Spannungspegel-Daten."""
        if len(data) >= 4:
            voltage_mv = int.from_bytes(data[0:2], 'big', signed=True)
            voltage_diff_mv = int.from_bytes(data[2:4], 'big', signed=True)
            result["fields"].append(("Voltage", f"{voltage_mv} mV"))
            result["fields"].append(("Differential Voltage", f"{voltage_diff_mv} mV"))

    @classmethod
    def _decode_error(cls, data: bytes, result: Dict[str, Any]):
        """Dekodiert Fehler-Daten."""
        if len(data) >= 4:
            error_code = int.from_bytes(data[0:2], 'big')
            error_count = int.from_bytes(data[2:4], 'big')
            result["fields"].append(("Error Code", f"0x{error_code:04X}"))
            result["fields"].append(("Error Count", str(error_count)))

    @classmethod
    def _decode_phy_stats(cls, data: bytes, result: Dict[str, Any]):
        """Dekodiert PHY-Statistiken."""
        if len(data) >= 16:
            rx_frames = int.from_bytes(data[0:4], 'big')
            tx_frames = int.from_bytes(data[4:8], 'big')
            rx_errors = int.from_bytes(data[8:12], 'big')
            link_speed = int.from_bytes(data[12:16], 'big')
            result["fields"].append(("RX Frames", str(rx_frames)))
            result["fields"].append(("TX Frames", str(tx_frames)))
            result["fields"].append(("RX Errors", str(rx_errors)))
            result["fields"].append(("Link Speed", f"{link_speed} Mbps"))


# ---------------------------------------------------------------------------
# GMSLDecoder — GMSL2/3 (Maxim/AED SLA Module)
# ---------------------------------------------------------------------------

class GMSLDecoder:
    """Decoder für GMSL2/3 (Maxim SerDes) Datenströme.

    Daten von AED GmbH SLA (SerDes Logging Adapter) Modulen
    kommen typischerweise in TECMP-Frames gekapselt an.
    Die innere Payload enthält GMSL-Paket-Header mit Virtual-Channel-ID
    und CSI-2-kompatiblen Datentypen.
    """

    # CSI-2 kompatible Datentypen (von GMSL übernommen)
    DATA_TYPES = {
        0x00: "Frame Start",
        0x01: "Frame End",
        0x10: "YUV420 8-bit",
        0x18: "YUV420 10-bit",
        0x1A: "YUV420 Legacy",
        0x1E: "YUV422 8-bit",
        0x1F: "YUV422 10-bit",
        0x22: "RGB444",
        0x24: "RGB888",
        0x2A: "RAW6",
        0x2B: "RAW8",
        0x2C: "RAW10",
        0x2D: "RAW12",
        0x2E: "RAW14",
        0x2F: "RAW16",
        0x30: "User Defined Type 1",
        0x31: "User Defined Type 2",
        0x32: "User Defined Type 3",
        0x33: "User Defined Type 4",
        0x12: "Embedded Data",
    }

    # GMSL Linkgeschwindigkeit
    LINK_SPEEDS = {
        0: "GMSL2 3Gbps",
        1: "GMSL2 6Gbps",
        2: "GMSL3 12Gbps",
        3: "GMSL3 24Gbps",
    }

    @classmethod
    def decode(cls, data: bytes, is_tecmp_encapsulated: bool = True) -> Dict[str, Any]:
        """Dekodiert GMSL-Frame aus Rohdaten oder TECMP-Payload.

        GMSL-Paket-Aufbau (innerhalb TECMP Ethernet Raw):
          Byte 0:    Link-ID (4 bit) + VC (2 bit) + Reserved (2 bit)
          Byte 1:    Data Type (6 bit) + Reserved (2 bit)
          Bytes 2-3: Word Count (Payload-Länge in Bytes)
          Bytes 4+:  Payload-Daten
        """
        result = {"protocol": "GMSL2/3", "fields": []}

        if len(data) < 4:
            result["error"] = "GMSL header too short"
            return result

        link_id = (data[0] >> 4) & 0x0F
        virtual_channel = (data[0] >> 2) & 0x03
        data_type = data[1] & 0x3F
        word_count = int.from_bytes(data[2:4], 'big')

        result["link_id"] = link_id
        result["virtual_channel"] = virtual_channel
        result["data_type_code"] = data_type
        result["word_count"] = word_count

        dt_name = cls.DATA_TYPES.get(data_type, f"Unknown (0x{data_type:02X})")

        result["fields"].append(("Link ID", str(link_id)))
        result["fields"].append(("Virtual Channel", str(virtual_channel)))
        result["fields"].append(("Data Type", f"0x{data_type:02X} ({dt_name})"))
        result["fields"].append(("Word Count", f"{word_count} bytes"))

        # Frame Start/End Metadaten
        if data_type == 0x00 and len(data) >= 8:  # Frame Start
            frame_number = int.from_bytes(data[4:6], 'big')
            result["fields"].append(("Frame Number", str(frame_number)))
        elif data_type == 0x12 and len(data) > 4:  # Embedded Data
            result["fields"].append(("Embedded Data Length", f"{len(data) - 4} bytes"))

        # Payload-Statistik
        payload_len = min(word_count, len(data) - 4)
        if payload_len > 0:
            result["fields"].append(("Payload Size", f"{payload_len} bytes"))

        return result


# ---------------------------------------------------------------------------
# FPDLinkDecoder — FPD-Link III/IV (TI/AED SLA Module)
# ---------------------------------------------------------------------------

class FPDLinkDecoder:
    """Decoder für FPD-Link III/IV (TI SerDes) Datenströme.

    Ähnlich wie GMSL, von AED GmbH SLA-Modulen.
    FPD-Link IV verwendet CSI-2-kompatibles Framing.
    """

    # FPD-Link Generationen
    GENERATIONS = {
        3: "FPD-Link III",
        4: "FPD-Link IV",
    }

    # CSI-2 kompatible Datentypen (gleich wie GMSL)
    DATA_TYPES = GMSLDecoder.DATA_TYPES.copy()

    # FPD-Link IV Modi
    MODES = {
        0x00: "Single View",
        0x01: "Dual View",
        0x02: "Surround View",
        0x03: "Dual Serializer",
    }

    @classmethod
    def decode(cls, data: bytes, is_tecmp_encapsulated: bool = True) -> Dict[str, Any]:
        """Dekodiert FPD-Link-Frame.

        FPD-Link-Paket-Aufbau (innerhalb TECMP Ethernet Raw):
          Byte 0:    Generation (4 bit) + Mode (4 bit)
          Byte 1:    VC (2 bit) + Data Type (6 bit)
          Bytes 2-3: Payload-Länge
          Bytes 4+:  Payload-Daten
        """
        result = {"protocol": "FPD-Link III/IV", "fields": []}

        if len(data) < 4:
            result["error"] = "FPD-Link header too short"
            return result

        generation = (data[0] >> 4) & 0x0F
        mode = data[0] & 0x0F
        virtual_channel = (data[1] >> 6) & 0x03
        data_type = data[1] & 0x3F
        payload_length = int.from_bytes(data[2:4], 'big')

        result["generation"] = generation
        result["mode"] = mode
        result["virtual_channel"] = virtual_channel
        result["data_type_code"] = data_type
        result["payload_length"] = payload_length

        gen_name = cls.GENERATIONS.get(generation, f"Gen {generation}")
        mode_name = cls.MODES.get(mode, f"Unknown (0x{mode:X})")
        dt_name = cls.DATA_TYPES.get(data_type, f"Unknown (0x{data_type:02X})")

        result["fields"].append(("Generation", gen_name))
        result["fields"].append(("Mode", mode_name))
        result["fields"].append(("Virtual Channel", str(virtual_channel)))
        result["fields"].append(("Data Type", f"0x{data_type:02X} ({dt_name})"))
        result["fields"].append(("Payload Length", f"{payload_length} bytes"))

        # Frame Start/End
        if data_type == 0x00 and len(data) >= 8:  # Frame Start
            frame_number = int.from_bytes(data[4:6], 'big')
            result["fields"].append(("Frame Number", str(frame_number)))
        elif data_type == 0x12 and len(data) > 4:  # Embedded Data
            result["fields"].append(("Embedded Data Length", f"{len(data) - 4} bytes"))

        # Payload-Statistik
        payload_actual = min(payload_length, len(data) - 4)
        if payload_actual > 0:
            result["fields"].append(("Payload Size", f"{payload_actual} bytes"))

        return result


# ---------------------------------------------------------------------------
# ProtocolDetector — Einheitliche Protokollerkennung
# ---------------------------------------------------------------------------

class ProtocolDetector:
    """Erkennt das Protokoll eines rohen Scapy-Pakets und dekodiert es."""

    @classmethod
    def detect(cls, pkt) -> str:
        """Gibt den Protokollnamen als String zurück.

        Returns:
            'TECMP', 'IEEE1722', 'PLP', 'GMSL', 'FPDLink', oder 'Unknown'
        """
        try:
            from scapy.all import Ether, IP, UDP, Raw
        except ImportError:
            return "Unknown"

        if not pkt.haslayer(Ether):
            return "Unknown"

        eth = pkt[Ether]

        # IEEE 1722 (AVTP) — EtherType 0x22F0
        if eth.type == IEEE1722Decoder.AVTP_ETHERTYPE:
            return "IEEE1722"

        # TECMP via EtherType 0x99FE
        if eth.type == TECMPDecoder.TECMP_ETHERTYPE:
            # Prüfe ob PLP oder GMSL/FPD-Link innerhalb TECMP
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                return cls._classify_tecmp_content(raw_data)
            return "TECMP"

        # TECMP via UDP Port 50000
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if (udp.sport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT or
                    udp.dport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT):
                if pkt.haslayer(Raw):
                    raw_data = bytes(pkt[Raw].load)
                    return cls._classify_tecmp_content(raw_data)
                return "TECMP"

        return "Unknown"

    @classmethod
    def _classify_tecmp_content(cls, data: bytes) -> str:
        """Klassifiziert 0x99FE-Inhalt: ASAM CMP, PLP oder TECMP.

        Erkennungslogik (alle teilen EtherType 0x99FE):
          - ASAM CMP: byte[0]=0x01 (CmpVersion), byte[1]=0x00 (Reserved)
          - TECMP:    byte[4] in (2, 3) → Version 2 oder 3
          - PLP:      TECMP mit data_type 0x0100-0x01FF (Physical Layer)
        """
        if len(data) < 8:
            return "TECMP"

        # ASAM CMP: CmpVersion=0x01, Reserved=0x00
        if data[0] == 0x01 and data[1] == 0x00:
            # Zusaetzliche Plausibilitaet: TECMP hat an byte[0-1] die DeviceID,
            # die selten genau 0x0100 ist. ASAM CMP hat MessageType an byte[4].
            # TECMP hat Version (2 oder 3) an byte[4].
            if data[4] not in (2, 3):
                return "ASAM CMP"

        if len(data) < 12:
            return "TECMP"

        data_type = int.from_bytes(data[6:8], 'big')

        # PLP-Datentypen (0x0100-0x01FF)
        if 0x0100 <= data_type <= 0x01FF:
            return "PLP"

        return "TECMP"

    @classmethod
    def decode(cls, pkt) -> Dict[str, Any]:
        """Erkennt und dekodiert ein Paket, gibt ein einheitliches Ergebnis-Dict zurück.

        Rückgabe-Dict enthält immer:
          - 'protocol': str
          - 'fields': List[Tuple[str, str]]
          - 'source': str
          - 'destination': str
          - 'length': int
          - 'info': str (zusammenfassende Info-Zeile)
          - 'device_id': int (0 wenn nicht TECMP)
          - 'data_type_code': int (0 wenn nicht zutreffend)
          - 'timestamp': float (Paket-Zeitstempel)
          - 'raw_bytes': bytes
        """
        import time
        try:
            from scapy.all import Ether, IP, UDP, Raw
        except ImportError:
            return cls._make_result("Unknown", [], bytes(pkt), "?", "?", 0, "Scapy nicht verfügbar")

        protocol = cls.detect(pkt)
        raw_bytes = bytes(pkt)
        length = len(raw_bytes)
        timestamp = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        # Quell- und Zieladresse extrahieren
        source = "?"
        destination = "?"
        if pkt.haslayer(Ether):
            source = pkt[Ether].src
            destination = pkt[Ether].dst
        if pkt.haslayer(IP):
            source = pkt[IP].src
            destination = pkt[IP].dst

        device_id = 0
        data_type_code = 0
        decoded_fields = []
        info = ""

        if protocol == "IEEE1722":
            if pkt.haslayer(Raw):
                decoded = IEEE1722Decoder.decode(bytes(pkt[Raw].load))
            elif pkt.haslayer(Ether) and len(raw_bytes) > 14:
                decoded = IEEE1722Decoder.decode(raw_bytes[14:])
            else:
                decoded = {"fields": []}
            decoded_fields = decoded.get("fields", [])
            subtype = decoded.get("subtype", -1)
            subtype_name = IEEE1722Decoder.SUBTYPES.get(subtype, "Unknown")
            info = f"AVTP {subtype_name}"

        elif protocol == "ASAM CMP":
            raw_payload = b""
            if pkt.haslayer(Raw):
                raw_payload = bytes(pkt[Raw].load)
            if raw_payload:
                decoded = ASAMCMPDecoder.decode(raw_payload)
                decoded_fields = decoded.get("fields", [])
                device_id = decoded.get("device_id", 0)
                msg_type = decoded.get("msg_type", 0)
                msg_type_name = ASAMCMPDecoder.MESSAGE_TYPES.get(
                    msg_type, f"0x{msg_type:02X}")
                stream_id = decoded.get("stream_id", 0)
                info = (f"ASAM CMP {msg_type_name}"
                        f" [Dev 0x{device_id:04X} Stream {stream_id}]")
            else:
                info = "ASAM CMP"

        elif protocol in ("TECMP", "PLP"):
            raw_payload = b""
            if pkt.haslayer(Raw):
                raw_payload = bytes(pkt[Raw].load)

            if raw_payload:
                decoded = TECMPDecoder.decode(raw_payload)
                decoded_fields = decoded.get("fields", [])
                device_id = decoded.get("device_id", 0)
                data_type_code = decoded.get("data_type", 0)
                msg_type = decoded.get("msg_type", 0)
                msg_type_name = TECMPDecoder.MESSAGE_TYPES.get(msg_type, "Unknown")
                dt_name = TECMPDecoder.DATA_TYPES.get(data_type_code, "Unknown")
                info = f"TECMP {msg_type_name} - {dt_name} [Dev 0x{device_id:04X}]"

                # Bei PLP zusätzliche Dekodierung
                if protocol == "PLP" and decoded.get("entries"):
                    for entry in decoded["entries"]:
                        payload_hex = entry.get("payload", "")
                        if payload_hex:
                            plp_data = bytes.fromhex(payload_hex)
                            plp_decoded = PLPDecoder.decode(plp_data)
                            decoded_fields.extend(plp_decoded.get("fields", []))
                            event_name = PLPDecoder.EVENT_TYPES.get(
                                plp_decoded.get("event_type", 0), "Unknown")
                            info = f"PLP {event_name}"
            else:
                info = protocol

        elif protocol in ("GMSL", "FPDLink"):
            # GMSL/FPD-Link kommen als TECMP-gekapselt
            raw_payload = b""
            if pkt.haslayer(Raw):
                raw_payload = bytes(pkt[Raw].load)
            if raw_payload:
                tecmp_decoded = TECMPDecoder.decode(raw_payload)
                device_id = tecmp_decoded.get("device_id", 0)
                data_type_code = tecmp_decoded.get("data_type", 0)
                # Innere Payload aus TECMP-Entries extrahieren
                entries = tecmp_decoded.get("entries", [])
                if entries:
                    inner_payload = entries[0].get("payload", "")
                    if inner_payload:
                        inner_bytes = bytes.fromhex(inner_payload)
                        if protocol == "GMSL":
                            decoded = GMSLDecoder.decode(inner_bytes)
                        else:
                            decoded = FPDLinkDecoder.decode(inner_bytes)
                        decoded_fields = decoded.get("fields", [])
                        dt_code = decoded.get("data_type_code", 0)
                        dt_name = GMSLDecoder.DATA_TYPES.get(dt_code, "Unknown")
                        info = f"{protocol} VC{decoded.get('virtual_channel', '?')} {dt_name}"
                    else:
                        info = protocol
                else:
                    info = protocol
        else:
            info = f"Len={length}"

        result = cls._make_result(
            protocol, decoded_fields, raw_bytes,
            source, destination, length, info
        )
        result["device_id"] = device_id
        result["data_type_code"] = data_type_code
        result["timestamp"] = timestamp
        return result

    @staticmethod
    def _make_result(protocol: str, fields: list, raw_bytes: bytes,
                     source: str, destination: str, length: int,
                     info: str) -> Dict[str, Any]:
        """Erstellt ein standardisiertes Ergebnis-Dict."""
        return {
            "protocol": protocol,
            "fields": fields,
            "raw_bytes": raw_bytes,
            "source": source,
            "destination": destination,
            "length": length,
            "info": info,
            "device_id": 0,
            "data_type_code": 0,
            "timestamp": 0.0,
        }
