"""DoIP (ISO 13400) Codec — Diagnostic over Internet Protocol.

Header: Version(1) + InvVersion(1) + PayloadType(2) + PayloadLength(4) = 8 Bytes
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

DOIP_PORT = 13400

PAYLOAD_TYPES = {
    0x0000: "GenericNACK",
    0x0001: "VehicleIdentificationRequest",
    0x0002: "VehicleIdentificationRequestEID",
    0x0003: "VehicleIdentificationRequestVIN",
    0x0004: "VehicleAnnouncementResponse",
    0x0005: "RoutingActivationRequest",
    0x0006: "RoutingActivationResponse",
    0x0007: "AliveCheckRequest",
    0x0008: "AliveCheckResponse",
    0x4001: "DoIPEntityStatusRequest",
    0x4002: "DoIPEntityStatusResponse",
    0x4003: "DiagPowerModeInfoRequest",
    0x4004: "DiagPowerModeInfoResponse",
    0x8001: "DiagnosticMessage",
    0x8002: "DiagnosticMessagePositiveAck",
    0x8003: "DiagnosticMessageNegativeAck",
}

ROUTING_ACTIVATION_TYPES = {
    0x00: "Default", 0x01: "WWH-OBD", 0xE0: "CentralSecurity",
}

NACK_CODES = {
    0x00: "IncorrectPatternFormat",
    0x01: "UnknownPayloadType",
    0x02: "MessageTooLarge",
    0x03: "OutOfMemory",
    0x04: "InvalidPayloadLength",
}

ROUTING_ACTIVATION_RESPONSE_CODES = {
    0x00: "DeniedUnknownSourceAddress",
    0x01: "DeniedAllSocketsRegistered",
    0x02: "DeniedDifferentSourceAddress",
    0x03: "DeniedAlreadyActive",
    0x04: "DeniedMissingAuthentication",
    0x05: "DeniedRejectedConfirmation",
    0x06: "DeniedUnsupportedType",
    0x10: "SuccessfullyActivated",
    0x11: "ActivatedConfirmationRequired",
}


@dataclass
class DoIPMessage:
    """Geparstes DoIP-Paket."""
    version: int = 0x02
    payload_type: int = 0
    payload_type_name: str = ''
    payload_length: int = 0
    source_address: int = 0
    target_address: int = 0
    uds_data: bytes = b''
    raw: bytes = b''
    fields: List[Tuple[str, str]] = field(default_factory=list)


def parse_doip(data: bytes) -> Optional[DoIPMessage]:
    """Parst einen DoIP-Frame (ab TCP/UDP Payload)."""
    if len(data) < 8:
        return None

    version = data[0]
    inv_version = data[1]
    payload_type = struct.unpack('>H', data[2:4])[0]
    payload_length = struct.unpack('>I', data[4:8])[0]

    msg = DoIPMessage(
        version=version,
        payload_type=payload_type,
        payload_type_name=PAYLOAD_TYPES.get(payload_type,
                                             f"Unknown (0x{payload_type:04X})"),
        payload_length=payload_length,
        raw=data,
    )

    msg.fields.append(("Version", f"0x{version:02X}"))
    msg.fields.append(("Payload Type",
                       f"0x{payload_type:04X} ({msg.payload_type_name})"))
    msg.fields.append(("Payload Length", str(payload_length)))

    payload = data[8:8 + payload_length]

    if payload_type == 0x8001:  # DiagnosticMessage
        if len(payload) >= 4:
            msg.source_address = struct.unpack('>H', payload[0:2])[0]
            msg.target_address = struct.unpack('>H', payload[2:4])[0]
            msg.uds_data = payload[4:]
            msg.fields.append(("Source Address",
                               f"0x{msg.source_address:04X}"))
            msg.fields.append(("Target Address",
                               f"0x{msg.target_address:04X}"))
            msg.fields.append(("UDS Data", msg.uds_data.hex().upper()))

    elif payload_type == 0x0005:  # RoutingActivationRequest
        if len(payload) >= 7:
            src = struct.unpack('>H', payload[0:2])[0]
            act_type = payload[2]
            msg.source_address = src
            msg.fields.append(("Source Address", f"0x{src:04X}"))
            msg.fields.append(("Activation Type",
                               ROUTING_ACTIVATION_TYPES.get(act_type,
                                                             f"0x{act_type:02X}")))

    elif payload_type == 0x0006:  # RoutingActivationResponse
        if len(payload) >= 5:
            tester = struct.unpack('>H', payload[0:2])[0]
            entity = struct.unpack('>H', payload[2:4])[0]
            response_code = payload[4]
            msg.fields.append(("Tester Address", f"0x{tester:04X}"))
            msg.fields.append(("Entity Address", f"0x{entity:04X}"))
            msg.fields.append(("Response",
                               ROUTING_ACTIVATION_RESPONSE_CODES.get(
                                   response_code, f"0x{response_code:02X}")))

    elif payload_type == 0x0004:  # VehicleAnnouncementResponse
        if len(payload) >= 32:
            vin = payload[0:17].decode('ascii', errors='replace').rstrip('\x00')
            logical_addr = struct.unpack('>H', payload[17:19])[0]
            msg.fields.append(("VIN", vin))
            msg.fields.append(("Logical Address", f"0x{logical_addr:04X}"))

    return msg


def build_routing_activation(source_address: int = 0x0E80,
                              activation_type: int = 0x00) -> bytes:
    """Baut einen DoIP RoutingActivationRequest."""
    payload = struct.pack('>H', source_address)
    payload += bytes([activation_type])
    payload += b'\x00' * 4  # Reserved
    header = bytes([0x02, 0xFD])  # Version 0x02
    header += struct.pack('>H', 0x0005)  # PayloadType
    header += struct.pack('>I', len(payload))
    return header + payload


def build_diagnostic_message(source: int, target: int,
                              uds_data: bytes) -> bytes:
    """Baut einen DoIP DiagnosticMessage Frame."""
    payload = struct.pack('>H', source) + struct.pack('>H', target) + uds_data
    header = bytes([0x02, 0xFD])
    header += struct.pack('>H', 0x8001)
    header += struct.pack('>I', len(payload))
    return header + payload


def build_alive_check_response(source_address: int = 0x0E80) -> bytes:
    """Baut eine AliveCheckResponse."""
    payload = struct.pack('>H', source_address)
    header = bytes([0x02, 0xFD])
    header += struct.pack('>H', 0x0008)
    header += struct.pack('>I', len(payload))
    return header + payload
