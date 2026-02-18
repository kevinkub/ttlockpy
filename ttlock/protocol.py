"""TTLock BLE protocol packet building and parsing.

Every message (in both directions) is a binary frame:

  New-agreement format (protocol_type >= 5 or == 0):
    [0x7F][0x5A] [pt] [sv] [sc] [org_hi][org_lo] [sub_hi][sub_lo]
    [cmd] [enc] [len] [payload...] [crc]  + \\r\\n terminator

  Old-agreement format (protocol_type 3):
    [0x7F][0x5A] [cmd] [enc] [len] [payload...] [crc]  + \\r\\n terminator

The payload is AES-128-CBC encrypted (using the AES key as both key and IV).
Before the AES key is established (init phase) the payload is XOR-obfuscated.

Lock data dict keys used here:
  protocol_type, protocol_version, scene, group_id, org_id
"""

import struct
from dataclasses import dataclass, field
from .const import (
    PACKET_HEADER, PACKET_TERMINATOR, BLE_MTU, APP_COMMAND,
    CommandType,
)
from .crypto import crc_compute, aes_encrypt, aes_decrypt, xor_decode


@dataclass
class LockProtocol:
    """Protocol parameters for a specific lock, read from manufacturer data."""
    protocol_type: int = 5
    protocol_version: int = 3
    scene: int = 1
    group_id: int = 1
    org_id: int = 1

    @property
    def is_new_agreement(self) -> bool:
        return self.protocol_type >= 5 or self.protocol_type == 0


def build_packet(proto: LockProtocol, cmd_type: int, payload: bytes,
                 aes_key: bytes | None = None) -> bytes:
    """Encode a command into a BLE packet ready to be written to the lock.

    *payload* is the raw (unencrypted) command payload produced by a
    command builder.  It is AES-encrypted when *aes_key* is given and
    non-empty; otherwise it is sent as-is (empty payloads require no key).
    """
    if payload and aes_key is None:
        raise ValueError("AES key required for non-empty payload")

    enc_payload = aes_encrypt(payload, aes_key) if (payload and aes_key) else payload

    if proto.is_new_agreement:
        header = (
            PACKET_HEADER
            + bytes([proto.protocol_type, proto.protocol_version, proto.scene])
            + struct.pack(">HH", proto.group_id, proto.org_id)
            + bytes([cmd_type, APP_COMMAND, len(enc_payload)])
        )
    else:
        header = PACKET_HEADER + bytes([cmd_type, APP_COMMAND, len(enc_payload)])

    packet = header + enc_payload
    return packet + bytes([crc_compute(packet)]) + PACKET_TERMINATOR


def split_into_chunks(packet: bytes) -> list[bytes]:
    """Split *packet* into MTU-sized chunks for BLE write-without-response."""
    return [packet[i:i + BLE_MTU] for i in range(0, len(packet), BLE_MTU)]


def parse_response(raw: bytes, aes_key: bytes | None = None,
                   ignore_crc: bool = False) -> dict:
    """Parse a raw response frame received from the lock.

    Returns a dict with keys:
      cmd_type  – CommandType integer
      response  – CommandResponse integer (0=FAILED, 1=SUCCESS)
      data      – decoded payload bytes (after the cmd/response prefix)
      crc_ok    – whether CRC matched
    """
    # Strip terminator if present
    if raw.endswith(PACKET_TERMINATOR):
        raw = raw[:-2]

    if len(raw) < 7:
        raise ValueError(f"Response too short ({len(raw)} bytes)")

    if raw[:2] != PACKET_HEADER:
        raise ValueError("Bad header bytes")

    # Determine protocol agreement
    protocol_type = raw[2]
    is_new = (protocol_type >= 5 or protocol_type == 0)

    if is_new:
        if len(raw) < 13:
            raise ValueError("New-agreement response too short")
        cmd_type = raw[9]
        encrypt_seed = raw[10]
        data_len = raw[11]
        enc_data = raw[12:12 + data_len]
        expected_crc_pos = 12 + data_len
    else:
        cmd_type = raw[2]
        encrypt_seed = raw[3]
        data_len = raw[4]
        enc_data = raw[5:5 + data_len]
        expected_crc_pos = 5 + data_len

    # CRC check
    received_crc = raw[-1]
    computed_crc = crc_compute(raw[:-1])
    crc_ok = (received_crc == computed_crc)

    # Decode payload
    if enc_data:
        if aes_key:
            decoded = aes_decrypt(enc_data, aes_key)
        else:
            decoded = xor_decode(enc_data, encrypt_seed)
    else:
        decoded = b""

    # Decoded payload layout: [cmd_type][response_code][data...]
    if len(decoded) >= 2:
        resp_code = decoded[1]
        cmd_data = decoded[2:]
    elif len(decoded) == 1:
        resp_code = decoded[0]
        cmd_data = b""
    else:
        resp_code = 0
        cmd_data = b""

    return {
        "cmd_type": cmd_type,
        "response": resp_code,
        "data": cmd_data,
        "crc_ok": crc_ok,
    }
