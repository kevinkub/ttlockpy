"""Command payload builders and response parsers.

Each function here either:
  - builds the *payload* bytes to be encrypted and sent, or
  - parses the *data* bytes from a decrypted response.

Payload layout for outgoing commands:
  The bytes returned by a build_* function are the raw payload that gets
  AES-encrypted by protocol.build_packet().

Response data layout for incoming responses:
  After the protocol layer strips [cmd_type][response_code], the remaining
  bytes are passed to the parse_* functions here.

Date/time strings use the format "YYMMDDHHmm" (10 chars → 5 bytes) or
"YYMMDDHHmmss" (12 chars → 6 bytes) where every pair of characters encodes
a decimal integer.  The year is two-digit (e.g. "26" for 2026).
"""

import struct
import time
from datetime import datetime

from .const import (
    CommandType, CommandResponse, KeyboardPwdType, PwdOperateType,
    ICOperate, AutoLockOperate, PassageModeOperate, FeatureValue,
    LockedStatus,
)


# ---------------------------------------------------------------------------
# Date/time helpers
# ---------------------------------------------------------------------------

def _dt_to_bytes(dt_str: str) -> bytes:
    """Convert a "YYMMDDHHmm[ss]" string to bytes (one byte per pair)."""
    return bytes(int(dt_str[i:i+2]) for i in range(0, len(dt_str), 2))


def now_yymmddhhmm() -> str:
    d = datetime.now()
    return d.strftime("%y%m%d%H%M")


def now_yymmddhhmmss() -> str:
    d = datetime.now()
    return d.strftime("%y%m%d%H%M%S")


# Default validity window used for user-time auth
DEFAULT_START = "0001311400"   # YY=00 MM=01 DD=31 HH=14 mm=00
DEFAULT_END   = "9911301400"   # YY=99 MM=11 DD=30 HH=14 mm=00


# ---------------------------------------------------------------------------
# Pairing sequence
# ---------------------------------------------------------------------------

def build_init() -> bytes:
    """COMM_INITIALIZATION – empty payload, no AES key needed."""
    return b""


def build_get_aes_key() -> bytes:
    """COMM_GET_AES_KEY – payload is the ASCII string 'SCIENER'."""
    return b"SCIENER"


def parse_aes_key(data: bytes) -> bytes:
    """Extract the 16-byte AES key from a GET_AES_KEY response."""
    if len(data) < 16:
        raise ValueError(f"AES key response too short: {len(data)} bytes")
    return data[:16]


def build_add_admin(admin_ps: int, unlock_key: int) -> bytes:
    """COMM_ADD_ADMIN – send admin_ps + unlock_key + 'SCIENER'."""
    return struct.pack(">II", admin_ps, unlock_key) + b"SCIENER"


def build_calibrate_time() -> bytes:
    """COMM_TIME_CALIBRATE – send current time as YYMMDDHHmmss bytes."""
    return _dt_to_bytes(now_yymmddhhmmss())


def build_search_device_feature() -> bytes:
    """COMM_SEARCH_DEVICE_FEATURE – empty payload."""
    return b""


def parse_device_features(data: bytes) -> set[FeatureValue]:
    """Decode the 32-bit feature bitmap from a SEARCH_DEVICE_FEATURE response."""
    if len(data) < 5:
        return set()
    features_int = struct.unpack(">I", data[1:5])[0]
    result: set[FeatureValue] = set()
    for fv in FeatureValue:
        bit = int(fv)
        if features_int & (1 << bit):
            result.add(fv)
    return result


def build_operate_finished() -> bytes:
    """COMM_OPERATE_FINISHED – empty payload."""
    return b""


# ---------------------------------------------------------------------------
# Authentication (used for every connected operation)
# ---------------------------------------------------------------------------

def build_check_admin(admin_ps: int) -> bytes:
    """COMM_CHECK_ADMIN – authenticate step 1: send admin_ps.

    The lock returns a random challenge (psFromLock).
    """
    # Layout: adminPs(4 bytes) | lockFlagPos(4 bytes, high byte overlaps) | uid(4 bytes)
    # In practice uid=0, lockFlagPos=0, which simplifies to just adminPs padded.
    data = bytearray(11)
    struct.pack_into(">I", data, 0, admin_ps)      # adminPs at 0
    struct.pack_into(">I", data, 3, 0)             # lockFlagPos at 3 (overlapping)
    struct.pack_into(">I", data, 7, 0)             # uid at 7
    return bytes(data)


def parse_check_admin(data: bytes) -> int:
    """Return psFromLock from a CHECK_ADMIN response."""
    if len(data) < 4:
        raise ValueError("CHECK_ADMIN response too short")
    return struct.unpack(">I", data[:4])[0]


def build_check_random(ps_from_lock: int, unlock_key: int) -> bytes:
    """COMM_CHECK_RANDOM – authenticate step 2: prove knowledge of unlock_key."""
    return struct.pack(">I", ps_from_lock + unlock_key)


def build_check_user_time(
    start_date: str = DEFAULT_START,
    end_date: str   = DEFAULT_END,
    uid: int = 0,
    lock_flag_pos: int = 0,
) -> bytes:
    """COMM_CHECK_USER_TIME – V3 auth: provide a validity window.

    The lock returns a random challenge (psFromLock).
    Date format: "YYMMDDHHmm" (10 chars → 5 bytes).
    """
    data = bytearray(17)
    start_b = _dt_to_bytes(start_date)
    end_b   = _dt_to_bytes(end_date)
    data[0:5]  = start_b
    data[5:10] = end_b
    struct.pack_into(">I", data, 9, lock_flag_pos)   # overlaps last byte of end_b
    struct.pack_into(">I", data, 13, uid)
    return bytes(data)


def parse_check_user_time(data: bytes) -> int:
    """Return psFromLock from a CHECK_USER_TIME response."""
    if len(data) < 4:
        raise ValueError("CHECK_USER_TIME response too short")
    return struct.unpack(">I", data[:4])[0]


# ---------------------------------------------------------------------------
# Lock / Unlock
# ---------------------------------------------------------------------------

def build_unlock(ps_from_lock: int, unlock_key: int) -> bytes:
    """COMM_UNLOCK payload: (psFromLock + unlockKey) + current Unix timestamp."""
    return struct.pack(">II", ps_from_lock + unlock_key, int(time.time()))


def parse_unlock(data: bytes) -> dict:
    """Parse an UNLOCK response, returning battery and timestamp info."""
    result: dict = {}
    if len(data) >= 1:
        result["battery"] = data[0]
    return result


def build_lock(ps_from_lock: int, unlock_key: int) -> bytes:
    """COMM_FUNCTION_LOCK payload: same structure as unlock."""
    return struct.pack(">II", ps_from_lock + unlock_key, int(time.time()))


def parse_lock(data: bytes) -> dict:
    result: dict = {}
    if len(data) >= 1:
        result["battery"] = data[0]
    return result


# ---------------------------------------------------------------------------
# Lock status
# ---------------------------------------------------------------------------

def build_search_status() -> bytes:
    """COMM_SEARCH_BICYCLE_STATUS – payload is 'SCIENER'."""
    return b"SCIENER"


def parse_search_status(data: bytes) -> LockedStatus:
    """Return LockedStatus from a SEARCH_BICYCLE_STATUS response."""
    if len(data) < 2:
        return LockedStatus.UNKNOWN
    raw = data[1]
    if raw == 0:
        return LockedStatus.LOCKED
    elif raw == 1:
        return LockedStatus.UNLOCKED
    return LockedStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Auto-lock
# ---------------------------------------------------------------------------

def build_get_autolock() -> bytes:
    """COMM_AUTO_LOCK_MANAGE – query current setting."""
    return bytes([AutoLockOperate.SEARCH])


def build_set_autolock(seconds: int) -> bytes:
    """COMM_AUTO_LOCK_MANAGE – set auto-lock delay in seconds."""
    return bytes([AutoLockOperate.MODIFY, seconds >> 8, seconds & 0xFF])


def parse_autolock(data: bytes) -> int:
    """Return auto-lock time in seconds from response."""
    if len(data) < 4:
        return -1
    return struct.unpack(">H", data[2:4])[0]


# ---------------------------------------------------------------------------
# Admin passcode
# ---------------------------------------------------------------------------

def build_get_admin_code() -> bytes:
    return b""


def parse_admin_code(data: bytes) -> str:
    return data.decode("ascii", errors="replace").rstrip("\x00")


def build_set_admin_code(passcode: str) -> bytes:
    encoded = passcode.encode("ascii")
    return bytes([len(encoded)]) + encoded


# ---------------------------------------------------------------------------
# PIN codes (keyboard passwords)
# ---------------------------------------------------------------------------

def build_add_passcode(
    pwd_type: KeyboardPwdType,
    passcode: str,
    start_date: str = "000101000000",
    end_date: str   = "991231235900",
) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD – add a new passcode."""
    code = passcode.encode("ascii")
    start_b = _dt_to_bytes(start_date[:10])   # YYMMDDHHmm
    end_b   = _dt_to_bytes(end_date[:10])

    buf = bytes([PwdOperateType.ADD, int(pwd_type), len(code)]) + code + start_b
    if pwd_type != KeyboardPwdType.PERMANENT:
        buf += end_b
    return buf


def build_update_passcode(
    pwd_type: KeyboardPwdType,
    old_passcode: str,
    new_passcode: str,
    start_date: str = "000101000000",
    end_date: str   = "991231235900",
) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD – change an existing passcode."""
    old_code = old_passcode.encode("ascii")
    new_code = new_passcode.encode("ascii")
    start_b  = _dt_to_bytes(start_date[:10])
    end_b    = _dt_to_bytes(end_date[:10])
    return (
        bytes([PwdOperateType.MODIFY, int(pwd_type), len(old_code)])
        + old_code
        + bytes([len(new_code)])
        + new_code
        + start_b
        + end_b
    )


def build_delete_passcode(pwd_type: KeyboardPwdType, passcode: str) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD – remove one passcode."""
    code = passcode.encode("ascii")
    return bytes([PwdOperateType.REMOVE_ONE, int(pwd_type), len(code)]) + code


def build_clear_passcodes() -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD – delete all passcodes."""
    return bytes([PwdOperateType.CLEAR])


def build_list_passcodes(sequence: int = 0) -> bytes:
    """COMM_PWD_LIST – retrieve stored passcodes starting at *sequence*."""
    return struct.pack(">H", sequence)


def parse_passcodes(data: bytes) -> tuple[int, list[dict]]:
    """Parse a PWD_LIST response.

    Returns (next_sequence, [passcode_dicts]).
    Each dict: type, passcode, start_date, end_date.
    """
    if len(data) < 2:
        return 0, []
    total = struct.unpack(">H", data[0:2])[0]
    if total == 0:
        return 0, []
    sequence = struct.unpack(">H", data[2:4])[0]
    passcodes = []
    idx = 4
    while idx < len(data):
        idx += 1   # record length byte (skip)
        pwd_type = data[idx]; idx += 1
        code_len = data[idx]; idx += 1
        new_code = data[idx:idx+code_len].decode("ascii", errors="replace"); idx += code_len
        code_len = data[idx]; idx += 1
        passcode = data[idx:idx+code_len].decode("ascii", errors="replace"); idx += code_len
        start_raw = data[idx:idx+5]; idx += 5
        start_date = "20" + "".join(f"{b:02d}" for b in start_raw)
        end_date = ""
        if pwd_type in (int(KeyboardPwdType.PERIOD), int(KeyboardPwdType.COUNT)):
            end_raw = data[idx:idx+5]; idx += 5
            end_date = "20" + "".join(f"{b:02d}" for b in end_raw)
        elif pwd_type == int(KeyboardPwdType.CIRCLE):
            idx += 2  # skip cycle-specific bytes
        passcodes.append({
            "type": pwd_type,
            "passcode": passcode,
            "new_passcode": new_code,
            "start_date": start_date,
            "end_date": end_date,
        })
    return sequence, passcodes


# ---------------------------------------------------------------------------
# IC cards
# ---------------------------------------------------------------------------

def build_add_ic_card(
    card_number: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> bytes:
    """COMM_IC_MANAGE – enter add-card mode (or add a specific card number)."""
    if card_number and start_date and end_date:
        # Add specific card with known number
        cn = int(card_number)
        if cn > 0xFFFFFFFF:
            buf = struct.pack(">Q", cn)
            data = bytes([ICOperate.ADD]) + buf[2:] + _dt_to_bytes(start_date[2:] + end_date[2:])
        else:
            buf = struct.pack(">I", cn)
            data = bytes([ICOperate.ADD]) + buf + _dt_to_bytes(start_date[2:] + end_date[2:])
        return data
    return bytes([ICOperate.ADD])


def build_update_ic_card(card_number: str, start_date: str, end_date: str) -> bytes:
    """COMM_IC_MANAGE – update card validity."""
    cn = int(card_number)
    if cn > 0xFFFFFFFF:
        card_b = struct.pack(">Q", cn)[2:]   # 6 bytes
    else:
        card_b = struct.pack(">I", cn)        # 4 bytes
    date_b = _dt_to_bytes(start_date[2:] + end_date[2:])
    return bytes([ICOperate.MODIFY]) + card_b + date_b


def build_delete_ic_card(card_number: str) -> bytes:
    cn = int(card_number)
    if cn > 0xFFFFFFFF:
        return bytes([ICOperate.DELETE]) + struct.pack(">Q", cn)[2:]
    return bytes([ICOperate.DELETE]) + struct.pack(">I", cn)


def build_clear_ic_cards() -> bytes:
    return bytes([ICOperate.CLEAR])


def build_list_ic_cards(sequence: int = 0) -> bytes:
    return bytes([ICOperate.IC_SEARCH]) + struct.pack(">H", sequence)


def parse_ic_card_add(data: bytes) -> tuple[str, int]:
    """Parse an IC add response.  Returns (card_number_str, status_code)."""
    if len(data) < 3:
        return "", 0
    status = data[1]
    if status == ICOperate.STATUS_ADD_SUCCESS:
        remaining = len(data) - 3
        if remaining == 4 or (remaining == 8 and data[-4:] == b"\xff\xff\xff\xff"):
            card = struct.unpack(">I", data[3:7])[0]
        else:
            card = struct.unpack(">Q", data[3:11])[0]
        return str(card), status
    return "", status


def parse_ic_cards(data: bytes) -> tuple[int, list[dict]]:
    """Parse a list-IC-cards response.  Returns (next_sequence, [card_dicts])."""
    if len(data) < 2:
        return 0, []
    battery = data[0]
    op_type = data[1]
    if op_type != ICOperate.IC_SEARCH:
        return 0, []
    sequence = struct.unpack(">H", data[2:4])[0]
    cards = []
    idx = 4
    while idx < len(data):
        if len(data) == 24:
            card_num = struct.unpack(">Q", data[idx:idx+8])[0]; idx += 8
        else:
            card_num = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
        start_raw = data[idx:idx+5]; idx += 5
        end_raw   = data[idx:idx+5]; idx += 5
        cards.append({
            "card_number": str(card_num),
            "start_date": "20" + "".join(f"{b:02d}" for b in start_raw),
            "end_date":   "20" + "".join(f"{b:02d}" for b in end_raw),
        })
    return sequence, cards


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def build_add_fingerprint() -> bytes:
    """COMM_FR_MANAGE – enter fingerprint enrolment mode."""
    return bytes([ICOperate.ADD])


def build_update_fingerprint(fp_number: str, start_date: str, end_date: str) -> bytes:
    fp = int(fp_number)
    fp_b = struct.pack(">Q", fp)[2:]   # 6 bytes
    date_b = _dt_to_bytes(start_date[2:] + end_date[2:])
    return bytes([ICOperate.MODIFY]) + fp_b + date_b


def build_delete_fingerprint(fp_number: str) -> bytes:
    fp = int(fp_number)
    return bytes([ICOperate.DELETE]) + struct.pack(">Q", fp)[2:]


def build_clear_fingerprints() -> bytes:
    return bytes([ICOperate.CLEAR])


def build_list_fingerprints(sequence: int = 0) -> bytes:
    return bytes([ICOperate.FR_SEARCH]) + struct.pack(">H", sequence)


def parse_fingerprint_add(data: bytes) -> tuple[str, int]:
    """Parse a fingerprint ADD response.  Returns (fp_number_str, status)."""
    if len(data) < 3:
        return "", 0
    status = data[1]
    if status == ICOperate.STATUS_ADD_SUCCESS:
        raw = b"\x00\x00" + data[3:9]
        fp = struct.unpack(">Q", raw)[0]
        return str(fp), status
    return "", status


def parse_fingerprints(data: bytes) -> tuple[int, list[dict]]:
    """Parse a list-fingerprints response."""
    if len(data) < 2:
        return 0, []
    battery = data[0]
    op_type = data[1]
    if op_type != ICOperate.FR_SEARCH:
        return 0, []
    sequence = struct.unpack(">H", data[2:4])[0]
    fps = []
    idx = 4
    while idx < len(data):
        raw = b"\x00\x00" + data[idx:idx+6]; idx += 6
        fp_num = struct.unpack(">Q", raw)[0]
        start_raw = data[idx:idx+5]; idx += 5
        end_raw   = data[idx:idx+5]; idx += 5
        fps.append({
            "fp_number":  str(fp_num),
            "start_date": "20" + "".join(f"{b:02d}" for b in start_raw),
            "end_date":   "20" + "".join(f"{b:02d}" for b in end_raw),
        })
    return sequence, fps


# ---------------------------------------------------------------------------
# Passage mode
# ---------------------------------------------------------------------------

def build_get_passage_mode(sequence: int = 0) -> bytes:
    return bytes([PassageModeOperate.QUERY, sequence])


def build_set_passage_mode(
    pm_type: int,
    week_or_day: int,
    month: int,
    start_hour: str,
    end_hour: str,
) -> bytes:
    """COMM_CONFIGURE_PASSAGE_MODE – add a passage-mode entry.

    start_hour / end_hour format: "HHMM" e.g. "0800".
    """
    return bytes([
        PassageModeOperate.ADD,
        pm_type, week_or_day, month,
        int(start_hour[:2]), int(start_hour[2:]),
        int(end_hour[:2]),   int(end_hour[2:]),
    ])


def build_delete_passage_mode(
    pm_type: int,
    week_or_day: int,
    month: int,
    start_hour: str,
    end_hour: str,
) -> bytes:
    return bytes([
        PassageModeOperate.DELETE,
        pm_type, week_or_day, month,
        int(start_hour[:2]), int(start_hour[2:]),
        int(end_hour[:2]),   int(end_hour[2:]),
    ])


def build_clear_passage_mode() -> bytes:
    return bytes([PassageModeOperate.CLEAR])


def parse_passage_modes(data: bytes) -> tuple[int, list[dict]]:
    """Parse a GET_PASSAGE_MODE response."""
    if not data:
        return 0, []
    op_type  = data[1] if len(data) > 1 else 0
    sequence = data[2] if len(data) > 2 else 0
    modes = []
    idx = 3
    while idx + 6 < len(data):
        modes.append({
            "type":        data[idx],
            "week_or_day": data[idx+1],
            "month":       data[idx+2],
            "start_hour":  f"{data[idx+3]:02d}{data[idx+4]:02d}",
            "end_hour":    f"{data[idx+5]:02d}{data[idx+6]:02d}",
        })
        idx += 7
    return sequence, modes


# ---------------------------------------------------------------------------
# Operation log
# ---------------------------------------------------------------------------

def build_get_operation_log(sequence: int = 0xFFFF) -> bytes:
    return struct.pack(">H", sequence)


def parse_operation_log(data: bytes) -> tuple[int, list[dict]]:
    """Parse a GET_OPERATE_LOG response."""
    if len(data) < 2:
        return 0, []
    total = struct.unpack(">H", data[0:2])[0]
    if total == 0:
        return 0, []
    sequence = struct.unpack(">H", data[2:4])[0]
    logs = []
    idx = 4
    while idx < len(data):
        rec_len = data[idx]; idx += 1
        rec_start = idx
        if idx + 8 > len(data):
            break
        rec_type = data[idx]; idx += 1
        year   = data[idx]; idx += 1
        month  = data[idx]; idx += 1
        day    = data[idx]; idx += 1
        hour   = data[idx]; idx += 1
        minute = data[idx]; idx += 1
        second = data[idx]; idx += 1
        battery = data[idx]; idx += 1
        operate_date = f"20{year:02d}{month:02d}{day:02d}{hour:02d}{minute:02d}{second:02d}"
        entry = {
            "record_type": rec_type,
            "operate_date": operate_date,
            "battery": battery,
        }
        # Remaining bytes in this record are type-dependent; just store as hex
        remaining = rec_len - (idx - rec_start)
        if remaining > 0 and idx + remaining <= len(data):
            entry["extra"] = data[idx:idx+remaining].hex()
            idx += remaining
        logs.append(entry)
    return sequence, logs
