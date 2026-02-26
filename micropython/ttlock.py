"""
TTLock MicroPython BLE Library

Usage:
    import asyncio
    import ttlock

    asyncio.run(ttlock.discover())                      # scan and print nearby locks
    asyncio.run(ttlock.pair("AA:BB:CC:DD:EE:FF"))       # pair (lock must be blinking)
    asyncio.run(ttlock.unlock())                        # unlock using saved lock.json

Requires: aioble, ucryptolib (built-in on ESP32 etc.)
"""

import asyncio
import struct
import json
import time
import os

import aioble
import bluetooth

try:
    from ucryptolib import aes as _AES
except ImportError:
    from cryptolib import aes as _AES


# ── BLE UUIDs ────────────────────────────────────────────────────────────────

_SVC = bluetooth.UUID("00001910-0000-1000-8000-00805f9b34fb")
_WR = bluetooth.UUID("0000fff2-0000-1000-8000-00805f9b34fb")
_NTF = bluetooth.UUID("0000fff4-0000-1000-8000-00805f9b34fb")


# ── Protocol constants ───────────────────────────────────────────────────────

_HDR = b"\x7f\x5a"
_TERM = b"\x0d\x0a"
_APP = 0xAA
_MTU = 20
_TIMEOUT = 5000
_RETRIES = 3
_CREDS_FILE = "lock.json"

_DEFAULT_KEY = bytes(
    [0x98, 0x76, 0x23, 0xE8, 0xA9, 0x23, 0xA1, 0xBB,
     0x3D, 0x9E, 0x7D, 0x03, 0x78, 0x12, 0x45, 0x88]
)

# Dallas/Maxim 1-Wire CRC8 lookup table
_CRC = bytes([
    0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
    157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
    35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
    190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
    70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
    219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
    101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
    248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
    140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
    17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
    175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
    50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
    202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
    87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
    233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
    116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53,
])

# Advertisement (type, version) combos to ignore
_SKIP = {(18, 25), (0xFF, 0xFF), (52, 18)}


# ── Low-level helpers ────────────────────────────────────────────────────────

def _crc8(data):
    c = 0
    for b in data:
        c = _CRC[c ^ b]
    return c


def _pkcs7_pad(d):
    n = 16 - (len(d) % 16)
    return d + bytes([n] * n)


def _pkcs7_unpad(d):
    return d[:-d[-1]]


def _encrypt(plain, key):
    return _AES(key, 2, key).encrypt(_pkcs7_pad(plain))


def _decrypt(ct, key):
    return _pkcs7_unpad(_AES(key, 2, key).decrypt(ct))


def _xor_decode(data, seed):
    c = _CRC[len(data) & 0xFF]
    return bytes(seed ^ b ^ c for b in data)


def _rand_int(hi=99999999):
    return (struct.unpack(">I", os.urandom(4))[0] % hi) + 1


# Offset between Unix epoch (1970) and MicroPython epoch (2000)
_EPOCH_OFFSET = 946684800


def _now_unix():
    t = time.time()
    return int(t + _EPOCH_OFFSET if t < _EPOCH_OFFSET else t)


def _now_bytes():
    """Current time as 6 packed-BCD bytes: YY MM DD HH mm ss."""
    y, mo, d, h, mi, s = time.localtime()[:6]
    s_fmt = "%02d%02d%02d%02d%02d%02d" % (y % 100, mo, d, h, mi, s)
    return bytes(int(s_fmt[i : i + 2], 16) for i in range(0, 12, 2))


# ── Packet framing ──────────────────────────────────────────────────────────

def _build_packet(cmd, payload, key, pt=5, pv=3, sc=1):
    """Build a TTLock BLE command packet."""
    enc = _encrypt(payload, key) if key else payload
    f = bytearray(_HDR)
    if pt == 3:
        # Old-agreement format
        f.append(cmd)
        f.append(_APP)
        f.append(len(enc))
        f.extend(enc)
    else:
        # New-agreement format (protocol_type >= 5 or == 0)
        f.extend(bytes([pt, pv, sc]))
        f.extend(struct.pack(">HH", 1, 1))  # group_id, org_id
        f.append(cmd)
        f.append(_APP)
        f.append(len(enc))
        f.extend(enc)
    f.append(_crc8(f))
    f.extend(_TERM)
    return bytes(f)


def _parse_response(raw, key, pt=5):
    """Parse a TTLock BLE response frame.

    Returns (cmd_echo, success, data, crc_ok).
    """
    if raw[:2] != _HDR or raw[-2:] != _TERM:
        raise ValueError("bad frame")
    if pt == 3:
        ebyte, plen = raw[3], raw[4]
        enc = raw[5 : 5 + plen]
        crc_pos = 5 + plen
    else:
        ebyte, plen = raw[10], raw[11]
        enc = raw[12 : 12 + plen]
        crc_pos = 12 + plen
    crc_ok = _crc8(raw[:crc_pos]) == raw[crc_pos]
    pl = _xor_decode(enc, ebyte) if key is None else _decrypt(enc, key)
    if len(pl) < 2:
        raise ValueError("response too short")
    return pl[0], pl[1] == 1, pl[2:], crc_ok


# ── BLE I/O ──────────────────────────────────────────────────────────────────

async def _ble_write(ch, data):
    """Write data in MTU-sized chunks."""
    for i in range(0, len(data), _MTU):
        await ch.write(data[i : i + _MTU], response=False)


async def _ble_read(ch, timeout_ms=_TIMEOUT):
    """Accumulate notification chunks until the \\r\\n terminator is seen."""
    buf = bytearray()
    deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
    while True:
        remaining = time.ticks_diff(deadline, time.ticks_ms())
        if remaining <= 0:
            raise OSError("response timeout")
        d = await ch.notified(timeout_ms=remaining)
        buf.extend(bytes(d))
        if len(buf) >= 2 and buf[-2:] == bytearray(_TERM):
            return bytes(buf)


async def _cmd(wc, nc, opcode, payload, key, pt=5, pv=3, sc=1, check_crc=True):
    """Send a command and return (cmd_echo, success, data)."""
    pkt = _build_packet(opcode, payload, key, pt, pv, sc)
    for attempt in range(_RETRIES):
        await _ble_write(wc, pkt)
        raw = await _ble_read(nc)
        echo, ok, data, crc_ok = _parse_response(raw, key, pt)
        if not check_crc or crc_ok:
            return echo, ok, data
        if attempt < _RETRIES - 1:
            print("  CRC mismatch, retrying...")
    raise ValueError("CRC check failed after %d attempts" % _RETRIES)


# ── Advertisement parsing ────────────────────────────────────────────────────

def _get_mfr(result):
    """Extract (company_id, data) from an aioble scan result.

    aioble stores manufacturer data internally as a dict {company_id: data}.
    We access it directly to recover the company_id, which encodes the
    TTLock protocol_type and protocol_version.
    """
    try:
        d = result._manufacturer
        if d:
            cid = next(iter(d))
            return cid, d[cid]
    except (AttributeError, StopIteration):
        pass
    return None


def _parse_adv(company_id, mfr_data):
    """Parse TTLock advertisement data. Returns info dict or None."""
    # Re-prepend the 2-byte company ID (LE) stripped by the BLE stack.
    # These bytes encode protocol_type and protocol_version.
    raw = struct.pack("<H", company_id) + bytes(mfr_data)
    if len(raw) < 8:
        return None

    pt, pv = raw[0], raw[1]

    if pt == 5 and pv == 3:
        # Protocol 5.3 (modern locks)
        sc, params, batt = raw[2], raw[3], raw[4]
    else:
        # Older protocols: type/version at offsets 4-5, scene at 7
        if len(raw) < 10:
            return None
        pt, pv, sc = raw[4], raw[5], raw[7]
        params, batt = raw[8], raw[9]

    if (pt, pv) in _SKIP:
        return None

    # MAC is always the last 6 bytes, reversed byte order
    if len(raw) < 6:
        return None
    mac_b = raw[-6:]
    mac = ":".join("%02X" % mac_b[5 - i] for i in range(6))

    return dict(
        mac=mac,
        protocol_type=pt,
        protocol_version=pv,
        scene=sc,
        battery=batt,
        is_unlocked=bool(params & 1),
        has_events=bool(params & 2),
        is_setting_mode=bool(params & 4),
    )


async def _find_lock(address, scan_ms=10000):
    """Scan for a specific lock by MAC address. Returns (device, info) or (None, None)."""
    target = address.upper()
    async with aioble.scan(scan_ms, services=[_SVC]) as scanner:
        async for result in scanner:
            mfr = _get_mfr(result)
            if mfr is None:
                continue
            info = _parse_adv(mfr[0], mfr[1])
            if info is None:
                continue
            if info["mac"].upper() == target:
                return result.device, info
    return None, None


# ── Connect helper ───────────────────────────────────────────────────────────

async def _connect(device):
    """Connect to a device and return (connection, write_char, notify_char)."""
    conn = await device.connect()
    svc = await conn.service(_SVC)
    wc = await svc.characteristic(_WR)
    nc = await svc.characteristic(_NTF)
    await nc.subscribe(notify=True)
    return conn, wc, nc


# ── Public API ───────────────────────────────────────────────────────────────

async def discover(duration_ms=10000):
    """Scan and print nearby TTLock devices."""
    print("Scanning for TTLock devices (%ds)..." % (duration_ms // 1000))
    found = []
    seen = set()

    async with aioble.scan(duration_ms, services=[_SVC]) as scanner:
        async for result in scanner:
            mfr = _get_mfr(result)
            if mfr is None:
                continue
            info = _parse_adv(mfr[0], mfr[1])
            if info is None or info["mac"] in seen:
                continue
            seen.add(info["mac"])
            info["name"] = result.name() or "?"
            info["rssi"] = result.rssi
            found.append(info)

            mode = "PAIRING" if info["is_setting_mode"] else "normal"
            state = "unlocked" if info["is_unlocked"] else "locked"
            print(
                "  %-17s  %-16s  rssi=%-4d  bat=%3d%%  %-8s  %s"
                % (info["mac"], info["name"], info["rssi"],
                   info["battery"], state, mode)
            )

    if not found:
        print("No TTLock devices found.")
    else:
        print("Found %d device(s)." % len(found))
    return found


async def pair(address, scan_ms=10000):
    """Pair with a TTLock device at the given BLE address.

    The lock must be in setting mode (blinking LED).
    On success, saves credentials to lock.json.
    """
    print("Looking for %s..." % address)
    device, info = await _find_lock(address, scan_ms)
    if device is None:
        print("Lock not found. Is it powered on and in pairing mode?")
        return None

    if not info["is_setting_mode"]:
        print("Warning: lock does not appear to be in setting/pairing mode.")

    pt = info["protocol_type"]
    pv = info["protocol_version"]
    sc = info["scene"]

    print("Connecting (protocol %d.%d)..." % (pt, pv))
    conn, wc, nc = await _connect(device)

    try:
        # Step 1 — INITIALIZATION (0x45)
        print("[1/7] Initialization")
        await _cmd(wc, nc, 0x45, b"", None, pt, pv, sc, check_crc=False)

        # Step 2 — GET_AES_KEY (0x19)
        print("[2/7] Getting AES key")
        _, ok, kd = await _cmd(wc, nc, 0x19, b"SCIENER", _DEFAULT_KEY, pt, pv, sc)
        if not ok:
            raise RuntimeError("GET_AES_KEY failed")
        aes_key = bytes(kd[:16])

        # Step 3 — ADD_ADMIN (0x56)
        print("[3/7] Adding admin")
        admin_ps = _rand_int()
        unlock_key = _rand_int()
        payload = struct.pack(">II", admin_ps, unlock_key) + b"SCIENER"
        _, ok, _ = await _cmd(wc, nc, 0x56, payload, aes_key, pt, pv, sc)
        if not ok:
            raise RuntimeError("ADD_ADMIN failed")

        # Step 4 — TIME_CALIBRATE (0x43)
        print("[4/7] Syncing time")
        try:
            await _cmd(wc, nc, 0x43, _now_bytes(), aes_key, pt, pv, sc)
        except Exception:
            print("  (time sync failed, continuing)")

        # Step 5 — SEARCH_DEVICE_FEATURE (0x01)
        print("[5/7] Reading features")
        _, ok, fd = await _cmd(wc, nc, 0x01, b"", aes_key, pt, pv, sc)
        features = 0
        if ok:
            if len(fd) >= 5:
                features = struct.unpack(">I", fd[1:5])[0]
            elif len(fd) >= 4:
                features = struct.unpack(">I", fd[0:4])[0]

        # Step 6 — Admin PIN (conditional on feature bit 18)
        admin_code = None
        if features & (1 << 18):
            print("[6/7] Setting admin code")
            _, ok, cd = await _cmd(wc, nc, 0x65, b"", aes_key, pt, pv, sc)
            if ok and cd:
                admin_code = bytes(cd).decode("ascii").strip("\x00")
            if not admin_code:
                admin_code = "%07d" % _rand_int(9999999)
                pin_payload = bytes([len(admin_code)]) + admin_code.encode()
                _, ok, _ = await _cmd(wc, nc, 0x53, pin_payload, aes_key, pt, pv, sc)
                if not ok:
                    print("  Warning: failed to set admin code")
                    admin_code = None
            if admin_code:
                print("  Admin code: %s" % admin_code)
        else:
            print("[6/7] Admin code not supported, skipping")

        # Step 7 — OPERATE_FINISHED (0x57)
        print("[7/7] Finishing")
        await _cmd(wc, nc, 0x57, b"", aes_key, pt, pv, sc)

    finally:
        await conn.disconnect()

    # Persist credentials
    creds = dict(
        address=address.upper(),
        protocol_type=pt,
        protocol_version=pv,
        scene=sc,
        aes_key=aes_key.hex(),
        admin_ps=admin_ps,
        unlock_key=unlock_key,
    )
    if admin_code:
        creds["admin_passcode"] = admin_code

    with open(_CREDS_FILE, "w") as f:
        json.dump(creds, f)

    print("Paired! Credentials saved to %s" % _CREDS_FILE)
    return creds


async def unlock(creds_file=_CREDS_FILE):
    """Unlock using credentials previously saved by pair()."""
    with open(creds_file) as f:
        c = json.load(f)

    address = c["address"]
    pt = c["protocol_type"]
    pv = c["protocol_version"]
    sc = c["scene"]
    aes_key = bytes.fromhex(c["aes_key"])
    admin_ps = c["admin_ps"]
    unlock_key = c["unlock_key"]

    print("Scanning for %s..." % address)
    device, _ = await _find_lock(address)
    if device is None:
        print("Lock not found. Is it nearby and powered on?")
        return

    print("Connecting...")
    conn, wc, nc = await _connect(device)

    try:
        # ── Authentication ──
        if pv >= 3:
            # V3 auth: CHECK_USER_TIME (0x55)
            print("Authenticating (v3)...")
            auth_pl = bytearray(17)
            # Default validity window (accept-all)
            auth_pl[0:5] = bytes([0x00, 0x01, 0x31, 0x14, 0x00])   # start
            auth_pl[5:10] = bytes([0x99, 0x11, 0x30, 0x14, 0x00])  # end
            struct.pack_into(">I", auth_pl, 9, 0)       # lock_flag_pos (overlaps end[4])
            struct.pack_into(">I", auth_pl, 13, admin_ps)  # UID
            _, ok, ad = await _cmd(wc, nc, 0x55, bytes(auth_pl), aes_key, pt, pv, sc)
            if not ok:
                raise RuntimeError("Authentication failed")
            ps_from_lock = struct.unpack(">I", ad[:4])[0]
        else:
            # Legacy auth: CHECK_ADMIN (0x41) + CHECK_RANDOM (0x30)
            print("Authenticating (legacy)...")
            admin_pl = bytearray(11)
            struct.pack_into(">I", admin_pl, 0, admin_ps)
            struct.pack_into(">I", admin_pl, 3, 0)         # lock_flag_pos (overlaps)
            struct.pack_into(">I", admin_pl, 7, admin_ps)   # UID
            _, ok, ad = await _cmd(wc, nc, 0x41, bytes(admin_pl), aes_key, pt, pv, sc)
            if not ok:
                raise RuntimeError("CHECK_ADMIN failed")
            ps_from_lock = struct.unpack(">I", ad[:4])[0]

            check_val = (ps_from_lock + unlock_key) & 0xFFFFFFFF
            _, ok, _ = await _cmd(
                wc, nc, 0x30, struct.pack(">I", check_val), aes_key, pt, pv, sc
            )
            if not ok:
                raise RuntimeError("CHECK_RANDOM failed")

        # ── Unlock (0x47) ──
        print("Unlocking...")
        proof = (ps_from_lock + unlock_key) & 0xFFFFFFFF
        unlock_pl = struct.pack(">II", proof, _now_unix())
        _, ok, ud = await _cmd(wc, nc, 0x47, unlock_pl, aes_key, pt, pv, sc)
        if not ok:
            raise RuntimeError("Unlock command failed")

        battery = ud[0] if ud else None
        msg = "Unlocked!"
        if battery is not None:
            msg += " (battery %d%%)" % battery
        print(msg)

    finally:
        await conn.disconnect()
