# TTLock Bluetooth Low Energy Protocol

This document describes the BLE protocol used by TTLock smart locks, focusing on
discovery, pairing, and unlocking. It is derived from the Python implementation
in this repository.

---

## 1. BLE Transport

### Service and Characteristics

| Role   | UUID                                   |
|--------|----------------------------------------|
| Service | `00001910-0000-1000-8000-00805f9b34fb` |
| Write   | `0000fff2-0000-1000-8000-00805f9b34fb` |
| Notify  | `0000fff4-0000-1000-8000-00805f9b34fb` |

All commands are written to the **Write** characteristic (write-without-response).
The lock sends replies as notifications on the **Notify** characteristic.

### Chunking

The BLE MTU is **20 bytes**. Packets larger than 20 bytes are split into
consecutive 20-byte chunks written in order. On the receive side, incoming
notification chunks are accumulated in a buffer until the `\r\n` terminator is
seen, at which point the complete frame is processed.

---

## 2. Packet Format

Every message — in both directions — is a binary frame bookended by a fixed
header (`0x7F 0x5A`) and a `\r\n` terminator. Two frame layouts exist depending
on the lock's protocol type.

### 2.1 New-Agreement Format (protocol_type >= 5 or == 0)

```
Offset  Length  Field
─────────────────────────────────────────
 0      2       Header              0x7F 0x5A
 2      1       Protocol Type       e.g. 0x05
 3      1       Protocol Version    e.g. 0x03
 4      1       Scene               e.g. 0x01
 5      2       Group ID            big-endian uint16
 7      2       Org ID              big-endian uint16
 9      1       Command Type        opcode (see §6)
10      1       Encrypt Byte        0xAA for commands from the app
11      1       Payload Length      N (length of encrypted payload)
12      N       Encrypted Payload   AES-128-CBC ciphertext
12+N    1       CRC                 Dallas/Maxim 1-Wire CRC8
13+N    2       Terminator          0x0D 0x0A
```

### 2.2 Old-Agreement Format (protocol_type == 3)

```
Offset  Length  Field
─────────────────────────────────────────
 0      2       Header              0x7F 0x5A
 2      1       Command Type        opcode
 3      1       Encrypt Byte        0xAA
 4      1       Payload Length      N
 5      N       Encrypted Payload
 5+N    1       CRC
 6+N    2       Terminator          0x0D 0x0A
```

### 2.3 CRC

The CRC is computed over all preceding bytes in the packet (everything before
the CRC byte itself) using the **Dallas/Maxim 1-Wire CRC8** algorithm with the
standard 256-entry lookup table:

```python
def crc_compute(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = CRC_TABLE[crc ^ byte]
    return crc
```

### 2.4 Response Payload Layout

After decryption, every response payload has the structure:

```
[0]   Command Type echoed back
[1]   Response Code: 0x01 = SUCCESS, 0x00 = FAILED
[2…]  Command-specific data
```

---

## 3. Encryption

### 3.1 AES-128-CBC

All command payloads are encrypted with **AES-128-CBC** using PKCS7 padding. The
**key is also used as the IV** (a TTLock convention). During pairing step 2 the
default factory key is used; after pairing the lock's own key is used.

**Default AES key (factory):**

```
98 76 23 E8 A9 23 A1 BB 3D 9E 7D 03 78 12 45 88
```

### 3.2 XOR Obfuscation (pre-pairing)

Before the AES key is established (i.e. during the `INITIALIZATION` step) the
lock's responses use a lightweight XOR scheme instead of AES:

```python
def xor_decode(data: bytes, seed: int | None = None) -> bytes:
    if seed is None:
        seed = data[-1]   # last byte of ciphertext
        data = data[:-1]
    crc = CRC_TABLE[len(data) & 0xFF]
    return bytes(seed ^ b ^ crc for b in data)
```

The `seed` is the **Encrypt Byte** from the packet header (offset 10 in
new-agreement format, offset 3 in old-agreement format).

---

## 4. Discovery

TTLock devices advertise the service UUID `00001910-…` and include a
**manufacturer data** block in their advertisement. After re-prepending the
two-byte company ID (stripped by most BLE stacks), the raw bytes decode as
follows.

### 4.1 Protocol 5.3 (modern locks)

```
Offset  Field
──────────────────────────
 0      Protocol Type       (0x05)
 1      Protocol Version    (0x03)
 2      Scene
 3      Params              bit field (see below)
 4      Battery             0–100 %
 …
 -6     MAC[5] … MAC[0]    6 bytes, reversed byte order
```

### 4.2 Older protocols

For other protocol type / version combinations the layout shifts — protocol type
and version are re-read from offsets 4–5 and scene from offset 7. The params
and battery bytes follow at offsets 8–9. MAC is always the last 6 bytes,
reversed.

### 4.3 Params Bit Field

| Bit | Meaning                                        |
|-----|------------------------------------------------|
| 0   | `is_unlocked` — 1 = unlocked, 0 = locked      |
| 1   | `has_events` — 1 = pending events to retrieve  |
| 2   | `is_setting_mode` — 1 = pairing / factory mode |

### 4.4 Filtered-out Devices

Certain protocol type / version combinations are ignored during scanning:

| Type | Version | Meaning    |
|------|---------|------------|
| 18   | 25      | DFU mode   |
| 0xFF | 0xFF    | DFU mode   |
| 52   | 18      | Wristband  |

---

## 5. Pairing

Pairing registers an admin identity with a factory-fresh lock. The lock must be
in **setting mode** (bit 2 of the params byte set, typically indicated by a
blinking LED).

### Step 1 — INITIALIZATION (0x45)

| Field   | Value         |
|---------|---------------|
| Command | `0x45`        |
| Payload | empty         |
| AES key | none (XOR)    |

Opens the pairing session. The response is XOR-decoded (no AES key yet).
CRC is ignored on this step.

### Step 2 — GET_AES_KEY (0x19)

| Field   | Value                                           |
|---------|-------------------------------------------------|
| Command | `0x19`                                          |
| Payload | ASCII `SCIENER` (7 bytes)                       |
| AES key | default factory key (`9876 23E8 …`)             |

The lock returns its unique **16-byte AES key** in the response data
(bytes 0–15). This key is stored and used for all subsequent communication.

### Step 3 — ADD_ADMIN (0x56)

| Field   | Value                                           |
|---------|-------------------------------------------------|
| Command | `0x56`                                          |
| Payload | `admin_ps` (uint32 BE) + `unlock_key` (uint32 BE) + ASCII `SCIENER` |
| AES key | lock's AES key (from step 2)                    |

`admin_ps` and `unlock_key` are random 32-bit integers generated by the client
(range 1 – 99 999 999). Both must be persisted — they are required for every
future authentication and unlock operation.

### Step 4 — TIME_CALIBRATE (0x43) — optional

| Field   | Value                                           |
|---------|-------------------------------------------------|
| Command | `0x43`                                          |
| Payload | current time as 6 bytes: `[YY, MM, DD, HH, mm, ss]` |
| AES key | lock's AES key                                  |

Synchronises the lock's real-time clock. Failures are silently ignored.

### Step 5 — SEARCH_DEVICE_FEATURE (0x01)

| Field   | Value         |
|---------|---------------|
| Command | `0x01`        |
| Payload | empty         |
| AES key | lock's AES key |

The response contains a **feature bitmap** (uint32 BE at data bytes 1–4).
Each bit indicates whether the lock supports a capability — see §7.

### Step 6 — Admin PIN (conditional)

If feature bit 18 (`GET_ADMIN_CODE`) is set:

1. **GET_ADMIN_CODE (0x65)** — retrieve the current admin PIN (ASCII string in
   response data).
2. If blank, generate a random 7-digit PIN and send it with
   **SET_ADMIN_KEYBOARD_PWD (0x53)** — payload: `[length] [ASCII digits…]`.

### Step 7 — OPERATE_FINISHED (0x57)

| Field   | Value         |
|---------|---------------|
| Command | `0x57`        |
| Payload | empty         |
| AES key | lock's AES key |

Signals the end of the pairing sequence.

### Stored Credentials

After a successful pairing the following must be persisted for future sessions:

```json
{
  "address":          "AA:BB:CC:DD:EE:FF",
  "protocol_type":    5,
  "protocol_version": 3,
  "scene":            1,
  "aes_key":          "987623e8a923a1bb3d9e7d0378124588",
  "admin_ps":         12345678,
  "unlock_key":       87654321,
  "admin_passcode":   "1234567"
}
```

---

## 6. Authentication and Unlocking

Every operational session (unlock, lock, status query, etc.) requires
authentication first. Two authentication methods exist.

### 6.1 V3 Authentication — CHECK_USER_TIME (0x55)

Used with protocol version 3 (the common modern path).

| Field   | Value                                     |
|---------|-------------------------------------------|
| Command | `0x55`                                    |
| Payload | 17 bytes (see below)                      |
| AES key | lock's AES key                            |

**Payload layout:**

```
Offset  Length  Field
──────────────────────────────────────────
 0      5       Start date      YYMMDDHHmm as packed bytes
 5      5       End date        YYMMDDHHmm as packed bytes
 9      4       Lock flag pos   uint32 BE (overlaps last byte of end date)
13      4       UID             uint32 BE
```

Default validity window (accept-all):
- Start: `00 01 31 14 00`  (YY=00 MM=01 DD=31 HH=14 mm=00)
- End:   `99 11 30 14 00`  (YY=99 MM=11 DD=30 HH=14 mm=00)

**Response:** first 4 bytes of data = `psFromLock` (uint32 BE), a random
challenge value.

### 6.2 Legacy Authentication — CHECK_ADMIN (0x41) + CHECK_RANDOM (0x30)

Older locks use a two-step flow:

**Step 1 — CHECK_ADMIN (0x41):**

```
Payload (11 bytes):
  [0–3]   admin_ps        uint32 BE
  [3–6]   lock_flag_pos   uint32 BE (overlapping)
  [7–10]  UID             uint32 BE
```

Response: `psFromLock` (uint32 BE, first 4 bytes).

**Step 2 — CHECK_RANDOM (0x30):**

```
Payload (4 bytes):
  [0–3]   (psFromLock + unlock_key)  uint32 BE
```

Proves knowledge of `unlock_key` without transmitting it directly.

### 6.3 Unlock (0x47)

| Field   | Value                                     |
|---------|-------------------------------------------|
| Command | `0x47`                                    |
| AES key | lock's AES key                            |

**Payload (8 bytes):**

```
Offset  Length  Field
──────────────────────────────
 0      4       (psFromLock + unlock_key)   uint32 BE
 4      4       Unix timestamp (seconds)    uint32 BE
```

The sum `psFromLock + unlock_key` serves as proof that the client knows
`unlock_key` without revealing it. The timestamp lets the lock log when the
unlock occurred.

**Response data:** byte 0 = battery level (0–100).

### 6.4 Lock (0x58)

Identical payload structure to Unlock:

```
Payload (8 bytes):
  [0–3]   (psFromLock + unlock_key)   uint32 BE
  [4–7]   Unix timestamp              uint32 BE
```

### 6.5 Full Unlock Sequence Diagram

```
 Client                              Lock
   │                                   │
   │── BLE Connect ──────────────────►│
   │── Subscribe to Notify char ─────►│
   │                                   │
   │   ┌─ Authentication ───────────┐  │
   │   │ CHECK_USER_TIME (0x55)     │  │
   │──►│ payload: validity window   │──►│
   │◄──│ response: psFromLock       │◄──│
   │   └────────────────────────────┘  │
   │                                   │
   │   ┌─ Unlock ───────────────────┐  │
   │   │ UNLOCK (0x47)              │  │
   │──►│ payload: psFromLock +      │──►│
   │   │   unlock_key, timestamp    │  │
   │◄──│ response: battery level    │◄──│
   │   └────────────────────────────┘  │
   │                                   │
   │── BLE Disconnect ───────────────►│
```

---

## 7. Feature Bitmap

Returned by `SEARCH_DEVICE_FEATURE` (0x01) as a uint32 BE at response data
bytes 1–4. Each bit position maps to a lock capability:

| Bit | Feature                    |
|-----|----------------------------|
| 0   | Passcode (PIN codes)       |
| 1   | IC cards                   |
| 2   | Fingerprint                |
| 3   | Wristband                  |
| 4   | Auto-lock                  |
| 5   | Passcode with delete       |
| 6   | Firmware setting           |
| 7   | Modify passcode            |
| 8   | Manual lock                |
| 9   | Password display / hide    |
| 10  | Gateway unlock             |
| 11  | Freeze lock                |
| 12  | Cyclic password            |
| 13  | Magnetometer               |
| 14  | Config gateway unlock      |
| 15  | Audio management           |
| 16  | NB lock                    |
| 18  | Get admin code             |
| 19  | Hotel lock                 |
| 20  | No clock chip              |
| 21  | Cannot click unlock        |
| 22  | Passage mode               |
| 23  | Passage mode + auto-lock   |
| 24  | Wireless keyboard          |
| 25  | Lamp                       |
| 28  | Tamper alert               |
| 29  | Reset button               |
| 30  | Privacy lock               |
| 32  | Dead lock                  |
| 34  | Cyclic IC / fingerprint    |
| 36  | Unlock direction           |
| 37  | Finger vein                |
| 38  | Telink chip                |
| 39  | NB activate configuration  |
| 40  | Cyclic passcode recovery   |
| 41  | Wireless key fob           |
| 42  | Accessory battery          |

---

## 8. Command Reference

| Opcode | Name                       | Payload (outgoing)                                 |
|--------|----------------------------|----------------------------------------------------|
| `0x45` | INITIALIZATION             | empty                                              |
| `0x19` | GET_AES_KEY                | `"SCIENER"` (7 bytes)                              |
| `0x56` | ADD_ADMIN                  | admin_ps (u32) + unlock_key (u32) + `"SCIENER"`   |
| `0x43` | TIME_CALIBRATE             | `[YY, MM, DD, HH, mm, ss]` (6 bytes)              |
| `0x01` | SEARCH_DEVICE_FEATURE      | empty                                              |
| `0x65` | GET_ADMIN_CODE             | empty                                              |
| `0x53` | SET_ADMIN_KEYBOARD_PWD     | `[len] [ASCII digits…]`                            |
| `0x57` | OPERATE_FINISHED           | empty                                              |
| `0x55` | CHECK_USER_TIME            | validity window (17 bytes, see §6.1)               |
| `0x41` | CHECK_ADMIN                | admin_ps + flags + uid (11 bytes)                  |
| `0x30` | CHECK_RANDOM               | (psFromLock + unlock_key) as u32                   |
| `0x47` | UNLOCK                     | (psFromLock + unlock_key) as u32 + timestamp u32   |
| `0x58` | FUNCTION_LOCK              | same as UNLOCK                                     |
| `0x14` | SEARCH_BICYCLE_STATUS      | `"SCIENER"` (7 bytes)                              |
| `0x52` | RESET_LOCK                 | empty (no response expected)                       |

---

## 9. Date/Time Encoding

Dates and times throughout the protocol use a **packed decimal** encoding where
every two ASCII characters of a date string become one byte:

```
"260215143000"  →  [0x26, 0x02, 0x15, 0x14, 0x30, 0x00]
  YY   MM  DD   HH   mm   ss
```

Two formats are used:
- **YYMMDDHHmm** — 10 characters → 5 bytes (validity windows, PIN dates)
- **YYMMDDHHmmss** — 12 characters → 6 bytes (clock calibration)

---

## 10. Constants

| Constant          | Value                                          |
|-------------------|------------------------------------------------|
| Packet header     | `0x7F 0x5A`                                    |
| Packet terminator | `0x0D 0x0A` (`\r\n`)                           |
| App command byte  | `0xAA`                                         |
| BLE MTU           | 20 bytes                                       |
| Default AES key   | `98 76 23 E8 A9 23 A1 BB 3D 9E 7D 03 78 12 45 88` |
| Command timeout   | 5 seconds                                      |
| CRC retry limit   | 3 attempts                                     |
