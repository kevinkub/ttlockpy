# TTLock Python

A Python rewrite of the TTLock BLE SDK with a clean CLI interface.

The original JavaScript SDK lives in `origin/` for reference.

> **Disclaimer:** This project was written entirely by AI (Claude) based on the
> original JavaScript SDK source code.  It has not yet been tested against real
> hardware.  Testing is planned once the hardware arrives and time permits.
> Use at your own risk and expect bugs — contributions and bug reports are very
> welcome.

## Requirements

- Python 3.11+
- Bluetooth adapter (host OS must have BLE support)
- Linux: BlueZ (`sudo apt install bluez`)
- macOS: CoreBluetooth (built-in)
- Windows: Windows Runtime BLE (Win 10+)

```
pip install -r requirements.txt
```

## Quick start

```sh
# Find nearby locks (shows address, battery, locked status)
python ttlock.py discover

# Pair a factory-fresh lock (LED must be blinking)
python ttlock.py pair --address AA:BB:CC:DD:EE:FF --save lock.json

# Unlock / lock
python ttlock.py unlock --lock lock.json
python ttlock.py lock   --lock lock.json

# Query locked/unlocked state
python ttlock.py status --lock lock.json

# Monitor events from BLE advertising (no connection needed)
python ttlock.py listen

# Factory reset
python ttlock.py reset --lock lock.json
```

## All commands

```
python ttlock.py <command> [subcommand] [options]

discover                           Scan for TTLock devices
pair       --address ADDR          Pair with a new lock
unlock     --lock FILE             Unlock
lock       --lock FILE             Lock
reset      --lock FILE             Factory reset
status     --lock FILE             Poll locked/unlocked status
listen     [--timeout N]           Passive BLE event monitor
log        --lock FILE             Print operation log

autolock get  --lock FILE          Read auto-lock delay
autolock set  --lock FILE --seconds N   Set auto-lock delay

passage list   --lock FILE         List passage-mode intervals
passage add    --lock FILE --type weekly|monthly --day N
               --start HHMM --end HHMM
passage delete --lock FILE --type weekly|monthly --day N
               --start HHMM --end HHMM
passage clear  --lock FILE

pin list   --lock FILE             List PIN codes
pin add    --lock FILE --code CODE [--type permanent|timed|count|circle]
           [--start YYMMDDHHmmss] [--end YYMMDDHHmmss]
pin update --lock FILE --old CODE --new CODE
pin delete --lock FILE --code CODE
pin clear  --lock FILE

card list   --lock FILE            List IC cards
card add    --lock FILE            Scan a new card (interactive)
card update --lock FILE --number N --start DATE --end DATE
card delete --lock FILE --number N
card clear  --lock FILE

fingerprint list   --lock FILE     List fingerprints
fingerprint add    --lock FILE     Enrol a fingerprint (interactive)
fingerprint update --lock FILE --id ID --start DATE --end DATE
fingerprint delete --lock FILE --id ID
fingerprint clear  --lock FILE
```

## Library usage

```python
import asyncio
from ttlock import TTLock, discover_locks

async def main():
    # Scan
    locks = await discover_locks(timeout=10)
    for l in locks:
        print(l.address, l.mac, l.battery)

    # Connect and operate
    lock = TTLock.from_file("lock.json")
    async with lock:
        await lock.unlock()
        print("Battery:", lock.battery)
        log = await lock.get_operation_log()
    lock.save("lock.json")

asyncio.run(main())
```

## Lock data file (lock.json)

```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "name": "TTLock",
  "mac": "AA:BB:CC:DD:EE:FF",
  "battery": 85,
  "locked_status": 0,
  "auto_lock_time": 5,
  "protocol_type": 5,
  "protocol_version": 3,
  "scene": 1,
  "aes_key": "0123456789abcdef0123456789abcdef",
  "admin_ps": 12345678,
  "unlock_key": 87654321,
  "admin_passcode": "1234567"
}
```

## Architecture

```
ttlock/
├── const.py      All enums and BLE UUIDs
├── crypto.py     AES-128-CBC, CRC, XOR helpers
├── protocol.py   BLE packet builder / parser
├── commands.py   Per-command payload builders and response parsers
├── scanner.py    BLE discovery (bleak)
└── lock.py       TTLock class – high-level async API

ttlock.py         CLI entry point (argparse)
requirements.txt
```

## Notes on compatibility

- Targets **protocol V3** locks (protocolType=5, subVersion=3) — the most common variant.
- Older V2/V2S locks use a different packet format; they will be detected during `discover` but most operations may not work.
- The `listen` command does not require a connection — it reads lock/unlock state directly from BLE advertisements.
- On macOS the BLE address shown by `discover` is a CoreBluetooth UUID, not a MAC address. Use that UUID for `pair` and subsequent commands.
