#!/usr/bin/env python3
"""TTLock CLI – control TTLock BLE smart locks from the command line.

Usage:
  python ttlock.py discover
  python ttlock.py pair    --address AA:BB:CC:DD:EE:FF --save lock.json
  python ttlock.py unlock  --lock lock.json
  python ttlock.py lock    --lock lock.json
  python ttlock.py reset   --lock lock.json
  python ttlock.py status  --lock lock.json
  python ttlock.py listen  [--timeout 60]

  python ttlock.py autolock get  --lock lock.json
  python ttlock.py autolock set  --lock lock.json --seconds 30

  python ttlock.py passage list   --lock lock.json
  python ttlock.py passage add    --lock lock.json --type weekly --day 0 \\
                                  --start 0800 --end 2000
  python ttlock.py passage delete --lock lock.json --type weekly --day 0 \\
                                  --start 0800 --end 2000
  python ttlock.py passage clear  --lock lock.json

  python ttlock.py pin list   --lock lock.json
  python ttlock.py pin add    --lock lock.json --code 123456
  python ttlock.py pin update --lock lock.json --old 123456 --new 654321
  python ttlock.py pin delete --lock lock.json --code 123456 [--type permanent]
  python ttlock.py pin clear  --lock lock.json

  python ttlock.py card list   --lock lock.json
  python ttlock.py card add    --lock lock.json
  python ttlock.py card update --lock lock.json --number 1234567 \\
                               --start 20260101 --end 20261231
  python ttlock.py card delete --lock lock.json --number 1234567
  python ttlock.py card clear  --lock lock.json

  python ttlock.py fingerprint list   --lock lock.json
  python ttlock.py fingerprint add    --lock lock.json
  python ttlock.py fingerprint update --lock lock.json --id 12345 \\
                                      --start 20260101 --end 20261231
  python ttlock.py fingerprint delete --lock lock.json --id 12345
  python ttlock.py fingerprint clear  --lock lock.json

  python ttlock.py log --lock lock.json
"""

import argparse
import asyncio
import json
import sys

from ttlock import TTLock, discover_locks, listen_for_events
from ttlock.const import KeyboardPwdType, PassageModeType, LockedStatus
from ttlock.lock import LockData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_lock(path: str) -> TTLock:
    return TTLock.from_file(path)


def _save_lock(lock: TTLock, path: str) -> None:
    lock.save(path)
    print(f"Lock data saved to {path}")


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

async def cmd_discover(args) -> None:
    print(f"Scanning for TTLock devices ({args.timeout}s)…")
    locks = await discover_locks(timeout=args.timeout)
    if not locks:
        print("No TTLock devices found.")
        return
    for lock in locks:
        tag = "[PAIRING MODE]" if lock.is_setting_mode else ""
        print(
            f"  {lock.address}  {lock.name:<20}  "
            f"RSSI:{lock.rssi:4d} dBm  Battery:{lock.battery:3d}%  "
            f"{'UNLOCKED' if lock.is_unlocked else 'LOCKED':8s}  {tag}"
        )
        print(f"    MAC: {lock.mac}  "
              f"Protocol: {lock.protocol.protocol_type}.{lock.protocol.protocol_version}  "
              f"Scene: {lock.protocol.scene}")


async def cmd_pair(args) -> None:
    # Build minimal LockData from the discovered or user-supplied address
    print(f"Connecting to {args.address}…")

    # If no protocol is known yet, try to discover first
    proto_type, proto_ver, scene = 5, 3, 1  # safe V3 defaults
    if args.discover:
        print("Scanning to detect protocol parameters…")
        found = await discover_locks(timeout=args.scan_timeout)
        for lock in found:
            if lock.address.upper() == args.address.upper() or \
               lock.mac.upper() == args.address.upper():
                proto_type = lock.protocol.protocol_type
                proto_ver  = lock.protocol.protocol_version
                scene      = lock.protocol.scene
                print(f"  Protocol {proto_type}.{proto_ver}  scene={scene}")
                break

    data = LockData(
        address          = args.address,
        protocol_type    = proto_type,
        protocol_version = proto_ver,
        scene            = scene,
    )
    lock = TTLock(data)
    async with lock:
        print("Pairing…")
        await lock.pair()
    print("Pairing successful!")
    _save_lock(lock, args.save)


async def cmd_unlock(args) -> None:
    lock = _load_lock(args.lock)
    print(f"Connecting to {lock.data.address}…")
    async with lock:
        print("Unlocking…")
        await lock.unlock()
    print(f"Unlocked.  Battery: {lock.battery}%")
    _save_lock(lock, args.lock)


async def cmd_lock(args) -> None:
    lock = _load_lock(args.lock)
    print(f"Connecting to {lock.data.address}…")
    async with lock:
        print("Locking…")
        await lock.lock()
    print(f"Locked.  Battery: {lock.battery}%")
    _save_lock(lock, args.lock)


async def cmd_reset(args) -> None:
    lock = _load_lock(args.lock)
    print(f"Connecting to {lock.data.address}…")
    async with lock:
        print("Resetting to factory defaults…")
        await lock.reset()
    print("Reset complete.  Lock is now in pairing mode.")


async def cmd_status(args) -> None:
    lock = _load_lock(args.lock)
    print(f"Connecting to {lock.data.address}…")
    async with lock:
        status = await lock.get_locked_status()
    name = "UNLOCKED" if status == LockedStatus.UNLOCKED else \
           "LOCKED"   if status == LockedStatus.LOCKED   else "UNKNOWN"
    print(f"Status: {name}")
    _save_lock(lock, args.lock)


async def cmd_listen(args) -> None:
    print(f"Listening for lock events (timeout={args.timeout}s, Ctrl-C to stop)…")
    seen: dict[str, bool] = {}

    def on_event(lock) -> None:
        key = lock.address
        state = "UNLOCKED" if lock.is_unlocked else "LOCKED"
        if seen.get(key) != lock.is_unlocked:
            seen[key] = lock.is_unlocked
            print(f"  {lock.address}  {lock.name:<20}  {state}  "
                  f"battery={lock.battery}%  events={'yes' if lock.has_events else 'no'}")

    try:
        await listen_for_events(on_event, timeout=args.timeout if args.timeout else None)
    except KeyboardInterrupt:
        pass


# -- autolock ----------------------------------------------------------------

async def cmd_autolock_get(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        seconds = await lock.get_autolock_time()
    print(f"Auto-lock time: {seconds} seconds" if seconds >= 0 else "Auto-lock: not supported")
    _save_lock(lock, args.lock)


async def cmd_autolock_set(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.set_autolock_time(args.seconds)
    print(f"Auto-lock set to {args.seconds} seconds.")
    _save_lock(lock, args.lock)


# -- passage mode ------------------------------------------------------------

async def cmd_passage_list(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        modes = await lock.get_passage_mode()
    _print_json(modes)


async def cmd_passage_add(args) -> None:
    lock = _load_lock(args.lock)
    pm_type = int(PassageModeType[args.type.upper()])
    async with lock:
        await lock.add_passage_mode(pm_type, args.day, args.month or 0,
                                    args.start, args.end)
    print("Passage mode added.")


async def cmd_passage_delete(args) -> None:
    lock = _load_lock(args.lock)
    pm_type = int(PassageModeType[args.type.upper()])
    async with lock:
        await lock.delete_passage_mode(pm_type, args.day, args.month or 0,
                                       args.start, args.end)
    print("Passage mode deleted.")


async def cmd_passage_clear(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.clear_passage_mode()
    print("All passage modes cleared.")


# -- PIN codes ---------------------------------------------------------------

_PWD_TYPE_MAP = {
    "permanent": KeyboardPwdType.PERMANENT,
    "timed":     KeyboardPwdType.PERIOD,
    "count":     KeyboardPwdType.COUNT,
    "circle":    KeyboardPwdType.CIRCLE,
}


async def cmd_pin_list(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        codes = await lock.get_passcodes()
    _print_json(codes)


async def cmd_pin_add(args) -> None:
    lock = _load_lock(args.lock)
    pwd_type = _PWD_TYPE_MAP.get(args.type, KeyboardPwdType.PERMANENT)
    async with lock:
        await lock.add_passcode(args.code, pwd_type,
                                args.start or "000101000000",
                                args.end   or "991231235900")
    print(f"PIN {args.code} added.")


async def cmd_pin_update(args) -> None:
    lock = _load_lock(args.lock)
    pwd_type = _PWD_TYPE_MAP.get(args.type, KeyboardPwdType.PERMANENT)
    async with lock:
        await lock.update_passcode(args.old, args.new, pwd_type,
                                   args.start or "000101000000",
                                   args.end   or "991231235900")
    print(f"PIN updated: {args.old} → {args.new}")


async def cmd_pin_delete(args) -> None:
    lock = _load_lock(args.lock)
    pwd_type = _PWD_TYPE_MAP.get(args.type, KeyboardPwdType.PERMANENT)
    async with lock:
        await lock.delete_passcode(args.code, pwd_type)
    print(f"PIN {args.code} deleted.")


async def cmd_pin_clear(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.clear_passcodes()
    print("All PIN codes cleared.")


# -- IC cards ----------------------------------------------------------------

async def cmd_card_list(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        cards = await lock.get_ic_cards()
    _print_json(cards)


async def cmd_card_add(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        card_number = await lock.add_ic_card(
            args.start or "000101000000",
            args.end   or "991231235900",
        )
    print(f"IC card added: {card_number}")
    _save_lock(lock, args.lock)


async def cmd_card_update(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.update_ic_card(args.number, args.start, args.end)
    print(f"IC card {args.number} updated.")


async def cmd_card_delete(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.delete_ic_card(args.number)
    print(f"IC card {args.number} deleted.")


async def cmd_card_clear(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.clear_ic_cards()
    print("All IC cards cleared.")


# -- Fingerprints ------------------------------------------------------------

async def cmd_fp_list(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        fps = await lock.get_fingerprints()
    _print_json(fps)


async def cmd_fp_add(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        fp_id = await lock.add_fingerprint(
            args.start or "000101000000",
            args.end   or "991231235900",
        )
    print(f"Fingerprint added: ID={fp_id}")
    _save_lock(lock, args.lock)


async def cmd_fp_update(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.update_fingerprint(args.id, args.start, args.end)
    print(f"Fingerprint {args.id} updated.")


async def cmd_fp_delete(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.delete_fingerprint(args.id)
    print(f"Fingerprint {args.id} deleted.")


async def cmd_fp_clear(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        await lock.clear_fingerprints()
    print("All fingerprints cleared.")


# -- Operation log -----------------------------------------------------------

async def cmd_log(args) -> None:
    lock = _load_lock(args.lock)
    async with lock:
        entries = await lock.get_operation_log()
    _print_json(entries)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ttlock.py",
        description="Control TTLock BLE smart locks",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # discover
    d = sub.add_parser("discover", help="Scan for TTLock devices")
    d.add_argument("--timeout", type=float, default=10.0,
                   help="Scan duration in seconds (default: 10)")

    # pair
    pa = sub.add_parser("pair", help="Pair with a new lock")
    pa.add_argument("--address", required=True, help="BLE address or MAC")
    pa.add_argument("--save", default="lock.json",
                    help="File to save lock credentials (default: lock.json)")
    pa.add_argument("--discover", action="store_true", default=True,
                    help="Scan first to detect protocol parameters")
    pa.add_argument("--scan-timeout", type=float, default=10.0)

    # unlock / lock / reset / status
    for name in ("unlock", "lock", "reset", "status"):
        s = sub.add_parser(name)
        s.add_argument("--lock", default="lock.json")

    # listen
    li = sub.add_parser("listen", help="Monitor lock events from BLE advertisements")
    li.add_argument("--timeout", type=float, default=None,
                    help="Stop after N seconds (default: run until Ctrl-C)")

    # log
    lg = sub.add_parser("log", help="Retrieve operation log")
    lg.add_argument("--lock", default="lock.json")

    # autolock
    al = sub.add_parser("autolock", help="Auto-lock timer")
    al_sub = al.add_subparsers(dest="subcommand", required=True)
    al_get = al_sub.add_parser("get"); al_get.add_argument("--lock", default="lock.json")
    al_set = al_sub.add_parser("set")
    al_set.add_argument("--lock", default="lock.json")
    al_set.add_argument("--seconds", type=int, required=True)

    # passage
    pm = sub.add_parser("passage", help="Passage mode")
    pm_sub = pm.add_subparsers(dest="subcommand", required=True)

    pm_list = pm_sub.add_parser("list"); pm_list.add_argument("--lock", default="lock.json")

    for pm_cmd in ("add", "delete"):
        s = pm_sub.add_parser(pm_cmd)
        s.add_argument("--lock", default="lock.json")
        s.add_argument("--type", choices=["weekly", "monthly"], default="weekly")
        s.add_argument("--day",   type=int, default=0,
                       help="0=every day, 1-7=Mon-Sun (weekly), 1-31 (monthly)")
        s.add_argument("--month", type=int, default=0)
        s.add_argument("--start", default="0000", help="Start time HHMM (default: 0000)")
        s.add_argument("--end",   default="2359", help="End time HHMM (default: 2359)")

    pm_clear = pm_sub.add_parser("clear")
    pm_clear.add_argument("--lock", default="lock.json")

    # pin
    pin = sub.add_parser("pin", help="PIN codes (keyboard passwords)")
    pin_sub = pin.add_subparsers(dest="subcommand", required=True)

    pin_sub.add_parser("list").add_argument("--lock", default="lock.json")

    pin_add = pin_sub.add_parser("add")
    pin_add.add_argument("--lock", default="lock.json")
    pin_add.add_argument("--code", required=True)
    pin_add.add_argument("--type", choices=list(_PWD_TYPE_MAP), default="permanent")
    pin_add.add_argument("--start", default=None, help="YYMMDDHHmmss")
    pin_add.add_argument("--end",   default=None, help="YYMMDDHHmmss")

    pin_upd = pin_sub.add_parser("update")
    pin_upd.add_argument("--lock", default="lock.json")
    pin_upd.add_argument("--old",  required=True)
    pin_upd.add_argument("--new",  required=True)
    pin_upd.add_argument("--type", choices=list(_PWD_TYPE_MAP), default="permanent")
    pin_upd.add_argument("--start", default=None)
    pin_upd.add_argument("--end",   default=None)

    pin_del = pin_sub.add_parser("delete")
    pin_del.add_argument("--lock", default="lock.json")
    pin_del.add_argument("--code", required=True)
    pin_del.add_argument("--type", choices=list(_PWD_TYPE_MAP), default="permanent")

    pin_sub.add_parser("clear").add_argument("--lock", default="lock.json")

    # card
    card = sub.add_parser("card", help="IC cards")
    card_sub = card.add_subparsers(dest="subcommand", required=True)

    card_sub.add_parser("list").add_argument("--lock", default="lock.json")

    card_add = card_sub.add_parser("add")
    card_add.add_argument("--lock", default="lock.json")
    card_add.add_argument("--start", default=None, help="YYMMDDHHmmss validity start")
    card_add.add_argument("--end",   default=None, help="YYMMDDHHmmss validity end")

    card_upd = card_sub.add_parser("update")
    card_upd.add_argument("--lock",   default="lock.json")
    card_upd.add_argument("--number", required=True)
    card_upd.add_argument("--start",  required=True)
    card_upd.add_argument("--end",    required=True)

    card_del = card_sub.add_parser("delete")
    card_del.add_argument("--lock",   default="lock.json")
    card_del.add_argument("--number", required=True)

    card_sub.add_parser("clear").add_argument("--lock", default="lock.json")

    # fingerprint
    fp = sub.add_parser("fingerprint", help="Fingerprints")
    fp_sub = fp.add_subparsers(dest="subcommand", required=True)

    fp_sub.add_parser("list").add_argument("--lock", default="lock.json")

    fp_add = fp_sub.add_parser("add")
    fp_add.add_argument("--lock",  default="lock.json")
    fp_add.add_argument("--start", default=None)
    fp_add.add_argument("--end",   default=None)

    fp_upd = fp_sub.add_parser("update")
    fp_upd.add_argument("--lock",  default="lock.json")
    fp_upd.add_argument("--id",    required=True)
    fp_upd.add_argument("--start", required=True)
    fp_upd.add_argument("--end",   required=True)

    fp_del = fp_sub.add_parser("delete")
    fp_del.add_argument("--lock", default="lock.json")
    fp_del.add_argument("--id",   required=True)

    fp_sub.add_parser("clear").add_argument("--lock", default="lock.json")

    return p


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_DISPATCH = {
    "discover":           cmd_discover,
    "pair":               cmd_pair,
    "unlock":             cmd_unlock,
    "lock":               cmd_lock,
    "reset":              cmd_reset,
    "status":             cmd_status,
    "listen":             cmd_listen,
    "log":                cmd_log,
    ("autolock",  "get"): cmd_autolock_get,
    ("autolock",  "set"): cmd_autolock_set,
    ("passage",  "list"): cmd_passage_list,
    ("passage",   "add"): cmd_passage_add,
    ("passage","delete"): cmd_passage_delete,
    ("passage", "clear"): cmd_passage_clear,
    ("pin",      "list"): cmd_pin_list,
    ("pin",       "add"): cmd_pin_add,
    ("pin",    "update"): cmd_pin_update,
    ("pin",    "delete"): cmd_pin_delete,
    ("pin",     "clear"): cmd_pin_clear,
    ("card",     "list"): cmd_card_list,
    ("card",      "add"): cmd_card_add,
    ("card",   "update"): cmd_card_update,
    ("card",   "delete"): cmd_card_delete,
    ("card",    "clear"): cmd_card_clear,
    ("fingerprint", "list"):   cmd_fp_list,
    ("fingerprint",  "add"):   cmd_fp_add,
    ("fingerprint", "update"): cmd_fp_update,
    ("fingerprint", "delete"): cmd_fp_delete,
    ("fingerprint", "clear"):  cmd_fp_clear,
}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    key = (args.command, getattr(args, "subcommand", None))
    handler = _DISPATCH.get(key) or _DISPATCH.get(args.command)

    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(handler(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
