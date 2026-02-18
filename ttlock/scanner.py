"""BLE scanner for TTLock devices.

Uses *bleak* which works on Linux (BlueZ), macOS (CoreBluetooth), and Windows.

TTLock locks advertise with service UUID 00001910-... and embed a custom
manufacturer data block whose raw bytes carry the protocol version, lock
state, battery level, and MAC address.
"""

import asyncio
from dataclasses import dataclass, field

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .const import TTLOCK_SERVICE_UUID
from .protocol import LockProtocol


@dataclass
class DiscoveredLock:
    """A TTLock device found during a BLE scan."""
    address: str          # BLE address (MAC on Linux, UUID on macOS)
    name: str
    rssi: int
    mac: str              # Physical MAC address from manufacturer data
    battery: int
    is_unlocked: bool
    has_events: bool
    is_setting_mode: bool  # True when factory-fresh / in pairing mode
    protocol: LockProtocol = field(default_factory=LockProtocol)


def _parse_manufacturer_data(company_id: int, payload: bytes) -> dict | None:
    """Decode TTLock manufacturer data.

    BLE manufacturer data is keyed by a 16-bit company ID.  noble (the JS
    library) presented this as raw bytes where byte 0 is company_id_lo and
    byte 1 is company_id_hi.  Bleak strips those two bytes, so we prepend
    them back before parsing.
    """
    raw = bytes([company_id & 0xFF, (company_id >> 8) & 0xFF]) + payload
    if len(raw) < 15:
        return None

    offset = 0
    protocol_type    = raw[offset]; offset += 1
    protocol_version = raw[offset]; offset += 1

    # DFU mode – not a usable lock state
    if (protocol_type == 18 and protocol_version == 25) or \
       (protocol_type == 0xFF and protocol_version == 0xFF):
        return None
    # Wristband – not a lock
    if protocol_type == 52 and protocol_version == 18:
        return None

    if protocol_type == 5 and protocol_version == 3:
        scene = raw[offset]; offset += 1
    else:
        offset = 4
        protocol_type    = raw[offset]; offset += 1
        protocol_version = raw[offset]; offset += 1
        offset = 7
        scene = raw[offset]; offset += 1

    if offset >= len(raw):
        return None

    params  = raw[offset]; offset += 1
    battery = raw[offset] if offset < len(raw) else 0

    is_unlocked    = bool(params & 0x01)
    has_events     = bool(params & 0x02)
    is_setting_mode = bool(params & 0x04)

    # MAC is in the last 6 bytes, reversed
    mac_bytes = raw[-6:]
    mac = ":".join(f"{b:02X}" for b in reversed(mac_bytes))

    return {
        "protocol_type":    protocol_type,
        "protocol_version": protocol_version,
        "scene":            scene,
        "battery":          battery,
        "is_unlocked":      is_unlocked,
        "has_events":       has_events,
        "is_setting_mode":  is_setting_mode,
        "mac":              mac,
    }


def _is_ttlock(adv: AdvertisementData) -> bool:
    uuids = [u.lower() for u in adv.service_uuids]
    return TTLOCK_SERVICE_UUID.lower() in uuids


def _device_from_advertisement(
    device: BLEDevice, adv: AdvertisementData
) -> DiscoveredLock | None:
    if not _is_ttlock(adv):
        return None

    parsed: dict | None = None
    for company_id, payload in adv.manufacturer_data.items():
        parsed = _parse_manufacturer_data(company_id, payload)
        if parsed:
            break

    if parsed is None:
        return None

    proto = LockProtocol(
        protocol_type    = parsed["protocol_type"],
        protocol_version = parsed["protocol_version"],
        scene            = parsed["scene"],
        group_id         = 1,
        org_id           = 1,
    )

    return DiscoveredLock(
        address         = device.address,
        name            = device.name or "TTLock",
        rssi            = adv.rssi if adv.rssi is not None else 0,
        mac             = parsed["mac"],
        battery         = parsed["battery"],
        is_unlocked     = parsed["is_unlocked"],
        has_events      = parsed["has_events"],
        is_setting_mode = parsed["is_setting_mode"],
        protocol        = proto,
    )


async def discover_locks(timeout: float = 10.0) -> list[DiscoveredLock]:
    """Scan for TTLock BLE devices and return a list of discovered locks.

    *timeout* – scan duration in seconds.
    """
    found: dict[str, DiscoveredLock] = {}

    def callback(device: BLEDevice, adv: AdvertisementData) -> None:
        lock = _device_from_advertisement(device, adv)
        if lock:
            found[device.address] = lock   # update with latest advertisement

    scanner = BleakScanner(detection_callback=callback,
                           service_uuids=[TTLOCK_SERVICE_UUID])
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return list(found.values())


async def listen_for_events(
    callback,
    timeout: float | None = None,
) -> None:
    """Passively monitor BLE advertisements to detect lock/unlock events.

    *callback(lock: DiscoveredLock)* is called each time a TTLock
    advertisement is received.  Set *timeout* to stop after N seconds;
    pass None to run indefinitely (until Ctrl-C).
    """
    def _cb(device: BLEDevice, adv: AdvertisementData) -> None:
        lock = _device_from_advertisement(device, adv)
        if lock:
            callback(lock)

    scanner = BleakScanner(detection_callback=_cb)
    await scanner.start()
    try:
        if timeout:
            await asyncio.sleep(timeout)
        else:
            while True:
                await asyncio.sleep(1)
    finally:
        await scanner.stop()
