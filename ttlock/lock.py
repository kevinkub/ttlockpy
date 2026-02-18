"""High-level TTLock BLE API.

Usage example::

    import asyncio, json
    from ttlock.lock import TTLock

    async def main():
        lock = TTLock.from_file("lock.json")
        async with lock:
            await lock.unlock()
            print("Battery:", lock.battery)
        lock.save("lock.json")

    asyncio.run(main())
"""

import asyncio
import json
import os
import random
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bleak import BleakClient
from bleak.exc import BleakError

from .const import (
    DEFAULT_AES_KEY, WRITE_CHAR_UUID, NOTIFY_CHAR_UUID,
    BLE_MTU, CommandType, CommandResponse, LockedStatus,
    FeatureValue, KeyboardPwdType, ICOperate,
)
from .protocol import LockProtocol, build_packet, parse_response, split_into_chunks
from . import commands as cmd


# ---------------------------------------------------------------------------
# Lock data (persisted to JSON)
# ---------------------------------------------------------------------------

@dataclass
class LockData:
    """All data needed to connect and authenticate with a paired lock."""
    address: str = ""            # BLE address
    name: str = "TTLock"
    mac: str = ""                # Physical MAC from manufacturer data
    battery: int = -1
    locked_status: int = int(LockedStatus.UNKNOWN)
    auto_lock_time: int = -1
    # Protocol parameters (from manufacturer data)
    protocol_type: int = 5
    protocol_version: int = 3
    scene: int = 1
    # Credentials obtained during pairing
    aes_key: str = ""            # hex-encoded 16-byte key
    admin_ps: int = 0
    unlock_key: int = 0
    admin_passcode: str = ""

    def is_paired(self) -> bool:
        return bool(self.aes_key and self.admin_ps and self.unlock_key)

    def get_aes_key(self) -> bytes:
        if self.aes_key:
            return bytes.fromhex(self.aes_key)
        return DEFAULT_AES_KEY

    def get_protocol(self) -> LockProtocol:
        return LockProtocol(
            protocol_type    = self.protocol_type,
            protocol_version = self.protocol_version,
            scene            = self.scene,
            group_id         = 1,
            org_id           = 1,
        )


# ---------------------------------------------------------------------------
# Main TTLock class
# ---------------------------------------------------------------------------

class TTLock:
    """Bluetooth interface for a single TTLock device.

    After construction, call `connect()` (or use the async context manager)
    before calling any operation methods.
    """

    def __init__(self, data: LockData):
        self.data = data
        self._client: BleakClient | None = None
        self._rx_buffer = bytearray()
        self._response_queue: asyncio.Queue = asyncio.Queue()
        self.battery: int = data.battery

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "TTLock":
        with open(path) as f:
            raw = json.load(f)
        return cls(LockData(**raw))

    @classmethod
    def from_address(cls, address: str, name: str = "TTLock") -> "TTLock":
        return cls(LockData(address=address, name=name))

    def save(self, path: str | Path) -> None:
        with open(path, "w") as f:
            json.dump(asdict(self.data), f, indent=2)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self, timeout: float = 15.0) -> None:
        """Connect to the lock and subscribe to notifications."""
        self._client = BleakClient(self.data.address, timeout=timeout)
        await self._client.connect()
        await self._client.start_notify(NOTIFY_CHAR_UUID, self._on_notification)

    async def disconnect(self) -> None:
        if self._client and self._client.is_connected:
            try:
                await self._client.stop_notify(NOTIFY_CHAR_UUID)
            except Exception:
                pass
            await self._client.disconnect()
        self._client = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def __aenter__(self) -> "TTLock":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # BLE I/O
    # ------------------------------------------------------------------

    def _on_notification(self, _handle: int, data: bytes) -> None:
        """Accumulate incoming BLE chunks and dispatch complete frames."""
        self._rx_buffer.extend(data)
        if self._rx_buffer[-2:] == b"\r\n":
            frame = bytes(self._rx_buffer)
            self._rx_buffer.clear()
            self._response_queue.put_nowait(frame)

    async def _send_command(
        self,
        cmd_type: CommandType,
        payload: bytes,
        aes_key: bytes | None = None,
        wait_response: bool = True,
        ignore_crc: bool = False,
    ) -> dict | None:
        """Build, send, and optionally await a lock command."""
        proto = self.data.get_protocol()
        packet = build_packet(proto, int(cmd_type), payload, aes_key)

        for chunk in split_into_chunks(packet):
            await self._client.write_gatt_char(WRITE_CHAR_UUID, chunk,
                                               response=False)

        if not wait_response:
            return None

        # Wait for the lock to reply (with retry on bad CRC)
        for _attempt in range(3):
            try:
                frame = await asyncio.wait_for(
                    self._response_queue.get(), timeout=5.0
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response to command 0x{cmd_type:02X}")

            parsed = parse_response(frame, aes_key=aes_key,
                                    ignore_crc=ignore_crc)
            if parsed["crc_ok"] or ignore_crc:
                if parsed["response"] != CommandResponse.SUCCESS:
                    raise RuntimeError(
                        f"Command 0x{cmd_type:02X} failed "
                        f"(response=0x{parsed['response']:02X})"
                    )
                return parsed
        raise RuntimeError(f"Command 0x{cmd_type:02X}: persistent CRC errors")

    async def wait_for_notification(self, timeout: float = 30.0) -> dict | None:
        """Block until the lock sends an unsolicited notification (e.g. card scan)."""
        aes_key = self.data.get_aes_key() if self.data.is_paired() else None
        try:
            frame = await asyncio.wait_for(
                self._response_queue.get(), timeout=timeout
            )
            return parse_response(frame, aes_key=aes_key, ignore_crc=True)
        except asyncio.TimeoutError:
            return None

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    async def _auth_check_user_time(self) -> int:
        """V3 auth: validate the time window, get psFromLock."""
        resp = await self._send_command(
            CommandType.CHECK_USER_TIME,
            cmd.build_check_user_time(),
            aes_key=self.data.get_aes_key(),
        )
        return cmd.parse_check_user_time(resp["data"])

    async def _auth_admin_login(self) -> int:
        """Older-protocol auth: verify admin identity, get psFromLock."""
        resp = await self._send_command(
            CommandType.CHECK_ADMIN,
            cmd.build_check_admin(self.data.admin_ps),
            aes_key=self.data.get_aes_key(),
        )
        ps_from_lock = cmd.parse_check_admin(resp["data"])
        await self._send_command(
            CommandType.CHECK_RANDOM,
            cmd.build_check_random(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        return ps_from_lock

    # ------------------------------------------------------------------
    # Pairing
    # ------------------------------------------------------------------

    async def pair(self) -> None:
        """Pair with a factory-fresh lock and store credentials in self.data.

        The lock must be in pairing/setting mode (LED blinking).
        """
        proto = self.data.get_protocol()

        # Step 1: Initialise (no AES key, no payload)
        await self._send_command(
            CommandType.INITIALIZATION,
            cmd.build_init(),
            aes_key=None,
            ignore_crc=True,
        )

        # Step 2: Get the lock's AES key (use default key)
        resp = await self._send_command(
            CommandType.GET_AES_KEY,
            cmd.build_get_aes_key(),
            aes_key=DEFAULT_AES_KEY,
        )
        aes_key = cmd.parse_aes_key(resp["data"])
        self.data.aes_key = aes_key.hex()

        # Step 3: Register admin credentials
        admin_ps   = random.randint(1, 99_999_999)
        unlock_key = random.randint(1, 99_999_999)
        await self._send_command(
            CommandType.ADD_ADMIN,
            cmd.build_add_admin(admin_ps, unlock_key),
            aes_key=aes_key,
        )
        self.data.admin_ps   = admin_ps
        self.data.unlock_key = unlock_key

        # Step 4: Calibrate clock (best-effort)
        try:
            await self._send_command(
                CommandType.TIME_CALIBRATE,
                cmd.build_calibrate_time(),
                aes_key=aes_key,
                ignore_crc=True,
            )
        except Exception:
            pass

        # Step 5: Query features
        resp = await self._send_command(
            CommandType.SEARCH_DEVICE_FEATURE,
            cmd.build_search_device_feature(),
            aes_key=aes_key,
        )
        features = cmd.parse_device_features(resp["data"])

        # Step 6: Get / set admin PIN
        if FeatureValue.GET_ADMIN_CODE in features:
            resp = await self._send_command(
                CommandType.GET_ADMIN_CODE,
                cmd.build_get_admin_code(),
                aes_key=aes_key,
            )
            admin_passcode = cmd.parse_admin_code(resp["data"])
            if not admin_passcode:
                admin_passcode = str(random.randint(1_000_000, 9_999_999))
                await self._send_command(
                    CommandType.SET_ADMIN_KEYBOARD_PWD,
                    cmd.build_set_admin_code(admin_passcode),
                    aes_key=aes_key,
                )
            self.data.admin_passcode = admin_passcode

        # Step 7: Signal end of pairing sequence
        await self._send_command(
            CommandType.OPERATE_FINISHED,
            cmd.build_operate_finished(),
            aes_key=aes_key,
        )

    # ------------------------------------------------------------------
    # Unlock / Lock / Status
    # ------------------------------------------------------------------

    async def unlock(self) -> None:
        """Unlock the lock."""
        ps_from_lock = await self._auth_check_user_time()
        resp = await self._send_command(
            CommandType.UNLOCK,
            cmd.build_unlock(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        parsed = cmd.parse_unlock(resp["data"])
        if "battery" in parsed:
            self.battery = parsed["battery"]
            self.data.battery = self.battery
        self.data.locked_status = int(LockedStatus.UNLOCKED)

    async def lock(self) -> None:
        """Lock the lock."""
        ps_from_lock = await self._auth_check_user_time()
        resp = await self._send_command(
            CommandType.FUNCTION_LOCK,
            cmd.build_lock(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        parsed = cmd.parse_lock(resp["data"])
        if "battery" in parsed:
            self.battery = parsed["battery"]
            self.data.battery = self.battery
        self.data.locked_status = int(LockedStatus.LOCKED)

    async def reset(self) -> None:
        """Factory-reset the lock (clears all credentials, returns to pairing mode)."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.RESET_LOCK,
            b"",
            aes_key=self.data.get_aes_key(),
            wait_response=False,
        )

    async def get_locked_status(self) -> LockedStatus:
        """Query the lock for its current locked/unlocked state."""
        resp = await self._send_command(
            CommandType.SEARCH_BICYCLE_STATUS,
            cmd.build_search_status(),
            aes_key=self.data.get_aes_key(),
        )
        status = cmd.parse_search_status(resp["data"])
        self.data.locked_status = int(status)
        return status

    # ------------------------------------------------------------------
    # Auto-lock
    # ------------------------------------------------------------------

    async def get_autolock_time(self) -> int:
        """Return the auto-lock delay in seconds (-1 if not supported)."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.AUTO_LOCK_MANAGE,
            cmd.build_get_autolock(),
            aes_key=self.data.get_aes_key(),
        )
        seconds = cmd.parse_autolock(resp["data"])
        self.data.auto_lock_time = seconds
        return seconds

    async def set_autolock_time(self, seconds: int) -> None:
        """Set the auto-lock delay in seconds (0 disables auto-lock)."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.AUTO_LOCK_MANAGE,
            cmd.build_set_autolock(seconds),
            aes_key=self.data.get_aes_key(),
        )
        self.data.auto_lock_time = seconds

    # ------------------------------------------------------------------
    # Passage mode
    # ------------------------------------------------------------------

    async def get_passage_mode(self) -> list[dict]:
        """Return the list of configured passage-mode intervals."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_get_passage_mode(),
            aes_key=self.data.get_aes_key(),
            ignore_crc=True,
        )
        _, modes = cmd.parse_passage_modes(resp["data"])
        return modes

    async def add_passage_mode(
        self,
        pm_type: int,
        week_or_day: int,
        month: int,
        start_hour: str,
        end_hour: str,
    ) -> None:
        """Add a passage-mode entry.

        pm_type: 1=weekly, 2=monthly.
        week_or_day: 0=every day, 1-7=Mon-Sun (weekly) or 1-31 (monthly).
        month: 0 for weekly, month number for monthly.
        start_hour / end_hour: "HHMM" strings e.g. "0800".
        """
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_set_passage_mode(pm_type, week_or_day, month,
                                       start_hour, end_hour),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_passage_mode(
        self, pm_type: int, week_or_day: int, month: int,
        start_hour: str, end_hour: str,
    ) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_delete_passage_mode(pm_type, week_or_day, month,
                                          start_hour, end_hour),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_passage_mode(self) -> None:
        """Remove all passage-mode entries."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_clear_passage_mode(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # PIN codes (keyboard passwords)
    # ------------------------------------------------------------------

    async def get_passcodes(self) -> list[dict]:
        """Return all stored PIN codes."""
        await self._auth_admin_login()
        all_codes: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.PWD_LIST,
                cmd.build_list_passcodes(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
            )
            next_seq, codes = cmd.parse_passcodes(resp["data"])
            all_codes.extend(codes)
            if next_seq == 0 or not codes:
                break
            sequence = next_seq
        return all_codes

    async def add_passcode(
        self,
        passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> None:
        """Add a PIN code."""
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_add_passcode(pwd_type, passcode, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def update_passcode(
        self,
        old_passcode: str,
        new_passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> None:
        """Update an existing PIN code."""
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_update_passcode(pwd_type, old_passcode, new_passcode,
                                      start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_passcode(
        self,
        passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
    ) -> None:
        """Delete one PIN code."""
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_delete_passcode(pwd_type, passcode),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_passcodes(self) -> None:
        """Delete all PIN codes from the lock."""
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_clear_passcodes(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # IC cards
    # ------------------------------------------------------------------

    async def get_ic_cards(self) -> list[dict]:
        """Return all stored IC cards."""
        await self._auth_admin_login()
        all_cards: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.IC_MANAGE,
                cmd.build_list_ic_cards(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
            )
            next_seq, cards = cmd.parse_ic_cards(resp["data"])
            all_cards.extend(cards)
            if next_seq == 0 or not cards:
                break
            sequence = next_seq
        return all_cards

    async def add_ic_card(
        self,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> str:
        """Enter IC card enrolment mode and wait for a card to be scanned.

        Returns the scanned card number string.
        """
        resp = await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_add_ic_card(),
            aes_key=self.data.get_aes_key(),
        )
        # Lock enters add mode; wait for card scan notification
        print("  Hold IC card near the lock...")
        notif = await self.wait_for_notification(timeout=30.0)
        if notif is None:
            raise TimeoutError("No IC card scanned within 30 seconds")
        card_number, status = cmd.parse_ic_card_add(notif["data"])
        if not card_number:
            raise RuntimeError("IC card add failed")
        return card_number

    async def update_ic_card(
        self, card_number: str,
        start_date: str, end_date: str,
    ) -> None:
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_update_ic_card(card_number, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_ic_card(self, card_number: str) -> None:
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_delete_ic_card(card_number),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_ic_cards(self) -> None:
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_clear_ic_cards(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # Fingerprints
    # ------------------------------------------------------------------

    async def get_fingerprints(self) -> list[dict]:
        """Return all stored fingerprints."""
        await self._auth_admin_login()
        all_fps: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.FR_MANAGE,
                cmd.build_list_fingerprints(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
            )
            next_seq, fps = cmd.parse_fingerprints(resp["data"])
            all_fps.extend(fps)
            if next_seq == 0 or not fps:
                break
            sequence = next_seq
        return all_fps

    async def add_fingerprint(
        self,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> str:
        """Enter fingerprint enrolment mode.

        Prompts the user to scan their finger multiple times.
        Returns the fingerprint ID string on success.
        """
        resp = await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_add_fingerprint(),
            aes_key=self.data.get_aes_key(),
        )
        print("  Place your finger on the sensor (scan multiple times)...")
        fp_number = ""
        while True:
            notif = await self.wait_for_notification(timeout=30.0)
            if notif is None:
                raise TimeoutError("Fingerprint enrolment timed out")
            fp_num, status = cmd.parse_fingerprint_add(notif["data"])
            if status == ICOperate.STATUS_FR_PROGRESS:
                print("  Scan again...")
                continue
            if status == ICOperate.STATUS_ADD_SUCCESS:
                fp_number = fp_num
                break
            raise RuntimeError(f"Fingerprint add failed (status={status})")
        return fp_number

    async def update_fingerprint(
        self, fp_number: str,
        start_date: str, end_date: str,
    ) -> None:
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_update_fingerprint(fp_number, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_fingerprint(self, fp_number: str) -> None:
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_delete_fingerprint(fp_number),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_fingerprints(self) -> None:
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_clear_fingerprints(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # Operation log
    # ------------------------------------------------------------------

    async def get_operation_log(self) -> list[dict]:
        """Retrieve all operation log entries from the lock."""
        resp = await self._send_command(
            CommandType.GET_OPERATE_LOG,
            cmd.build_get_operation_log(),
            aes_key=self.data.get_aes_key(),
        )
        _, entries = cmd.parse_operation_log(resp["data"])
        return entries
