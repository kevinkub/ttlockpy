"""Constants and enumerations for the TTLock BLE protocol."""

from enum import IntEnum

# BLE service and characteristic UUIDs
TTLOCK_SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
WRITE_CHAR_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID = "0000fff4-0000-1000-8000-00805f9b34fb"

# Default AES key used during pairing (before lock's own key is obtained)
DEFAULT_AES_KEY = bytes([
    0x98, 0x76, 0x23, 0xE8,
    0xA9, 0x23, 0xA1, 0xBB,
    0x3D, 0x9E, 0x7D, 0x03,
    0x78, 0x12, 0x45, 0x88,
])

# Packet framing
PACKET_HEADER = bytes([0x7F, 0x5A])
PACKET_TERMINATOR = b"\r\n"
BLE_MTU = 20            # max bytes per BLE write
APP_COMMAND = 0xAA      # encrypt byte we send to the lock


class CommandType(IntEnum):
    INITIALIZATION = 0x45           # Pairing step 1
    GET_AES_KEY = 0x19              # Pairing step 2: get lock AES key
    ADD_ADMIN = 0x56                # Pairing step 3: register admin credentials
    CHECK_ADMIN = 0x41              # Auth step 1 (older protocol)
    CHECK_RANDOM = 0x30             # Auth step 2 (older protocol)
    CHECK_USER_TIME = 0x55          # Auth (V3 protocol): send validity window
    SET_ADMIN_KEYBOARD_PWD = 0x53   # Set admin PIN code
    GET_ADMIN_CODE = 0x65           # Read admin PIN code
    UNLOCK = 0x47                   # Unlock
    FUNCTION_LOCK = 0x58            # Lock
    TIME_CALIBRATE = 0x43           # Synchronise lock clock
    MANAGE_KEYBOARD_PASSWORD = 0x03 # Add / edit / delete PIN codes
    PWD_LIST = 0x07                 # List PIN codes
    GET_OPERATE_LOG = 0x25          # Read operation log
    RESET_LOCK = 0x52               # Factory reset
    SEARCH_DEVICE_FEATURE = 0x01    # Query lock capabilities (feature bitmap)
    IC_MANAGE = 0x05                # IC card operations
    FR_MANAGE = 0x06                # Fingerprint operations
    AUTO_LOCK_MANAGE = 0x36         # Get / set auto-lock timeout
    READ_DEVICE_INFO = 0x90         # Read device info string
    CONTROL_REMOTE_UNLOCK = 0x37    # Enable / disable remote unlock
    AUDIO_MANAGE = 0x62             # Enable / disable lock beeps
    CONFIGURE_PASSAGE_MODE = 0x66   # Passage mode management
    SHOW_PASSWORD = 0x59            # Show / hide passcode on keypad
    OPERATE_FINISHED = 0x57         # Signal end of multi-step operation
    SEARCH_BICYCLE_STATUS = 0x14    # Poll lock/unlock status


class CommandResponse(IntEnum):
    FAILED = 0x00
    SUCCESS = 0x01


class LockedStatus(IntEnum):
    UNKNOWN = -1
    LOCKED = 0
    UNLOCKED = 1


class KeyboardPwdType(IntEnum):
    PERMANENT = 1   # Always valid
    COUNT = 2       # Limited number of uses
    PERIOD = 3      # Time-limited window
    CIRCLE = 4      # Recurring schedule


class PwdOperateType(IntEnum):
    CLEAR = 1       # Delete all passcodes
    ADD = 2         # Add a passcode
    REMOVE_ONE = 3  # Delete one passcode
    MODIFY = 5      # Update a passcode


class ICOperate(IntEnum):
    IC_SEARCH = 1
    ADD = 2
    DELETE = 3
    CLEAR = 4
    MODIFY = 5
    FR_SEARCH = 6
    WRITE_FR = 7
    # Status codes returned inside the ADD response
    STATUS_ADD_SUCCESS = 0x01
    STATUS_ENTER_ADD_MODE = 0x02
    STATUS_FR_PROGRESS = 0x03
    STATUS_FR_RECEIVE_TEMPLATE = 0x04


class AutoLockOperate(IntEnum):
    SEARCH = 0x01
    MODIFY = 0x02


class PassageModeOperate(IntEnum):
    QUERY = 1
    ADD = 2
    DELETE = 3
    CLEAR = 4


class PassageModeType(IntEnum):
    WEEKLY = 1
    MONTHLY = 2


class FeatureValue(IntEnum):
    PASSCODE = 0
    IC = 1
    FINGER_PRINT = 2
    WRIST_BAND = 3
    AUTO_LOCK = 4
    PASSCODE_WITH_DELETE = 5
    FIRMWARE_SETTING = 6
    MODIFY_PASSCODE = 7
    MANUAL_LOCK = 8
    PASSWORD_DISPLAY_OR_HIDE = 9
    GATEWAY_UNLOCK = 10
    FREEZE_LOCK = 11
    CYCLIC_PASSWORD = 12
    MAGNETOMETER = 13
    CONFIG_GATEWAY_UNLOCK = 14
    AUDIO_MANAGEMENT = 15
    NB_LOCK = 16
    GET_ADMIN_CODE = 18
    HOTEL_LOCK = 19
    LOCK_NO_CLOCK_CHIP = 20
    CAN_NOT_CLICK_UNLOCK = 21
    PASSAGE_MODE = 22
    PASSAGE_MODE_AND_AUTO_LOCK = 23
    WIRELESS_KEYBOARD = 24
    LAMP = 25
    TAMPER_ALERT = 28
    RESET_BUTTON = 29
    PRIVACK_LOCK = 30
    DEAD_LOCK = 32
    CYCLIC_IC_OR_FINGERPRINT = 34
    UNLOCK_DIRECTION = 36
    FINGER_VEIN = 37
    TELINK_CHIP = 38
    NB_ACTIVATE_CONFIGURATION = 39
    CYCLIC_PASSCODE_CAN_RECOVERY = 40
    WIRELESS_KEY_FOB = 41
    ACCESSORY_BATTERY = 42
