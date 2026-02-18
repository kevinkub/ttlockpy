"""ttlock – Python library for TTLock BLE smart locks.

Public API::

    from ttlock import TTLock, LockData, discover_locks, listen_for_events
    from ttlock.const import KeyboardPwdType, PassageModeType, LockedStatus
"""

from .lock import TTLock, LockData
from .scanner import discover_locks, listen_for_events, DiscoveredLock

__all__ = [
    "TTLock",
    "LockData",
    "discover_locks",
    "listen_for_events",
    "DiscoveredLock",
]
