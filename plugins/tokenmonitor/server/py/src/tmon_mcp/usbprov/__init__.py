"""Host side of the USB serial provisioning protocol (compat/PROVISION_WIRE.md).

A faithful port of tokenmonitor-mcp/internal/usbprov (go): the SLIP+CRC32 wire
codec, the hardcoded USB device-identity table, port enumeration and
classification, the session state machine, the OS-exclusive serial open, and the
leader-mediated port lease (manager + follower client + wire types).
"""

from __future__ import annotations

from . import frame, leasewire
from .enum import (
    EnumerateUnsupported,
    Port,
    device_id_from_serial,
    enumerate,
    normalize_serial,
)
from .lease import (
    DEFAULT_LEASE_MAX_TTL,
    DEFAULT_LEASE_MIN_TTL,
    LeaseBusy,
    LeaseManager,
    LeaseUnknown,
    NopController,
    SerialController,
    random_lease_id,
)
from .leaseclient import DEFAULT_LEASE_TTL, LeaseClient, LeasedPort
from .scan import ScanResult, registry_matches, resolve
from .serial_port import (
    Handle,
    OpenUnsupported,
    PortBusy,
    SerialTransport,
    acquire_port_lock,
    canonical_port,
    open_exclusive,
)
from .session import (
    DeviceInfo,
    DeviceMismatch,
    Handshake,
    OutcomeUnknown,
    ProvisionOpts,
    ProvisionResult,
    SessionCancelled,
    SessionIO,
    Timeouts,
    UnsupportedProto,
    default_timeouts,
    identify,
    run_provision,
)
from .usbids import (
    DEVICE_TABLE,
    TIER_PROBE,
    TIER_REGISTRY_MATCH,
    TIER_SHARED,
    USBID,
    classify_vid_pid,
    label_for,
)

__all__ = [
    "frame",
    "leasewire",
    # enum
    "EnumerateUnsupported",
    "Port",
    "device_id_from_serial",
    "enumerate",
    "normalize_serial",
    # usbids
    "DEVICE_TABLE",
    "TIER_PROBE",
    "TIER_REGISTRY_MATCH",
    "TIER_SHARED",
    "USBID",
    "classify_vid_pid",
    "label_for",
    # scan
    "ScanResult",
    "registry_matches",
    "resolve",
    # serial
    "Handle",
    "OpenUnsupported",
    "PortBusy",
    "SerialTransport",
    "acquire_port_lock",
    "canonical_port",
    "open_exclusive",
    # session
    "DeviceInfo",
    "DeviceMismatch",
    "Handshake",
    "OutcomeUnknown",
    "ProvisionOpts",
    "ProvisionResult",
    "SessionCancelled",
    "SessionIO",
    "Timeouts",
    "UnsupportedProto",
    "default_timeouts",
    "identify",
    "run_provision",
    # lease
    "DEFAULT_LEASE_MAX_TTL",
    "DEFAULT_LEASE_MIN_TTL",
    "LeaseBusy",
    "LeaseManager",
    "LeaseUnknown",
    "NopController",
    "SerialController",
    "random_lease_id",
    # lease client
    "DEFAULT_LEASE_TTL",
    "LeaseClient",
    "LeasedPort",
]
