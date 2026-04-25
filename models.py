# air-bt — Data models
# Created by InnerFireZ — https://github.com/InnerFireZ/air-bt

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class GATTCharacteristic:
    uuid: str
    handle: int
    properties: list[str]          # READ, WRITE, WRITE_NO_RESPONSE, NOTIFY, INDICATE, etc.
    description: str = "Unknown"
    value: Optional[bytes] = None   # last read value
    writable_without_auth: bool = False
    readable_without_auth: bool = False
    notifiable_without_auth: bool = False
    write_responses: list[str] = field(default_factory=list)


@dataclass
class GATTService:
    uuid: str
    name: str = "Unknown Service"
    characteristics: list[GATTCharacteristic] = field(default_factory=list)


@dataclass
class BTDevice:
    mac: str
    rssi: int
    name: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "BLE"           # BLE / Classic / Dual
    protocol: str = "Unknown"          # MiBeacon, Tuya, iBeacon, UART, etc.

    # Advertisement data
    tx_power: Optional[int] = None
    adv_flags: Optional[int] = None
    manufacturer_data: dict = field(default_factory=dict)
    service_data: dict = field(default_factory=dict)
    adv_uuids: list[str] = field(default_factory=list)

    # GATT enumeration results
    services: list[GATTService] = field(default_factory=list)
    gatt_enumerated: bool = False

    # Security findings
    open_writes: int = 0
    open_reads: int = 0
    notifiable: int = 0
    sec_flags: list[str] = field(default_factory=list)   # OPEN_WRITE, NO_BONDING, etc.
    sec_score: str = "?"                                  # A / B / C / D / F
    known_vuln: Optional[str] = None                     # CVE or advisory ID (most severe)
    known_vuln_type: Optional[str] = None               # RCE/DoS/AuthBypass/etc.
    vuln_count: int = 0                                  # total matched CVEs
    matched_vulns: list = field(default_factory=list)   # full BLEVuln list

    # Capabilities inferred from UUIDs
    capabilities: list[str] = field(default_factory=list)

    # Live sensor data (populated during PoC/probe)
    battery: Optional[int] = None          # 0-100 %
    temperature: Optional[float] = None    # °C
    heart_rate: Optional[int] = None       # bpm
    firmware: Optional[str] = None
    manufacturer_name: Optional[str] = None
    model_number: Optional[str] = None

    # Tracking
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    seen_count: int = 1

    def touch(self, rssi: int):
        self.rssi = rssi
        self.last_seen = datetime.now()
        self.seen_count += 1

    def all_characteristics(self) -> list[GATTCharacteristic]:
        chars = []
        for svc in self.services:
            chars.extend(svc.characteristics)
        return chars

    def open_write_chars(self) -> list[GATTCharacteristic]:
        return [c for c in self.all_characteristics() if c.writable_without_auth]

    def open_read_chars(self) -> list[GATTCharacteristic]:
        return [c for c in self.all_characteristics() if c.readable_without_auth]
