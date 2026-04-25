"""
air-bt — BLE Scanner
Async BLE advertisement scanning via bleak.
Handles advertisement parsing, RSSI filtering, device registry, and passive CVE matching.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import asyncio
import logging
from datetime import datetime

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from models import BTDevice
from data.oui import lookup_vendor
from data.protocols import detect_protocol, is_chinese_device
from data.uuids import resolve_uuid, get_capabilities_from_uuids
from data.cve import match_vulns

log = logging.getLogger("air-bt.ble")


class BLEScanner:
    def __init__(self, rssi_threshold: int = -80, adapter: str = "hci0"):
        self.rssi_threshold = rssi_threshold
        self.adapter = adapter
        self.devices: dict[str, BTDevice] = {}   # MAC → BTDevice
        self._scanner: BleakScanner | None = None
        self._running = False
        self._lock = asyncio.Lock()

    def _on_advertisement(self, device: BLEDevice, adv: AdvertisementData):
        """Callback invoked for every BLE advertisement received."""
        rssi = adv.rssi if adv.rssi is not None else -999
        if rssi < self.rssi_threshold:
            return

        mac = device.address.upper()
        name = device.name or adv.local_name or "Unknown"

        # Parse advertisement data
        manufacturer_data = dict(adv.manufacturer_data)
        service_data = {str(k): v for k, v in adv.service_data.items()}
        adv_uuids = [str(u) for u in (adv.service_uuids or [])]

        vendor = lookup_vendor(mac)
        protocol = detect_protocol(manufacturer_data, service_data, adv_uuids, name)
        chinese = is_chinese_device(protocol, vendor, manufacturer_data)

        all_uuids = adv_uuids + list(service_data.keys())
        capabilities = get_capabilities_from_uuids(all_uuids)

        # TX power from adv data
        tx_power = adv.tx_power

        if mac in self.devices:
            dev = self.devices[mac]
            dev.touch(rssi)
            # Update mutable fields that can change between advertisements
            if name != "Unknown":
                dev.name = name
            dev.tx_power = tx_power or dev.tx_power
            for u in adv_uuids:
                if u not in dev.adv_uuids:
                    dev.adv_uuids.append(u)
            dev.manufacturer_data.update(manufacturer_data)
            dev.service_data.update(service_data)
            if capabilities:
                for c in capabilities:
                    if c not in dev.capabilities:
                        dev.capabilities.append(c)
        else:
            dev = BTDevice(
                mac=mac,
                rssi=rssi,
                name=name,
                vendor=vendor,
                device_type="BLE",
                protocol=protocol,
                tx_power=tx_power,
                manufacturer_data=manufacturer_data,
                service_data=service_data,
                adv_uuids=adv_uuids,
                capabilities=capabilities,
            )
            # Chinese device flag
            if chinese:
                if "Chinese OEM" not in dev.sec_flags:
                    dev.sec_flags.append("Chinese OEM")

            # Initial CVE matching from advertisement data
            vulns = match_vulns(name, adv_uuids, dev.device_type)
            if vulns:
                dev.known_vuln = vulns[0].cve_id
                dev.known_vuln_type = vulns[0].vuln_type
                dev.vuln_count = len(vulns)
                dev.matched_vulns = vulns
                dev.sec_flags.append("KNOWN_VULN")

            self._compute_sec_score(dev)
            self.devices[mac] = dev
            log.debug(f"New device: {mac} ({name}) RSSI={rssi} Protocol={protocol}")

    def _compute_sec_score(self, dev: BTDevice):
        """Assign A–F security score based on findings."""
        score = 100
        if "OPEN_WRITE" in dev.sec_flags:
            score -= 35
        if "OPEN_READ" in dev.sec_flags:
            score -= 15
        if "NO_BONDING" in dev.sec_flags:
            score -= 20
        if "NOTIFY_UNAUTH" in dev.sec_flags:
            score -= 10
        if "KNOWN_VULN" in dev.sec_flags:
            score -= 25
        if "WEAK_PAIRING" in dev.sec_flags:
            score -= 15

        if score >= 90:
            dev.sec_score = "A"
        elif score >= 75:
            dev.sec_score = "B"
        elif score >= 55:
            dev.sec_score = "C"
        elif score >= 35:
            dev.sec_score = "D"
        else:
            dev.sec_score = "F"

    async def start(self):
        """Start BLE scanning."""
        self._running = True
        self._scanner = BleakScanner(
            detection_callback=self._on_advertisement,
            bluez={"adapter": self.adapter},
        )
        await self._scanner.start()
        log.info(f"BLE scanner started on {self.adapter} (RSSI >= {self.rssi_threshold})")

    async def pause(self):
        """Stop scanning temporarily so a connection can be made (BlueZ limitation)."""
        if self._scanner:
            try:
                await self._scanner.stop()
            except Exception:
                pass

    async def resume(self):
        """Restart scanning after a connection attempt."""
        if not self._running:
            return
        try:
            self._scanner = BleakScanner(
                detection_callback=self._on_advertisement,
                bluez={"adapter": self.adapter},
            )
            await self._scanner.start()
        except Exception as e:
            log.warning(f"Scanner resume failed: {e}")

    async def stop(self):
        """Stop BLE scanning."""
        self._running = False
        if self._scanner:
            await self._scanner.stop()
        log.info("BLE scanner stopped")

    def get_devices(self) -> list[BTDevice]:
        """Return current device list sorted by RSSI descending."""
        return sorted(self.devices.values(), key=lambda d: d.rssi, reverse=True)

    def get_device(self, mac: str) -> BTDevice | None:
        return self.devices.get(mac.upper())
