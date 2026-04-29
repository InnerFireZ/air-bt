"""
air-bt — GATT Enumerator
Connects to a BLE device WITHOUT pairing and dumps:
  - Services, Characteristics, Descriptors
  - Properties (READ/WRITE/NOTIFY/etc.)
  - Unauthenticated reads on all readable chars
  - Flags writable, readable, notifiable chars that require no auth
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import asyncio
import logging
import struct
from bleak import BleakClient, BleakError
from bleak.exc import BleakDeviceNotFoundError
from bleak.backends.characteristic import BleakGATTCharacteristic

from models import BTDevice, GATTService, GATTCharacteristic
from scanner.ble import get_cached_ble_device, clear_cached_ble_device, is_random_mac, hci_get_classic_name


def _bleak_target(dev: BTDevice):
    """Prefer the cached BLEDevice object over raw MAC string.

    BleakClient accepts either a MAC string or a BLEDevice.  Using the BLEDevice
    avoids a BlueZ cache lookup by MAC and survives scanner.pause() gaps as long
    as the device hasn't rotated its address since the last advertisement.
    """
    return get_cached_ble_device(dev.mac) or dev.mac
from data.uuids import resolve_uuid, get_capabilities_from_uuids
from data.cve import match_vulns
from data.protocols import detect_protocol

log = logging.getLogger("air-bt.gatt")

# Timeout per connection attempt
CONNECT_TIMEOUT = 10.0
# Timeout per read attempt
READ_TIMEOUT = 2.0


async def enumerate_gatt(dev: BTDevice, timeout: float = CONNECT_TIMEOUT) -> bool:
    """
    Connect to device without bonding, enumerate GATT, attempt reads.
    Updates dev in-place. Returns True on success.
    """
    log.info(f"GATT probe: {dev.mac} ({dev.name})")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                log.warning(f"Could not connect to {dev.mac}")
                return False

            dev.services.clear()

            for svc in client.services:
                svc_uuid = str(svc.uuid)
                svc_name, _ = resolve_uuid(svc_uuid)
                gatt_svc = GATTService(uuid=svc_uuid, name=svc_name)

                for char in svc.characteristics:
                    char_uuid = str(char.uuid)
                    char_name, _ = resolve_uuid(char_uuid)
                    props = list(char.properties)

                    gatt_char = GATTCharacteristic(
                        uuid=char_uuid,
                        handle=char.handle,
                        properties=props,
                        description=char_name,
                    )

                    # Probe write capability without auth — mirrors the read probe above.
                    # A single zero byte is written; auth errors → not open, anything
                    # else (success or non-auth failure) → flag as open.
                    if "write" in props or "write-without-response" in props:
                        try:
                            no_resp = "write-without-response" in props
                            await asyncio.wait_for(
                                client.write_gatt_char(char.handle, bytes([0x00]),
                                                       response=not no_resp),
                                timeout=READ_TIMEOUT,
                            )
                            gatt_char.writable_without_auth = True
                        except asyncio.TimeoutError:
                            log.debug(f"Write timeout: {char_uuid}")
                        except BleakError as e:
                            err = str(e).lower()
                            if "authentication" in err or "encrypt" in err or \
                                    "insufficient" in err or "not permitted" in err:
                                log.debug(f"Auth required for write: {char_uuid}")
                            else:
                                gatt_char.writable_without_auth = True
                                log.debug(f"Write error (non-auth) {char_uuid}: {e}")
                        except Exception as e:
                            log.debug(f"Unexpected write error {char_uuid}: {e}")

                    # Attempt unauthenticated read
                    if "read" in props:
                        try:
                            value = await asyncio.wait_for(
                                client.read_gatt_char(char.handle),
                                timeout=READ_TIMEOUT,
                            )
                            gatt_char.value = bytes(value)
                            gatt_char.readable_without_auth = True
                        except asyncio.TimeoutError:
                            log.debug(f"Read timeout: {char_uuid}")
                        except BleakError as e:
                            err = str(e).lower()
                            if "authentication" in err or "encrypt" in err or "insufficient" in err:
                                gatt_char.readable_without_auth = False
                                log.debug(f"Auth required for read: {char_uuid}")
                            else:
                                log.debug(f"Read error {char_uuid}: {e}")
                        except Exception as e:
                            log.debug(f"Unexpected read error {char_uuid}: {e}")

                    # Detect unauthenticated notify
                    if "notify" in props or "indicate" in props:
                        gatt_char.notifiable_without_auth = True

                    gatt_svc.characteristics.append(gatt_char)

                dev.services.append(gatt_svc)

            dev.gatt_enumerated = True

            # Opportunistically read key info chars while still connected
            _INFO_UUIDS = {
                "00002a19-0000-1000-8000-00805f9b34fb": "battery",
                "00002a6e-0000-1000-8000-00805f9b34fb": "temperature",
                "00002a29-0000-1000-8000-00805f9b34fb": "manufacturer_name",
                "00002a24-0000-1000-8000-00805f9b34fb": "model_number",
                "00002a26-0000-1000-8000-00805f9b34fb": "firmware",
            }
            for uuid, field_name in _INFO_UUIDS.items():
                char = next((c for c in dev.all_characteristics()
                             if c.uuid.lower() == uuid and c.readable_without_auth), None)
                if char is None:
                    continue
                try:
                    raw = await asyncio.wait_for(client.read_gatt_char(char.handle), timeout=3.0)
                    raw = bytes(raw)
                    if field_name == "battery" and raw:
                        dev.battery = raw[0]
                    elif field_name == "temperature" and len(raw) >= 2:
                        dev.temperature = round(struct.unpack_from("<h", raw)[0] / 100.0, 1)
                    elif field_name in ("manufacturer_name", "model_number", "firmware"):
                        try:
                            setattr(dev, field_name, raw.decode("utf-8").strip().rstrip("\x00"))
                        except Exception:
                            setattr(dev, field_name, raw.hex())
                except Exception:
                    pass

            # Try to read the GAP Device Name characteristic (0x2A00) directly by UUID.
            #
            # Many devices don't properly advertise their Generic Access service (0x1800)
            # so the char never appears in dev.all_characteristics() and the loop above
            # misses it.  Reading by UUID string bypasses service-discovery gaps.
            #
            # On iOS the char is auth-gated so this silently fails — the full iPhone
            # owner name ("John's iPhone") can only be retrieved via Bluetooth Classic
            # HCI name resolution (see hci_get_classic_name), not BLE GATT.
            _GAP_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
            _name_is_generic = dev.name in ("Unknown", "iPhone", "Android", "")
            try:
                raw_name = await asyncio.wait_for(
                    client.read_gatt_char(_GAP_DEVICE_NAME), timeout=3.0
                )
                gatt_name = bytes(raw_name).decode("utf-8", errors="replace").strip().rstrip("\x00")
                if gatt_name and len(gatt_name) > len(dev.name):
                    log.info(f"Device name from 0x2A00: {dev.mac} → {gatt_name!r}")
                    dev.name = gatt_name
            except Exception:
                # Auth-gated, not found, or device doesn't support it — silently skip.
                pass

            # Recount open access stats
            dev.open_writes = sum(1 for c in dev.all_characteristics() if c.writable_without_auth)
            dev.open_reads = sum(1 for c in dev.all_characteristics() if c.readable_without_auth)
            dev.notifiable = sum(1 for c in dev.all_characteristics() if c.notifiable_without_auth)

            # Update security flags
            if dev.open_writes > 0 and "OPEN_WRITE" not in dev.sec_flags:
                dev.sec_flags.append("OPEN_WRITE")
            if dev.open_reads > 0 and "OPEN_READ" not in dev.sec_flags:
                dev.sec_flags.append("OPEN_READ")
            if dev.notifiable > 0 and "NOTIFY_UNAUTH" not in dev.sec_flags:
                dev.sec_flags.append("NOTIFY_UNAUTH")

            # NO_BONDING: device allowed at least one read or write without pairing.
            # A bare connection with pair=False only means the device accepted
            # the link; we only flag it if actual GATT access succeeded unauthenticated.
            if (dev.open_reads > 0 or dev.open_writes > 0) and "NO_BONDING" not in dev.sec_flags:
                dev.sec_flags.append("NO_BONDING")

            # Re-detect protocol from real GATT services (many devices hide UUIDs until connected)
            all_svc_uuids = [str(s.uuid) for s in dev.services]
            all_char_uuids = [str(c.uuid) for c in dev.all_characteristics()]
            all_uuids = all_svc_uuids + all_char_uuids

            if dev.protocol == "Unknown":
                new_protocol = detect_protocol({}, {}, all_svc_uuids, dev.name)
                if new_protocol != "Unknown":
                    dev.protocol = new_protocol
                    log.info(f"Protocol updated after GATT: {dev.mac} → {new_protocol}")

            # Update capabilities from real services
            new_caps = get_capabilities_from_uuids(all_uuids)
            for c in new_caps:
                if c not in dev.capabilities:
                    dev.capabilities.append(c)

            # active_probe=True unlocks BLESA and other probe-only CVEs
            vulns = match_vulns(dev.name, all_uuids, dev.device_type, active_probe=True)
            if vulns:
                dev.known_vuln = vulns[0].short_name or vulns[0].cve_id
                dev.known_vuln_type = vulns[0].vuln_type
                dev.vuln_count = len(vulns)
                dev.matched_vulns = vulns
                if "KNOWN_VULN" not in dev.sec_flags:
                    dev.sec_flags.append("KNOWN_VULN")

            log.info(
                f"GATT done: {dev.mac} | "
                f"services={len(dev.services)} "
                f"open_writes={dev.open_writes} "
                f"open_reads={dev.open_reads} "
                f"notifiable={dev.notifiable}"
            )

        # After disconnecting, attempt Bluetooth Classic HCI name resolution for
        # devices still showing a generic name.  Classic BT name request works
        # WITHOUT pairing on dual-mode devices (phones, laptops, speakers) and
        # returns the full user-visible name ("John's iPhone") — unlike BLE GATT
        # which is auth-gated on iOS/Android.
        #
        # Limitation: iPhones use a DIFFERENT MAC for Classic BT than their
        # rotating BLE random address, so this lookup only resolves names for
        # devices with public/static MACs (non-random).
        if dev.name in ("Unknown", "iPhone", "Android", "") and not is_random_mac(dev.mac):
            classic_name = await asyncio.get_event_loop().run_in_executor(
                None, hci_get_classic_name, dev.mac
            )
            if classic_name:
                log.info(f"Classic BT name resolved: {dev.mac} → {classic_name!r}")
                dev.name = classic_name

        return True

    except asyncio.TimeoutError:
        log.warning(f"Connection timeout: {dev.mac}")
    except BleakError as e:
        _is_not_found = (
            isinstance(e, BleakDeviceNotFoundError)
            or "not found" in str(e).lower()
        )
        if _is_not_found:
            clear_cached_ble_device(dev.mac)
            if is_random_mac(dev.mac):
                log.warning(
                    f"Device not found: {dev.mac} — random/private MAC may have rotated "
                    f"(iOS/Android RPA). Rescan to re-discover."
                )
            else:
                log.warning(
                    f"Device not found: {dev.mac} — out of range or BlueZ cache expired. "
                    f"Rescan to re-discover."
                )
        else:
            log.warning(f"BleakError {dev.mac}: {e}")
    except Exception as e:
        log.warning(f"Unexpected error {dev.mac}: {e}")

    return False


async def subscribe_notifications(
    dev: BTDevice,
    on_data,
    duration: float = 30.0,
    timeout: float = CONNECT_TIMEOUT,
):
    """
    Subscribe to all notifiable characteristics and stream data.
    on_data(mac, char_uuid, data: bytes) is called for each notification.
    """
    notifiable_chars = [c for c in dev.all_characteristics() if c.notifiable_without_auth]
    if not notifiable_chars:
        log.info(f"No notifiable characteristics on {dev.mac}")
        return

    log.info(f"Subscribing to {len(notifiable_chars)} chars on {dev.mac}")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                return

            def make_handler(uuid):
                def handler(_, data):
                    on_data(dev.mac, uuid, bytes(data))
                return handler

            for char in notifiable_chars:
                try:
                    await client.start_notify(char.handle, make_handler(char.uuid))
                except Exception as e:
                    log.debug(f"Subscribe error {char.uuid}: {e}")

            await asyncio.sleep(duration)

            for char in notifiable_chars:
                try:
                    await client.stop_notify(char.handle)
                except Exception:
                    pass

    except BleakError as e:
        _is_not_found = (
            isinstance(e, BleakDeviceNotFoundError)
            or "not found" in str(e).lower()
        )
        if _is_not_found:
            clear_cached_ble_device(dev.mac)
            hint = ("random/private MAC may have rotated (RPA)"
                    if is_random_mac(dev.mac)
                    else "out of range or BlueZ cache expired")
            log.warning(f"Notification stream {dev.mac}: device not found — {hint}. Rescan.")
        else:
            log.warning(f"Notification stream error {dev.mac}: {e}")
    except Exception as e:
        log.warning(f"Notification stream error {dev.mac}: {e}")
