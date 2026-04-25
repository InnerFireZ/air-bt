"""
air-bt — Pre-built payload library
Known payloads for common BLE device types (LED strips, smart plugs, sensors, etc).
Each entry: name, target protocol/device, UUID, payload bytes, description.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

from dataclasses import dataclass


@dataclass
class Payload:
    name: str
    protocol: str
    target_uuid: str
    data: bytes
    description: str
    requires_response: bool = False


PAYLOAD_LIBRARY: list[Payload] = [

    # ── ELK-BLEDOM / Chinese BLE LED Strips ──────────────────────────────────
    # Protocol: 7e 00 <cmd> <p1> <p2> <p3> <p4> <p5> ef
    # Write to char FFF3 (primary) or FFE9 (alt variant) — NO AUTH REQUIRED
    Payload(
        name="ELK-BLEDOM Power ON",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e0004f00001ff00ef"),
        description="Turn ELK-BLEDOM LED strip ON",
    ),
    Payload(
        name="ELK-BLEDOM Power OFF",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e0004f00000ff00ef"),
        description="Turn ELK-BLEDOM LED strip OFF",
    ),
    Payload(
        name="ELK-BLEDOM Set Red",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000503ff00000000ef"),
        description="Set ELK-BLEDOM to full red",
    ),
    Payload(
        name="ELK-BLEDOM Set Green",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e00050300ff000000ef"),
        description="Set ELK-BLEDOM to full green",
    ),
    Payload(
        name="ELK-BLEDOM Set Blue",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e0005030000ff0000ef"),
        description="Set ELK-BLEDOM to full blue",
    ),
    Payload(
        name="ELK-BLEDOM Set White",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000503ffffff0000ef"),
        description="Set ELK-BLEDOM to full white",
    ),
    Payload(
        name="ELK-BLEDOM Brightness 100%",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000101640000000001ef"),
        description="Set ELK-BLEDOM brightness to 100%",
    ),
    Payload(
        name="ELK-BLEDOM Brightness 50%",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000101320000000001ef"),
        description="Set ELK-BLEDOM brightness to 50%",
    ),
    Payload(
        name="ELK-BLEDOM Brightness 0%",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000101000000000001ef"),
        description="Set ELK-BLEDOM brightness to 0% (dim off)",
    ),
    Payload(
        name="ELK-BLEDOM Flash Mode",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000302250000000001ef"),
        description="Set ELK-BLEDOM to flash effect (mode 0x25, speed medium)",
    ),
    Payload(
        name="ELK-BLEDOM Strobe Mode",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000302280000000001ef"),
        description="Set ELK-BLEDOM to strobe effect (mode 0x28)",
    ),
    Payload(
        name="ELK-BLEDOM Rainbow Cycle",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000302870000000001ef"),
        description="Set ELK-BLEDOM to rainbow cycle effect",
    ),
    Payload(
        name="ELK-BLEDOM Color Fade",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000302380000000001ef"),
        description="Set ELK-BLEDOM to smooth color fade effect",
    ),
    Payload(
        name="ELK-BLEDOM Request State",
        protocol="ELK-BLEDOM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("ef0177"),
        description="Request current state/color from ELK-BLEDOM (response on FFF4)",
        requires_response=True,
    ),
    # Alt variant (uses FFE9 write char instead of FFF3)
    Payload(
        name="ELK-BLEDOM Alt Power ON",
        protocol="ELK-BLEDOM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e0004f00001ff00ef"),
        description="Turn ELK-BLEDOM alt variant ON (FFE9 write char)",
    ),
    Payload(
        name="ELK-BLEDOM Alt Power OFF",
        protocol="ELK-BLEDOM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e0004f00000ff00ef"),
        description="Turn ELK-BLEDOM alt variant OFF (FFE9 write char)",
    ),
    Payload(
        name="ELK-BLEDOM Alt Set Red",
        protocol="ELK-BLEDOM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("7e000503ff00000000ef"),
        description="Set ELK-BLEDOM alt variant to full red",
    ),

    # ── Govee Smart Bulbs / Strips ────────────────────────────────────────────
    Payload(
        name="Govee Power ON",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("3301010000000000000000000000000033"),
        description="Turn Govee light ON",
    ),
    Payload(
        name="Govee Power OFF",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("3301000000000000000000000000000033"),
        description="Turn Govee light OFF",
    ),
    Payload(
        name="Govee Set Red",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("33050dff00000000000000000000000000cb"),
        description="Set Govee light to full red",
    ),
    Payload(
        name="Govee Set Green",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("33050d00ff000000000000000000000000cb"),
        description="Set Govee light to full green",
    ),
    Payload(
        name="Govee Set Blue",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("33050d0000ff00000000000000000000cb"),
        description="Set Govee light to full blue",
    ),
    Payload(
        name="Govee Set White Max",
        protocol="Govee",
        target_uuid="00010203-0405-0607-0809-0a0b0c0d2b11",
        data=bytes.fromhex("33040164000000000000000000000000cb"),
        description="Set Govee light to max white brightness",
    ),

    # ── Tuya BLE Generic (smart plugs, lights, relays) ────────────────────────
    Payload(
        name="Tuya Query Device",
        protocol="Tuya BLE",
        target_uuid="00002b10-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("55aa000100000001"),
        description="Query Tuya BLE device status",
    ),

    # ── Nordic UART (generic Chinese IoT) ─────────────────────────────────────
    Payload(
        name="UART Hello",
        protocol="Nordic UART",
        target_uuid="6e400002-b5a3-f393-e0a9-e50e24dcca9e",
        data=b"AT\r\n",
        description="Send AT command probe to UART-bridged device",
    ),
    Payload(
        name="UART Version Query",
        protocol="Nordic UART",
        target_uuid="6e400002-b5a3-f393-e0a9-e50e24dcca9e",
        data=b"AT+VERSION\r\n",
        description="Query firmware version via Nordic UART bridge",
    ),
    Payload(
        name="UART Info Query",
        protocol="Nordic UART",
        target_uuid="6e400002-b5a3-f393-e0a9-e50e24dcca9e",
        data=b"AT+INFO\r\n",
        description="Query device info via Nordic UART bridge",
    ),

    # ── Generic fitness band / ID115 clones ───────────────────────────────────
    Payload(
        name="Generic Band Sync Time",
        protocol="Generic Chinese OEM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("01"),
        description="Trigger time sync on generic fitness band",
    ),
    Payload(
        name="Generic Band Steps Query",
        protocol="Generic Chinese OEM",
        target_uuid="0000fff3-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("07"),
        description="Query step count on generic fitness band",
    ),

    # ── BLE Lock / Door Sensors ───────────────────────────────────────────────
    Payload(
        name="Generic Lock Open Probe",
        protocol="Generic Chinese OEM",
        target_uuid="0000fff1-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("a001"),
        description="Probe lock open command (generic pattern)",
    ),

    # ── Smart Relay / Switch ──────────────────────────────────────────────────
    Payload(
        name="Generic Relay ON",
        protocol="Generic Chinese OEM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("cc0103330033"),
        description="Turn on generic BLE relay module",
    ),
    Payload(
        name="Generic Relay OFF",
        protocol="Generic Chinese OEM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("cc0104330034"),
        description="Turn off generic BLE relay module",
    ),
    Payload(
        name="Generic Relay Status",
        protocol="Generic Chinese OEM",
        target_uuid="0000ffe9-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("cc0101330031"),
        description="Query status of generic BLE relay module",
    ),

    # ── Xiaomi / Mi scale / sensors ───────────────────────────────────────────
    Payload(
        name="Xiaomi Start Measure",
        protocol="MiBeacon",
        target_uuid="0000fec7-0000-1000-8000-00805f9b34fb",
        data=bytes.fromhex("0100"),
        description="Trigger measurement on Xiaomi sensor device",
    ),

    # ── OTA / DFU probes ──────────────────────────────────────────────────────
    Payload(
        name="Nordic DFU Enter Bootloader",
        protocol="Nordic DFU",
        target_uuid="00001531-1212-efde-1523-785feabcd123",
        data=bytes.fromhex("01"),
        description="Attempt to enter Nordic DFU bootloader mode (requires auth on most devices)",
        requires_response=True,
    ),
]


def elk_bledom_rgb(r: int, g: int, b: int, alt_char: bool = False) -> Payload:
    """Build a custom ELK-BLEDOM RGB color payload."""
    r, g, b = max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b))
    data = bytes([0x7e, 0x00, 0x05, 0x03, r, g, b, 0x00, 0x00, 0xef])
    uuid = "0000ffe9-0000-1000-8000-00805f9b34fb" if alt_char else "0000fff3-0000-1000-8000-00805f9b34fb"
    return Payload(
        name=f"ELK-BLEDOM RGB({r},{g},{b})",
        protocol="ELK-BLEDOM",
        target_uuid=uuid,
        data=data,
        description=f"Set ELK-BLEDOM LED strip to RGB({r},{g},{b})",
    )


def elk_bledom_brightness(pct: int, alt_char: bool = False) -> Payload:
    """Build a custom ELK-BLEDOM brightness payload. pct = 0-100."""
    val = max(0, min(100, pct))
    data = bytes([0x7e, 0x00, 0x01, 0x01, val, 0x00, 0x00, 0x00, 0x00, 0x01, 0xef])
    uuid = "0000ffe9-0000-1000-8000-00805f9b34fb" if alt_char else "0000fff3-0000-1000-8000-00805f9b34fb"
    return Payload(
        name=f"ELK-BLEDOM Brightness {pct}%",
        protocol="ELK-BLEDOM",
        target_uuid=uuid,
        data=data,
        description=f"Set ELK-BLEDOM brightness to {pct}%",
    )


def get_payloads_for_protocol(protocol: str) -> list[Payload]:
    """Return all payloads matching a protocol name."""
    return [p for p in PAYLOAD_LIBRARY if p.protocol.lower() == protocol.lower()
            or p.protocol == "Generic Chinese OEM"]


def get_payload_by_name(name: str) -> Payload | None:
    """Return a specific payload by name."""
    for p in PAYLOAD_LIBRARY:
        if p.name.lower() == name.lower():
            return p
    return None
