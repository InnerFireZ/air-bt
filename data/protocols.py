"""
air-bt — Protocol detection
Identifies BLE protocols from advertisement data:
MiBeacon, Tuya, iBeacon, Eddystone, Apple Nearby, Google Fast Pair,
Nordic UART, ELK-BLEDOM, Govee, Generic Chinese OEM and more.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import struct


def detect_protocol(
    manufacturer_data: dict,
    service_data: dict,
    service_uuids: list[str],
    device_name: str,
) -> str:
    """
    Returns the most likely protocol/platform name for a BLE advertisement.
    """
    uuids_lower = [u.lower() for u in service_uuids]
    name_lower = (device_name or "").lower()

    # --- Xiaomi MiBeacon ---
    # Company ID 0x05AC or service UUID fe95
    if 0x05AC in manufacturer_data or "0000fe95-0000-1000-8000-00805f9b34fb" in uuids_lower:
        return "MiBeacon"

    # --- Apple (iBeacon / AirDrop / FindMy / AirTag) ---
    if 0x004C in manufacturer_data:
        payload = manufacturer_data[0x004C]
        if len(payload) >= 2:
            subtype = payload[0]
            if subtype == 0x02:
                return "iBeacon"
            elif subtype == 0x05:
                return "AirDrop"
            elif subtype == 0x07:
                return "AirPods"
            elif subtype == 0x0F:
                return "FindMy"
            elif subtype == 0x10:
                return "Apple Nearby"
        return "Apple"

    # --- Google Eddystone ---
    if "0000feaa-0000-1000-8000-00805f9b34fb" in uuids_lower:
        if "0000feaa-0000-1000-8000-00805f9b34fb" in service_data:
            frame = service_data["0000feaa-0000-1000-8000-00805f9b34fb"]
            if frame and frame[0] == 0x00:
                return "Eddystone-UID"
            elif frame and frame[0] == 0x10:
                return "Eddystone-URL"
            elif frame and frame[0] == 0x20:
                return "Eddystone-TLM"
        return "Eddystone"

    # --- Google Fast Pair ---
    if "0000fe2c-0000-1000-8000-00805f9b34fb" in uuids_lower:
        return "Google Fast Pair"

    # --- Google Nearby Share ---
    if "0000fea0-0000-1000-8000-00805f9b34fb" in uuids_lower:
        return "Google Nearby"

    # --- Samsung SmartThings ---
    if 0x0075 in manufacturer_data or "0000fd5a-0000-1000-8000-00805f9b34fb" in uuids_lower:
        return "Samsung SmartThings"

    # --- Tuya BLE ---
    if "00001910-0000-1000-8000-00805f9b34fb" in uuids_lower:
        return "Tuya BLE"

    # --- Nordic UART (very common on Chinese IoT) ---
    if "6e400001-b5a3-f393-e0a9-e50e24dcca9e" in uuids_lower:
        return "Nordic UART"

    # --- Nordic DFU ---
    if "00001530-1212-efde-1523-785feabcd123" in uuids_lower:
        return "Nordic DFU"

    # --- Govee ---
    if "00010203-0405-0607-0809-0a0b0c0d1910" in uuids_lower:
        return "Govee"

    # --- Microchip UART ---
    if "49535343-fe7d-4ae5-8fa9-9fafd205e455" in uuids_lower:
        return "Microchip UART"

    # --- Fitbit ---
    if "adabfb00-6e7d-4601-bda2-bffaa68956ba" in uuids_lower:
        return "Fitbit"

    # --- Microsoft Swift Pair ---
    if 0x0006 in manufacturer_data:
        payload = manufacturer_data[0x0006]
        if payload and payload[0] == 0x03:
            return "MS Swift Pair"

    # --- Generic Chinese OEM heuristics ---
    if any(k in [0xFFFF, 0xFFF0, 0xFF00] for k in manufacturer_data):
        return "Generic Chinese OEM"

    # --- ELK-BLEDOM / Chinese BLE LED strips (no-auth RGB control) ---
    # Service UUID FFF0 + write char FFF3 is the standard ELK-BLEDOM fingerprint
    if any(u in uuids_lower for u in [
        "0000fff0-0000-1000-8000-00805f9b34fb",
        "0000ffe5-0000-1000-8000-00805f9b34fb",
    ]):
        return "ELK-BLEDOM"
    if any(kw in name_lower for kw in [
        "elk-bledom", "elk-bulb", "elk-lamp", "elkblue", "melk",
        "ledble", "lednet", "led_ble", "ledstrip", "qhm-led",
        "triones", "magic home", "ilinker", "zj-", "btle-led",
        "ble-led", "iled", "ilis", "smlight", "sovvid",
    ]):
        return "ELK-BLEDOM"

    # Name-based fallbacks
    if any(kw in name_lower for kw in ["mi ", "xiaomi", "redmi"]):
        return "Xiaomi"
    if any(kw in name_lower for kw in ["huawei", "honor"]):
        return "Huawei"
    if any(kw in name_lower for kw in ["tuya", "smart life"]):
        return "Tuya BLE"
    if any(kw in name_lower for kw in ["govee", "gvh"]):
        return "Govee"

    return "Unknown"


def is_chinese_device(protocol: str, vendor: str, manufacturer_data: dict) -> bool:
    """Heuristic: is this likely a Chinese-made device?"""
    chinese_protocols = {"MiBeacon", "Tuya BLE", "Govee", "Generic Chinese OEM",
                         "Xiaomi", "Huawei", "ELK-BLEDOM"}
    chinese_vendors = {"Xiaomi", "Huawei", "Tuya Smart", "Espressif", "OPPO/Realme", "OnePlus"}

    if protocol in chinese_protocols:
        return True
    if vendor in chinese_vendors:
        return True
    if any(k in [0xFFFF, 0xFFF0, 0xFF00, 0x05AC] for k in manufacturer_data):
        return True
    return False
