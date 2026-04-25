#!/usr/bin/env python3
"""
air-bt — Debug / diagnostic script
Run this to diagnose BLE adapter or connection issues.
Usage: sudo .venv_bt/bin/python3 debug.py [MAC]
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import asyncio
import sys

async def test_scan():
    from bleak import BleakScanner
    print("[1] Starting BLE scan for 5 seconds...")
    found = []

    def cb(device, adv):
        rssi = adv.rssi or -999
        if rssi < -80:
            return
        entry = f"  {device.address}  RSSI={rssi:4}  name={device.name or '?':20}  uuids={list(adv.service_uuids)[:2]}"
        if entry not in found:
            found.append(entry)
            print(entry)

    scanner = BleakScanner(detection_callback=cb, bluez={"adapter": "hci0"})
    await scanner.start()
    await asyncio.sleep(5)
    await scanner.stop()
    print(f"[1] Scan done. {len(found)} devices above -80 dBm\n")
    return found

async def test_connect(mac: str):
    from bleak import BleakClient
    print(f"[2] Connecting to {mac} (pair=False)...")
    try:
        async with BleakClient(mac, timeout=15.0, pair=False) as client:
            print(f"    connected={client.is_connected}")
            print(f"    services ({len(list(client.services))}):")
            for svc in client.services:
                print(f"      SVC {svc.uuid}")
                for char in svc.characteristics:
                    print(f"        CHAR {char.uuid}  props={char.properties}")
    except Exception as e:
        print(f"    ERROR: {e}")
    print()

async def test_elk_write(mac: str):
    from bleak import BleakClient
    ELK_UUIDS = [
        "0000fff3-0000-1000-8000-00805f9b34fb",
        "0000ffe9-0000-1000-8000-00805f9b34fb",
        "0000ffb2-0000-1000-8000-00805f9b34fb",
    ]
    POWER_ON     = bytes.fromhex("7e0004f00001ff00ef")
    RED          = bytes.fromhex("7e000503ff00000000ef")
    GREEN        = bytes.fromhex("7e00050300ff000000ef")
    BLUE         = bytes.fromhex("7e0005030000ff0000ef")
    RAINBOW_AUTO = bytes.fromhex("7e000302870000000001ef")

    print(f"[3] ELK-BLEDOM write test on {mac}...")
    try:
        async with BleakClient(mac, timeout=15.0, pair=False) as client:
            if not client.is_connected:
                print("    Not connected")
                return

            # Find working write UUID
            write_uuid = None
            for uuid in ELK_UUIDS:
                try:
                    await client.write_gatt_char(uuid, POWER_ON, response=False)
                    write_uuid = uuid
                    print(f"    ✓ Working UUID: {uuid}")
                    break
                except Exception as e:
                    print(f"    ✗ {uuid}: {e}")

            if write_uuid is None:
                print("    No working UUID found — trying all discovered writable chars:")
                for svc in client.services:
                    for char in svc.characteristics:
                        if "write" in char.properties or "write-without-response" in char.properties:
                            print(f"    Trying {char.uuid} ...")
                            try:
                                await client.write_gatt_char(char.uuid, POWER_ON, response=False)
                                write_uuid = char.uuid
                                print(f"    ✓ Found writable: {char.uuid}")
                                break
                            except Exception as e:
                                print(f"    ✗ {e}")
                    if write_uuid:
                        break
                return

            print("    Running color sequence...")
            for name, cmd in [("RED", RED), ("GREEN", GREEN), ("BLUE", BLUE)]:
                await client.write_gatt_char(write_uuid, cmd, response=False)
                print(f"    → {name}")
                await asyncio.sleep(0.8)

            await client.write_gatt_char(write_uuid, RAINBOW_AUTO, response=False)
            print("    → RAINBOW AUTO MODE set")
            await asyncio.sleep(1.0)

    except Exception as e:
        print(f"    ERROR: {type(e).__name__}: {e}")
    print()

async def main():
    mac = sys.argv[1] if len(sys.argv) > 1 else None

    # Step 1: always scan
    await test_scan()

    if mac:
        # Step 2: enumerate GATT
        await test_connect(mac)
        # Step 3: write test
        await test_elk_write(mac)
    else:
        print("Tip: run again with MAC address to test write:")
        print(f"  sudo .venv_bt/bin/python3 debug.py BE:58:00:00:FE:CA")

asyncio.run(main())
