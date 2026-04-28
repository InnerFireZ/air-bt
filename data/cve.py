"""
air-bt — Bluetooth CVE / vulnerability database
53 CVEs and advisories across BlueBorne, BleedingTooth, BrakTooth, SweynTooth,
BLUFFS, BLESA, KNOB, BIAS, HID injection, DoS, and IoT-specific vulnerabilities.
Matched against device name patterns, UUID fingerprints, manufacturer data, and BT type.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt

Vuln types:
  RCE          - Remote Code Execution
  DoS          - Denial of Service / crash
  AuthBypass   - Authentication / pairing bypass
  InfoDisc     - Information disclosure / key leak
  UnauthWrite  - Unauthenticated write / control
  OTA          - Firmware replacement via DFU/OTA
  Spoof        - Device impersonation / spoofing
  Inject       - Keystroke / command injection
"""

import re
from dataclasses import dataclass, field


@dataclass
class BLEVuln:
    cve_id: str
    name: str
    description: str
    affected_pattern: str        # regex matched against device name; "" = name not used
    affected_uuids: list[str]    # if non-empty, at least one must match
    severity: str                # CRITICAL / HIGH / MEDIUM / LOW
    vuln_type: str               # RCE / DoS / AuthBypass / InfoDisc / UnauthWrite / OTA / Spoof / Inject
    affected_bt_type: str = "Any"  # "Classic", "BLE", "Dual", "Any"
    requires_active_probe: bool = False  # if True, only match after GATT enumeration
    short_name: str = ""           # friendly display label; falls back to cve_id if empty


# Severity sort order for picking the worst match
_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


VULN_DB: list[BLEVuln] = [

    # ══════════════════════════════════════════════════════════════════════════
    # BlueBorne (2017) — affects ALL Bluetooth stacks, no pairing needed
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2017-1000251",
        name="BlueBorne — Linux RCE (L2CAP)",
        description="Linux kernel L2CAP stack overflow via crafted configuration request. "
                    "No pairing required, attacker within radio range gets kernel RCE.",
        affected_pattern="(?i)(linux|ubuntu|debian|raspberry|rpi|kali|openwrt|router|gateway|"
                         "embedded|iot.?hub|hub|bridge|speaker|headset|headphone)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="Classic",
        short_name="BlueBorne",
    ),
    BLEVuln(
        cve_id="CVE-2017-1000250",
        name="BlueBorne — Linux BlueZ SDP Leak",
        description="BlueZ SDP server leaks kernel stack memory via out-of-bounds read in "
                    "service discovery. Exploitable without authentication.",
        affected_pattern="(?i)(linux|ubuntu|raspberry|rpi|kali|openwrt)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="InfoDisc",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2017-0781",
        name="BlueBorne — Android BNEP RCE",
        description="Android Bluetooth BNEP heap overflow via crafted BNEP response. "
                    "Pre-Android 8 — no user interaction, no pairing needed.",
        affected_pattern="(?i)(android|samsung|galaxy|huawei|xiaomi|redmi|oppo|vivo|honor|"
                         "pixel|nexus|oneplus|motorola|lenovo|lg.?g|lg.?v[0-9])",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2017-0782",
        name="BlueBorne — Android BNEP Info Disclosure",
        description="Android BNEP filter_nettype info disclosure — side-channel for heap spray.",
        affected_pattern="(?i)(android|samsung|galaxy|huawei|xiaomi|redmi|oppo)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="InfoDisc",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2017-0783",
        name="BlueBorne — Android/Linux Info Disclosure",
        description="Linux/Android Bluetooth PAN driver leaks kernel addresses.",
        affected_pattern="(?i)(android|linux|samsung|galaxy)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="InfoDisc",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2017-0785",
        name="BlueBorne — Android SDP Info Disclosure",
        description="Android SDP server out-of-bounds read — used as BlueBorne info leak primitive.",
        affected_pattern="(?i)(android|samsung|galaxy|huawei|xiaomi)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="InfoDisc",
        affected_bt_type="Classic",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BleedingTooth (2020) — Linux kernel, BLE + Classic
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2020-12351",
        name="BleedingTooth — Linux L2CAP Heap Overflow (RCE)",
        description="Linux kernel heap overflow in L2CAP via crafted A2MP packet. "
                    "Zero-click RCE against any Linux with Bluetooth enabled (kernel < 5.9).",
        affected_pattern="(?i)(linux|ubuntu|debian|raspberry|rpi|kali|chromebook|chromeos|"
                         "openwrt|router|gateway|speaker|headset)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="Classic",
        short_name="BleedingTooth",
    ),
    BLEVuln(
        cve_id="CVE-2020-12352",
        name="BleedingTooth — Linux A2MP Info Disclosure",
        description="Linux kernel uninitialized stack data leak via A2MP remote feature request.",
        affected_pattern="(?i)(linux|ubuntu|raspberry|rpi|kali)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="InfoDisc",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2020-24490",
        name="BleedingTooth — Linux BLE Heap Overflow (DoS/RCE)",
        description="Linux kernel BLE extended advertisement parser heap overflow. "
                    "Sending crafted HCI LE Extended Advertising Report can crash or compromise kernel.",
        affected_pattern="(?i)(linux|ubuntu|raspberry|rpi|kali)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BrakTooth (2021) — BR/EDR DoS / RCE, affects many SoC vendors
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2021-28139",
        name="BrakTooth / SweynTooth — ESP32 Deadlock",
        description="ESP32 BLE stack deadlock via malformed LL_FEATURE_REQ or L2CAP packet. "
                    "Causes device freeze requiring power cycle (DoS).",
        affected_pattern="(?i)(esp32|esp8266|esp.?iot|tuya|smart.?life|smart.?plug|smart.?bulb|"
                         "sonoff|tasmota|atom|m5stack)",
        affected_uuids=["00001910-0000-1000-8000-00805f9b34fb"],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2021-34143",
        name="BrakTooth — BR/EDR LMP DoS (Invalid Feature)",
        description="Sending LMP_features_req with specially crafted opcode causes crash on "
                    "Qualcomm, ESP32, and MediaTek BR/EDR stacks. No pairing needed.",
        affected_pattern="(?i)(qualcomm|qcom|csrblue|cambridge|esp32|mediatek|mt[0-9])",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="Classic",
        short_name="BrakTooth",
    ),
    BLEVuln(
        cve_id="CVE-2021-34145",
        name="BrakTooth — BR/EDR Invalid Timing DoS",
        description="Malformed LMP_timing_accuracy_req packet causes DoS on Infineon/Cypress SoCs. "
                    "Affects headsets, speakers, laptops with Cypress BT chips.",
        affected_pattern="(?i)(cypress|infineon|cyw[0-9]|broadcom|bcm[0-9]|bose|jbl|sony|"
                         "sennheiser|jabra|plantronics|poly)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2021-34146",
        name="BrakTooth — BR/EDR Truncated SCO DoS",
        description="Truncated LMP_SCO_link_req causes crash on TI CC256x and Cypress chips. "
                    "Affects Bluetooth audio devices and embedded systems.",
        affected_pattern="(?i)(texas.?instruments|ti.?cc|bose|jbl|sony|jabra|harman|"
                         "infinity|klipsch)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2021-34147",
        name="BrakTooth — BR/EDR Invalid Max Slots DoS",
        description="LMP_max_slots_req with invalid slot value causes infinite loop/crash on "
                    "Intel and Qualcomm BT controllers.",
        affected_pattern="(?i)(intel|qualcomm|qcom|thinkpad|dell|lenovo|hp.?laptop|surface)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2021-34148",
        name="BrakTooth — BR/EDR Null Pointer DoS",
        description="Out-of-order LMP PDU causes null pointer dereference in Qualcomm BT stack.",
        affected_pattern="(?i)(qualcomm|qcom|snapdragon|samsung|xiaomi|oneplus|oppo)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="Classic",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # SweynTooth — BLE link layer crashes (2019-2021)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2019-16336",
        name="SweynTooth — nRF52 Link Layer Deadlock",
        description="Nordic Semiconductor nRF52 BLE stack deadlock via LL_FEATURE_RSP with "
                    "incorrect sequence number. Crashes device.",
        affected_pattern="(?i)(nordic|nrf|thingy|bbc.?micro|microbit)",
        affected_uuids=[
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e",  # Nordic UART
            "0000fe59-0000-1000-8000-00805f9b34fb",  # Nordic DFU
        ],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-17519",
        name="SweynTooth — nRF52 Length Overflow",
        description="BLE LL length field overflow on nRF52 causes buffer overflow and crash.",
        affected_pattern="(?i)(nordic|nrf|thingy)",
        affected_uuids=[
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
        ],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-17517",
        name="SweynTooth — nRF52 HCI Desync",
        description="Sending LL_REJECT_IND before pairing completes desynchronizes HCI state on nRF52.",
        affected_pattern="(?i)(nordic|nrf)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-17518",
        name="SweynTooth — nRF52 UART OOB Write",
        description="Out-of-bounds write via oversized ATT PDU in Nordic UART service on nRF52.",
        affected_pattern="(?i)(nordic|nrf)",
        affected_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-17520",
        name="SweynTooth — Cypress/PSoC Overflow",
        description="BLE LL PDU length overflow crashes Cypress PSoC6 / CYW20x BLE stack.",
        affected_pattern="(?i)(cypress|infineon|cyw[0-9]|psoc|broadcom|bcm[0-9])",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-17061",
        name="SweynTooth — Telink TLSR DoS",
        description="Telink TLSR8x BLE stack crash via malformed LL_CONNECTION_UPDATE_IND.",
        affected_pattern="(?i)(telink|tlsr|tasmota|sonoff|mi.?light|yeelight|mipow)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2021-28135",
        name="SweynTooth — Truncated L2CAP DoS",
        description="Truncated L2CAP PDU causes unhandled exception/crash on multiple BLE stacks.",
        affected_pattern="(?i)(esp|nordic|nrf|cypress|telink|dialog|bluez)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2021-28136",
        name="SweynTooth — Invalid Opcode DoS",
        description="Sending an ATT PDU with invalid opcode crashes several BLE stacks. "
                    "Wide-reaching — affects ESP32, Dialog, and Cambridge Silicon Radio.",
        affected_pattern="(?i)(esp|dialog|cambridge|csr|qualcomm)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2021-28137",
        name="SweynTooth — OOB PDU Crash",
        description="Out-of-bounds PDU payload causes crash on Dialog DA14xx and similar SoCs.",
        affected_pattern="(?i)(dialog|da14|renesas|da1[0-9])",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2021-28138",
        name="SweynTooth — HCI Desync (Generic)",
        description="HCI desynchronization via crafted BLE LL packet on multiple SoCs.",
        affected_pattern="(?i)(esp|nordic|nrf|cypress|dialog)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BLEEDINGBIT (2018) — TI CC26xx / Aruba OTA
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2018-16986",
        name="BLEEDINGBIT — TI CC26xx BLE RCE",
        description="Texas Instruments CC26xx BLE advertisement parser heap overflow. "
                    "Attacker within BLE range can achieve RCE without pairing via crafted adv packets. "
                    "Affects enterprise APs, medical devices, and industrial IoT with TI radios.",
        affected_pattern="(?i)(texas.?instruments|ti.?ble|cc26|cc26[0-9][0-9]|aruba|cisco.?meraki|"
                         "zebra|kontakt|estimote|gimbal)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="BLE",
        short_name="BleedingBit",
    ),
    BLEVuln(
        cve_id="CVE-2018-7080",
        name="BLEEDINGBIT — Aruba/Cisco OTA Backdoor",
        description="Aruba and Cisco Meraki access points expose an unauthenticated OTA DFU "
                    "backdoor via BLE. Attacker can push arbitrary firmware without credentials.",
        affected_pattern="(?i)(aruba|cisco|meraki|arubanetworks)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="OTA",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # KNOB / BIAS — BR/EDR session key attacks
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2019-9506",
        name="KNOB Attack",
        description="Key Negotiation of Bluetooth: MitM forces 1-byte entropy on BR/EDR link keys, "
                    "making session keys brute-forceable in real time.",
        affected_pattern="",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="Classic",
        short_name="KNOB",
    ),
    BLEVuln(
        cve_id="CVE-2020-10135",
        name="BIAS Attack",
        description="Bluetooth Impersonation AttackS: legacy authentication bypass in BR/EDR "
                    "secure connections — allows impersonating a bonded device without knowing the link key.",
        affected_pattern="",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="Classic",
        short_name="BIAS",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BLUFFS (2023) — BLE session key downgrade
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2023-24023",
        name="BLUFFS — BLE Session Key Compromise",
        description="BLUFFS (Bluetooth Forward and Future Secrecy): attacker forces weak session keys "
                    "in BLE secure connections, breaking forward secrecy. Affects Bluetooth Core 4.2–5.4. "
                    "Virtually all modern BLE devices are affected.",
        affected_pattern="",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="BLE",
        requires_active_probe=True,
        short_name="BLUFFS",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BLESA (2020) — BLE reconnection spoofing
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2020-12268",
        name="BLESA — BLE Reconnection Spoofing",
        description="BLE Spoofing Attack: reconnection procedure bypass allowing device impersonation. "
                    "Only flagged after active probe confirms reconnection without re-authentication.",
        affected_pattern="",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="Spoof",
        affected_bt_type="BLE",
        requires_active_probe=True,
        short_name="BLESA",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Invalid Curve Attack (2018) — BLE LE Secure Connections
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2018-5383",
        name="Invalid Curve Attack — BLE Pairing",
        description="BLE LE Secure Connections pairing fails to validate ECDH public key curve point. "
                    "MitM can inject a crafted key to compromise the pairing — affects Bluetooth 4.x–5.0.",
        affected_pattern="",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="BLE",
        requires_active_probe=True,
        short_name="InvalidCurve",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BlueFrag — Android 8/9 RCE
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2020-0022",
        name="BlueFrag — Android RCE",
        description="Android Bluetooth BNEP heap overflow — zero-click RCE on Android 8.0/8.1. "
                    "DoS on Android 9. Requires attacker knows target MAC address.",
        affected_pattern="(?i)(android|samsung|galaxy|huawei|xiaomi|redmi|oppo|vivo|honor|"
                         "pixel|oneplus|motorola)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="Classic",
        short_name="BlueFrag",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BR/EDR pairing spoofing (2020)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2020-26555",
        name="BR/EDR PIN Pairing Spoofing",
        description="Bluetooth PIN pairing allows an attacker to pose as a legacy device during pairing, "
                    "forcing weak PIN negotiation (Bluetooth Core 1.0–5.2).",
        affected_pattern="",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="Spoof",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2020-26558",
        name="Passkey Entry Eavesdrop",
        description="Bluetooth LE and BR/EDR passkey entry pairing is vulnerable to MitM eavesdropping "
                    "that allows recovering the passkey (Bluetooth Core 2.1–5.2).",
        affected_pattern="",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="InfoDisc",
        affected_bt_type="Any",
        requires_active_probe=True,
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Apple / iOS specific
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2019-8648",
        name="Apple MagicPairing Memory Corruption",
        description="Heap corruption in Apple MagicPairing (AirPods, Apple Watch, keyboard pairing). "
                    "Crafted Bluetooth packet within range can cause RCE in bluetoothd.",
        affected_pattern="(?i)(apple|airpods|airpod|iphone|ipad|macbook|imac|magic.?mouse|"
                         "magic.?keyboard|apple.?watch|airplay)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="RCE",
        affected_bt_type="Classic",
    ),
    BLEVuln(
        cve_id="CVE-2023-42846",
        name="Apple Bluetooth DoS (iOS 17)",
        description="Specially crafted BLE advertisement causes bluetoothd crash / phone reboot on iOS 17.0. "
                    "Publicly weaponized via 'Flipper Zero' style attacks in 2023.",
        affected_pattern="(?i)(apple|airpods|iphone|ipad)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Windows Bluetooth
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2024-21306",
        name="Windows Bluetooth Driver RCE",
        description="Microsoft Windows Bluetooth driver remote code execution via crafted HID report. "
                    "Affects Windows 10/11 and Windows Server with Bluetooth.",
        affected_pattern="(?i)(microsoft|surface|thinkpad|dell|hp|lenovo|asus|acer|windows)",
        affected_uuids=[
            "00001812-0000-1000-8000-00805f9b34fb",  # HID
        ],
        severity="HIGH",
        vuln_type="RCE",
        affected_bt_type="Any",
    ),
    BLEVuln(
        cve_id="CVE-2022-30190",
        name="Windows BT DoS (L2CAP)",
        description="Windows Bluetooth L2CAP driver null pointer dereference causes BSOD via "
                    "malformed L2CAP packet from a nearby device.",
        affected_pattern="(?i)(microsoft|surface|thinkpad|dell|hp|lenovo|windows)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="Classic",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # HID injection
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2023-45866",
        name="BlueDucky / Unauthenticated HID Injection",
        description="Unauthenticated Bluetooth HID keystroke injection on Linux, Android, and iOS. "
                    "Attacker pairs as HID device without confirmation and injects keystrokes.",
        affected_pattern="",
        affected_uuids=[
            "00001812-0000-1000-8000-00805f9b34fb",
            "1812",
        ],
        severity="HIGH",
        vuln_type="Inject",
        affected_bt_type="Any",
        short_name="BlueDucky",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # DFU / OTA exposure
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-DFU-001",
        name="Exposed Nordic DFU Bootloader",
        description="Nordic Semiconductor DFU bootloader service is accessible without authentication. "
                    "An attacker can push arbitrary firmware to the device over BLE.",
        affected_pattern="",
        affected_uuids=["00001530-1212-efde-1523-785feabcd123"],
        severity="HIGH",
        vuln_type="OTA",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="ADV-DFU-002",
        name="Exposed Silabs OTA Service",
        description="Silicon Labs Gecko OTA update service (UUID 1D14D6EE) is exposed without auth. "
                    "Allows unauthenticated firmware update.",
        affected_pattern="",
        affected_uuids=["1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0"],
        severity="HIGH",
        vuln_type="OTA",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="ADV-DFU-003",
        name="Exposed TI OAD (Over-Air Download)",
        description="Texas Instruments OAD service exposed without authentication — "
                    "allows remote firmware replacement.",
        affected_pattern="",
        affected_uuids=[
            "f000ffc0-0451-4000-b000-000000000000",
            "f000ffc1-0451-4000-b000-000000000000",
        ],
        severity="HIGH",
        vuln_type="OTA",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Nordic UART open access
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-UART-001",
        name="Nordic UART Open Access",
        description="Nordic UART service (NUS) is exposed without authentication — "
                    "common in cheap IoT prototypes. Allows arbitrary data send/receive.",
        affected_pattern="",
        affected_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
        severity="MEDIUM",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Unauthenticated write — Chinese IoT
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-ELKBLEDOM-001",
        name="ELK-BLEDOM No Auth RGB Control",
        description="ELK-BLEDOM and compatible Chinese BLE LED strips accept full RGB/power "
                    "control commands with zero authentication. Any nearby device can control "
                    "the light without pairing. Char FFF3 or FFE9 is writable by anyone.",
        affected_pattern="(?i)(elk.?ble|elk.?bulb|elk.?lamp|elkblue|melk|ledble|lednet|"
                         "led.?ble|ledstrip|qhm.?led|triones|magic.?home|ilinker|zj.?|"
                         "btle.?led|ble.?led|iled|ilis|smlight|sovvid)",
        affected_uuids=[
            "0000fff0-0000-1000-8000-00805f9b34fb",
            "0000ffe5-0000-1000-8000-00805f9b34fb",
        ],
        severity="MEDIUM",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="ADV-TUYA-001",
        name="Tuya No Auth Write",
        description="Many Tuya-based smart home devices expose control characteristics "
                    "without requiring pairing, allowing anyone nearby to control them.",
        affected_pattern="(?i)(tuya|smart.?life|ble.*bulb|ble.*plug|bk3[0-9][0-9][0-9]|cb3s|cb2s)",
        affected_uuids=["00001910-0000-1000-8000-00805f9b34fb"],
        severity="MEDIUM",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2022-20422",
        name="Xiaomi Band Unauth Write",
        description="Xiaomi Mi Band and compatible fitness trackers accept GATT writes "
                    "without authentication, allowing spoofing of activity data.",
        affected_pattern="(?i)(mi.?band|id115|fitpro|h.?band|veryfit|xiaomi.?band|leband|letsfit|"
                         "y.?band|zepp|amazfit|hplus)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2020-7958",
        name="Govee No Auth Write",
        description="Govee smart home devices (lights, thermometers, strips) accept "
                    "unauthenticated BLE write commands — anyone can control them.",
        affected_pattern="(?i)(govee|gvh|ihoment)",
        affected_uuids=["00010203-0405-0607-0809-0a0b0c0d1910"],
        severity="MEDIUM",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="ADV-MIBEACON-001",
        name="MiBeacon Replay / Spoof",
        description="Xiaomi MiBeacon v1-v3 devices (LYWSD03MC, CGG1, MiFlora) broadcast "
                    "sensor data without encryption/authentication — trivially replayable or spoofable.",
        affected_pattern="(?i)(xiaomi|mi.?flora|lywsd|cgd1|cgdk2|mija|mibeacon|miband|hhccjcy)",
        affected_uuids=["0000fe95-0000-1000-8000-00805f9b34fb"],
        severity="LOW",
        vuln_type="Spoof",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Medical / industrial
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2019-13473",
        name="Siemens Hearing Aid Auth Bypass",
        description="Siemens/Signia hearing aids accept unauthenticated BLE connections and allow "
                    "reading/writing audio parameters without bonding.",
        affected_pattern="(?i)(siemens|signia|widex|oticon|phonak|starkey|hearing.?aid|hearing.?loop)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="BLE",
    ),
    BLEVuln(
        cve_id="CVE-2019-13474",
        name="Siemens Hearing Aid Remote Config",
        description="Siemens hearing aids allow unauthenticated firmware config writes over BLE, "
                    "potentially causing hearing damage or device malfunction.",
        affected_pattern="(?i)(siemens|signia|widex|oticon|phonak|starkey)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Flipper Zero / advertisement flood DoS (no CVE but well known)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-BLE-FLOOD-001",
        name="BLE Advertisement Flood DoS",
        description="High-rate BLE advertisement flooding (as popularized by Flipper Zero attacks) "
                    "can crash or disable Bluetooth stacks on iOS, Android, and Windows "
                    "that process all advertisement packets in software.",
        affected_pattern="(?i)(apple|iphone|ipad|android|samsung|windows|surface)",
        affected_uuids=[],
        severity="MEDIUM",
        vuln_type="DoS",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Smart speaker / audio DoS
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-SPEAKER-001",
        name="BLE Speaker Unauthenticated Control",
        description="Many BLE-enabled speakers and soundbars (LG, Sony, Bose, JBL clones) "
                    "expose volume/playback GATT characteristics without authentication.",
        affected_pattern="(?i)(lg.?s[0-9]|lg.?sp[0-9]|sony.?srs|bose|jbl|harman|klipsch|"
                         "anker.?sound|tribit|tronsmart|marshall|ultimate.?ears|ue.?boom|"
                         "soundcore|soundlink|charge|flip|pulse|wonder)",
        affected_uuids=[
            "00001844-0000-1000-8000-00805f9b34fb",  # VCS (Volume Control Service)
            "00001848-0000-1000-8000-00805f9b34fb",  # CSIS (Coordinated Set)
        ],
        severity="LOW",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # WhisperPair (2026) — Google Fast Pair KBP auth bypass
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2025-36911",
        name="WhisperPair — Fast Pair Key-Based Pairing Auth Bypass",
        description="WhisperPair: vulnerable Fast Pair accessories respond to Key-Based Pairing "
                    "(KBP) requests even when NOT in pairing mode and without validating the ECDH "
                    "session key. Attacker within ~14 m sends a crafted KBP write; the device leaks "
                    "its BR/EDR address in the encrypted response, enabling tracking and full "
                    "Bluetooth Classic pairing hijack (microphone/audio access). "
                    "Affects Sony, Jabra, JBL, Marshall, Xiaomi, Nothing, OnePlus, Soundcore, "
                    "Logitech, and Google's own Pixel Buds. Disclosed January 2026.",
        affected_pattern="(?i)(sony|jabra|jbl|marshall|xiaomi|nothing.?ear|oneplus.?buds|"
                         "soundcore|logitech|pixel.?buds|bose|anker|beats|sennheiser|"
                         "samsung.?buds|galaxy.?buds|airpods)",
        affected_uuids=["0000fe2c-0000-1000-8000-00805f9b34fb"],
        severity="HIGH",
        vuln_type="AuthBypass",
        affected_bt_type="BLE",
        short_name="WhisperPair",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Smart locks — BLE no-auth access
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-LOCK-001",
        name="BLE Smart Lock Unauthenticated Access",
        description="Multiple BLE smart locks (August, Level, Noke, Igloohome, Lockly) accept "
                    "connections without pairing and expose lock-state or control characteristics "
                    "without authentication. Research has demonstrated unauthenticated state reads "
                    "and command injection on affected models.",
        affected_pattern="(?i)(august|level.?lock|noke|igloo|lockly|schlage|kwikset|yale|kevo|"
                         "ultraloq|smartlock|smart.?lock|doorlock|door.?lock|padlock|deadbolt|"
                         "ttlock|elock|smart.?padlock|fingerprint.?lock)",
        affected_uuids=[
            "00003a77-0000-1000-8000-00805f9b34fb",  # August Smart Lock
            "9a66f400-0800-9191-11e4-012d1540cb8e",  # Noke padlock
        ],
        severity="HIGH",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
        short_name="LockNoAuth",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # iBeacon / Eddystone — passive location tracking
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-IBEACON-001",
        name="iBeacon / Eddystone Passive Location Fingerprinting",
        description="Devices broadcasting Apple iBeacon or Google Eddystone frames disclose static "
                    "UUID, major/minor identifiers, and calibrated TX power in every advertisement. "
                    "These can be used to uniquely fingerprint an installation, estimate physical "
                    "proximity, and track device movement. No connection or authentication required — "
                    "purely passive eavesdropping. Tile trackers with non-rotating IDs are similarly "
                    "vulnerable to persistent surveillance.",
        affected_pattern="",
        affected_uuids=["0000feaa-0000-1000-8000-00805f9b34fb"],  # Eddystone
        severity="MEDIUM",
        vuln_type="InfoDisc",
        affected_bt_type="BLE",
        short_name="BeaconTrack",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Medical — Medtronic insulin pump wireless auth bypass
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2019-10964",
        name="Medtronic MiniMed Insulin Pump Wireless Auth Bypass",
        description="Medtronic MiniMed 508 and Paradigm insulin pumps (and the remote controller) "
                    "communicate via a proprietary wireless protocol with no authentication. A nearby "
                    "attacker can inject commands to change insulin dose delivery. FDA issued a safety "
                    "alert (August 2019); affected units were recalled.",
        affected_pattern="(?i)(medtronic|minimed|paradigm|insulin.?pump|guardian.?link|carelink|"
                         "contour.?next|630g|670g|770g)",
        affected_uuids=[],
        severity="CRITICAL",
        vuln_type="UnauthWrite",
        affected_bt_type="Any",
        short_name="MedtronicPump",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Medical — Abbott/St. Jude pacemaker info disclosure
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2016-8375",
        name="Abbott/St. Jude Medical Pacemaker Unencrypted Telemetry",
        description="Abbott (St. Jude Medical) implantable cardiac devices expose unencrypted wireless "
                    "telemetry without authentication. Passive eavesdropping reveals pacing parameters "
                    "and patient data. Merlin@home programmer also affected. FDA safety advisory issued.",
        affected_pattern="(?i)(abbott|st.?jude|merlin|pacemaker|cardiac|icd|defibrillator|"
                         "accent|anthem|endurity|assurity|fortify|ellipse|quadra|unify)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="InfoDisc",
        affected_bt_type="Any",
        short_name="PacemakerLeak",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Medical — continuous glucose monitors (CGM) unauth data
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-CGMS-001",
        name="CGM Unauthenticated Glucose Data Broadcast",
        description="Continuous Glucose Monitors (Abbott FreeStyle Libre, Dexcom G5/G6, Medtronic "
                    "Guardian) broadcast or expose glucose readings over BLE without encryption. "
                    "Readings can be passively captured and replayed to spoof values in monitoring apps, "
                    "potentially leading to incorrect insulin dosing decisions.",
        affected_pattern="(?i)(dexcom|freestyle|libre|g[567].?cgm|abbott.?diabetes|medtronic.?cgm|"
                         "eversense|guardian|enlite|cgm|glucose.?monitor|libreview)",
        affected_uuids=["f8083532-849e-531c-c594-30f1f86a4ea5"],  # Dexcom CGM service
        severity="HIGH",
        vuln_type="InfoDisc",
        affected_bt_type="BLE",
        short_name="CGMExposed",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Nordic UART — arbitrary command injection (extended advisory)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-UART-002",
        name="Nordic UART Service Arbitrary Command Injection",
        description="Devices exposing the Nordic UART Service (NUS) without authentication allow "
                    "an attacker to send arbitrary ASCII/binary commands and read all responses. "
                    "Many IoT prototypes and production devices use NUS as a debug/control channel, "
                    "enabling config dumps, setting changes, and in some cases OS shell access.",
        affected_pattern="(?i)(nordic|nrf|uart|nus|diy|proto|dev.?board|feather|nano|seed|adafruit|"
                         "particle|arduino.?ble|esp.?uart|bluepill|stm32.?ble)",
        affected_uuids=["6e400001-b5a3-f393-e0a9-e50e24dcca9e"],
        severity="HIGH",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
        short_name="UARTInject",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Android BLE heap overflow
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2018-9358",
        name="Android BLE Stack Heap Overflow (processConnect)",
        description="Android Bluetooth Low Energy stack heap overflow in processConnect() — "
                    "a malformed connection request can crash com.android.bluetooth. "
                    "Affects Android 6.0–8.1 before 2018-06 security patch.",
        affected_pattern="(?i)(android|samsung|galaxy|huawei|xiaomi|nexus|pixel|oppo|vivo|honor)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="DoS",
        affected_bt_type="BLE",
        short_name="AndroidBLECrash",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BLE tracker passive surveillance
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-TRACKER-001",
        name="BLE Tracker Passive Surveillance (Tile/SmartTag)",
        description="Bluetooth trackers (Tile, Samsung SmartTag, Chipolo) broadcast static or "
                    "slowly-rotating identifiers that enable persistent location tracking. "
                    "An attacker with fixed BLE scanners can map the movements of any person "
                    "carrying a Tile or SmartTag without the victim's knowledge.",
        affected_pattern="(?i)(tile|samsung.?tag|smart.?tag2|chipolo|nut.?smart|key.?finder|"
                         "pebblebee|orbit|item|mynt|cube.?tracker|trackr)",
        affected_uuids=["0000feed-0000-1000-8000-00805f9b34fb"],  # Tile service UUID
        severity="MEDIUM",
        vuln_type="InfoDisc",
        affected_bt_type="BLE",
        short_name="TrackerSurv",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # Google Quick Share / Nearby Share (2024)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="CVE-2024-38271",
        name="Google Quick Share Forced Wi-Fi Connection",
        description="Google Quick Share (formerly Nearby Share) on Windows forces connection to an "
                    "attacker-controlled Wi-Fi network without user consent via a crafted BLE "
                    "advertisement. An attacker within BLE range can redirect all network traffic.",
        affected_pattern="(?i)(quick.?share|nearby.?share|android|pixel|google)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="Spoof",
        affected_bt_type="BLE",
        short_name="QuickShareMITM",
    ),
    BLEVuln(
        cve_id="CVE-2024-38272",
        name="Google Quick Share File Write Without Consent",
        description="Google Quick Share for Windows allows arbitrary file writes to any path via "
                    "crafted BLE Nearby Share session without user confirmation. Combined with "
                    "path traversal this achieves remote code execution.",
        affected_pattern="(?i)(quick.?share|nearby.?share|android|pixel|google)",
        affected_uuids=[],
        severity="HIGH",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
        short_name="QuickShareRCE",
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # BLE speaker unauth volume control (VCS)
    # ══════════════════════════════════════════════════════════════════════════
    BLEVuln(
        cve_id="ADV-SPEAKER-002",
        name="BLE Speaker Unauth Volume Control via VCS",
        description="BLE speakers and soundbars implementing the Volume Control Service (0x1844) "
                    "often do not require authentication for Volume Control Point writes. "
                    "Any nearby device can mute, maximize volume, or set arbitrary levels.",
        affected_pattern="(?i)(speaker|soundbar|soundlink|soundcore|jbl|bose|sony.?srs|anker|"
                         "tribit|tronsmart|marshall|ue.?boom|flip|charge|pulse|wonder|earphone)",
        affected_uuids=["00001844-0000-1000-8000-00805f9b34fb"],  # VCS
        severity="LOW",
        vuln_type="UnauthWrite",
        affected_bt_type="BLE",
        short_name="SpeakerVCS",
    ),
]


def match_vulns(
    device_name: str,
    uuids: list[str],
    device_type: str = "BLE",
    active_probe: bool = False,
) -> list[BLEVuln]:
    """
    Return matching vulnerabilities for a device, sorted by severity (worst first).

    Args:
        device_name:  Advertised device name.
        uuids:        List of service/characteristic UUID strings.
        device_type:  "BLE", "Classic", or "Dual".
        active_probe: True after GATT enumeration — unlocks probe-only CVEs.
    """
    matches = []
    uuids_lower = [u.lower() for u in uuids]
    name = device_name or ""

    for vuln in VULN_DB:
        # Skip probe-only CVEs during passive scan
        if vuln.requires_active_probe and not active_probe:
            continue

        # Type gate
        if vuln.affected_bt_type != "Any":
            if device_type == "BLE" and vuln.affected_bt_type == "Classic":
                continue
            if device_type == "Classic" and vuln.affected_bt_type == "BLE":
                continue
            # "Dual" matches both

        uuid_match = (
            any(u.lower() in uuids_lower for u in vuln.affected_uuids)
            if vuln.affected_uuids else False
        )
        name_match = (
            bool(re.search(vuln.affected_pattern, name))
            if vuln.affected_pattern else False
        )

        if not vuln.affected_uuids and not vuln.affected_pattern:
            matches.append(vuln)
        elif vuln.affected_uuids and vuln.affected_pattern:
            if uuid_match or name_match:
                matches.append(vuln)
        elif vuln.affected_uuids:
            if uuid_match:
                matches.append(vuln)
        elif vuln.affected_pattern:
            if name_match:
                matches.append(vuln)

    # Sort by severity (CRITICAL first)
    matches.sort(key=lambda v: _SEV.get(v.severity, 99))
    return matches
