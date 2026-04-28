#!/usr/bin/env python3
"""
air-bt — BLE Security Scanner
Created by InnerFireZ

Flow: Scan → Ctrl+C → Pick Target → Auto-Probe → Pick Attack → Execute
"""
# © InnerFireZ — https://github.com/InnerFireZ/air-bt

import asyncio
import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, IntPrompt
from rich import box

from scanner.ble import BLEScanner
from scanner.gatt import enumerate_gatt, subscribe_notifications
from scanner.writer import (
    exploit_open_writes, fuzz_characteristic, run_payload, elk_bledom_rainbow_poc,
    probe_overflow, OverflowFinding,
    fuzz_mutate, MutationResult,
)
from scanner.ble import is_random_mac
from scanner.poc import (
    poc_generic_dump, poc_audio_device, poc_hid_injection,
    poc_iot_sensor, poc_smart_plug, poc_fitness_tracker,
    poc_health_monitor, poc_write_probe, run_best_poc,
    poc_whisperpair,
    poc_dfu_probe, poc_tuya_control, poc_govee_control,
    poc_mibeacon_decode, poc_sweyntooth_probe,
    poc_hearing_aid_probe, poc_blueborne_info,
    poc_nordic_uart, poc_speaker_control, poc_smart_lock_probe, poc_ibeacon_track,
    poc_reconnect_auth_bypass, ReconnectBypass,
)
from display.table import build_main_table, build_detail_panel
from export import export_json, export_csv, export_html
from models import BTDevice
from payloads.library import get_payloads_for_protocol, PAYLOAD_LIBRARY

console = Console()
log = logging.getLogger("air-bt")


def parse_args():
    parser = argparse.ArgumentParser(
        description="air-bt — Interactive BLE security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--adapter", default="hci0")
    parser.add_argument("--rssi",    type=int,   default=-80,  help="RSSI threshold dBm (default: -80)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout (default: 10s)")
    parser.add_argument("--output",  metavar="FILE",           help="Export to .json/.csv/.html on exit")
    parser.add_argument("--passive", action="store_true",      help="Passive scan only — no auto-probe connections")
    parser.add_argument("--probe-delay", type=float, default=1.5, help="Seconds between background probes (default: 1.5)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


# ── Scan phase ────────────────────────────────────────────────────────────────

async def scan_phase(scanner: BLEScanner, args) -> list[BTDevice]:
    """
    Scan BLE advertisements.  While scanning, a background worker connects to
    each new device (strongest-first), enumerates GATT and enriches FLAGS/CVEs
    in real-time.  Press Ctrl+C to stop and select a target.
    Pass --passive to skip background connections.
    """
    stop_event = asyncio.Event()

    def _sig(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    await scanner.start()
    start   = time.time()
    mode_label = "passive" if args.passive else "probe"

    # Shared state for the background probe worker
    probing_mac: list[str | None] = [None]   # mutable cell
    probe_log:   list[str]        = []

    async def bg_probe_worker():
        """Connect to each new device, enumerate GATT, update flags live."""
        probed: set[str] = set()
        await asyncio.sleep(3.0)   # let scanner collect a few devices first

        while not stop_event.is_set():
            devices = scanner.get_devices()
            # Only probe devices not yet enumerated, pick strongest RSSI first
            candidates = [d for d in devices if d.mac not in probed]
            if not candidates:
                await asyncio.sleep(args.probe_delay)
                continue

            dev = candidates[0]
            probed.add(dev.mac)
            probing_mac[0] = dev.mac

            await scanner.pause()
            try:
                ok = await enumerate_gatt(dev, timeout=args.timeout)
                if ok:
                    scanner._compute_sec_score(dev)
                    # Build a compact findings line for the log
                    findings = []
                    if dev.open_writes:  findings.append(f"[bright_red]{dev.open_writes} open-write[/]")
                    if dev.open_reads:   findings.append(f"[red]{dev.open_reads} open-read[/]")
                    if dev.notifiable:   findings.append(f"[orange1]{dev.notifiable} notify[/]")
                    if dev.known_vuln:   findings.append(f"[red]{dev.known_vuln}[/]")
                    summary = f"[cyan]{dev.mac}[/] [white]{dev.name or '?'}[/]"
                    if findings:
                        summary += "  " + "  ".join(findings)
                    else:
                        summary += "  [dim]no open access[/]"
                    probe_log.append(summary)
                else:
                    probe_log.append(f"[dim]{dev.mac} — could not connect[/]")
            except Exception as e:
                probe_log.append(f"[dim]{dev.mac} — probe error: {e}[/]")
            finally:
                probing_mac[0] = None
                await scanner.resume()

            await asyncio.sleep(args.probe_delay)

    probe_task = None
    if not args.passive:
        probe_task = asyncio.create_task(bg_probe_worker())

    # SIGWINCH: clear Rich's cached terminal size so the next render uses the
    # actual new dimensions immediately after a window resize.
    loop = asyncio.get_running_loop()
    def _on_resize():
        try:
            console._width  = None   # force Rich to re-query on next render
            console._height = None
        except Exception:
            pass
    try:
        loop.add_signal_handler(signal.SIGWINCH, _on_resize)
    except (AttributeError, OSError):
        pass   # Windows / unsupported platforms

    try:
        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while not stop_event.is_set():
                elapsed = int(time.time() - start)
                table   = build_main_table(scanner.get_devices(), mode_label,
                                           elapsed, probing_mac[0])

                if probe_log:
                    from rich.layout import Layout as _Layout
                    log_lines = probe_log[-8:]
                    log_panel = Panel(
                        "\n".join(log_lines),
                        title="[bold cyan]Probe Results[/]",
                        border_style="cyan",
                    )
                    layout = _Layout()
                    layout.split_column(
                        _Layout(table,     name="top", ratio=4),
                        _Layout(log_panel, name="log", ratio=1),
                    )
                    live.update(layout)
                else:
                    live.update(table)

                await asyncio.sleep(1.0)
    except Exception:
        pass
    finally:
        try:
            loop.remove_signal_handler(signal.SIGWINCH)
        except Exception:
            pass
        if probe_task:
            probe_task.cancel()
            try:
                await probe_task
            except asyncio.CancelledError:
                pass
        await scanner.stop()

    signal.signal(signal.SIGINT,  signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

    return scanner.get_devices()


# ── Target selection ──────────────────────────────────────────────────────────

_SEC_COLOR = {"A": "bright_green", "B": "green", "C": "yellow", "D": "orange1", "F": "bright_red", "?": "dim"}
_TYPE_COLOR = {"RCE": "bright_red", "DoS": "red", "UnauthWrite": "bright_red",
               "AuthBypass": "orange1", "Inject": "bright_red", "OTA": "yellow",
               "Spoof": "yellow", "InfoDisc": "cyan"}


def _cve_str(dev: BTDevice) -> str:
    if not dev.known_vuln:
        return "[dim]-[/]"
    tc = _TYPE_COLOR.get(dev.known_vuln_type or "", "red")
    cnt = f"[dim]+{dev.vuln_count - 1}[/]" if dev.vuln_count > 1 else ""
    return f"[{tc}]{dev.known_vuln}[/] [dim]{dev.known_vuln_type or ''}[/]{cnt}"


def _rssi_bar(rssi: int) -> str:
    if rssi >= -50: return "[bright_green]▂▄▆█[/]"
    if rssi >= -60: return "[green]▂▄▆_[/]"
    if rssi >= -70: return "[yellow]▂▄__[/]"
    if rssi >= -80: return "[red]▂___[/]"
    return "[dim]____[/]"


def show_target_table(devices: list[BTDevice]):
    t = Table(box=box.MINIMAL_DOUBLE_HEAD, header_style="bold cyan", expand=True,
              title=f"[bold cyan]Discovered Devices[/] — [white]{len(devices)}[/] found")
    t.add_column("#",        width=4,  justify="right", style="bold yellow")
    t.add_column("MAC",      width=18, style="cyan",        no_wrap=True)
    t.add_column("NAME",     width=20, style="bright_white")
    t.add_column("RSSI",     width=10, justify="right")
    t.add_column("VENDOR",   width=16, style="white")
    t.add_column("PROTOCOL", width=16, style="magenta")
    t.add_column("SEC",      width=4,  justify="center")
    t.add_column("FLAGS",    width=36, style="white")
    t.add_column("CVE",      width=30)
    t.add_column("CAPS",     width=26, style="bright_cyan")

    for i, dev in enumerate(devices, 1):
        sc = _SEC_COLOR.get(dev.sec_score, "white")
        flags = []
        fc = {"OPEN_WRITE": "bright_red", "OPEN_READ": "red", "NO_BONDING": "yellow",
              "NOTIFY_UNAUTH": "orange1", "KNOWN_VULN": "bright_red", "WEAK_PAIRING": "yellow", "Chinese OEM": "cyan"}
        for f in dev.sec_flags:
            c = fc.get(f, "white")
            flags.append(f"[{c}]{f}[/]")
        caps = ", ".join(dev.capabilities[:3])
        if len(dev.capabilities) > 3:
            caps += f" +{len(dev.capabilities)-3}"
        t.add_row(
            str(i),
            dev.mac,
            (dev.name or "Unknown")[:20],
            f"{_rssi_bar(dev.rssi)} {dev.rssi}",
            (dev.vendor or "?")[:16],
            (dev.protocol or "?")[:16],
            f"[{sc}]{dev.sec_score}[/]",
            " ".join(flags) or "[dim]-[/]",
            _cve_str(dev),
            caps or "[dim]-[/]",
        )
    console.print(t)


def pick_target(devices: list[BTDevice]) -> BTDevice | None:
    """Show numbered device list, return chosen device."""
    while True:
        console.print()
        show_target_table(devices)
        console.print("\n[dim]r[/] = rescan  [dim]q[/] = quit\n")
        raw = console.input("[bold yellow]Select target #: [/]").strip().lower()
        if raw == "q":
            return None
        if raw == "r":
            return "rescan"  # type: ignore
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(devices):
                return devices[idx]
        except ValueError:
            pass
        console.print("[red]Invalid choice — enter a number, r, or q[/]")


# ── Attack menu ───────────────────────────────────────────────────────────────

def _has_cap(dev: BTDevice, *keywords) -> bool:
    caps_lower = [c.lower() for c in dev.capabilities]
    return any(any(kw in c for c in caps_lower) for kw in keywords)


_ELK_SVC = {"0000fff0-0000-1000-8000-00805f9b34fb",
             "0000ffe5-0000-1000-8000-00805f9b34fb",
             "0000ffb0-0000-1000-8000-00805f9b34fb"}
_ELK_NAMES = ["elk-ble","elk-bulb","elk-lamp","elkblue","melk","ledble","lednet",
              "led_ble","ledstrip","qhm-led","triones","magic home","ilinker","btle-led","ble-led"]


def _is_elk(dev: BTDevice) -> bool:
    if dev.protocol == "ELK-BLEDOM":
        return True
    if any(kw in (dev.name or "").lower() for kw in _ELK_NAMES):
        return True
    if {s.uuid.lower() for s in dev.services} & _ELK_SVC:
        return True
    return False


def build_attack_menu(dev: BTDevice) -> list[dict]:
    """Dynamically build attack options based on device findings."""
    menu = []

    def add(label: str, tag: str, desc: str = "", **kw):
        menu.append({"label": label, "tag": tag, "desc": desc, **kw})

    # Pre-compute shared sets used throughout the menu builder
    _matched_ids  = {v.cve_id for v in dev.matched_vulns}
    _svc_set      = {s.uuid.lower() for s in dev.services}
    _adv_set      = {u.lower() for u in dev.adv_uuids}
    _char_uuids   = {c.uuid.lower() for c in dev.all_characteristics()}
    _name_vendor  = ((dev.name or "") + " " + (dev.vendor or "")).lower()

    # ── Navigation
    add("Back to target list",         "back")
    add("Show full device details",    "details")

    # ── GATT
    if not dev.gatt_enumerated:
        add("GATT Enumerate (connect + probe)", "gatt",
            desc="Discover services, characteristics, read open values")
    else:
        add("Re-enumerate GATT",               "gatt",
            desc=f"Re-probe ({len(dev.services)} svcs, {dev.open_writes}W {dev.open_reads}R {dev.notifiable}N)")

    # ── Notification capture
    if dev.gatt_enumerated and dev.notifiable > 0:
        add("Subscribe Notifications (30s)",   "notify",
            desc=f"Stream {dev.notifiable} notifiable chars for 30 seconds")

    # ── Open-write attacks
    if dev.gatt_enumerated and dev.open_writes > 0:
        add("Exploit Open Writes",             "exploit",
            desc=f"Write test payloads to {dev.open_writes} unauthenticated writable chars")
        add("Overflow / Boundary Probe",       "overflow_probe",
            desc=f"Test {dev.open_writes} writable char(s) with escalating sizes 0→512B — finds missing length validation and crash bugs")
        add("Mutation Fuzzer",                 "mutfuzz",
            desc=f"Structured mutation fuzzing — bit flips, boundary bytes, length corruption (100 iters)")
        add("Fuzz Characteristics",            "fuzz",
            desc=f"Send random payloads to {dev.open_writes} writable chars (50 iterations)")

    # ── ELK-BLEDOM
    if _is_elk(dev):
        add("ELK-BLEDOM Rainbow PoC",          "elk_rainbow",
            desc="Cycle all colors — unauthenticated LED strip control")

    # ── Capability-based PoCs
    if dev.gatt_enumerated:
        if _has_cap(dev, "audio", "headset", "speaker", "microphone", "volume", "a2dp", "avrcp", "aics", "vcs", "mics"):
            add("Audio Device PoC",            "poc_audio",
                desc="Read device info, subscribe audio notifications, volume probe")
        if _has_cap(dev, "hid", "keyboard", "mouse", "gamepad", "human interface"):
            add("HID Keyboard Injection PoC",  "poc_hid",
                desc="Inject keystrokes via unauthenticated HID report characteristic")
        if _has_cap(dev, "temperature", "humidity", "pressure", "sensor", "environment"):
            add("IoT Sensor Dump",             "poc_sensor",
                desc="Read temperature, humidity, pressure, battery, heart rate")
        if _has_cap(dev, "smart plug", "relay", "outlet", "switch", "energy"):
            add("Smart Plug Control PoC",      "poc_plug",
                desc="Probe on/off/status commands")
        if _has_cap(dev, "fitness", "step", "pedometer", "running", "cycling", "csc", "rsc"):
            add("Fitness Tracker PoC",         "poc_fitness",
                desc="Read steps, heart rate, sync time, battery")
        if _has_cap(dev, "blood pressure", "glucose", "pulse ox", "health", "weight", "bp monitor"):
            add("Health Monitor PoC",          "poc_health",
                desc="Read blood pressure, glucose, pulse oximeter values")
        add("Generic GATT Dump",               "poc_generic",
            desc="Read all open chars, subscribe all notifications, dump values")
        add("Systematic Write Probe",          "poc_write_probe",
            desc="Probe all writable chars with known command patterns")

    # ── Named payloads for this protocol
    proto_payloads = get_payloads_for_protocol(dev.protocol)
    for p in proto_payloads:
        add(f"Payload: {p.name}",              "payload",
            desc=p.description, payload=p)

    # ── DFU / OTA exposure
    _dfu_svcs = {
        "00001530-1212-efde-1523-785feabcd123",  # Nordic DFU
        "1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0",  # Silicon Labs Gecko OTA
        "f000ffc0-0451-4000-b000-000000000000",  # TI OAD
    }
    if _dfu_svcs & (_svc_set | _adv_set):
        add("DFU/OTA Exposure Probe",              "dfu_probe",
            desc="Probe Nordic DFU / Silabs OTA / TI OAD — unauthenticated firmware update")

    # ── Tuya BLE unauth control
    _tuya_svc = "00001910-0000-1000-8000-00805f9b34fb"
    if dev.protocol == "Tuya BLE" or _tuya_svc in _svc_set or "ADV-TUYA-001" in _matched_ids:
        add("Tuya BLE Control PoC (ADV-TUYA-001)", "tuya_control",
            desc="Send power/query commands without authentication via Tuya GATT service")

    # ── Govee unauth control
    _govee_svc = "00010203-0405-0607-0809-0a0b0c0d1910"
    _govee_ctrl = "00010203-0405-0607-0809-0a0b0c0d2b11"
    if _govee_svc in _svc_set or _govee_ctrl in _char_uuids or "CVE-2020-7958" in _matched_ids:
        add("Govee Device Control PoC (CVE-2020-7958)", "govee_control",
            desc="Control Govee smart lights/strips without authentication")

    # ── MiBeacon data disclosure
    _mi_uuid = "0000fe95-0000-1000-8000-00805f9b34fb"
    _has_mi = (
        any("fe95" in k.lower() for k in dev.service_data)
        or _mi_uuid in _adv_set
        or dev.protocol in ("MiBeacon", "Xiaomi")
    )
    if _has_mi:
        add("MiBeacon Decode (ADV-MIBEACON-001)",   "mibeacon",
            desc="Decode unencrypted sensor data broadcast by Xiaomi MiBeacon devices")

    # ── SweynTooth / BrakTooth
    _sweyn_cve_ids = {
        "CVE-2019-16336", "CVE-2019-17517", "CVE-2019-17518", "CVE-2019-17519",
        "CVE-2019-17520", "CVE-2021-28139", "CVE-2021-28135", "CVE-2021-28136",
        "CVE-2019-17061",  "CVE-2021-28137",
    }
    _sweyn_keywords = ["nrf", "nordic", "esp32", "cypress", "telink", "dialog",
                       "da14", "psoc", "cyw", "tlsr"]
    _has_sweyn = (
        bool(_sweyn_cve_ids & _matched_ids)
        or any(kw in _name_vendor for kw in _sweyn_keywords)
    )
    if _has_sweyn and dev.gatt_enumerated:
        add("SweynTooth/BrakTooth Crash Probe",    "sweyntooth",
            desc="GATT-level stability probe for Link Layer crash CVEs (Nordic/ESP32/Cypress)")

    # ── Medical hearing aid unauth access
    _hearing_cves = {"CVE-2019-13473", "CVE-2019-13474"}
    _hearing_kws  = ["signia", "siemens", "widex", "oticon", "phonak", "starkey",
                     "hearing", "resound", "bernafon"]
    _has_hearing = (
        bool(_hearing_cves & _matched_ids)
        or any(kw in _name_vendor for kw in _hearing_kws)
    )
    if _has_hearing:
        add("Hearing Aid Unauth Probe (CVE-2019-13473/74)", "hearing_aid",
            desc="Connect without pairing, read/write audio profiles on medical hearing aids")

    # ── BlueBorne / BleedingTooth / BlueFrag
    _blueborne_cves = {
        "CVE-2017-1000251", "CVE-2017-1000250", "CVE-2017-0781", "CVE-2017-0782",
        "CVE-2020-12351",   "CVE-2020-12352",   "CVE-2020-0022",
        "CVE-2019-8648",    "CVE-2022-30190",   "CVE-2024-21306",
    }
    if _blueborne_cves & _matched_ids:
        add("BlueBorne/BleedingTooth Report",      "blueborne_info",
            desc="Classic BT L2CAP CVE report — l2ping reachability test + remediation notes")

    # ── Nordic UART injection (ADV-UART-001, ADV-UART-002)
    _nus_svc = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
    _has_nus = (
        _nus_svc in _svc_set
        or _nus_svc in _adv_set
        or dev.protocol == "Nordic UART"
        or bool({"ADV-UART-001", "ADV-UART-002"} & _matched_ids)
    )
    if _has_nus:
        add("Nordic UART Command Injection (ADV-UART-002)", "nordic_uart",
            desc="Send AT/binary probes to unauthenticated NUS RX char, capture responses")

    # ── BLE VCS speaker control (ADV-SPEAKER-002)
    _vcs_svc = "00001844-0000-1000-8000-00805f9b34fb"
    _vcs_cp  = "00002b7e-0000-1000-8000-00805f9b34fb"
    _has_vcs = _vcs_svc in _svc_set or _vcs_cp in _char_uuids or "ADV-SPEAKER-002" in _matched_ids
    if _has_vcs:
        add("BLE Speaker Volume Control PoC (ADV-SPEAKER-002)", "speaker_control",
            desc="Mute/set volume via unauthenticated Volume Control Service (VCS)")

    # ── Smart lock access probe (ADV-LOCK-001)
    _lock_svcs = {
        "00003a77-0000-1000-8000-00805f9b34fb",
        "9a66f400-0084-42da-aed1-bc60b8a02476",
        "a92ee100-5501-11e4-916c-0800200c9a66",
        "4fafc201-1fb5-459e-8fcc-c5c9c331914b",
    }
    _lock_kws = ["lock", "deadbolt", "padlock", "door", "entry", "august",
                 "schlage", "yale", "kwikset", "noke", "igloohome", "ultraloq"]
    _has_lock = (
        bool(_lock_svcs & _svc_set)
        or any(kw in _name_vendor for kw in _lock_kws)
    )
    if _has_lock:
        add("Smart Lock Unauth Probe (ADV-LOCK-001)", "smart_lock",
            desc="Read-only recon: enumerate accessible data without authentication (no unlock)")

    # ── iBeacon / Eddystone / Tile passive decode (ADV-IBEACON-001)
    _has_beacon = (
        0x004C in dev.manufacturer_data        # Apple iBeacon / AirTag / FindMy
        or any("feaa" in k.lower() for k in dev.service_data)   # Eddystone
        or any("feed" in u.lower() for u in dev.adv_uuids)      # Tile
        or dev.protocol in ("iBeacon", "Eddystone", "Eddystone-UID", "Eddystone-URL", "Eddystone-TLM")
    )
    if _has_beacon:
        add("iBeacon/Eddystone/Tile Passive Decode (ADV-IBEACON-001)", "ibeacon_track",
            desc="Parse beacon UUID/major/minor, Eddystone URL/UID/TLM, Tile presence — no connection needed")

    # ── WhisperPair (CVE-2025-36911)
    # Show whenever the CVE already matched (name-based: Sony/Jabra/JBL/etc.) OR
    # the Fast Pair service UUID is visible.  Many headphones only advertise 0xfe2c
    # when in pairing mode, so the UUID check alone misses most real targets.
    _fp_svc = "0000fe2c-0000-1000-8000-00805f9b34fb"
    _has_fp = (
        _fp_svc in [s.uuid.lower() for s in dev.services]
        or _fp_svc in [u.lower() for u in dev.adv_uuids]
        or dev.protocol == "Google Fast Pair"
        or "CVE-2025-36911" in _matched_ids
    )
    if _has_fp:
        add("WhisperPair PoC (CVE-2025-36911)",    "whisperpair",
            desc="Probe Fast Pair KBP auth bypass — extract leaked BR/EDR address")

    # ── Reconnection auth-bypass probe
    if dev.gatt_enumerated:
        _auth_gated_count = sum(
            1 for c in dev.all_characteristics()
            if ("read" in c.properties and not c.readable_without_auth)
            or ({"write", "write-without-response"} & set(c.properties) and not c.writable_without_auth)
        )
        if _auth_gated_count > 0:
            add("Reconnection Auth-Bypass Probe (BLESA-style)", "reconnect_bypass",
                desc=f"Test {_auth_gated_count} auth-gated char(s) — does device skip re-auth on reconnect?")

    # ── Auto best PoC
    if dev.gatt_enumerated:
        add("Auto PoC (best match)",           "auto_poc",
            desc="Dispatch to best PoC based on capabilities and protocol")

    # ── CVE info
    if dev.matched_vulns:
        add(f"Show CVE/Advisory details ({dev.vuln_count} entries)", "cve_info",
            desc="Display all matched vulnerabilities with descriptions")

    # ── Export
    add("Export device results",               "export",
        desc="Save findings to JSON/CSV/HTML")

    return menu


def show_attack_menu(dev: BTDevice, menu: list[dict]):
    sc = _SEC_COLOR.get(dev.sec_score, "white")

    # Build colorized flag list
    _fc = {"OPEN_WRITE": "bright_red", "OPEN_READ": "red", "NO_BONDING": "yellow",
           "NOTIFY_UNAUTH": "orange1", "KNOWN_VULN": "bright_red", "WEAK_PAIRING": "yellow",
           "Chinese OEM": "cyan"}
    flag_parts = [f"[{_fc.get(f, 'white')}]{f}[/]" for f in dev.sec_flags]
    flags_str = "  ".join(flag_parts) if flag_parts else "[dim]none[/]"

    gatt_line = (f"\n  [dim]Services:[/] {len(dev.services)}  "
                 f"[bright_red]Open writes:[/] {dev.open_writes}  "
                 f"[red]Open reads:[/] {dev.open_reads}  "
                 f"[orange1]Notifiable:[/] {dev.notifiable}") if dev.gatt_enumerated else \
                "\n  [dim]GATT not yet enumerated[/]"

    vuln_line = ""
    if dev.vuln_count:
        top = dev.known_vuln or ""
        tc = _TYPE_COLOR.get(dev.known_vuln_type or "", "red")
        more = f" [dim]+{dev.vuln_count-1} more[/]" if dev.vuln_count > 1 else ""
        vuln_line = f"\n  [red]CVEs:[/] [{tc}]{top}[/] [dim]{dev.known_vuln_type or ''}[/]{more}"

    bat_line = ""
    if dev.battery is not None:
        bc = "bright_green" if dev.battery > 60 else ("yellow" if dev.battery > 20 else "bright_red")
        bat_line = f"  [{bc}]BAT {dev.battery}%[/]"
    if dev.firmware:
        bat_line += f"  [dim]FW {dev.firmware}[/]"
    if dev.manufacturer_name:
        bat_line += f"  [dim]{dev.manufacturer_name}[/]"
    if bat_line:
        bat_line = "\n " + bat_line

    body = (f"[bold cyan]{dev.mac}[/]  [white]{dev.name or 'Unknown'}[/]  "
            f"[magenta]{dev.protocol}[/]  RSSI=[yellow]{dev.rssi}[/]  "
            f"SEC=[{sc}]{dev.sec_score}[/]"
            f"\n  [bold]Flags:[/] {flags_str}"
            f"{gatt_line}{vuln_line}{bat_line}")

    console.print(Panel(body, title="[bold]Target — Attack Menu[/]", border_style="cyan"))

    t = Table(box=box.SIMPLE, header_style="bold cyan", expand=False)
    t.add_column("#",       width=4,  justify="right", style="bold yellow")
    t.add_column("ATTACK",  width=40, style="bright_white")
    t.add_column("DETAILS", width=60, style="dim")

    for i, item in enumerate(menu):
        tag = item["tag"]
        if tag == "back":
            t.add_row("0", f"[dim]{item['label']}[/]", "")
        elif tag in ("exploit", "elk_rainbow", "poc_hid", "poc_write_probe", "whisperpair",
                     "dfu_probe", "tuya_control", "govee_control", "sweyntooth",
                     "hearing_aid", "blueborne_info", "nordic_uart", "speaker_control",
                     "smart_lock", "ibeacon_track"):
            t.add_row(str(i), f"[bright_red]{item['label']}[/]", item.get("desc", ""))
        elif tag in ("fuzz",):
            t.add_row(str(i), f"[red]{item['label']}[/]", item.get("desc", ""))
        elif tag in ("notify", "poc_audio", "poc_sensor", "poc_fitness", "poc_health", "poc_plug",
                     "poc_generic", "auto_poc", "mibeacon"):
            t.add_row(str(i), f"[cyan]{item['label']}[/]", item.get("desc", ""))
        elif tag == "gatt":
            t.add_row(str(i), f"[green]{item['label']}[/]", item.get("desc", ""))
        elif tag == "cve_info":
            t.add_row(str(i), f"[red]{item['label']}[/]", item.get("desc", ""))
        else:
            t.add_row(str(i), item["label"], item.get("desc", ""))

    console.print(t)


def pick_attack(menu: list[dict]) -> dict | None:
    while True:
        raw = console.input("\n[bold yellow]Select attack #: [/]").strip()
        try:
            idx = int(raw)
            if 0 <= idx < len(menu):
                return menu[idx]
        except ValueError:
            pass
        console.print(f"[red]Enter a number 0–{len(menu)-1}[/]")


# ── Attack runners ────────────────────────────────────────────────────────────

async def run_attack(scanner: BLEScanner, dev: BTDevice, choice: dict, args) -> bool:
    """Execute selected attack. Returns False if user chose 'back'."""
    tag = choice["tag"]

    if tag == "back":
        return False

    if tag == "details":
        console.print(build_detail_panel(dev))
        console.input("[dim]Press Enter to continue...[/]")
        return True

    if tag == "cve_info":
        _show_cve_details(dev)
        console.input("[dim]Press Enter to continue...[/]")
        return True

    if tag == "export":
        _do_export(dev, args)
        return True

    # All connection-based attacks need scanner stopped
    await scanner.pause()
    try:
        if tag == "gatt":
            console.print(f"\n[cyan]Enumerating GATT on {dev.mac}...[/]")
            ok = await enumerate_gatt(dev, timeout=args.timeout)
            if ok:
                scanner._compute_sec_score(dev)
                console.print(build_detail_panel(dev))
            else:
                console.print(f"[red]GATT enumeration failed for {dev.mac}[/]")

        elif tag == "notify":
            log_entries: list[str] = []
            def on_notify(mac, uuid, data):
                line = f"[cyan]{mac}[/] [dim]{uuid}[/] [white]{data.hex()}[/]"
                if data:
                    try:
                        line += f" ([green]{data.decode('utf-8', errors='replace')}[/])"
                    except Exception:
                        pass
                log_entries.append(line)
                console.print(f"  [NOTIFY] {line}")
            console.print(f"\n[cyan]Subscribing to notifications for 30s on {dev.mac}...[/]")
            await subscribe_notifications(dev, on_notify, duration=30.0, timeout=args.timeout)
            console.print(f"\n[green]Captured {len(log_entries)} notifications.[/]")

        elif tag == "exploit":
            console.print(f"\n[bright_red]Exploiting open writes on {dev.mac}...[/]")
            results = await exploit_open_writes(dev, timeout=args.timeout,
                                                log_cb=lambda m: console.print(f"  {m}"))
            _show_write_results(results)

        elif tag == "fuzz":
            writable = [c for c in dev.all_characteristics() if c.writable_without_auth]
            if not writable:
                console.print("[yellow]No writable-without-auth chars found.[/]")
            else:
                console.print(f"\n[red]Fuzzing {len(writable)} char(s) on {dev.mac} (50 iters each)...[/]")
                for char in writable:
                    console.print(f"  Fuzzing [cyan]{char.uuid}[/]")
                    results = await fuzz_characteristic(dev, char.uuid, iterations=50, timeout=args.timeout)
                    _show_write_results(results)

        elif tag == "mutfuzz":
            writable = [c for c in dev.all_characteristics() if c.writable_without_auth]
            if not writable:
                console.print("[yellow]No writable-without-auth chars found.[/]")
            else:
                console.print(f"\n[bright_red]Mutation Fuzzer on {dev.mac} — {len(writable)} char(s), 100 iters each...[/]")
                all_mut: list = []
                for char in writable:
                    mut_results = await fuzz_mutate(
                        dev, char.uuid, iterations=100, timeout=args.timeout,
                        log_cb=lambda m: console.print(f"  {m}"),
                    )
                    all_mut.extend(mut_results)
                _show_mutation_results(all_mut)

        elif tag == "overflow_probe":
            console.print(f"\n[bright_red]Overflow / Boundary Probe on {dev.mac}...[/]")
            findings = await probe_overflow(dev, timeout=args.timeout,
                                            log_cb=lambda m: console.print(f"  {m}"))
            _show_overflow_results(findings)

        elif tag == "reconnect_bypass":
            console.print(f"\n[bright_red]Reconnection Auth-Bypass Probe on {dev.mac}...[/]")
            rb_findings = await poc_reconnect_auth_bypass(
                dev, timeout=args.timeout,
                log_cb=lambda m: console.print(f"  {m}"),
            )
            _show_reconnect_results(rb_findings)

        elif tag == "elk_rainbow":
            console.print(f"\n[bright_red]ELK-BLEDOM Rainbow PoC on {dev.mac}...[/]")
            results = await elk_bledom_rainbow_poc(dev, timeout=args.timeout,
                                                   log_cb=lambda m: console.print(f"  {m}"))
            _show_write_results(results)

        elif tag == "poc_audio":
            console.print(f"\n[cyan]Audio Device PoC on {dev.mac}...[/]")
            await poc_audio_device(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_hid":
            console.print(f"\n[bright_red]HID Injection PoC on {dev.mac}...[/]")
            await poc_hid_injection(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_sensor":
            console.print(f"\n[cyan]IoT Sensor Dump on {dev.mac}...[/]")
            await poc_iot_sensor(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_plug":
            console.print(f"\n[cyan]Smart Plug PoC on {dev.mac}...[/]")
            await poc_smart_plug(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_fitness":
            console.print(f"\n[cyan]Fitness Tracker PoC on {dev.mac}...[/]")
            await poc_fitness_tracker(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_health":
            console.print(f"\n[cyan]Health Monitor PoC on {dev.mac}...[/]")
            await poc_health_monitor(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_generic":
            console.print(f"\n[cyan]Generic GATT Dump on {dev.mac}...[/]")
            await poc_generic_dump(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "poc_write_probe":
            console.print(f"\n[red]Write Probe on {dev.mac}...[/]")
            await poc_write_probe(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "whisperpair":
            console.print(f"\n[bright_red]WhisperPair PoC (CVE-2025-36911) on {dev.mac}...[/]")
            results = await poc_whisperpair(
                dev, log_cb=lambda m: console.print(f"  {m}"),
                timeout=args.timeout, adapter=args.adapter,
            )
            _show_write_results(results)

        elif tag == "dfu_probe":
            console.print(f"\n[bright_red]DFU/OTA Exposure Probe on {dev.mac}...[/]")
            results = await poc_dfu_probe(dev, log_cb=lambda m: console.print(f"  {m}"),
                                          timeout=args.timeout)
            _show_write_results(results)

        elif tag == "tuya_control":
            console.print(f"\n[bright_red]Tuya BLE Control PoC on {dev.mac}...[/]")
            results = await poc_tuya_control(dev, log_cb=lambda m: console.print(f"  {m}"),
                                             timeout=args.timeout)
            _show_write_results(results)

        elif tag == "govee_control":
            console.print(f"\n[bright_red]Govee Control PoC (CVE-2020-7958) on {dev.mac}...[/]")
            results = await poc_govee_control(dev, log_cb=lambda m: console.print(f"  {m}"),
                                              timeout=args.timeout)
            _show_write_results(results)

        elif tag == "mibeacon":
            console.print(f"\n[cyan]MiBeacon Decode on {dev.mac}...[/]")
            results = await poc_mibeacon_decode(dev, log_cb=lambda m: console.print(f"  {m}"),
                                                timeout=args.timeout)
            _show_write_results(results)

        elif tag == "sweyntooth":
            console.print(f"\n[bright_red]SweynTooth/BrakTooth Probe on {dev.mac}...[/]")
            results = await poc_sweyntooth_probe(dev, log_cb=lambda m: console.print(f"  {m}"),
                                                 timeout=args.timeout)
            _show_write_results(results)

        elif tag == "hearing_aid":
            console.print(f"\n[bright_red]Hearing Aid Unauth Probe on {dev.mac}...[/]")
            results = await poc_hearing_aid_probe(dev, log_cb=lambda m: console.print(f"  {m}"),
                                                  timeout=args.timeout)
            _show_write_results(results)

        elif tag == "blueborne_info":
            console.print(f"\n[bright_red]BlueBorne/BleedingTooth Report for {dev.mac}...[/]")
            results = await poc_blueborne_info(dev, log_cb=lambda m: console.print(f"  {m}"),
                                               timeout=args.timeout)
            _show_write_results(results)

        elif tag == "nordic_uart":
            console.print(f"\n[bright_red]Nordic UART Command Injection on {dev.mac}...[/]")
            results = await poc_nordic_uart(dev, log_cb=lambda m: console.print(f"  {m}"),
                                            timeout=args.timeout)
            _show_write_results(results)

        elif tag == "speaker_control":
            console.print(f"\n[bright_red]BLE Speaker Volume Control PoC on {dev.mac}...[/]")
            results = await poc_speaker_control(dev, log_cb=lambda m: console.print(f"  {m}"),
                                                timeout=args.timeout)
            _show_write_results(results)

        elif tag == "smart_lock":
            console.print(f"\n[bright_red]Smart Lock Unauth Probe on {dev.mac}...[/]")
            results = await poc_smart_lock_probe(dev, log_cb=lambda m: console.print(f"  {m}"),
                                                 timeout=args.timeout)
            _show_write_results(results)

        elif tag == "ibeacon_track":
            console.print(f"\n[bright_red]iBeacon/Eddystone/Tile Passive Decode on {dev.mac}...[/]")
            results = await poc_ibeacon_track(dev, log_cb=lambda m: console.print(f"  {m}"),
                                              timeout=args.timeout)
            _show_write_results(results)

        elif tag == "auto_poc":
            console.print(f"\n[cyan]Auto PoC on {dev.mac}...[/]")
            await run_best_poc(dev, log_cb=lambda m: console.print(f"  {m}"), timeout=args.timeout)

        elif tag == "payload":
            payload = choice["payload"]
            console.print(f"\n[cyan]Running payload [{payload.name}] on {dev.mac}...[/]")
            result = await run_payload(dev, payload, timeout=args.timeout)
            console.print(f"  {result}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted.[/]")
    finally:
        await scanner.resume()

    console.input("\n[dim]Press Enter to continue...[/]")
    return True


def _show_write_results(results):
    if not results:
        console.print("  [dim]No results.[/]")
        return
    ok = sum(1 for r in results if r.success)
    console.print(f"\n  [bold]Results: {ok}/{len(results)} writes succeeded[/]")
    for r in results:
        color = "green" if r.success else "dim"
        console.print(f"  [{color}]{r}[/]")


def _show_overflow_results(findings: list):
    if not findings:
        console.print("  [dim]No overflow findings.[/]")
        return

    _sev_color = {
        "CRITICAL": "bright_red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim",
        "INFO":     "dim",
    }
    _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    critical = [f for f in findings if f.severity == "CRITICAL"]
    high     = [f for f in findings if f.severity == "HIGH"]
    medium   = [f for f in findings if f.severity == "MEDIUM"]

    console.print()
    if critical:
        console.print(f"  [bright_red bold]⚠  {len(critical)} CRITICAL — device crashed during probe[/]")
    if high:
        console.print(f"  [red bold]▲  {len(high)} HIGH — oversized write accepted or device disconnected[/]")
    if medium:
        console.print(f"  [yellow]●  {len(medium)} MEDIUM — zero-length accepted or over-MTU write accepted[/]")

    console.print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        batch = sorted([f for f in findings if f.severity == sev], key=lambda f: f.size)
        if not batch:
            continue
        c = _sev_color[sev]
        for f in batch:
            crash_note = ""
            if f.crashed is True:
                crash_note = "  [bright_red]← DEVICE CRASHED[/]"
            elif f.crashed is False:
                crash_note = "  [yellow]← recovered[/]"
            short_uuid = f.char_uuid.upper()[:8] + "…"
            console.print(
                f"  [{c}][{sev:8}][/]  {short_uuid}  "
                f"[white]{f.size:>4}B[/]  {f.detail}{crash_note}"
            )

    console.print()
    total = len(findings)
    actionable = len(critical) + len(high) + len(medium)
    console.print(f"  [bold]Total: {total} findings  ({actionable} actionable)[/]")


def _show_mutation_results(results: list):
    if not results:
        console.print("  [dim]No mutation results.[/]")
        return

    accepted    = sum(1 for r in results if r.outcome == "accepted")
    rejected    = sum(1 for r in results if r.outcome == "rejected")
    timeouts    = sum(1 for r in results if r.outcome == "timeout")
    disconnects = sum(1 for r in results if r.outcome == "disconnect")
    crashes     = sum(1 for r in results if r.crashed)

    console.print()
    console.print(f"  [bold]Mutations: {len(results)}[/]  "
                  f"accept=[green]{accepted}[/]  reject=[dim]{rejected}[/]  "
                  f"timeout=[yellow]{timeouts}[/]  disc=[red]{disconnects}[/]  "
                  f"crash=[bright_red]{crashes}[/]")

    # ATT error breakdown
    err_counts: dict[str, int] = {}
    for r in results:
        if r.att_error:
            err_counts[r.att_error] = err_counts.get(r.att_error, 0) + 1
    if err_counts:
        from scanner.writer import _ATT_DESCRIPTIONS
        console.print()
        console.print("  [bold]ATT error codes seen:[/]")
        for code, cnt in sorted(err_counts.items(), key=lambda x: -x[1]):
            desc  = _ATT_DESCRIPTIONS.get(code, "Unknown")
            color = "yellow" if code == "0x0e" else ("green" if code in ("0x0d", "0x05", "0x0f") else "dim")
            console.print(f"    [{color}]{code}[/]  {desc:<35}  ×{cnt}")

    # Strategy acceptance heatmap
    strat_acc: dict[str, int] = {}
    strat_tot: dict[str, int] = {}
    for r in results:
        strat_tot[r.strategy] = strat_tot.get(r.strategy, 0) + 1
        if r.outcome == "accepted":
            strat_acc[r.strategy] = strat_acc.get(r.strategy, 0) + 1
    if strat_acc:
        console.print()
        console.print("  [bold]Strategies with accepted writes:[/]")
        for strat, cnt in sorted(strat_acc.items(), key=lambda x: -x[1]):
            tot  = strat_tot.get(strat, 0)
            pct  = int(cnt / tot * 100) if tot else 0
            bar  = "█" * (pct // 10)
            console.print(f"    [cyan]{strat:16}[/]  {bar:<10} {pct:3}%  ({cnt}/{tot})")

    # Notable events
    notable = [r for r in results if r.is_notable or r.crashed]
    if notable:
        console.print()
        console.print(f"  [bold red]Notable events ({len(notable)}):[/]")
        for r in notable[:15]:
            c = "bright_red" if r.crashed else ("red" if r.outcome == "disconnect" else "yellow")
            crash_mark = "  [bright_red]← CRASHED[/]" if r.crashed else ""
            console.print(
                f"    [{c}]#{r.iteration:3}[/]  [{r.strategy:15}]  "
                f"[white]{r.payload.hex()[:24]}[/]  → {r.outcome.upper()}{crash_mark}"
            )


def _show_reconnect_results(findings: list):
    if not findings:
        console.print("  [dim]No reconnect findings.[/]")
        return

    _sev_color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "dim", "INFO": "dim"}

    bypasses  = [f for f in findings if f.bypass]
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs     = [f for f in findings if f.severity == "HIGH"]

    console.print()
    if criticals:
        console.print(f"  [bright_red bold]⚠  {len(criticals)} CRITICAL — write bypass: unauthenticated control without pairing[/]")
    if highs and not criticals:
        console.print(f"  [red bold]▲  {len(highs)} HIGH — read bypass or inconsistent auth enforcement[/]")
    if not bypasses:
        console.print("  [green]✓  No auth bypass detected — device correctly re-challenges on reconnect[/]")

    # Phase comparison table header
    console.print()
    console.print(f"  [dim]{'UUID':36}  {'OP':5}  {'Phase1':8}  {'Phase2 (imm)':12}  {'Phase3 (3s)':11}[/]")
    console.print(f"  [dim]{'─'*36}  {'─'*5}  {'─'*8}  {'─'*12}  {'─'*11}[/]")

    outcome_color = {
        "allowed":  "bright_red",
        "blocked":  "green",
        "error":    "dim",
        "timeout":  "yellow",
        "skipped":  "dim",
    }

    for f in sorted(findings, key=lambda x: (x.severity != "CRITICAL", x.severity != "HIGH", x.char_uuid)):
        c   = _sev_color.get(f.severity, "white")
        p1c = outcome_color.get(f.phase1, "white")
        p2c = outcome_color.get(f.phase2, "white")
        p3c = outcome_color.get(f.phase3, "white")
        bypass_mark = "  [bright_red]← BYPASS[/]" if f.bypass else ""
        console.print(
            f"  [{c}]{f.char_uuid[:36]:36}[/]  "
            f"{f.operation:5}  "
            f"[{p1c}]{f.phase1:8}[/]  "
            f"[{p2c}]{f.phase2:12}[/]  "
            f"[{p3c}]{f.phase3:11}[/]"
            f"{bypass_mark}"
        )
        if f.read_value:
            hex_val = f.read_value.hex()
            try:
                txt = f.read_value.decode("utf-8", errors="replace").strip()
                console.print(f"  [dim]  └ value: {hex_val}  ({txt})[/]")
            except Exception:
                console.print(f"  [dim]  └ value: {hex_val}[/]")

    console.print()
    console.print(f"  [bold]Total: {len(findings)} finding(s)  |  {len(bypasses)} bypass(es)[/]")


def _show_cve_details(dev: BTDevice):
    sev_col = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}
    type_col = {"RCE": "bright_red", "DoS": "red", "UnauthWrite": "bright_red",
                "AuthBypass": "orange1", "Inject": "bright_red", "OTA": "yellow",
                "Spoof": "yellow", "InfoDisc": "cyan"}
    console.print(f"\n[bold red]CVE/Advisory matches for {dev.mac} ({dev.name}):[/]\n")
    for v in dev.matched_vulns:
        sc = sev_col.get(v.severity, "white")
        tc = type_col.get(v.vuln_type, "white")
        console.print(f"  [{sc}]{v.severity:8s}[/] [{tc}]{v.vuln_type:12s}[/] [bold]{v.cve_id}[/]")
        console.print(f"           [white]{v.name}[/]")
        console.print(f"           [dim]{v.description}[/]")
        console.print()


def _do_export(dev: BTDevice, args):
    path = args.output if args.output else f"airbt_{dev.mac.replace(':','')}.json"
    export_json([dev], path)
    console.print(f"[green]Exported to {path}[/]")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()

    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    scanner = BLEScanner(rssi_threshold=args.rssi, adapter=args.adapter)

    while True:
        # ── SCAN ──────────────────────────────────────────────────────────────
        devices = await scan_phase(scanner, args)

        if not devices:
            console.print("[yellow]No devices found. Try lowering --rssi (e.g. --rssi -100).[/]")
            return

        # ── PICK TARGET ────────────────────────────────────────────────────────
        while True:
            choice = pick_target(devices)

            if choice is None:
                # quit
                break
            if choice == "rescan":
                # Restart scanner, keep already-probed devices
                scanner._running = False
                old_devs = dict(scanner.devices)
                devices = await scan_phase(scanner, args)
                for mac, dev in old_devs.items():
                    if mac not in scanner.devices:
                        scanner.devices[mac] = dev
                devices = scanner.get_devices()
                continue

            dev: BTDevice = choice

            # Warn about random/private MACs (iOS RPA, Android) upfront
            if is_random_mac(dev.mac):
                console.print(
                    f"\n[yellow]⚠ {dev.mac} uses a BLE random/private address (detected from BlueZ).[/]\n"
                    f"  [dim]iOS and Android rotate this address after unauthenticated disconnects.[/]\n"
                    f"  [dim]If connections fail with 'Device not found', rescan to re-discover.[/]"
                )

            # Auto-probe on first visit if not yet done
            if not dev.gatt_enumerated:
                console.print(f"\n[cyan]Probing {dev.mac} ({dev.name})...[/]")
                await scanner.pause()
                try:
                    ok = await enumerate_gatt(dev, timeout=args.timeout)
                    if ok:
                        scanner._compute_sec_score(dev)
                    else:
                        msg = (f"[yellow]Could not connect to {dev.mac} — showing passive findings only[/]")
                        if is_random_mac(dev.mac):
                            msg += ("\n  [dim]Tip: random-MAC devices (iOS/Android) often reject unauthenticated "
                                    "connections or rotate address immediately. Try while screen is unlocked.[/]")
                        console.print(msg)
                finally:
                    await scanner.resume()

            # Always show full findings panel after probe (or passive data if probe failed)
            console.print()
            console.print(build_detail_panel(dev))

            # ── ATTACK LOOP ────────────────────────────────────────────────────
            while True:
                console.print()
                menu = build_attack_menu(dev)
                show_attack_menu(dev, menu)
                attack = pick_attack(menu)
                if attack is None:
                    break
                stay = await run_attack(scanner, dev, attack, args)
                if not stay:
                    break  # back to target selection

        # Export on exit if requested
        if args.output and scanner.devices:
            devs = list(scanner.devices.values())
            ext = Path(args.output).suffix.lower()
            if ext == ".json":      export_json(devs, args.output)
            elif ext == ".csv":     export_csv(devs, args.output)
            elif ext == ".html":    export_html(devs, args.output)
            else:                   export_json(devs, args.output + ".json")
            console.print(f"[green]Results exported to {args.output}[/]")

        console.print(f"\n[bold green]Done.[/] Scanned {len(scanner.devices)} device(s).")
        break


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
