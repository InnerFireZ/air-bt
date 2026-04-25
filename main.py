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
from rich.spinner import Spinner
from rich.status import Status
from rich import box

from scanner.ble import BLEScanner
from scanner.gatt import enumerate_gatt, subscribe_notifications
from scanner.writer import exploit_open_writes, fuzz_characteristic, run_payload, elk_bledom_rainbow_poc
from scanner.poc import (
    poc_generic_dump, poc_audio_device, poc_hid_injection,
    poc_iot_sensor, poc_smart_plug, poc_fitness_tracker,
    poc_health_monitor, poc_write_probe, run_best_poc,
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
        elif tag in ("exploit", "elk_rainbow", "poc_hid", "poc_write_probe"):
            t.add_row(str(i), f"[bright_red]{item['label']}[/]", item.get("desc", ""))
        elif tag in ("fuzz",):
            t.add_row(str(i), f"[red]{item['label']}[/]", item.get("desc", ""))
        elif tag in ("notify", "poc_audio", "poc_sensor", "poc_fitness", "poc_health", "poc_plug", "poc_generic", "auto_poc"):
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
        with console.status(f"[cyan]Connecting to {dev.mac}...[/]", spinner="dots"):
            pass  # status shown during actual call below

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

            # Auto-probe on first visit if not yet done
            if not dev.gatt_enumerated:
                console.print(f"\n[cyan]Probing {dev.mac} ({dev.name})...[/]")
                await scanner.pause()
                try:
                    ok = await enumerate_gatt(dev, timeout=args.timeout)
                    if ok:
                        scanner._compute_sec_score(dev)
                    else:
                        console.print(f"[yellow]Could not connect to {dev.mac} — showing passive findings only[/]")
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
