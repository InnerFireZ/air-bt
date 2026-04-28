"""
air-bt — Live TUI display
airodump-ng style real-time table using Rich.
Responsive: adapts column set and widths to terminal size on every render.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import shutil
from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from rich import box

from models import BTDevice

# Security score → color
SCORE_COLOR = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "orange1",
    "F": "bright_red",
    "?": "dim",
}

_TYPE_COLORS = {
    "RCE":         "bright_red",
    "DoS":         "red",
    "AuthBypass":  "orange1",
    "UnauthWrite": "bright_red",
    "Inject":      "bright_red",
    "OTA":         "yellow",
    "Spoof":       "yellow",
    "InfoDisc":    "cyan",
}

_PROTO_COLORS = {
    "MiBeacon":          "bright_magenta",
    "Tuya BLE":          "bright_yellow",
    "Nordic UART":       "bright_cyan",
    "Govee":             "blue",
    "Generic Chinese OEM": "yellow",
    "iBeacon":           "white",
    "Eddystone":         "bright_white",
    "Google Fast Pair":  "bright_blue",
    "ELK-BLEDOM":        "bright_yellow",
}

_FLAG_COLORS = {
    "OPEN_WRITE":    "bright_red",
    "OPEN_READ":     "red",
    "NO_BONDING":    "yellow",
    "NOTIFY_UNAUTH": "orange1",
    "KNOWN_VULN":    "bright_red",
    "WEAK_PAIRING":  "yellow",
    "Chinese OEM":   "cyan",
}


def rssi_bar(rssi: int) -> str:
    if rssi >= -50: return "[bright_green]▂▄▆█[/]"
    if rssi >= -60: return "[green]▂▄▆_[/]"
    if rssi >= -70: return "[yellow]▂▄__[/]"
    if rssi >= -80: return "[red]▂___[/]"
    return "[dim]____[/]"


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n - 1] + "…"


def _sec_flags_str(flags: list[str]) -> str:
    parts = []
    for f in flags:
        c = _FLAG_COLORS.get(f, "white")
        parts.append(f"[{c}]{f}[/]")
    return " ".join(parts) if parts else "[dim]-[/]"


def _cve_cell(dev: BTDevice) -> str:
    if not dev.known_vuln:
        return "[dim]-[/]"
    tc = _TYPE_COLORS.get(dev.known_vuln_type or "", "red")
    cnt = f"[dim]+{dev.vuln_count - 1}[/]" if dev.vuln_count > 1 else ""
    # Type is encoded in colour; omit the text to keep the cell narrow.
    return f"[{tc}]{dev.known_vuln}[/]{cnt}"


def build_main_table(devices: list[BTDevice], mode: str, elapsed: int,
                     probing_mac: str | None = None) -> Table:
    # ── Measure terminal width on every call so resize is instant ────────────
    try:
        term_w = shutil.get_terminal_size().columns
    except Exception:
        term_w = 120

    # Layout breakpoints
    # < 100  → minimal:  MAC RSSI NAME SEC FLAGS CVE
    # 100-129 → compact: + PROTOCOL SVC W R N
    # 130-159 → standard: + VENDOR CAPS SEEN LAST
    # ≥ 160  → full:    + TYPE TX_PWR
    minimal  = term_w < 100
    compact  = 100 <= term_w < 130
    standard = 130 <= term_w < 160
    full     = term_w >= 160

    show_vendor   = standard or full
    show_type     = full
    show_protocol = not minimal
    show_gatt     = not minimal          # SVC / W/O AUTH / R/O AUTH / NOTIFY
    show_caps     = standard or full
    show_txpwr    = full
    show_seen     = standard or full
    show_last     = standard or full

    # Exact accounting of every fixed-width column so remaining space for
    # FLAGS and CVE is correct.  Column widths include Rich's 1-char padding
    # on each side, so content area = width - 2.
    #   width  5 → content 3  (fits 3-char headers like SVC, W/A, SEC)
    #   width  6 → content 4  (fits SEEN header)
    #   width 10 → content 8  (fits HH:MM:SS timestamp)
    _fw = 18 + 10 + 14 + 5   # MAC(18) RSSI(10) NAME(14) SEC(5)
    _fn = 4
    if show_vendor:    _fw += 12; _fn += 1   # VENDOR
    if show_type:      _fw += 7;  _fn += 1   # TYPE
    if show_protocol:  _fw += 12; _fn += 1   # PROTO
    if show_gatt:      _fw += 20; _fn += 4   # SVC(5)+W/A(5)+R/A(5)+NTF(5)
    if show_caps:      _fw += 18; _fn += 1   # CAPS
    if show_txpwr:     _fw += 8;  _fn += 1   # TXPWR
    if show_seen:      _fw += 6;  _fn += 1   # SEEN
    if show_last:      _fw += 10; _fn += 1   # LAST
    # FLAGS + CVE add 2 more columns; total separators = (_fn + 2) - 1
    remaining = max(term_w - _fw - (_fn + 1), 30)
    cve_w   = max(int(remaining * 0.28), 12)
    flags_w = max(remaining - cve_w, 20)

    probed = sum(1 for d in devices if d.gatt_enumerated)
    probe_status = (f"  [yellow]⟳ {probing_mac}[/]" if probing_mac
                    else (f"  [dim]{probed}/{len(devices)} probed[/]" if devices else ""))

    table = Table(
        box=box.MINIMAL_DOUBLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        title=(f"[bold cyan]air-bt[/] | Mode: [yellow]{mode}[/] | "
               f"Devices: [green]{len(devices)}[/] | Elapsed: [white]{elapsed}s[/]"
               f"{probe_status}  [dim]Ctrl+C → select target[/]"),
        title_style="bold",
    )

    # Always-visible columns
    table.add_column("MAC",      style="cyan",           no_wrap=True, width=18)
    if show_vendor:
        table.add_column("VENDOR",   style="white",      no_wrap=True, width=12)
    table.add_column("RSSI",     style="white",          width=10, justify="right")
    if show_type:
        table.add_column("TYPE",     style="bright_blue", no_wrap=True, width=7)
    if show_protocol:
        table.add_column("PROTO",    style="magenta",    no_wrap=True, width=12)
    table.add_column("NAME",     style="bright_white",   no_wrap=True, width=14)
    if show_gatt:
        # width=5 → content=3: fits 3-char headers (SVC, W/A, R/A, NTF) and 2-digit values
        table.add_column("SVC",  style="white",  width=5, justify="right")
        table.add_column("W/A",  style="white",  width=5, justify="right")
        table.add_column("R/A",  style="white",  width=5, justify="right")
        table.add_column("NTF",  style="white",  width=5, justify="right")
    if show_caps:
        table.add_column("CAPS", style="bright_cyan",    width=18)
    table.add_column("SEC",      style="white",          width=5, justify="center")
    table.add_column("FLAGS",    style="white",          width=flags_w)
    table.add_column("CVE",      style="red",            width=cve_w)
    if show_txpwr:
        table.add_column("TXPWR", style="dim",           width=8, justify="right")
    if show_seen:
        # width=6 → content=4: fits "SEEN" header and counts up to 9999
        table.add_column("SEEN", style="dim",            width=6, justify="right")
    if show_last:
        # width=10 → content=8: fits "HH:MM:SS" without truncation
        table.add_column("LAST", style="dim",            width=10)

    for dev in devices:
        is_probing  = probing_mac is not None and dev.mac == probing_mac
        score_color = SCORE_COLOR.get(dev.sec_score, "white")
        sec_text    = f"[{score_color}]{dev.sec_score}[/]"
        rssi_str    = f"{rssi_bar(dev.rssi)} {dev.rssi}"

        if is_probing:
            svc_count = open_w = open_r = notify = "[yellow]⟳[/]"
        elif dev.gatt_enumerated:
            svc_count = str(len(dev.services))
            open_w    = f"[bright_red]{dev.open_writes}[/]"  if dev.open_writes  else "0"
            open_r    = f"[red]{dev.open_reads}[/]"          if dev.open_reads   else "0"
            notify    = str(dev.notifiable)
        else:
            svc_count = open_w = open_r = notify = "[dim]-[/]"

        caps_str  = _truncate(", ".join(dev.capabilities), 18) if dev.capabilities else "[dim]-[/]"
        proto_col = _PROTO_COLORS.get(dev.protocol, "magenta")
        proto_str = f"[{proto_col}]{_truncate(dev.protocol or '?', 12)}[/]"
        mac_cell  = f"[bold yellow]⟳ {dev.mac}[/]" if is_probing else dev.mac
        name_cell = f"[yellow]{_truncate(dev.name or '?', 14)}[/]" if is_probing else _truncate(dev.name or "?", 14)

        row = [mac_cell]
        if show_vendor:   row.append(_truncate(dev.vendor or "?", 14))
        row.append(rssi_str)
        if show_type:     row.append(dev.device_type or "?")
        if show_protocol: row.append(proto_str)
        row.append(name_cell)
        if show_gatt:
            row += [svc_count, open_w, open_r, notify]
        if show_caps:     row.append(caps_str)
        row.append(sec_text)
        row.append(_sec_flags_str(dev.sec_flags))
        row.append(_cve_cell(dev))
        if show_txpwr:    row.append(f"{dev.tx_power} dBm" if dev.tx_power is not None else "[dim]-[/]")
        if show_seen:     row.append(str(dev.seen_count))
        if show_last:     row.append(dev.last_seen.strftime("%H:%M:%S"))

        table.add_row(*row)

    return table


def build_detail_panel(dev: BTDevice) -> Panel:
    """Build a detailed panel for a selected device showing all GATT data."""
    lines = []
    lines.append(f"[bold cyan]{dev.mac}[/]  [white]{dev.name}[/]  [magenta]{dev.protocol}[/]  RSSI=[yellow]{dev.rssi}[/]")
    lines.append(f"Vendor: [white]{dev.vendor}[/]  Type: [blue]{dev.device_type}[/]  TX Power: {dev.tx_power}")
    if dev.battery is not None:
        bc = "bright_green" if dev.battery > 60 else ("yellow" if dev.battery > 20 else "bright_red")
        lines.append(f"Battery: [{bc}]{dev.battery}%[/]" +
                     (f"  Temp: [cyan]{dev.temperature}°C[/]" if dev.temperature is not None else "") +
                     (f"  FW: [dim]{dev.firmware}[/]" if dev.firmware else "") +
                     (f"  Mfr: [dim]{dev.manufacturer_name}[/]" if dev.manufacturer_name else ""))
    lines.append(f"Capabilities: [cyan]{', '.join(dev.capabilities) or '-'}[/]")
    lines.append(f"Security: [bold]{dev.sec_score}[/]  Flags: {_sec_flags_str(dev.sec_flags)}")
    if dev.matched_vulns:
        sev_color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}
        for v in dev.matched_vulns:
            c  = sev_color.get(v.severity, "red")
            tc = _TYPE_COLORS.get(v.vuln_type, "white")
            lines.append(f"  [{c}]{v.cve_id}[/] [dim]{v.vuln_type} · {v.severity}[/]  {v.name}")
    elif dev.known_vuln:
        lines.append(f"[red]CVE/Advisory: {dev.known_vuln}[/]")
    lines.append("")

    if dev.gatt_enumerated:
        for svc in dev.services:
            lines.append(f"  [bold yellow]SERVICE[/] {svc.uuid}  [yellow]{svc.name}[/]")
            for char in svc.characteristics:
                props = ", ".join(char.properties)
                w_flag = "[bright_red]✎ OPEN_WRITE[/]" if char.writable_without_auth else ""
                r_flag = "[red]✔ OPEN_READ[/]"        if char.readable_without_auth  else ""
                n_flag = "[orange1]🔔 NOTIFY[/]"       if char.notifiable_without_auth else ""
                flags  = "  ".join(f for f in [w_flag, r_flag, n_flag] if f)
                val_str = ""
                if char.value:
                    val_str = f"  VALUE=[green]{char.value.hex()}[/]"
                    try:
                        val_str += f" ([white]{char.value.decode('utf-8').strip()}[/])"
                    except Exception:
                        pass
                lines.append(f"    [cyan]CHAR[/] {char.uuid}  [dim]{char.description}[/]  [{props}]{val_str}")
                if flags:
                    lines.append(f"         {flags}")
    else:
        lines.append("[dim]  GATT not yet enumerated[/]")

    if dev.adv_uuids:
        lines.append("")
        lines.append("  [bold]Advertised UUIDs:[/]")
        for u in dev.adv_uuids:
            lines.append(f"    {u}")

    return Panel("\n".join(lines), title=f"[bold]Device Detail: {dev.mac}[/]", border_style="cyan")
