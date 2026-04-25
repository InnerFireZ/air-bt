"""
air-bt — Export module
Save scan results to JSON, CSV, or HTML report.
Created by InnerFireZ — https://github.com/InnerFireZ/air-bt
"""

import csv
import json
import html
from datetime import datetime
from pathlib import Path
from models import BTDevice


def _device_to_dict(dev: BTDevice) -> dict:
    return {
        "mac": dev.mac,
        "name": dev.name,
        "vendor": dev.vendor,
        "rssi": dev.rssi,
        "type": dev.device_type,
        "protocol": dev.protocol,
        "tx_power": dev.tx_power,
        "capabilities": dev.capabilities,
        "sec_score": dev.sec_score,
        "sec_flags": dev.sec_flags,
        "known_vuln": dev.known_vuln,
        "open_writes": dev.open_writes,
        "open_reads": dev.open_reads,
        "notifiable": dev.notifiable,
        "gatt_enumerated": dev.gatt_enumerated,
        "first_seen": dev.first_seen.isoformat(),
        "last_seen": dev.last_seen.isoformat(),
        "seen_count": dev.seen_count,
        "adv_uuids": dev.adv_uuids,
        "services": [
            {
                "uuid": svc.uuid,
                "name": svc.name,
                "characteristics": [
                    {
                        "uuid": c.uuid,
                        "handle": c.handle,
                        "description": c.description,
                        "properties": c.properties,
                        "writable_without_auth": c.writable_without_auth,
                        "readable_without_auth": c.readable_without_auth,
                        "notifiable_without_auth": c.notifiable_without_auth,
                        "value": c.value.hex() if c.value else None,
                    }
                    for c in svc.characteristics
                ],
            }
            for svc in dev.services
        ],
    }


def export_json(devices: list[BTDevice], path: str):
    data = {
        "scan_time": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": [_device_to_dict(d) for d in devices],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"[+] JSON exported: {path}")


def export_csv(devices: list[BTDevice], path: str):
    fields = [
        "mac", "name", "vendor", "rssi", "type", "protocol",
        "tx_power", "sec_score", "sec_flags", "known_vuln",
        "open_writes", "open_reads", "notifiable",
        "capabilities", "first_seen", "last_seen", "seen_count",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for dev in devices:
            w.writerow({
                "mac": dev.mac,
                "name": dev.name,
                "vendor": dev.vendor,
                "rssi": dev.rssi,
                "type": dev.device_type,
                "protocol": dev.protocol,
                "tx_power": dev.tx_power,
                "sec_score": dev.sec_score,
                "sec_flags": "|".join(dev.sec_flags),
                "known_vuln": dev.known_vuln or "",
                "open_writes": dev.open_writes,
                "open_reads": dev.open_reads,
                "notifiable": dev.notifiable,
                "capabilities": "|".join(dev.capabilities),
                "first_seen": dev.first_seen.isoformat(),
                "last_seen": dev.last_seen.isoformat(),
                "seen_count": dev.seen_count,
            })
    print(f"[+] CSV exported: {path}")


def export_html(devices: list[BTDevice], path: str):
    score_color = {"A": "#00ff00", "B": "#88ff00", "C": "#ffff00", "D": "#ff8800", "F": "#ff0000", "?": "#888888"}
    rows = ""
    for dev in devices:
        sc = score_color.get(dev.sec_score, "#fff")
        flags = " ".join(dev.sec_flags)
        caps = ", ".join(dev.capabilities)
        rows += f"""
        <tr>
            <td>{html.escape(dev.mac)}</td>
            <td>{html.escape(dev.name)}</td>
            <td>{html.escape(dev.vendor)}</td>
            <td>{dev.rssi}</td>
            <td>{html.escape(dev.device_type)}</td>
            <td>{html.escape(dev.protocol)}</td>
            <td style="color:{sc};font-weight:bold">{dev.sec_score}</td>
            <td>{html.escape(flags)}</td>
            <td>{html.escape(dev.known_vuln or '')}</td>
            <td>{dev.open_writes}</td>
            <td>{dev.open_reads}</td>
            <td>{dev.notifiable}</td>
            <td>{html.escape(caps)}</td>
            <td>{dev.last_seen.strftime('%H:%M:%S')}</td>
        </tr>"""

    page = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>air-bt Scan Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; }}
  h1 {{ color:#58a6ff; }}
  table {{ border-collapse:collapse; width:100%; font-size:12px; }}
  th {{ background:#161b22; color:#58a6ff; padding:6px 10px; border:1px solid #30363d; }}
  td {{ padding:5px 10px; border:1px solid #21262d; }}
  tr:hover {{ background:#161b22; }}
  .badge {{ padding:2px 6px; border-radius:3px; font-size:11px; }}
</style>
</head>
<body>
<h1>air-bt Scan Report</h1>
<p>Generated: {datetime.now().isoformat()} | Devices: {len(devices)}</p>
<table>
<thead>
<tr>
  <th>MAC</th><th>NAME</th><th>VENDOR</th><th>RSSI</th><th>TYPE</th>
  <th>PROTOCOL</th><th>SEC</th><th>FLAGS</th><th>CVE</th>
  <th>OPEN W</th><th>OPEN R</th><th>NOTIFY</th><th>CAPABILITIES</th><th>LAST SEEN</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

    Path(path).write_text(page)
    print(f"[+] HTML report exported: {path}")
