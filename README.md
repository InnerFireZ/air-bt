# air-bt

**Real-time Bluetooth Low Energy security scanner**

Created by **InnerFireZ**

---

## What it does

air-bt passively scans BLE advertisements and **automatically connects** to every discovered device in the background, enumerating GATT services and enriching the live display with:

- Open write / read / notify characteristics (no auth required)
- Security score (A → F)
- Matched CVEs and advisories (53 entries across all major BT attack families)
- Battery, firmware, manufacturer info pulled live
- Protocol detection (MiBeacon, Tuya, ELK-BLEDOM, Nordic UART, iBeacon, Govee, and more)

After scanning, press **Ctrl+C** to enter the interactive menu where you pick a target and an attack from a dynamically built list based on what was found.

---

## Interface

```
air-bt | Mode: probe | Devices: 7 | Elapsed: 34s  ⟳ 70:28:45:XX:XX:XX  Ctrl+C → select target

 MAC               RSSI         NAME              SEC  FLAGS                                    CVE
 ⟳ 70:28:45:XX:XX:XX  ▂▄__-77  Oclean            ?    …                                        …
   BE:58:00:XX:XX:XX  ▂▄▆_-62  ELK-BLEDOM        F    OPEN_WRITE  NO_BONDING                   ADV-ELKBLEDOM-001 UnauthWrite
   94:B3:F7:XX:XX:XX  ▂▄__-75  LG S60TR          C    NOTIFY_UNAUTH                            -
   F0:18:98:XX:XX:XX  ▂___-84  Oclean X Pro      D    OPEN_WRITE  OPEN_READ  NO_BONDING         CVE-2023-24023 AuthBypass+3

╭─ Probe Results ──────────────────────────────────────────────────────────╮
│ BE:58:00:XX:XX:XX  ELK-BLEDOM   2 open-write  ADV-ELKBLEDOM-001          │
│ 70:28:45:XX:XX:XX  Oclean Y3L   4 open-write  2 open-read  CVE-2023-24023│
╰──────────────────────────────────────────────────────────────────────────╯
```

The table **adapts to terminal width** — columns are shown or hidden automatically as you resize.

---

## Attack menu (after selecting a target)

```
╭─ Target — Attack Menu ──────────────────────────────────────────────────╮
│ 70:28:45:XX:XX:XX  Oclean       BLE  RSSI=-77  SEC=F                     │
│ Flags: OPEN_WRITE  OPEN_READ  NO_BONDING  NOTIFY_UNAUTH  KNOWN_VULN      │
│ Services: 6  Open writes: 4  Open reads: 2  Notifiable: 3                │
│ CVEs: CVE-2023-24023 AuthBypass +3 more                                  │
╰─────────────────────────────────────────────────────────────────────────╯

  0  Back to target list
  1  Show full device details
  2  Re-enumerate GATT
  3  Subscribe Notifications (30s)       Stream 3 notifiable chars
  4  Exploit Open Writes                 Write test payloads to 4 unauth writable chars
  5  Fuzz Characteristics                Send random payloads (50 iterations)
  6  IoT Sensor Dump                     Read temperature, humidity, pressure, battery
  7  Generic GATT Dump                   Read all open chars, subscribe notifications
  8  Systematic Write Probe              Probe with known command patterns
  9  Auto PoC (best match)
 10  Show CVE/Advisory details (4 entries)
 11  Export device results
```

Available attacks are built **dynamically** based on what was found during probing — you only see options that are relevant to the specific device.

---

## Supported device PoCs

| PoC | Triggered by |
|-----|-------------|
| ELK-BLEDOM Rainbow | ELK-BLEDOM protocol / LED strip UUIDs |
| Audio Device | VCS / MICS / AICS / ASCS / BASS services |
| HID Keyboard Injection | HID service with open write |
| IoT Sensor Dump | Temperature / humidity / pressure / HR chars |
| Smart Plug Control | GPIO / relay / switch capabilities |
| Fitness Tracker | RSC / CSC / step counter services |
| Health Monitor | Blood pressure / glucose / pulse ox |
| Generic GATT Dump | Any device |
| Systematic Write Probe | Any writable chars |
| Auto PoC | Best match dispatched automatically |

---

## CVE database

53 CVEs and advisories covering:

| Family | CVEs |
|--------|------|
| BlueBorne | CVE-2017-1000251/1000250/0781/0782/0783/0785 |
| BleedingTooth | CVE-2020-12351/12352/24490 |
| BrakTooth | CVE-2021-34143/34145/34146/34147/34148 |
| SweynTooth | CVE-2019-16336/17517/17518/17519/17520/17061 + 4 more |
| BLEEDINGBIT | CVE-2018-16986/7080 |
| Auth attacks | KNOB / BIAS / BLUFFS / BLESA / Invalid Curve |
| HID injection | CVE-2023-45866 (MouseJack / KeyDucky) |
| Android / iOS / Windows | CVE-2020-0022 / CVE-2023-42846 / CVE-2024-21306 |
| IoT unauth write | ELK-BLEDOM / Tuya / MiBeacon advisories |
| Medical devices | CVE-2019-13473/13474 |
| DoS | BLE flood / speaker crash / UART overflow |

Each CVE has: severity (CRITICAL/HIGH/MEDIUM/LOW), type (RCE/DoS/AuthBypass/UnauthWrite/OTA/Spoof/Inject/InfoDisc), and matching logic based on device name patterns, advertised UUIDs, and BT device type.

---

## Requirements

- Linux with BlueZ
- Python 3.11+
- Root / CAP\_NET\_ADMIN (for raw BLE access)

```
sudo apt install bluetooth bluez python3-pip
pip install bleak rich
```

---

## Usage

```bash
# Full scan with auto-probe (recommended)
sudo python3 main.py

# Lower RSSI threshold to catch weak/distant devices
sudo python3 main.py --rssi -100

# Passive only — no connections during scan
sudo python3 main.py --passive

# Different adapter
sudo python3 main.py -i hci1

# Export results on exit
sudo python3 main.py --output results.json

# Verbose logging
sudo python3 main.py -v
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i / --adapter` | `hci0` | HCI adapter |
| `--rssi` | `-80` | Minimum RSSI threshold in dBm |
| `--timeout` | `10.0` | Per-device connection timeout (seconds) |
| `--probe-delay` | `1.5` | Seconds between background probes |
| `--passive` | off | Disable auto-probe connections during scan |
| `--output` | — | Export to `.json` / `.csv` / `.html` on exit |
| `-v / --verbose` | off | Debug logging |


---

## Disclaimer

air-bt is intended for **authorized security testing, research, and educational use only**.
Only scan and test devices you own or have explicit written permission to test.
Unauthorized access to Bluetooth devices may be illegal in your jurisdiction.
The author assumes no liability for misuse.

