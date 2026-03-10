# Network Scanner (GUI + CLI)

## GUI 

Run:

```bash
python3 advanced_ip_gui.py
```

Features:
- Enter network in CIDR format (for example `192.168.1.0/24`)
- Start/Stop one-time scan
- Start/Stop live scan (continuous monitoring for new and disappearing devices)
- Search/filter by free text, status, device type, and unknown devices
- Table with `IP`, `MAC`, `Nickname`, `Hostname`, `Ping (ms)`, `Open Ports`, `Device Type`, `Status`
- Save device nicknames linked to MAC addresses (double-click `Nickname` cell or use `Set Nickname`) and reuse them automatically
- Progress bar during scan
- Device type estimation (for example Windows PC, Mac, Router/Modem, Printer)
- Export menu for visible table as CSV/JSON and collected scan history as JSON/CSV
- In-session snapshot/change history for scans and live monitoring
- Live-mode visual highlighting:
  - New devices: green fade animation
  - Disappearing devices: red fade animation before removal

## CLI

Run:

```bash
python3 netscanner.py --network 192.168.1.0/24 --csv devices.csv
```

CLI output and CSV also include:
- `ping_ms` (response time when available)
- `open_ports` (comma-separated list of common open ports)
