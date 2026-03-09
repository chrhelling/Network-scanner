# Nettverksskanner (GUI + CLI)

## GUI (Advanced IP Scanner-lignende)

Kjør:

```bash
python3 advanced_ip_gui.py
```

Funksjoner:
- Skriv inn nettverk i CIDR (f.eks. `192.168.1.0/24`)
- Start/Stop scan
- Tabell med `IP`, `MAC`, `Hostname`, `Ping (ms)`, `Open Ports`, `Device Type`, `Status`
- Progresjonslinje under scanning
- Enhetstype-estimering (f.eks. Windows PC, Mac, Router/Modem, Printer)
- Eksport til CSV (inkluderer `ping_ms` og `open_ports`)

## CLI

Kjør:

```bash
python3 netscanner.py --network 192.168.1.0/24 --csv devices.csv
```

CLI-utskrift og CSV inneholder nå også:
- `ping_ms` (responstid når tilgjengelig)
- `open_ports` (kommaseparert liste med vanlige åpne porter)
