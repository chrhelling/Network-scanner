# Nettverksskanner (GUI + CLI)

## GUI (Advanced IP Scanner-lignende)

Kjør:

```bash
python3 advanced_ip_gui.py
```

Funksjoner:
- Skriv inn nettverk i CIDR (f.eks. `192.168.1.0/24`)
- Start/Stop scan
- Tabell med `IP`, `MAC`, `Hostname`, `Device Type`, `Status`
- Progresjonslinje under scanning
- Enhetstype-estimering (f.eks. Windows PC, Mac, Router/Modem, Printer)
- Eksport til CSV (inkluderer `device_type`)

## CLI

Kjør:

```bash
python3 netscanner.py --network 192.168.1.0/24 --csv devices.csv
```
