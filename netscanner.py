#!/usr/bin/env python3
"""
En enkel nettverksskanner for IP- og MAC-adresser.

Funksjoner:
- Skanner et IPv4-nettverk (f.eks. 192.168.1.0/24)
- Pinger adresser parallelt for å finne aktive enheter
- Leser MAC-adresser fra ARP-tabellen
- Viser hostname (hvis tilgjengelig)
- Kan eksportere til CSV

Eksempel:
  python netscanner.py --network 192.168.1.0/24 --csv devices.csv
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    alive: bool
    ping_ms: Optional[float]
    open_ports: List[int]


COMMON_PORTS: Tuple[int, ...] = (22, 53, 80, 139, 443, 445, 515, 548, 631, 9100, 1900, 3389)


def run_command(command: List[str], timeout: float = 3.0) -> str:
    """Kjører kommando og returnerer stdout+stderr som tekst."""
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        return completed.stdout or ""
    except subprocess.TimeoutExpired:
        return ""
    except OSError:
        return ""


def parse_ping_latency_ms(output: str) -> Optional[float]:
    """Prøver å parse RTT/latency i millisekunder fra ping-output."""
    for pattern in (
        r"time[=<]?\s*([0-9]+(?:[.,][0-9]+)?)\s*ms",
        r"avg[ =]+([0-9]+(?:[.,][0-9]+)?)",
    ):
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            try:
                return float(match.group(1).replace(",", "."))
            except ValueError:
                return None
    return None


def ping_host_info(ip: str, timeout_ms: int) -> Tuple[bool, Optional[float]]:
    """Pinger en host én gang. Returnerer (alive, latency_ms)."""
    system = platform.system().lower()

    if system == "windows":
        # -n 1 = 1 pakke, -w = timeout i millisekunder
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Linux/macOS: -c 1 = 1 pakke, -W timeout i sekunder (linux)
        # På macOS brukes -W i millisekunder i nyere versjoner; vi bruker også kort total timeout i subprocess.
        timeout_sec = max(1, int(round(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    output = run_command(cmd, timeout=max(1.5, timeout_ms / 1000 + 1.0))
    lowered = output.lower()

    # Treffer både engelsk og enkelte lokale varianter (best effort).
    if "ttl=" in lowered:
        return True, parse_ping_latency_ms(output)
    if "bytes from" in lowered:
        return True, parse_ping_latency_ms(output)
    if "reply from" in lowered:
        return True, parse_ping_latency_ms(output)
    if "1 received" in lowered or "1 packets received" in lowered:
        return True, parse_ping_latency_ms(output)

    return False, None


def ping_host(ip: str, timeout_ms: int) -> bool:
    """Kompatibilitetswrapper som returnerer kun alive."""
    alive, _ = ping_host_info(ip, timeout_ms)
    return alive


def probe_open_ports(ip: str, ports: Tuple[int, ...] = COMMON_PORTS, timeout: float = 0.18) -> Set[int]:
    """Sjekker et sett med vanlige porter og returnerer de som er åpne."""
    open_ports: Set[int] = set()
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.add(port)
        except OSError:
            pass
        finally:
            sock.close()
    return open_ports


def parse_arp_table() -> Dict[str, str]:
    """Leser ARP-tabellen og returnerer mapping ip -> mac."""
    system = platform.system().lower()
    if system == "windows":
        output = run_command(["arp", "-a"], timeout=5)
    else:
        # Fungerer på Linux/macOS i de fleste tilfeller.
        output = run_command(["arp", "-an"], timeout=5)

    ip_to_mac: Dict[str, str] = {}
    for line in output.splitlines():
        mac_match = MAC_RE.search(line)
        if not mac_match:
            continue

        mac = mac_match.group(0).replace("-", ":").lower()

        # Finn IP i linjen
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if not ip_match:
            continue

        ip = ip_match.group(1)
        ip_to_mac[ip] = mac

    return ip_to_mac


def resolve_hostname(ip: str) -> str:
    """Returnerer DNS-hostname hvis tilgjengelig, ellers tom streng."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return ""


def detect_default_network() -> Optional[str]:
    """Prøver å detektere lokalt /24-nett basert på lokal IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        ip_obj = ipaddress.ip_address(local_ip)
        net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
        return str(net)
    except Exception:
        return None


def scan_network(network: str, timeout_ms: int, workers: int) -> List[Device]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(ip) for ip in net.hosts()]

    alive_ips: List[str] = []
    ping_ms_map: Dict[str, Optional[float]] = {}
    lock = threading.Lock()

    def worker(ip: str) -> None:
        alive, latency_ms = ping_host_info(ip, timeout_ms=timeout_ms)
        if alive:
            with lock:
                alive_ips.append(ip)
                ping_ms_map[ip] = latency_ms

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(worker, hosts))

    # Oppdater ARP-tabell etter ping sweep
    arp = parse_arp_table()

    devices: List[Device] = []
    sorted_alive_ips = sorted(alive_ips, key=lambda x: tuple(int(p) for p in x.split(".")))

    open_ports_map: Dict[str, List[int]] = {}

    def port_worker(ip: str) -> None:
        open_ports = sorted(probe_open_ports(ip))
        with lock:
            open_ports_map[ip] = open_ports

    if sorted_alive_ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(sorted_alive_ips))) as executor:
            list(executor.map(port_worker, sorted_alive_ips))

    for ip in sorted_alive_ips:
        devices.append(
            Device(
                ip=ip,
                mac=arp.get(ip, ""),
                hostname=resolve_hostname(ip),
                alive=True,
                ping_ms=ping_ms_map.get(ip),
                open_ports=open_ports_map.get(ip, []),
            )
        )

    return devices


def print_devices(devices: List[Device], elapsed: float, network: str) -> None:
    print(f"Skannet nettverk: {network}")
    print(f"Tid: {elapsed:.2f}s")
    print(f"Aktive enheter: {len(devices)}")
    print()

    if not devices:
        print("Ingen aktive enheter funnet.")
        return

    ip_w = max(len("IP"), *(len(d.ip) for d in devices))
    mac_w = max(len("MAC"), *(len(d.mac) for d in devices))
    host_w = max(len("Hostname"), *(len(d.hostname) for d in devices))
    ping_w = max(len("Ping (ms)"), *(len(f"{d.ping_ms:.2f}") if d.ping_ms is not None else 1 for d in devices))
    ports_w = max(len("Open Ports"), *(len(",".join(str(p) for p in d.open_ports)) if d.open_ports else 1 for d in devices))

    header = f"{'IP':<{ip_w}}  {'MAC':<{mac_w}}  {'Hostname':<{host_w}}  {'Ping (ms)':<{ping_w}}  {'Open Ports':<{ports_w}}"
    print(header)
    print("-" * len(header))

    for d in devices:
        ping_text = f"{d.ping_ms:.2f}" if d.ping_ms is not None else "-"
        ports_text = ",".join(str(p) for p in d.open_ports) if d.open_ports else "-"
        print(f"{d.ip:<{ip_w}}  {d.mac:<{mac_w}}  {d.hostname:<{host_w}}  {ping_text:<{ping_w}}  {ports_text:<{ports_w}}")


def save_csv(devices: List[Device], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "alive", "ping_ms", "open_ports"])
        writer.writeheader()
        for d in devices:
            writer.writerow(
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "hostname": d.hostname,
                    "alive": d.alive,
                    "ping_ms": f"{d.ping_ms:.2f}" if d.ping_ms is not None else "",
                    "open_ports": ",".join(str(p) for p in d.open_ports),
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Skann lokalt nettverk for IP/MAC-adresser.")
    parser.add_argument(
        "--network",
        help="IPv4-nettverk i CIDR-format, f.eks. 192.168.1.0/24",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Ping-timeout i millisekunder per host (default: 600)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=128,
        help="Antall parallelle workers (default: 128)",
    )
    parser.add_argument(
        "--csv",
        help="Lagre resultat til CSV-fil",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    network = args.network
    if not network:
        network = detect_default_network()
        if not network:
            print("Kunne ikke automatisk finne nettverk. Bruk --network, f.eks. 192.168.1.0/24")
            return 1

    try:
        # Valider nettverk
        ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        print(f"Ugyldig nettverk: {network} ({exc})")
        return 1

    start = time.time()
    devices = scan_network(network=network, timeout_ms=max(100, args.timeout), workers=max(1, args.workers))
    elapsed = time.time() - start

    print_devices(devices, elapsed, network)

    if args.csv:
        save_csv(devices, args.csv)
        print(f"\nLagret CSV: {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
