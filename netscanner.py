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
import struct
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


COMMON_PORTS: Tuple[int, ...] = (
    21,
    22,
    23,
    53,
    80,
    139,
    443,
    445,
    515,
    548,
    554,
    631,
    8008,
    8080,
    8443,
    9100,
    1900,
    3389,
    5000,
    5001,
    32400,
    62078,
)


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


def _read_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_offset = offset
    seen = 0

    while offset < len(packet):
        if seen > 64:
            break
        seen += 1
        length = packet[offset]
        if length == 0:
            offset += 1
            break

        # DNS compression pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                break
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
            continue

        offset += 1
        if offset + length > len(packet):
            break
        label = packet[offset : offset + length].decode("utf-8", errors="ignore")
        labels.append(label)
        offset += length

    if not jumped:
        return ".".join(labels), offset
    return ".".join(labels), original_offset


def mdns_reverse_lookup(ip: str, timeout: float = 1.2) -> str:
    """Best-effort mDNS reverse lookup for hostname without external tools."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    rev_name = ".".join(reversed(parts)) + ".in-addr.arpa"

    # Build DNS query packet
    txid = 0  # mDNS usually uses 0
    flags = 0x0000
    qdcount = 1
    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii", errors="ignore") for lbl in rev_name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 12, 1)  # PTR / IN
    packet = header + question

    deadline = time.time() + timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(0.25)
        sock.sendto(packet, ("224.0.0.251", 5353))
    except OSError:
        return ""

    try:
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 12:
                continue
            _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
            offset = 12

            # Skip questions
            for _ in range(qd):
                _, offset = _read_dns_name(data, offset)
                offset += 4
                if offset > len(data):
                    break

            rr_total = an + ns + ar
            for _ in range(rr_total):
                name, offset = _read_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
                offset += 10
                if offset + rdlen > len(data):
                    break

                if rtype == 12 and name.rstrip(".").lower() == rev_name.lower():
                    target, _ = _read_dns_name(data, offset)
                    cleaned = target.strip().strip(".")
                    if cleaned and cleaned.lower() != ip.lower():
                        return cleaned
                offset += rdlen
    finally:
        sock.close()

    return ""


def _encode_netbios_name(name_16: bytes) -> bytes:
    encoded = bytearray()
    for b in name_16:
        encoded.append(ord("A") + ((b >> 4) & 0x0F))
        encoded.append(ord("A") + (b & 0x0F))
    return bytes(encoded)


def netbios_node_status_name(ip: str, timeout: float = 1.0) -> str:
    """NetBIOS Node Status query (UDP/137) for LAN hostnames."""
    try:
        # Wildcard NBSTAT query name: '*' + 15 null bytes
        wildcard = b"*\x00" + (b"\x00" * 14)
        qname = b"\x20" + _encode_netbios_name(wildcard) + b"\x00"
        header = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0)
        question = qname + struct.pack("!HH", 0x0021, 0x0001)  # NBSTAT / IN
        query = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if len(data) < 12:
        return ""

    qd, an = struct.unpack("!xxHH", data[2:8])
    offset = 12
    for _ in range(qd):
        _, offset = _read_dns_name(data, offset)
        offset += 4
        if offset > len(data):
            return ""

    # Parse first answer RDATA name table
    for _ in range(an):
        _, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            return ""
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(data):
            return ""

        if rtype != 0x0021 or rdlen < 1:
            offset += rdlen
            continue

        name_count = data[offset]
        entry_off = offset + 1
        for _ in range(name_count):
            if entry_off + 18 > offset + rdlen:
                break
            raw_name = data[entry_off : entry_off + 15].decode("ascii", errors="ignore").strip()
            suffix = data[entry_off + 15]
            flags = struct.unpack("!H", data[entry_off + 16 : entry_off + 18])[0]
            is_group = (flags & 0x8000) != 0
            entry_off += 18

            if not raw_name or raw_name == "*":
                continue
            if suffix == 0x00 and not is_group:
                return raw_name

        offset += rdlen

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
    """Returnerer hostname med flere fallback-metoder, ellers tom streng."""
    def sanitize(name: str) -> str:
        cleaned = (name or "").strip().strip(".")
        if not cleaned:
            return ""
        lowered = cleaned.lower()
        if lowered in {"?", "unknown", "unknown-host", "localhost"}:
            return ""
        if lowered == ip:
            return ""
        return cleaned

    # 1) Reverse DNS (PTR)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        candidate = sanitize(hostname)
        if candidate:
            return candidate
    except Exception:
        pass

    system = platform.system().lower()

    def reverse_ptr_name(ip_addr: str) -> str:
        parts = ip_addr.split(".")
        if len(parts) != 4:
            return ""
        return ".".join(reversed(parts)) + ".in-addr.arpa"

    # 2) ARP hint (kan inneholde navn på enkelte systemer)
    arp_cmd = ["arp", "-a", ip] if system == "windows" else ["arp", "-an", ip]
    arp_out = run_command(arp_cmd, timeout=1.2)
    if arp_out:
        # Eksempel: "my-host (192.168.1.10) at ..."
        arp_match = re.search(r"^\s*([^\s(]+)\s*\(\s*" + re.escape(ip) + r"\s*\)", arp_out, flags=re.IGNORECASE | re.MULTILINE)
        if arp_match:
            candidate = sanitize(arp_match.group(1))
            if candidate:
                return candidate

    # 3) Ping header (kan avsløre navn lokalt)
    if system == "windows":
        ping_out = run_command(["ping", "-a", "-n", "1", "-w", "700", ip], timeout=1.4)
        ping_match = re.search(r"^Pinging\s+([^\s\[]+)\s+\[", ping_out, flags=re.IGNORECASE | re.MULTILINE)
    else:
        ping_out = run_command(["ping", "-c", "1", ip], timeout=1.2)
        ping_match = re.search(r"^PING\s+([^\s(]+)\s+\(", ping_out, flags=re.IGNORECASE | re.MULTILINE)
    if ping_match:
        candidate = sanitize(ping_match.group(1))
        if candidate:
            return candidate

    # 4) nslookup fallback
    ns_out = run_command(["nslookup", ip], timeout=2.5)
    for pattern in (r"name\s*=\s*([^\s]+)", r"^Name:\s*([^\s]+)"):
        ns_match = re.search(pattern, ns_out, flags=re.IGNORECASE | re.MULTILINE)
        if ns_match:
            candidate = sanitize(ns_match.group(1))
            if candidate:
                return candidate

    # 4b) dig reverse lookup fallback
    dig_out = run_command(["dig", "+short", "-x", ip], timeout=2.0)
    if dig_out:
        for line in dig_out.splitlines():
            candidate = sanitize(line)
            if candidate:
                return candidate

    # 4c) Active mDNS reverse lookup (works for many Apple/mDNS-speaking devices)
    mdns_name = mdns_reverse_lookup(ip, timeout=1.2)
    candidate = sanitize(mdns_name)
    if candidate:
        return candidate

    if system == "darwin":
        # 5) dns-sd PTR query via mDNSResponder (works better for .local on macOS)
        ptr = reverse_ptr_name(ip)
        if ptr:
            dns_sd_out = run_command(["dns-sd", "-Q", ptr, "PTR"], timeout=1.8)
            dns_sd_match = re.search(r"\bPTR\s+([^\s.]+(?:\.[^\s.]+)*)\.?", dns_sd_out, flags=re.IGNORECASE)
            if dns_sd_match:
                candidate = sanitize(dns_sd_match.group(1))
                if candidate:
                    return candidate

        # 6) macOS local resolver cache (often includes mDNS-discovered hosts)
        ds_out = run_command(["dscacheutil", "-q", "host", "-a", "ip_address", ip], timeout=2.5)
        ds_match = re.search(r"^\s*name:\s*([^\s]+)", ds_out, flags=re.IGNORECASE | re.MULTILINE)
        if ds_match:
            candidate = sanitize(ds_match.group(1))
            if candidate:
                return candidate

        # 7) host(1) fallback
        host_out = run_command(["host", ip], timeout=2.5)
        host_match = re.search(r"domain name pointer\s+([^\s.]+(?:\.[^\s.]+)*)\.?", host_out, flags=re.IGNORECASE)
        if host_match:
            candidate = sanitize(host_match.group(1))
            if candidate:
                return candidate

        # 8) macOS SMB lookup fallback for many Windows/LAN devices
        smb_out = run_command(["smbutil", "lookup", ip], timeout=2.5)
        smb_match = re.search(r"^\s*name:\s*([^\s]+)", smb_out, flags=re.IGNORECASE | re.MULTILINE)
        if smb_match:
            candidate = sanitize(smb_match.group(1))
            if candidate:
                return candidate

    # 5) Windows DNS with LLMNR/NetBIOS fallback (PowerShell)
    if system == "windows":
        ps_cmd = (
            "try { "
            f"$r = Resolve-DnsName -Name '{ip}' -Type PTR -LlmnrFallback -NetbiosFallback -ErrorAction Stop; "
            "$r | Select-Object -ExpandProperty NameHost -First 1 "
            "} catch { '' }"
        )
        ps_out = run_command(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=2.0)
        ps_candidate = sanitize(ps_out.splitlines()[0] if ps_out else "")
        if ps_candidate:
            return ps_candidate

    # 6) NetBIOS (Windows LAN-enheter)
    if system == "windows":
        nb_out = run_command(["nbtstat", "-A", ip], timeout=1.8)
        nb_match = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", nb_out, flags=re.IGNORECASE | re.MULTILINE)
        if nb_match:
            candidate = sanitize(nb_match.group(1))
            if candidate:
                return candidate

    # 7) Direct NetBIOS node status query (cross-platform fallback)
    nb_direct = netbios_node_status_name(ip, timeout=1.0)
    candidate = sanitize(nb_direct)
    if candidate:
        return candidate

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

    hostname_map: Dict[str, str] = {}

    def host_worker(ip: str) -> None:
        hostname = resolve_hostname(ip)
        with lock:
            hostname_map[ip] = hostname

    if sorted_alive_ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(sorted_alive_ips))) as executor:
            list(executor.map(host_worker, sorted_alive_ips))

    for ip in sorted_alive_ips:
        devices.append(
            Device(
                ip=ip,
                mac=arp.get(ip, ""),
                hostname=hostname_map.get(ip, ""),
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
