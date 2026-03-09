#!/usr/bin/env python3
"""GUI-basert nettverksskanner inspirert av Advanced IP Scanner."""

from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import platform
import queue
import socket
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

from netscanner import detect_default_network, parse_arp_table, ping_host, resolve_hostname


@dataclass
class DeviceRow:
    ip: str
    mac: str = ""
    hostname: str = ""
    device_type: str = "Unknown"
    status: str = "Alive"


COMMON_PORTS = (80, 443, 445, 3389, 22, 139, 548, 515, 631, 9100, 53, 1900)
OUI_DEVICE_HINTS = {
    "00:1a:11": "Router/Network",
    "00:1d:7e": "Router/Network",
    "00:1f:90": "Router/Network",
    "10:62:eb": "Router/Network",
    "28:28:5d": "Router/Network",
    "3c:84:6a": "Router/Network",
    "44:65:0d": "Router/Network",
    "9c:3d:cf": "Router/Network",
    "b0:be:76": "Router/Network",
    "d8:47:32": "Router/Network",
    "00:17:88": "Printer",
    "3c:2a:f4": "Printer",
    "a4:5e:60": "Printer",
    "a8:5e:45": "Printer",
    "b4:b0:24": "Printer",
    "00:1c:b3": "Windows PC",
    "3c:52:82": "Windows PC",
    "54:ee:75": "Windows PC",
    "7c:10:c9": "Windows PC",
    "f0:1f:af": "Windows PC",
    "00:1f:f3": "Apple Device",
    "28:cf:e9": "Apple Device",
    "3c:07:54": "Apple Device",
    "40:30:04": "Apple Device",
    "b8:09:8a": "Apple Device",
    "dc:a6:32": "Apple Device",
    "00:16:6f": "Phone/Tablet",
    "08:ea:44": "Phone/Tablet",
    "34:ab:37": "Phone/Tablet",
    "50:32:75": "Phone/Tablet",
    "c0:ee:fb": "Phone/Tablet",
}


def probe_open_ports(ip: str, timeout: float = 0.18) -> set[int]:
    open_ports: set[int] = set()
    for port in COMMON_PORTS:
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


def classify_device(ip: str, mac: str, hostname: str) -> str:
    host_l = hostname.lower()
    mac_prefix = mac.lower().replace("-", ":")[0:8] if mac else ""

    if any(k in host_l for k in ("router", "gateway", "modem", "mikrotik", "openwrt", "fritz", "unifi")):
        return "Router/Modem"
    if any(k in host_l for k in ("printer", "hp", "epson", "canon", "brother")):
        return "Printer"
    if any(k in host_l for k in ("iphone", "ipad", "android", "pixel", "samsung")):
        return "Phone/Tablet"
    if any(k in host_l for k in ("macbook", "imac", "mac-mini")):
        return "Mac"
    if any(k in host_l for k in ("win-", "desktop-", "laptop-", "surface", "thinkpad")):
        return "Windows PC"
    if any(k in host_l for k in ("nas", "synology", "qnap")):
        return "NAS/Server"

    if mac_prefix in OUI_DEVICE_HINTS:
        return OUI_DEVICE_HINTS[mac_prefix]

    ports = probe_open_ports(ip)
    if 9100 in ports or 631 in ports or 515 in ports:
        return "Printer"
    if 445 in ports or 3389 in ports or 139 in ports:
        return "Windows PC"
    if 548 in ports:
        return "Mac"
    if 53 in ports and 80 in ports:
        return "Router/Modem"
    if 22 in ports:
        return "Linux/Unix Device"
    if 1900 in ports:
        return "Smart Device"
    if 80 in ports or 443 in ports:
        return "Network Device"

    return "Unknown"


class ScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("980x620")
        self.root.minsize(860, 520)

        self._configure_style()

        self._build_ui()

        self.results: Dict[str, DeviceRow] = {}
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.ui_queue: "queue.Queue[tuple]" = queue.Queue()
        self.scan_running = False

        self.root.after(100, self._process_ui_queue)

    def _configure_style(self) -> None:
        self.style = ttk.Style(self.root)
        is_mac = platform.system().lower() == "darwin"

        if is_mac:
            try:
                self.style.theme_use("aqua")
            except tk.TclError:
                pass
        else:
            try:
                self.style.theme_use("clam")
            except tk.TclError:
                pass

        bg = "#ECECEC" if is_mac else "#F2F2F2"
        toolbar_bg = "#E3E3E3" if is_mac else "#E8E8E8"
        table_bg = "#FFFFFF"
        alt_bg = "#F7F9FC"
        font = "SF Pro Text" if is_mac else "Segoe UI"

        self.root.configure(background=bg)

        self.style.configure("App.TFrame", background=bg)
        self.style.configure("Toolbar.TFrame", background=toolbar_bg)
        self.style.configure("App.TLabel", background=bg, font=(font, 12))
        self.style.configure("Toolbar.TLabel", background=toolbar_bg, font=(font, 12))
        self.style.configure(
            "Treeview",
            rowheight=26,
            font=(font, 12),
            background=table_bg,
            fieldbackground=table_bg,
            foreground="#111111",
        )
        self.style.configure("Treeview.Heading", font=(font, 12, "bold"), foreground="#111111")
        self.style.map(
            "Treeview",
            foreground=[("selected", "#111111"), ("!selected", "#111111")],
            background=[("selected", "#DDE8FF"), ("!selected", table_bg)],
        )

        self.table_bg = table_bg
        self.table_alt_bg = alt_bg

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=12, style="App.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)

        controls = ttk.Frame(frame, style="Toolbar.TFrame", padding=(12, 10))
        controls.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(controls, text="Network (CIDR):", style="Toolbar.TLabel").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4
        )
        self.network_var = tk.StringVar(value=detect_default_network() or "192.168.1.0/24")
        self.network_entry = ttk.Entry(controls, textvariable=self.network_var, width=24)
        self.network_entry.grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(controls, text="Timeout (ms):", style="Toolbar.TLabel").grid(
            row=0, column=2, sticky=tk.W, padx=(18, 8), pady=4
        )
        self.timeout_var = tk.StringVar(value="600")
        ttk.Entry(controls, textvariable=self.timeout_var, width=8).grid(row=0, column=3, sticky=tk.W, pady=4)

        ttk.Label(controls, text="Workers:", style="Toolbar.TLabel").grid(row=0, column=4, sticky=tk.W, padx=(18, 8), pady=4)
        self.workers_var = tk.StringVar(value="128")
        ttk.Entry(controls, textvariable=self.workers_var, width=8).grid(row=0, column=5, sticky=tk.W, pady=4)

        button_frame = ttk.Frame(controls)
        button_frame.grid(row=0, column=6, sticky=tk.E, padx=(20, 0))

        self.scan_btn = ttk.Button(button_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.export_btn = ttk.Button(button_frame, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)

        status_frame = ttk.Frame(frame)
        status_frame.pack(fill=tk.X, pady=(10, 6))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, style="App.TLabel").pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(14, 0))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        columns = ("status", "ip", "mac", "hostname", "device_type")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("status", text="Status")
        self.tree.heading("ip", text="IP")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("device_type", text="Device Type")

        self.tree.column("status", width=90, anchor=tk.W)
        self.tree.column("ip", width=165, anchor=tk.W)
        self.tree.column("mac", width=210, anchor=tk.W)
        self.tree.column("hostname", width=290, anchor=tk.W)
        self.tree.column("device_type", width=190, anchor=tk.W)

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.tag_configure("odd", background=self.table_bg)
        self.tree.tag_configure("even", background=self.table_alt_bg)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def start_scan(self) -> None:
        if self.scan_running:
            return

        try:
            network = str(ipaddress.ip_network(self.network_var.get().strip(), strict=False))
            timeout_ms = max(100, int(self.timeout_var.get().strip()))
            workers = max(1, int(self.workers_var.get().strip()))
        except ValueError as exc:
            messagebox.showerror("Invalid Input", f"Sjekk inputverdier:\n{exc}")
            return

        self.network_var.set(network)
        self._clear_table()

        self.scan_running = True
        self.stop_event.clear()
        self.scan_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.export_btn.configure(state=tk.DISABLED)
        self.status_var.set(f"Scanning {network}...")

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(network, timeout_ms, workers),
            daemon=True,
        )
        self.scan_thread.start()

    def stop_scan(self) -> None:
        if self.scan_running:
            self.stop_event.set()
            self.status_var.set("Stopping scan...")

    def export_csv(self) -> None:
        if not self.results:
            return

        path = filedialog.asksaveasfilename(
            title="Export results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "device_type", "status"])
            writer.writeheader()
            for row in sorted(self.results.values(), key=lambda d: tuple(int(p) for p in d.ip.split("."))):
                writer.writerow(
                    {
                        "ip": row.ip,
                        "mac": row.mac,
                        "hostname": row.hostname,
                        "device_type": row.device_type,
                        "status": row.status,
                    }
                )

        self.status_var.set(f"Exported: {path}")

    def _scan_worker(self, network: str, timeout_ms: int, workers: int) -> None:
        started = time.time()
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        total = len(hosts)
        processed = 0
        alive: List[str] = []

        self.ui_queue.put(("progress_setup", total))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(ping_host, ip, timeout_ms): ip for ip in hosts}

            for future in concurrent.futures.as_completed(future_to_ip):
                if self.stop_event.is_set():
                    break

                ip = future_to_ip[future]
                processed += 1

                is_alive = False
                try:
                    is_alive = future.result()
                except Exception:
                    is_alive = False

                self.ui_queue.put(("progress", processed, total))

                if is_alive:
                    alive.append(ip)
                    self.ui_queue.put(("row_alive", ip))

            if self.stop_event.is_set():
                for future in future_to_ip:
                    future.cancel()

        if not self.stop_event.is_set() and alive:
            arp = parse_arp_table()
            for ip in alive:
                mac = arp.get(ip, "")
                hostname = resolve_hostname(ip)
                device_type = classify_device(ip, mac, hostname)
                self.ui_queue.put(("row_update", ip, mac, hostname, device_type))

        elapsed = time.time() - started
        self.ui_queue.put(("scan_done", elapsed, self.stop_event.is_set()))

    def _process_ui_queue(self) -> None:
        while True:
            try:
                event = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            kind = event[0]

            if kind == "progress_setup":
                total = event[1]
                self.progress.configure(maximum=max(1, total), value=0)
            elif kind == "progress":
                processed, total = event[1], event[2]
                self.progress.configure(maximum=max(1, total), value=processed)
                self.status_var.set(f"Scanning... {processed}/{total}")
            elif kind == "row_alive":
                ip = event[1]
                row = DeviceRow(ip=ip)
                self.results[ip] = row
                tag = "even" if len(self.results) % 2 == 0 else "odd"
                self.tree.insert(
                    "",
                    tk.END,
                    iid=ip,
                    values=(row.status, row.ip, row.mac, row.hostname, row.device_type),
                    tags=(tag,),
                )
            elif kind == "row_update":
                ip, mac, hostname, device_type = event[1], event[2], event[3], event[4]
                if ip in self.results:
                    self.results[ip].mac = mac
                    self.results[ip].hostname = hostname
                    self.results[ip].device_type = device_type
                    row = self.results[ip]
                    self.tree.item(ip, values=(row.status, row.ip, row.mac, row.hostname, row.device_type))
            elif kind == "scan_done":
                elapsed, stopped = event[1], event[2]
                self.scan_running = False
                self.scan_btn.configure(state=tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                self.export_btn.configure(state=tk.NORMAL if self.results else tk.DISABLED)
                if stopped:
                    self.status_var.set(f"Stopped. Found {len(self.results)} active hosts in {elapsed:.2f}s")
                else:
                    self.status_var.set(f"Finished. Found {len(self.results)} active hosts in {elapsed:.2f}s")

        self.root.after(100, self._process_ui_queue)

    def _clear_table(self) -> None:
        self.results.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.progress.configure(maximum=100, value=0)


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
