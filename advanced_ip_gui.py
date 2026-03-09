#!/usr/bin/env python3
"""GUI-basert nettverksskanner inspirert av Advanced IP Scanner."""

from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import platform
import queue
import threading
import math
import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Set

from netscanner import detect_default_network, parse_arp_table, ping_host_info, probe_open_ports, resolve_hostname


@dataclass
class DeviceRow:
    ip: str
    mac: str = ""
    hostname: str = ""
    device_type: str = "Unknown"
    status: str = "Alive"
    ping_ms: str = "-"
    open_ports: str = "-"
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


def classify_device(mac: str, hostname: str, ports: Set[int]) -> str:
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

        self.results: Dict[str, DeviceRow] = {}
        self.scan_thread: Optional[threading.Thread] = None
        self.live_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.live_stop_event = threading.Event()
        self.ui_queue: "queue.Queue[tuple]" = queue.Queue()
        self.scan_running = False
        self.live_running = False
        self.row_base_tag: Dict[str, str] = {}
        self.highlight_tokens: Dict[str, int] = {}
        self.remove_tokens: Dict[str, int] = {}
        self.live_detail_cache: Dict[str, DeviceRow] = {}

        self._configure_style()
        self._build_ui()

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
        table_bg = "#12161C"
        alt_bg = "#1A212A"
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
            foreground="#F2F5F8",
        )
        self.style.configure(
            "Treeview.Heading",
            font=(font, 12, "bold"),
            foreground="#F2F5F8",
            background="#242D38",
        )
        self.style.map(
            "Treeview",
            foreground=[("selected", "#FFFFFF")],
            background=[("selected", "#2E5D97")],
        )

        self.table_bg = table_bg
        self.table_alt_bg = alt_bg

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=12, style="App.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)

        self.controls = ttk.Frame(frame, style="Toolbar.TFrame", padding=(12, 10))
        self.controls.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self.controls, text="Network (CIDR):", style="Toolbar.TLabel").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4
        )
        self.network_var = tk.StringVar(value=detect_default_network() or "192.168.1.0/24")
        self.network_entry = ttk.Entry(self.controls, textvariable=self.network_var, width=24)
        self.network_entry.grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(self.controls, text="Timeout (ms):", style="Toolbar.TLabel").grid(
            row=0, column=2, sticky=tk.W, padx=(18, 8), pady=4
        )
        self.timeout_var = tk.StringVar(value="600")
        ttk.Entry(self.controls, textvariable=self.timeout_var, width=8).grid(row=0, column=3, sticky=tk.W, pady=4)

        ttk.Label(self.controls, text="Workers:", style="Toolbar.TLabel").grid(
            row=0, column=4, sticky=tk.W, padx=(18, 8), pady=4
        )
        self.workers_var = tk.StringVar(value="128")
        ttk.Entry(self.controls, textvariable=self.workers_var, width=8).grid(row=0, column=5, sticky=tk.W, pady=4)

        ttk.Label(self.controls, text="Live (sec):", style="Toolbar.TLabel").grid(
            row=0, column=6, sticky=tk.W, padx=(18, 8), pady=4
        )
        self.live_interval_var = tk.StringVar(value="10")
        ttk.Entry(self.controls, textvariable=self.live_interval_var, width=6).grid(row=0, column=7, sticky=tk.W, pady=4)

        self.button_frame = ttk.Frame(self.controls)
        self.button_frame.grid(row=0, column=8, sticky=tk.E, padx=(20, 0))

        self.scan_btn = ttk.Button(self.button_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = ttk.Button(self.button_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)

        self.live_btn = ttk.Button(self.button_frame, text="Start Live", command=self.start_live_scan)
        self.live_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.live_stop_btn = ttk.Button(self.button_frame, text="Stop Live", command=self.stop_live_scan, state=tk.DISABLED)

        self.export_btn = ttk.Button(self.button_frame, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)

        self.controls.columnconfigure(8, weight=1)
        self.controls.bind("<Configure>", self._on_controls_resize)
        self._refresh_action_buttons()

        status_frame = ttk.Frame(frame)
        status_frame.pack(fill=tk.X, pady=(10, 6))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, style="App.TLabel").pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(14, 0))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        columns = ("status", "ip", "mac", "hostname", "ping_ms", "open_ports", "device_type")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("status", text="Status")
        self.tree.heading("ip", text="IP")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("ping_ms", text="Ping (ms)")
        self.tree.heading("open_ports", text="Open Ports")
        self.tree.heading("device_type", text="Device Type")

        self.tree.column("status", width=90, anchor=tk.W)
        self.tree.column("ip", width=165, anchor=tk.W)
        self.tree.column("mac", width=190, anchor=tk.W)
        self.tree.column("hostname", width=240, anchor=tk.W)
        self.tree.column("ping_ms", width=100, anchor=tk.W)
        self.tree.column("open_ports", width=210, anchor=tk.W)
        self.tree.column("device_type", width=170, anchor=tk.W)

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.tag_configure("odd", background=self.table_bg)
        self.tree.tag_configure("even", background=self.table_alt_bg)
        self.tree.tag_configure("new_device", background="#1F4D2E", foreground="#F4FFF7")

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def _on_controls_resize(self, event: tk.Event) -> None:
        # Move action buttons to a second row on narrow widths so controls stay visible.
        narrow = event.width < 1180
        if narrow:
            self.button_frame.grid_configure(row=1, column=0, columnspan=9, sticky=tk.W, padx=(0, 0), pady=(6, 0))
        else:
            self.button_frame.grid_configure(row=0, column=8, columnspan=1, sticky=tk.E, padx=(20, 0), pady=(0, 0))

    def _refresh_action_buttons(self) -> None:
        for widget in (self.scan_btn, self.stop_btn, self.live_btn, self.live_stop_btn, self.export_btn):
            widget.pack_forget()

        if self.scan_running:
            self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))
        else:
            self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        if self.live_running:
            self.live_stop_btn.pack(side=tk.LEFT, padx=(0, 6))
        else:
            self.live_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.export_btn.pack(side=tk.LEFT)

    @staticmethod
    def _hex_to_rgb(color: str) -> tuple[int, int, int]:
        color = color.lstrip("#")
        return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)

    @staticmethod
    def _rgb_to_hex(r: int, g: int, b: int) -> str:
        return f"#{r:02X}{g:02X}{b:02X}"

    def _row_highlight_tag(self, ip: str) -> str:
        return f"new_device_{ip.replace('.', '_')}"

    def _row_remove_tag(self, ip: str) -> str:
        return f"remove_device_{ip.replace('.', '_')}"

    @staticmethod
    def _ip_key(ip: str) -> tuple[int, int, int, int]:
        return tuple(int(p) for p in ip.split("."))

    def _is_special_tag_active(self, ip: str) -> bool:
        if not self.tree.exists(ip):
            return False
        tags = self.tree.item(ip, "tags")
        if not tags:
            return False
        first = tags[0]
        return first.startswith("new_device_") or first.startswith("remove_device_")

    def _set_row_values(self, ip: str, row: DeviceRow) -> None:
        if not self.tree.exists(ip):
            return
        self.tree.item(
            ip,
            values=(row.status, row.ip, row.mac, row.hostname, row.ping_ms, row.open_ports, row.device_type),
        )

    def _fade_remove_step(self, ip: str, token: int, step: int, steps: int, start_color: str, end_color: str) -> None:
        if self.remove_tokens.get(ip) != token:
            return
        if not self.tree.exists(ip):
            return

        if step >= steps:
            self.tree.delete(ip)
            self.results.pop(ip, None)
            self.row_base_tag.pop(ip, None)
            self.remove_tokens.pop(ip, None)
            self.highlight_tokens.pop(ip, None)
            return

        sr, sg, sb = self._hex_to_rgb(start_color)
        er, eg, eb = self._hex_to_rgb(end_color)
        t_linear = step / steps
        t = 1.0 - math.pow(1.0 - t_linear, 3)
        r = int(sr + (er - sr) * t)
        g = int(sg + (eg - sg) * t)
        b = int(sb + (eb - sb) * t)

        tag = self._row_remove_tag(ip)
        self.tree.tag_configure(tag, background=self._rgb_to_hex(r, g, b), foreground="#F2F5F8")
        self.tree.item(ip, tags=(tag,))

    def _start_remove_fade(self, ip: str) -> None:
        if not self.tree.exists(ip):
            return
        token = self.remove_tokens.get(ip, 0) + 1
        self.remove_tokens[ip] = token

        row = self.results.get(ip)
        if row:
            row.status = "Offline"
            self._set_row_values(ip, row)

        base_tag = self.row_base_tag.get(ip, "odd")
        end_color = self.table_alt_bg if base_tag == "even" else self.table_bg
        start_color = "#FF0000"
        steps = 100
        interval_ms = 8000 // steps

        for step in range(steps + 1):
            self.root.after(
                step * interval_ms,
                lambda ip=ip, token=token, step=step, steps=steps, start_color=start_color, end_color=end_color: self._fade_remove_step(
                    ip, token, step, steps, start_color, end_color
                ),
            )

    def _sync_live_table(self, rows: Dict[str, DeviceRow], new_ips: List[str]) -> None:
        new_ip_set = set(new_ips)
        current_ips = set(rows.keys())
        previous_ips = set(self.results.keys())

        removed_ips = sorted(previous_ips - current_ips, key=self._ip_key)
        for ip in removed_ips:
            if ip not in self.remove_tokens:
                self._start_remove_fade(ip)

        for ip in sorted(current_ips, key=self._ip_key):
            row = rows[ip]
            self.results[ip] = row

            if ip in self.remove_tokens:
                # Host came back before removal completed.
                self.remove_tokens.pop(ip, None)

            if self.tree.exists(ip):
                self._set_row_values(ip, row)
            else:
                self.tree.insert(
                    "",
                    tk.END,
                    iid=ip,
                    values=(row.status, row.ip, row.mac, row.hostname, row.ping_ms, row.open_ports, row.device_type),
                    tags=("odd",),
                )

        visible_ips = sorted((ip for ip in self.tree.get_children() if ip in current_ips), key=self._ip_key)
        for idx, ip in enumerate(visible_ips, start=1):
            base_tag = "even" if idx % 2 == 0 else "odd"
            self.row_base_tag[ip] = base_tag
            self.tree.move(ip, "", idx - 1)
            if not self._is_special_tag_active(ip):
                self.tree.item(ip, tags=(base_tag,))

        for ip in new_ips:
            if ip in self.results and self.tree.exists(ip):
                self._highlight_new_device(ip)

    def _fade_step(self, ip: str, token: int, step: int, steps: int, start_color: str, end_color: str) -> None:
        if self.highlight_tokens.get(ip) != token:
            return
        if not self.tree.exists(ip):
            return

        base_tag = self.row_base_tag.get(ip, "odd")
        if step >= steps:
            if ip in self.remove_tokens:
                return
            self.tree.item(ip, tags=(base_tag,))
            return

        sr, sg, sb = self._hex_to_rgb(start_color)
        er, eg, eb = self._hex_to_rgb(end_color)
        # Ease-out cubic gives a smoother visual decay than linear fade.
        t_linear = step / steps
        t = 1.0 - math.pow(1.0 - t_linear, 3)
        r = int(sr + (er - sr) * t)
        g = int(sg + (eg - sg) * t)
        b = int(sb + (eb - sb) * t)

        tag = self._row_highlight_tag(ip)
        self.tree.tag_configure(tag, background=self._rgb_to_hex(r, g, b), foreground="#F2F5F8")
        self.tree.item(ip, tags=(tag,))

    def _highlight_new_device(self, ip: str) -> None:
        if not self.tree.exists(ip):
            return
        if ip in self.remove_tokens:
            return
        token = self.highlight_tokens.get(ip, 0) + 1
        self.highlight_tokens[ip] = token
        base_tag = self.row_base_tag.get(ip, "odd")
        end_color = self.table_alt_bg if base_tag == "even" else self.table_bg
        start_color = "#00FF00"
        steps = 100
        interval_ms = 8000 // steps

        for step in range(steps + 1):
            self.root.after(
                step * interval_ms,
                lambda ip=ip, token=token, step=step, steps=steps, start_color=start_color, end_color=end_color: self._fade_step(
                    ip, token, step, steps, start_color, end_color
                ),
            )

    def start_scan(self) -> None:
        if self.scan_running or self.live_running:
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
        self.stop_btn.configure(state=tk.NORMAL)
        self.scan_btn.configure(state=tk.NORMAL)
        self.live_btn.configure(state=tk.DISABLED)
        self.live_stop_btn.configure(state=tk.DISABLED)
        self.export_btn.configure(state=tk.DISABLED)
        self._refresh_action_buttons()
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

    def start_live_scan(self) -> None:
        if self.live_running or self.scan_running:
            return

        try:
            network = str(ipaddress.ip_network(self.network_var.get().strip(), strict=False))
            timeout_ms = max(100, int(self.timeout_var.get().strip()))
            workers = max(1, int(self.workers_var.get().strip()))
            interval_sec = max(3, int(self.live_interval_var.get().strip()))
        except ValueError as exc:
            messagebox.showerror("Invalid Input", f"Sjekk inputverdier:\n{exc}")
            return

        self.network_var.set(network)
        self._clear_table()
        self.live_running = True
        self.live_stop_event.clear()
        self.scan_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.DISABLED)
        self.live_btn.configure(state=tk.NORMAL)
        self.live_stop_btn.configure(state=tk.NORMAL)
        self.export_btn.configure(state=tk.DISABLED)
        self._refresh_action_buttons()
        self.status_var.set(f"Live scanner aktiv ({interval_sec}s intervall)...")

        self.live_thread = threading.Thread(
            target=self._live_worker,
            args=(network, timeout_ms, workers, interval_sec),
            daemon=True,
        )
        self.live_thread.start()

    def stop_live_scan(self) -> None:
        if self.live_running:
            self.live_stop_event.set()
            self.status_var.set("Stopping live scanner...")

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
            writer = csv.DictWriter(
                f,
                fieldnames=["ip", "mac", "hostname", "ping_ms", "open_ports", "device_type", "status"],
            )
            writer.writeheader()
            for row in sorted(self.results.values(), key=lambda d: tuple(int(p) for p in d.ip.split("."))):
                writer.writerow(
                    {
                        "ip": row.ip,
                        "mac": row.mac,
                        "hostname": row.hostname,
                        "ping_ms": row.ping_ms,
                        "open_ports": row.open_ports,
                        "device_type": row.device_type,
                        "status": row.status,
                    }
                )

        self.status_var.set(f"Exported: {path}")

    def _scan_worker(self, network: str, timeout_ms: int, workers: int) -> None:
        started = time.time()
        self.live_detail_cache.clear()
        self._collect_snapshot(network, timeout_ms, workers, live_mode=False, emit_rows=True)
        elapsed = time.time() - started
        self.ui_queue.put(("scan_done", elapsed, self.stop_event.is_set()))

    def _live_worker(self, network: str, timeout_ms: int, workers: int, interval_sec: int) -> None:
        baseline_done = False
        previous_ips: Set[str] = set()

        while not self.live_stop_event.is_set():
            cycle_started = time.time()
            rows = self._collect_snapshot(network, timeout_ms, workers, live_mode=True)
            if self.live_stop_event.is_set():
                break

            current_ips = set(rows.keys())
            new_ips = sorted(current_ips - previous_ips, key=lambda x: tuple(int(p) for p in x.split(".")))
            if not baseline_done:
                new_ips = []
                baseline_done = True

            self.ui_queue.put(("live_cycle", rows, new_ips))
            previous_ips = current_ips

            elapsed = time.time() - cycle_started
            sleep_for = max(0.0, interval_sec - elapsed)
            if self.live_stop_event.wait(sleep_for):
                break

        self.ui_queue.put(("live_done",))

    def _collect_snapshot(
        self, network: str, timeout_ms: int, workers: int, live_mode: bool = False, emit_rows: bool = False
    ) -> Dict[str, DeviceRow]:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        total_hosts = len(hosts)
        processed_hosts = 0
        alive: List[str] = []
        ping_map: Dict[str, Optional[float]] = {}

        self.ui_queue.put(("progress_setup",))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(ping_host_info, ip, timeout_ms): ip for ip in hosts}

            for future in concurrent.futures.as_completed(future_to_ip):
                if (live_mode and self.live_stop_event.is_set()) or (not live_mode and self.stop_event.is_set()):
                    break
                ip = future_to_ip[future]
                processed_hosts += 1

                is_alive = False
                latency_ms: Optional[float] = None
                try:
                    is_alive, latency_ms = future.result()
                except Exception:
                    is_alive = False

                self.ui_queue.put(("progress", "ping", processed_hosts, total_hosts, live_mode))
                if is_alive:
                    alive.append(ip)
                    ping_map[ip] = latency_ms
                    if emit_rows:
                        self.ui_queue.put(("row_alive", ip, latency_ms))

            if (live_mode and self.live_stop_event.is_set()) or (not live_mode and self.stop_event.is_set()):
                for future in future_to_ip:
                    future.cancel()

        if (live_mode and self.live_stop_event.is_set()) or (not live_mode and self.stop_event.is_set()):
            return {}

        arp = parse_arp_table()
        rows: Dict[str, DeviceRow] = {}
        total_details = len(alive)
        processed_details = 0
        alive_sorted = sorted(alive, key=lambda x: tuple(int(p) for p in x.split(".")))

        # Parallel detail collection is the biggest speed-up for larger live host counts.
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(alive_sorted) or 1))) as executor:
            future_to_ip = {}
            for ip in alive_sorted:
                if live_mode and ip in self.live_detail_cache:
                    cached = self.live_detail_cache[ip]
                    rows[ip] = DeviceRow(
                        ip=ip,
                        mac=arp.get(ip, cached.mac),
                        hostname=cached.hostname,
                        device_type=cached.device_type,
                        status="Alive",
                        ping_ms=f"{ping_map[ip]:.2f}" if ping_map.get(ip) is not None else "-",
                        open_ports=cached.open_ports,
                    )
                    processed_details += 1
                    self.ui_queue.put(("progress", "details", processed_details, total_details, live_mode))
                    if emit_rows:
                        self.ui_queue.put(
                            ("row_update", ip, rows[ip].mac, rows[ip].hostname, rows[ip].open_ports, rows[ip].device_type)
                        )
                    continue

                future_to_ip[executor.submit(self._build_device_row, ip, arp.get(ip, ""), ping_map.get(ip))] = ip

            for future in concurrent.futures.as_completed(future_to_ip):
                if (live_mode and self.live_stop_event.is_set()) or (not live_mode and self.stop_event.is_set()):
                    break
                ip = future_to_ip[future]
                try:
                    row = future.result()
                except Exception:
                    row = DeviceRow(ip=ip, mac=arp.get(ip, ""), ping_ms=f"{ping_map[ip]:.2f}" if ping_map.get(ip) is not None else "-")
                rows[ip] = row
                processed_details += 1
                self.ui_queue.put(("progress", "details", processed_details, total_details, live_mode))
                if emit_rows:
                    self.ui_queue.put(("row_update", ip, row.mac, row.hostname, row.open_ports, row.device_type))

            if (live_mode and self.live_stop_event.is_set()) or (not live_mode and self.stop_event.is_set()):
                for future in future_to_ip:
                    future.cancel()

        if live_mode:
            # Cache only currently alive rows; avoids repeated port scanning each cycle.
            self.live_detail_cache = {ip: rows[ip] for ip in rows}

        return rows

    def _build_device_row(self, ip: str, mac: str, ping_ms_value: Optional[float]) -> DeviceRow:
        hostname = resolve_hostname(ip)
        ports = probe_open_ports(ip)
        ports_text = ",".join(str(p) for p in sorted(ports)) if ports else "-"
        device_type = classify_device(mac, hostname, ports)
        ping_text = f"{ping_ms_value:.2f}" if ping_ms_value is not None else "-"
        return DeviceRow(
            ip=ip,
            mac=mac,
            hostname=hostname,
            device_type=device_type,
            status="Alive",
            ping_ms=ping_text,
            open_ports=ports_text,
        )

    def _process_ui_queue(self) -> None:
        while True:
            try:
                event = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            kind = event[0]

            if kind == "progress_setup":
                self.progress.configure(maximum=100, value=0)
            elif kind == "progress":
                phase, processed, total, live_mode = event[1], event[2], max(1, event[3]), event[4]
                ratio = min(1.0, processed / total)
                if phase == "ping":
                    progress_value = ratio * 70
                    status_prefix = "Live: " if live_mode else ""
                    self.status_var.set(f"{status_prefix}Pinging hosts... {processed}/{total}")
                else:
                    progress_value = 70 + (ratio * 30)
                    status_prefix = "Live: " if live_mode else ""
                    self.status_var.set(f"{status_prefix}Collecting host details... {processed}/{total}")
                self.progress.configure(value=progress_value)
            elif kind == "row_alive":
                ip, latency_ms = event[1], event[2]
                ping_text = f"{latency_ms:.2f}" if latency_ms is not None else "-"
                row = DeviceRow(ip=ip, ping_ms=ping_text)
                self.results[ip] = row
                tag = "even" if len(self.results) % 2 == 0 else "odd"
                self.tree.insert(
                    "",
                    tk.END,
                    iid=ip,
                    values=(row.status, row.ip, row.mac, row.hostname, row.ping_ms, row.open_ports, row.device_type),
                    tags=(tag,),
                )
            elif kind == "row_update":
                ip, mac, hostname, open_ports, device_type = event[1], event[2], event[3], event[4], event[5]
                if ip in self.results:
                    self.results[ip].mac = mac
                    self.results[ip].hostname = hostname
                    self.results[ip].open_ports = open_ports
                    self.results[ip].device_type = device_type
                    row = self.results[ip]
                    self.tree.item(
                        ip,
                        values=(row.status, row.ip, row.mac, row.hostname, row.ping_ms, row.open_ports, row.device_type),
                    )
            elif kind == "scan_done":
                elapsed, stopped = event[1], event[2]
                if not stopped:
                    self.progress.configure(value=100)
                self.scan_running = False
                self.scan_btn.configure(state=tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                self.live_btn.configure(state=tk.NORMAL)
                self.export_btn.configure(state=tk.NORMAL if self.results else tk.DISABLED)
                self._refresh_action_buttons()
                if stopped:
                    self.status_var.set(f"Stopped. Found {len(self.results)} active hosts in {elapsed:.2f}s")
                else:
                    self.status_var.set(f"Finished. Found {len(self.results)} active hosts in {elapsed:.2f}s")
            elif kind == "live_cycle":
                rows, new_ips = event[1], event[2]
                self._sync_live_table(rows, new_ips)
                self.progress.configure(value=100)
                self.export_btn.configure(state=tk.NORMAL if self.results else tk.DISABLED)
                if new_ips:
                    self.status_var.set(f"Live: {len(new_ips)} ny(e) enhet(er) oppdaget. Totalt aktive: {len(rows)}")
                else:
                    self.status_var.set(f"Live: Ingen nye enheter. Totalt aktive: {len(rows)}")
            elif kind == "live_done":
                self.live_running = False
                self.live_btn.configure(state=tk.NORMAL)
                self.live_stop_btn.configure(state=tk.DISABLED)
                self.scan_btn.configure(state=tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                self._refresh_action_buttons()
                self.status_var.set("Live scanner stoppet.")

        self.root.after(100, self._process_ui_queue)

    def _clear_table(self) -> None:
        self.results.clear()
        self.live_detail_cache.clear()
        self.row_base_tag.clear()
        self.highlight_tokens.clear()
        self.remove_tokens.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.progress.configure(maximum=100, value=0)


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
