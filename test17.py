import customtkinter as ctk
import nmap
import threading
import os
import time
import yara
import serial
import subprocess
import socket
import json
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from groq import Groq
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
GROQ_API_KEY    = "MyAPIKey"
GROQ_MODEL      = "llama-3.3-70b-versatile"
NMAP_PATH       = r"C:\Program Files (x86)\Nmap\nmap.exe"
APP_NAME        = "ForensicSentinel V4"
APP_VERSION     = "4.0.0"

# IoT-specific ports to audit
IOT_PORTS       = "21,22,23,25,80,443,554,1883,1884,5683,8080,8443,8883,47808"

# Default YARA rules for firmware analysis
YARA_RULES_SRC  = """
rule Hardcoded_Credentials {
    meta:
        description = "Detects hardcoded credentials in firmware"
    strings:
        $s1 = "admin"   ascii wide nocase
        $s2 = "root"    ascii wide nocase
        $s3 = "password" ascii wide nocase
        $s4 = "12345"   ascii wide
        $s5 = "default" ascii wide nocase
    condition:
        2 of them
}

rule Suspicious_URLs {
    meta:
        description = "Detects suspicious or C2-like URLs"
    strings:
        $u1 = /https?:\\/\\/[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/ ascii
        $u2 = ".onion" ascii
        $u3 = "pastebin.com" ascii nocase
    condition:
        any of them
}

rule Shell_Backdoor {
    meta:
        description = "Detects shell backdoor indicators"
    strings:
        $b1 = "/bin/sh"  ascii
        $b2 = "/bin/bash" ascii
        $b3 = "nc -l"    ascii
        $b4 = "netcat"   ascii nocase
        $b5 = "telnetd"  ascii nocase
    condition:
        any of them
}

rule Crypto_Mining {
    meta:
        description = "Detects potential crypto mining strings"
    strings:
        $m1 = "stratum+tcp" ascii nocase
        $m2 = "minerd"      ascii nocase
        $m3 = "xmrig"       ascii nocase
    condition:
        any of them
}
"""

# ─── THEME ───────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg_dark":    "#0a0d14",
    "bg_panel":   "#111827",
    "bg_card":    "#1a2233",
    "accent":     "#00d4ff",
    "accent2":    "#7c3aed",
    "danger":     "#ef4444",
    "warn":       "#f59e0b",
    "success":    "#10b981",
    "text_dim":   "#6b7280",
    "scan":       "#0ea5e9",
    "vuln":       "#16a34a",
    "uart":       "#ea580c",
    "firmware":   "#d97706",
    "sniff":      "#2563eb",
    "report":     "#7c3aed",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════
class ForensicSentinel(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1480x960")
        self.minsize(1200, 700)
        self.configure(fg_color=COLORS["bg_dark"])

        self.stop_event   = threading.Event()   # Signal to halt all background threads
        self.active_threads: list[threading.Thread] = []

        # Central data store – all modules write here; AI report reads from here
        self.audit_data = {
            "scan_time":       None,
            "target_range":    "",
            "network_hosts":   [],          # [{"ip": str, "hostname": str}]
            "port_scan":       [],          # [{"ip", "port", "state", "service", "version", "severity"}]
            "packets":         [],          # [{"src", "dst", "proto", "sport", "dport"}]
            "uart_file":       "",
            "binwalk_output":  "",
            "yara_hits":       [],          # [{"file", "rule", "tags"}]
        }

        self._build_ui()
        self.log("▸ ForensicSentinel V4 online — all modules ready.", tag="system")
        self.log(f"▸ AI model: {GROQ_MODEL} (Groq)", tag="system")

    # ─────────────────────────────────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar outer container (fixed width, holds title + scrollable area) ──
        sidebar_outer = ctk.CTkFrame(self, width=330, corner_radius=0,
                                     fg_color=COLORS["bg_panel"])
        sidebar_outer.grid(row=0, column=0, sticky="nsew")
        sidebar_outer.grid_propagate(False)
        sidebar_outer.grid_columnconfigure(0, weight=1)
        sidebar_outer.grid_rowconfigure(1, weight=1)

        # Title block — pinned at top, never scrolls away
        title_frame = ctk.CTkFrame(sidebar_outer, fg_color=COLORS["bg_card"], corner_radius=0)
        title_frame.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(title_frame,
                     text="FORENSIC\nSENTINEL",
                     font=ctk.CTkFont(family="Courier New", size=22, weight="bold"),
                     text_color=COLORS["accent"]).pack(pady=(16, 0))
        ctk.CTkLabel(title_frame,
                     text=f"v{APP_VERSION}  ·  IoT Security Auditor",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS["text_dim"]).pack(pady=(2, 14))

        # Scrollable area — all controls live here
        sidebar = ctk.CTkScrollableFrame(sidebar_outer, corner_radius=0,
                                         fg_color=COLORS["bg_panel"],
                                         scrollbar_button_color=COLORS["accent"],
                                         scrollbar_button_hover_color=COLORS["accent2"])
        sidebar.grid(row=1, column=0, sticky="nsew")
        sidebar.grid_columnconfigure(0, weight=1)

        row = 0

        # ── Section: Network Scan ─────────────────────────────────────────
        row = self._section(sidebar, row, "① NETWORK DISCOVERY")
        self.range_entry = self._entry(sidebar, row, "Subnet  e.g. 192.168.1.0/24"); row += 1
        row = self._btn(sidebar, row, "▶  Scan Subnet", self._start_discovery, COLORS["scan"])
        self.ip_menu = ctk.CTkOptionMenu(sidebar, values=["─ Select discovered host ─"],
                                          fg_color=COLORS["bg_card"],
                                          button_color=COLORS["scan"],
                                          width=290, dynamic_resizing=False)
        self.ip_menu.grid(row=row, column=0, padx=20, pady=4, sticky="ew"); row += 1
        row = self._btn(sidebar, row, "▶  Audit Ports & Vulns", self._start_vuln_scan, COLORS["vuln"])

        # ── Section: Packet Sniffer ───────────────────────────────────────
        row = self._section(sidebar, row, "② PACKET SNIFFER")
        self.iface_entry = self._entry(sidebar, row, "Interface (blank = auto)"); row += 1
        row = self._btn(sidebar, row, "▶  Start Sniffing", self._start_sniffer, COLORS["sniff"])

        # ── Section: UART Dump ───────────────────────────────────────────
        row = self._section(sidebar, row, "③ UART FIRMWARE DUMP")
        self.com_entry  = self._entry(sidebar, row, "COM Port  e.g. COM3 or /dev/ttyUSB0"); row += 1
        self.baud_entry = self._entry(sidebar, row, "Baud Rate  e.g. 115200"); row += 1
        row = self._btn(sidebar, row, "▶  Start UART Capture", self._start_uart, COLORS["uart"])

        # ── Section: Firmware Analysis ───────────────────────────────────
        row = self._section(sidebar, row, "④ FIRMWARE ANALYSIS")
        self.fw_entry = self._entry(sidebar, row, "Path to firmware (.bin / .img)"); row += 1
        row = self._btn(sidebar, row, "▶  Binwalk + YARA Scan", self._start_firmware, COLORS["firmware"])

        # ── Section: Reporting ───────────────────────────────────────────
        row = self._section(sidebar, row, "⑤ AI REPORT")
        row = self._btn(sidebar, row, "▶  Generate Gemini Report", self._start_report, COLORS["report"])

        # ── KILL BUTTON ──────────────────────────────────────────────────
        kill_btn = ctk.CTkButton(sidebar, text="⏹  KILL ALL  —  EMERGENCY HALT",
                                  command=self._kill_all,
                                  fg_color=COLORS["danger"],
                                  hover_color="#b91c1c",
                                  font=ctk.CTkFont(size=13, weight="bold"),
                                  height=44, width=290, corner_radius=6)
        kill_btn.grid(row=row, column=0, padx=20, pady=(20, 8), sticky="ew"); row += 1

        ctk.CTkLabel(sidebar, text="All threads terminate immediately",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS["danger"]).grid(row=row, column=0, padx=20, pady=(0, 16))

        # ── Main Log Area ─────────────────────────────────────────────────
        log_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"], corner_radius=10)
        log_frame.grid(row=0, column=1, padx=(0, 16), pady=16, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        log_header = ctk.CTkFrame(log_frame, fg_color=COLORS["bg_card"], corner_radius=8)
        log_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 0))
        ctk.CTkLabel(log_header,
                     text="  ●  LIVE AUDIT LOG",
                     font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
                     text_color=COLORS["accent"]).pack(side="left", pady=8, padx=12)
        ctk.CTkButton(log_header, text="Clear",
                       command=self._clear_log,
                       fg_color="transparent",
                       border_color=COLORS["text_dim"],
                       border_width=1,
                       text_color=COLORS["text_dim"],
                       hover_color=COLORS["bg_card"],
                       width=60, height=28).pack(side="right", padx=12)

        self.textbox = ctk.CTkTextbox(log_frame,
                                       font=ctk.CTkFont(family="Courier New", size=12),
                                       fg_color=COLORS["bg_dark"],
                                       text_color="#c9d1d9",
                                       corner_radius=0,
                                       wrap="word")
        self.textbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self.textbox.tag_config("system",  foreground=COLORS["accent"])
        self.textbox.tag_config("success", foreground=COLORS["success"])
        self.textbox.tag_config("warn",    foreground=COLORS["warn"])
        self.textbox.tag_config("error",   foreground=COLORS["danger"])
        self.textbox.tag_config("hit",     foreground="#f97316")
        self.textbox.tag_config("info",    foreground="#94a3b8")

        # Status bar
        self.status_var = ctk.StringVar(value="Ready")
        status_bar = ctk.CTkLabel(self, textvariable=self.status_var,
                                   fg_color=COLORS["bg_panel"],
                                   font=ctk.CTkFont(size=11),
                                   text_color=COLORS["text_dim"],
                                   anchor="w")
        status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 8))

    # ─────────────────────────────────────────────────────────────────────────
    #  UI HELPERS
    # ─────────────────────────────────────────────────────────────────────────
    def _section(self, parent, row, text):
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"], corner_radius=6, height=28)
        frame.grid(row=row, column=0, sticky="ew", padx=12, pady=(12, 2))
        ctk.CTkLabel(frame, text=text,
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=10, pady=4)
        return row + 1

    def _entry(self, parent, row, placeholder):
        e = ctk.CTkEntry(parent, placeholder_text=placeholder,
                          fg_color=COLORS["bg_card"],
                          border_color="#2d3748",
                          width=290, height=34)
        e.grid(row=row, column=0, padx=20, pady=3, sticky="ew")
        return e

    def _btn(self, parent, row, text, cmd, color):
        b = ctk.CTkButton(parent, text=text, command=cmd,
                           fg_color=color, hover_color=self._darken(color),
                           font=ctk.CTkFont(size=12, weight="bold"),
                           height=36, width=290, corner_radius=6)
        b.grid(row=row, column=0, padx=20, pady=4, sticky="ew")
        return row + 1

    @staticmethod
    def _darken(hex_color: str, factor=0.7) -> str:
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        return "#{:02x}{:02x}{:02x}".format(int(r*factor), int(g*factor), int(b*factor))

    # ─────────────────────────────────────────────────────────────────────────
    #  LOGGING
    # ─────────────────────────────────────────────────────────────────────────
    def log(self, msg: str, tag: str = "info"):
        ts  = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        def _insert():
            self.textbox.insert("end", line, tag)
            self.textbox.see("end")
        self.after(0, _insert)

    def _clear_log(self):
        self.textbox.delete("1.0", "end")

    def _set_status(self, msg: str):
        self.after(0, lambda: self.status_var.set(msg))

    # ─────────────────────────────────────────────────────────────────────────
    #  THREAD MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────────
    def _spawn(self, target, *args):
        """Reset stop event and launch a daemon thread."""
        self.stop_event.clear()
        t = threading.Thread(target=target, args=args, daemon=True)
        self.active_threads.append(t)
        t.start()

    def _kill_all(self):
        self.stop_event.set()
        self.log("⏹  EMERGENCY HALT — all threads signalled to stop.", tag="error")
        self._set_status("HALTED")

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 1: NETWORK DISCOVERY
    # ═══════════════════════════════════════════════════════════════════════
    def _start_discovery(self):
        self._spawn(self._discovery_worker)

    def _discovery_worker(self):
        target = self.range_entry.get().strip() or "192.168.1.0/24"
        self.audit_data["target_range"] = target
        self.audit_data["scan_time"]    = datetime.now().isoformat()
        self.log(f"▸ Network discovery on {target} …", tag="system")
        self._set_status(f"Scanning {target}…")
        try:
            nm = self._get_nmap()

            # Phase 1: ping sweep to find live hosts (no port scan, no OS)
            self.log("  Phase 1/2 — ping sweep …", tag="info")
            nm.scan(hosts=target, arguments="-sn --host-timeout 10s")
            live_hosts = nm.all_hosts()

            if not live_hosts:
                self.log("▸ No hosts responded to ping sweep.", tag="warn")
                self.after(0, lambda: self.ip_menu.configure(values=["─ No hosts found ─"]))
                return

            self.log(f"  Found {len(live_hosts)} live host(s). Phase 2/2 — OS & vendor detection …", tag="info")

            # Phase 2: per-host scan with a minimal port touch so -O works
            hosts_found = []
            nm2 = self._get_nmap()
            for h in live_hosts:
                if self.stop_event.is_set(): break
                try:
                    # Scan top 100 ports + OS guess on each host individually
                    nm2.scan(hosts=h, arguments="-O --osscan-guess -F --host-timeout 15s")
                    info = nm2[h] if h in nm2.all_hosts() else None
                except Exception:
                    info = None

                # Hostname
                hostname = ""
                if info:
                    hostname = info.hostname() or ""
                if not hostname:
                    hostname = self._rdns(h)

                # MAC + vendor
                mac = vendor = ""
                if info:
                    try:
                        mac    = info["addresses"].get("mac", "")
                        vendor = info["vendor"].get(mac, "") if mac else ""
                    except Exception:
                        pass

                # OS guess
                os_guess = ""
                if info:
                    try:
                        osmatch = info.get("osmatch", [])
                        if osmatch:
                            best     = osmatch[0]
                            os_guess = f"{best['name']} ({best['accuracy']}%)"
                    except Exception:
                        pass

                device_name = self._make_device_label(hostname, vendor, os_guess, h)

                entry = {
                    "ip":          h,
                    "hostname":    hostname,
                    "mac":         mac,
                    "vendor":      vendor,
                    "os_guess":    os_guess,
                    "device_name": device_name,
                }
                hosts_found.append(entry)

                self.log(f"  ✔  {h:<16}  [{device_name}]", tag="success")
                if mac:
                    self.log(f"       MAC: {mac}  Vendor: {vendor or '—'}", tag="info")
                if os_guess:
                    self.log(f"       OS : {os_guess}", tag="info")

            self.audit_data["network_hosts"] = hosts_found

            menu_labels = [
                f"{h['ip']}  [{h['device_name']}]" for h in hosts_found
            ] or ["─ No hosts found ─"]
            self._menu_ip_map = {
                f"{h['ip']}  [{h['device_name']}]": h["ip"] for h in hosts_found
            }
            self.after(0, lambda: self.ip_menu.configure(values=menu_labels))
            self.log(f"▸ Discovery complete: {len(hosts_found)} host(s) found.", tag="success")
        except Exception as e:
            self.log(f"✘ Discovery error: {e}", tag="error")
        finally:
            self._set_status("Ready")

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _rdns(ip: str) -> str:
        """Reverse-DNS lookup with a short timeout fallback."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    @staticmethod
    def _make_device_label(hostname: str, vendor: str, os_guess: str, ip: str) -> str:
        """
        Build the friendliest possible single-line device name from
        whatever information nmap returned.
        """
        # Known IoT vendor keywords → friendly category
        IOT_VENDORS = {
            "hikvision": "Hikvision Camera",
            "dahua":     "Dahua Camera",
            "axis":      "Axis Camera",
            "reolink":   "Reolink Camera",
            "foscam":    "Foscam Camera",
            "tp-link":   "TP-Link Device",
            "espressif": "ESP IoT Device",
            "raspberry": "Raspberry Pi",
            "arduino":   "Arduino",
            "samsung":   "Samsung Device",
            "xiaomi":    "Xiaomi Device",
            "tuya":      "Tuya Smart Device",
            "shelly":    "Shelly Device",
            "sonoff":    "Sonoff Device",
            "nest":      "Nest Device",
            "ring":      "Ring Device",
            "cisco":     "Cisco Network",
            "netgear":   "Netgear Router",
            "asus":      "ASUS Router",
            "mikrotik":  "MikroTik Router",
            "ubiquiti":  "Ubiquiti Device",
            "synology":  "Synology NAS",
            "qnap":      "QNAP NAS",
            "apple":     "Apple Device",
            "android":   "Android Device",
            "microsoft": "Windows PC",
            "vmware":    "VMware Host",
        }
        combined = f"{vendor} {hostname} {os_guess}".lower()
        for keyword, label in IOT_VENDORS.items():
            if keyword in combined:
                return label

        # Fall back to hostname → OS → vendor → IP
        if hostname and hostname != ip:
            return hostname
        if os_guess:
            return os_guess.split("(")[0].strip()
        if vendor:
            return vendor
        return "Unknown Device"

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 2: PORT & VULNERABILITY SCAN
    # ═══════════════════════════════════════════════════════════════════════
    def _start_vuln_scan(self):
        selected = self.ip_menu.get()
        if "─" in selected or not selected:
            self.log("✘ Select a host from the dropdown first.", tag="warn")
            return
        # Resolve bare IP from "192.168.x.x  [Device Name]" label
        ip_map = getattr(self, "_menu_ip_map", {})
        target = ip_map.get(selected, selected.split()[0])
        # Find device name for richer log output
        device_name = next(
            (h["device_name"] for h in self.audit_data["network_hosts"] if h["ip"] == target),
            ""
        )
        self._spawn(self._vuln_worker, target, device_name)

    def _vuln_worker(self, target: str, device_name: str = ""):
        label = f"{target}  [{device_name}]" if device_name else target
        self.log(f"▸ Port & vulnerability scan on {label} …", tag="system")
        self._set_status(f"Scanning ports on {target}…")
        try:
            nm = self._get_nmap()
            nm.scan(target, IOT_PORTS, arguments="-sV --script=banner,vulners -T4 --host-timeout 60s")
            if target not in nm.all_hosts():
                self.log(f"✘ {target} did not respond.", tag="warn")
                return

            for port, data in nm[target].get("tcp", {}).items():
                if self.stop_event.is_set(): break
                svc      = data.get("name", "?")
                product  = data.get("product", "")
                version  = data.get("version", "")
                state    = data.get("state", "?")
                severity = self._port_severity(port, state)
                entry = {
                    "ip": target, "device_name": device_name, "port": port,
                    "state": state, "service": svc,
                    "version": f"{product} {version}".strip(),
                    "severity": severity,
                }
                self.audit_data["port_scan"].append(entry)
                tag = "hit" if severity == "HIGH" else ("warn" if severity == "MEDIUM" else "info")
                self.log(
                    f"  [{severity:6}]  {target}:{port}/{svc}  {state}  {product} {version}"
                    + (f"  ({device_name})" if device_name else ""),
                    tag=tag
                )
            self.log("▸ Port scan complete.", tag="success")
        except Exception as e:
            self.log(f"✘ Port scan error: {e}", tag="error")
        finally:
            self._set_status("Ready")

    @staticmethod
    def _port_severity(port: int, state: str) -> str:
        HIGH_RISK = {21, 23, 1883, 5683, 47808}   # FTP, Telnet, MQTT, CoAP, BACnet
        MEDIUM    = {22, 80, 554, 8080}
        if state != "open": return "INFO"
        if port in HIGH_RISK: return "HIGH"
        if port in MEDIUM:    return "MEDIUM"
        return "LOW"

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 3: PACKET SNIFFER
    # ═══════════════════════════════════════════════════════════════════════
    def _start_sniffer(self):
        self._spawn(self._sniff_worker)

    def _sniff_worker(self):
        iface = self.iface_entry.get().strip() or None
        self.log(f"▸ Packet sniffer started (iface={iface or 'auto'}) …", tag="system")
        self._set_status("Sniffing packets…")

        def _handle(pkt):
            if self.stop_event.is_set(): return True   # stop_filter
            if not pkt.haslayer(IP): return False
            ip = pkt[IP]
            proto  = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
            sport  = pkt.sport if hasattr(pkt, "sport") else 0
            dport  = pkt.dport if hasattr(pkt, "dport") else 0
            entry  = {"src": ip.src, "dst": ip.dst, "proto": proto,
                      "sport": sport, "dport": dport}
            self.audit_data["packets"].append(entry)
            self.log(f"  {proto:3}  {ip.src}:{sport}  →  {ip.dst}:{dport}", tag="info")
            return self.stop_event.is_set()

        try:
            kwargs = {"prn": _handle, "stop_filter": lambda p: self.stop_event.is_set(), "store": 0}
            if iface: kwargs["iface"] = iface
            sniff(**kwargs)
        except Exception as e:
            self.log(f"✘ Sniffer error: {e}", tag="error")
        finally:
            self.log(f"▸ Sniffer stopped — {len(self.audit_data['packets'])} packets captured.", tag="success")
            self._set_status("Ready")

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 4: UART DUMP
    # ═══════════════════════════════════════════════════════════════════════
    def _start_uart(self):
        port = self.com_entry.get().strip()
        if not port:
            self.log("✘ Enter a COM port before starting UART capture.", tag="warn")
            return
        baud = int(self.baud_entry.get().strip() or "115200")
        self._spawn(self._uart_worker, port, baud)

    def _uart_worker(self, port: str, baud: int):
        filename = f"uart_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        self.log(f"▸ UART capture: {port} @ {baud} baud → {filename}", tag="system")
        self._set_status(f"Capturing UART on {port}…")
        try:
            with serial.Serial(port, baud, timeout=2) as ser, \
                 open(filename, "wb") as f:
                bytes_written = 0
                while not self.stop_event.is_set():
                    if ser.in_waiting:
                        chunk = ser.read(ser.in_waiting)
                        f.write(chunk)
                        bytes_written += len(chunk)
                        self.log(f"  UART: {bytes_written} bytes captured…", tag="info")
                    else:
                        time.sleep(0.05)

            abs_path = os.path.abspath(filename)
            self.audit_data["uart_file"] = abs_path
            self.after(0, lambda: self.fw_entry.delete(0, "end"))
            self.after(0, lambda: self.fw_entry.insert(0, abs_path))
            self.log(f"▸ UART dump saved: {abs_path}  ({bytes_written} bytes)", tag="success")
        except Exception as e:
            self.log(f"✘ UART error: {e}", tag="error")
        finally:
            self._set_status("Ready")

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 5: FIRMWARE ANALYSIS (Binwalk + YARA)
    # ═══════════════════════════════════════════════════════════════════════
    def _start_firmware(self):
        path = self.fw_entry.get().strip()
        if not path or not os.path.exists(path):
            self.log("✘ Firmware file not found. Check the path.", tag="warn")
            return
        self._spawn(self._firmware_worker, path)

    def _firmware_worker(self, path: str):
        self.log(f"▸ Firmware analysis started: {path}", tag="system")
        self._set_status("Analysing firmware…")

        # ── Binwalk ──────────────────────────────────────────────────────
        self.log("  [1/2] Running Binwalk extraction …", tag="info")
        try:
            result = subprocess.run(
                ["binwalk", "-e", "--directory", os.path.dirname(path), path],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout + result.stderr
            self.audit_data["binwalk_output"] = output
            for line in output.splitlines()[:40]:   # log first 40 lines
                self.log(f"    {line}", tag="info")
            self.log("  Binwalk done.", tag="success")
        except FileNotFoundError:
            self.log("  ✘ Binwalk not found. Install it and add to PATH.", tag="warn")
            self.audit_data["binwalk_output"] = "Binwalk not available."
        except Exception as e:
            self.log(f"  ✘ Binwalk error: {e}", tag="error")
            self.audit_data["binwalk_output"] = str(e)

        if self.stop_event.is_set(): return

        # ── YARA ─────────────────────────────────────────────────────────
        self.log("  [2/2] Running YARA scan …", tag="info")
        try:
            rules = yara.compile(source=YARA_RULES_SRC)
            hits  = []
            scan_root = os.path.dirname(path)

            # Also scan extracted directory if it exists
            extracted = os.path.join(scan_root, f"_{os.path.basename(path)}.extracted")
            scan_dirs = [scan_root]
            if os.path.isdir(extracted): scan_dirs.append(extracted)

            for scan_dir in scan_dirs:
                for root, _, files in os.walk(scan_dir):
                    for fname in files:
                        if self.stop_event.is_set(): break
                        fpath = os.path.join(root, fname)
                        try:
                            matches = rules.match(fpath, timeout=10)
                            for m in matches:
                                entry = {
                                    "file":  fpath,
                                    "rule":  m.rule,
                                    "tags":  ", ".join(m.tags) if m.tags else "—",
                                }
                                hits.append(entry)
                                self.log(f"  ⚠ YARA HIT [{m.rule}] in {fname}", tag="hit")
                        except yara.TimeoutError:
                            self.log(f"  ✘ YARA timeout on {fname}", tag="warn")
                        except Exception:
                            continue

            self.audit_data["yara_hits"] = hits
            self.log(f"▸ YARA scan complete — {len(hits)} hit(s).", tag="success")
        except Exception as e:
            self.log(f"✘ YARA error: {e}", tag="error")
        finally:
            self._set_status("Ready")

    # ═══════════════════════════════════════════════════════════════════════
    #  MODULE 6: GROQ AI REPORT
    # ═══════════════════════════════════════════════════════════════════════
    def _start_report(self):
        self._spawn(self._report_worker)

    def _report_worker(self):
        self.log("▸ Connecting to Groq AI …", tag="system")
        self._set_status("Generating AI report…")
        try:
            client = Groq(api_key=GROQ_API_KEY)
            prompt = self._build_prompt()
            self.log("  Prompt built — awaiting Groq response …", tag="info")

            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": "You are a senior IoT security forensics expert. Write precise, professional, technical reports."},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.3,
                max_tokens=4096,
            )
            ai_text = response.choices[0].message.content
            self.log("▸ Groq response received.", tag="success")

            # Save PDF
            filename = f"ForensicReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            self._build_pdf(filename, ai_text)
            self.log(f"▸ Report saved: {os.path.abspath(filename)}", tag="success")
        except Exception as e:
            self.log(f"✘ Report error: {str(e)}", tag="error")
        finally:
            self._set_status("Ready")

    def _build_prompt(self) -> str:
        d = self.audit_data

        hosts_str = "\n".join(
            f"  - {h['ip']:<16}  [{h.get('device_name','?')}]"
            f"  MAC:{h.get('mac','—')}  Vendor:{h.get('vendor','—')}  OS:{h.get('os_guess','—')}"
            for h in d["network_hosts"]
        ) or "  No hosts found."

        ports_str = "\n".join(
            f"  - [{p['severity']:6}] {p['ip']}:{p['port']} ({p['service']}) {p['state']}"
            f"  {p['version']}"
            + (f"  [{p.get('device_name','')}]" if p.get('device_name') else "")
            for p in d["port_scan"]
        ) or "  No ports scanned."

        packets_str = f"{len(d['packets'])} packets captured."
        if d["packets"]:
            sample = d["packets"][:5]
            packets_str += "\n  Sample:\n" + "\n".join(
                f"  - {p['proto']} {p['src']}:{p['sport']} → {p['dst']}:{p['dport']}"
                for p in sample
            )

        yara_str = "\n".join(
            f"  - Rule [{h['rule']}] in {os.path.basename(h['file'])}"
            for h in d["yara_hits"]
        ) or "  No YARA hits."

        binwalk_snippet = (d["binwalk_output"] or "Not run.")[:800]

        return f"""You are a senior IoT security forensics expert. Analyse the following audit data and produce a structured, comprehensive security report.

FORMAT:
1. Executive Summary
2. Network Topology & Exposed Devices
3. Port & Service Vulnerability Analysis
4. Network Traffic Observations
5. Firmware Analysis Findings
6. YARA Malware/Indicator Scan Results
7. Risk Matrix (table: Finding | Severity | Recommendation)
8. Remediation Roadmap (prioritised steps)
9. Conclusion

Be precise, technical, and professional. Flag all HIGH and MEDIUM severity issues clearly.

═══════════════════════ AUDIT DATA ═══════════════════════
Scan time    : {d.get('scan_time', 'N/A')}
Target range : {d.get('target_range', 'N/A')}

DISCOVERED HOSTS ({len(d['network_hosts'])} total):
{hosts_str}

PORT SCAN RESULTS ({len(d['port_scan'])} entries):
{ports_str}

PACKET CAPTURE:
{packets_str}

FIRMWARE: {d.get('uart_file', 'N/A')}
BINWALK OUTPUT (first 800 chars):
{binwalk_snippet}

YARA SCAN RESULTS ({len(d['yara_hits'])} hit(s)):
{yara_str}
═══════════════════════════════════════════════════════════
"""

    def _build_pdf(self, filename: str, ai_text: str):
        """Build a styled PDF report using ReportLab Platypus."""
        doc  = SimpleDocTemplate(filename, pagesize=letter,
                                  leftMargin=0.8*inch, rightMargin=0.8*inch,
                                  topMargin=0.8*inch,  bottomMargin=0.8*inch)
        base = getSampleStyleSheet()
        styles = {
            "title":   ParagraphStyle("title",   fontName="Helvetica-Bold",  fontSize=20,
                                       spaceAfter=4,  textColor=colors.HexColor("#00d4ff"),
                                       alignment=TA_CENTER),
            "subtitle":ParagraphStyle("subtitle", fontName="Helvetica",       fontSize=11,
                                       spaceAfter=16, textColor=colors.grey,
                                       alignment=TA_CENTER),
            "h1":      ParagraphStyle("h1",       fontName="Helvetica-Bold",  fontSize=13,
                                       spaceBefore=14, spaceAfter=4,
                                       textColor=colors.HexColor("#7c3aed")),
            "body":    ParagraphStyle("body",     fontName="Helvetica",       fontSize=10,
                                       spaceAfter=4,   leading=14,
                                       textColor=colors.HexColor("#1a202c")),
            "mono":    ParagraphStyle("mono",     fontName="Courier",         fontSize=9,
                                       spaceAfter=2,   leading=12,
                                       textColor=colors.HexColor("#2d3748")),
        }

        story = [
            Paragraph("FORENSICSENTINEL V4", styles["title"]),
            Paragraph(f"IoT Security Audit Report  ·  {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["subtitle"]),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#00d4ff")),
            Spacer(1, 12),
        ]

        for line in ai_text.splitlines():
            stripped = line.strip()
            if not stripped:
                story.append(Spacer(1, 5))
            elif stripped.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
                story.append(Paragraph(stripped, styles["h1"]))
            else:
                style = styles["mono"] if stripped.startswith("|") else styles["body"]
                story.append(Paragraph(stripped.replace("&", "&amp;").replace("<", "&lt;"), style))

        doc.build(story)

    # ─────────────────────────────────────────────────────────────────────────
    #  UTILITY
    # ─────────────────────────────────────────────────────────────────────────
    def _get_nmap(self) -> nmap.PortScanner:
        """Return an nmap scanner, using the Windows path only if it exists."""
        if os.path.exists(NMAP_PATH):
            return nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
        return nmap.PortScanner()   # system PATH on Linux/macOS


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = ForensicSentinel()
    app.mainloop()
