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
import signal
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
GROQ_API_KEY    = ""     # ← Get free key at console.groq.com
GROQ_MODEL      = "llama-3.3-70b-versatile"
APP_NAME        = "ForensicSentinel V4"
APP_VERSION     = "4.0.0"

# ── Linux dependency install (run once as root) ───────────────────────────────
# sudo apt install nmap binwalk strace qemu-user qemu-user-static python3-pip
# pip install customtkinter python-nmap scapy pyserial yara-python groq reportlab

# IoT-specific ports — Tapo C100/C200: 443, 554, 2020 (ONVIF), 8800, 20002
IOT_PORTS = (
    "21,22,23,25,53,80,443,554,1883,1884,"
    "2020,2323,4433,5683,7547,8009,8080,8081,"
    "8088,8443,8554,8800,8883,8888,9000,"
    "10554,20002,47808"
)

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
            "qemu_analysis":   [],          # [{"binary", "arch", "syscalls", "network", "suspicious"}]
        }

        self._build_ui()
        self.log("▸ ForensicSentinel V4 online — Linux mode.", tag="system")
        self.log(f"▸ AI model: {GROQ_MODEL} (Groq)", tag="system")
        if os.geteuid() != 0:
            self.log("⚠ Running as regular user (not root).", tag="warn")
            self.log("  • Binwalk extraction → will use sudo automatically", tag="warn")
            self.log("  • OS detection & packet sniff → need root", tag="warn")
            self.log("  • PyCharm tip: Run > Edit Configurations > set interpreter to:", tag="warn")
            self.log("    /usr/bin/sudo /usr/bin/python3", tag="warn")
        else:
            self.log("▸ Running as root — all modules fully available.", tag="success")

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

        # ── Section: QEMU Dynamic Analysis ───────────────────────────────
        row = self._section(sidebar, row, "⑤ QEMU DYNAMIC ANALYSIS")
        self.qemu_entry = self._entry(sidebar, row, "Path to extracted binary"); row += 1
        self.qemu_arch  = ctk.CTkOptionMenu(
            sidebar,
            values=["auto-detect", "mips", "mipsel", "arm", "aarch64", "x86_64", "i386", "ppc"],
            fg_color=COLORS["bg_card"],
            button_color="#b45309",
            width=290, dynamic_resizing=False
        )
        self.qemu_arch.grid(row=row, column=0, padx=20, pady=4, sticky="ew"); row += 1
        self.qemu_timeout = self._entry(sidebar, row, "Emulation timeout (sec, default 30)"); row += 1
        row = self._btn(sidebar, row, "▶  Run QEMU Emulation", self._start_qemu, "#b45309")

        # ── Section: Reporting ───────────────────────────────────────────
        row = self._section(sidebar, row, "⑥ AI REPORT")
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
            "tapo":      "Tapo Camera",
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
            nm.scan(target, IOT_PORTS, '-sV')

            if target not in nm.all_hosts():
                self.log(f"✘ {target} did not respond.", tag="warn")
                return

            for port, data in nm[target].get('tcp', {}).items():
                if self.stop_event.is_set():
                    break
                state    = data.get('state', '?')
                svc      = data.get('name', '?')
                product  = data.get('product', '')
                version  = data.get('version', '')
                ver_str  = f"{product} {version}".strip()
                severity = self._port_severity(port, state)

                entry = {
                    "ip":          target,
                    "device_name": device_name,
                    "port":        port,
                    "state":       state,
                    "service":     svc,
                    "version":     ver_str,
                    "severity":    severity,
                }
                self.audit_data["port_scan"].append(entry)
                tag = "hit" if severity == "HIGH" else ("warn" if severity == "MEDIUM" else "info")
                self.log(
                    f"  [{severity:6}]  {target}:{port} ({svc})  {state}  {ver_str}"
                    + (f"  ← {device_name}" if device_name else ""),
                    tag=tag
                )

            self.log("▸ Port scan complete.", tag="success")
        except Exception as e:
            self.log(f"✘ Port scan error: {e}", tag="error")
        finally:
            self._set_status("Ready")

    @staticmethod
    def _port_severity(port: int, state: str) -> str:
        HIGH_RISK = {21, 23, 1883, 5683, 47808, 2323}               # FTP, Telnet, MQTT, CoAP, BACnet, alt-Telnet
        MEDIUM    = {22, 80, 554, 2020, 8080, 8554, 10554, 8800, 20002}  # SSH, HTTP, RTSP, ONVIF, Tapo ports
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

        base_dir    = os.path.dirname(path)
        fw_name     = os.path.basename(path)
        extract_dir = os.path.join(base_dir, f"_{fw_name}.extracted")
        is_root     = (os.geteuid() == 0)

        # ── Binwalk ──────────────────────────────────────────────────────
        self.log("  [1/2] Running Binwalk extraction …", tag="info")

        try:
            cmd = (["sudo"] if not is_root else []) + [
                "binwalk", "--run-as=root", "-e", "-M", "-C", base_dir, path
            ]
            self.log(f"  CMD: {' '.join(cmd)}", tag="info")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            full_output = result.stdout + result.stderr
            self.audit_data["binwalk_output"] = full_output
            self.log(f"  Return code: {result.returncode}", tag="info")

            SKIP = ("Extractor Exception", "Traceback", "ModuleException",
                    "File \"/", "self.load()", "raise Module", "------",
                    "binwalk.core", "% user_info")
            for line in full_output.splitlines():
                stripped = line.strip()
                if stripped and not any(s in stripped for s in SKIP):
                    self.log(f"    {stripped}", tag="info")

            # Search for ANY new directory created in base_dir after extraction
            fw_stem  = fw_name.split(".")[0].lower()
            found_dir = None
            for entry in sorted(os.listdir(base_dir)):
                full = os.path.join(base_dir, entry)
                if not os.path.isdir(full): continue
                el = entry.lower()
                if fw_stem in el or (entry.startswith("_") and fw_stem in el):
                    found_dir = full
                    break

            if found_dir:
                self.log(f"  ✔ Extracted to: {found_dir}", tag="success")
                extract_dir = found_dir
                for binary in ("busybox", "httpd", "uhttpd", "lighttpd"):
                    target = self._find_binary(found_dir, binary)
                    if target:
                        self.log(f"  ✔ Auto-filled QEMU target: {target}", tag="success")
                        self.after(0, lambda b=target: self.qemu_entry.delete(0, "end"))
                        self.after(0, lambda b=target: self.qemu_entry.insert(0, b))
                        break
            else:
                # Fallback: try unsquashfs directly
                self.log("  Binwalk produced no dir — trying unsquashfs fallback …", tag="warn")
                offset = self._find_squashfs_offset(path)
                if offset is not None:
                    out_dir = os.path.join(base_dir, f"{fw_stem}_squashfs")
                    cmd2 = (["sudo"] if not is_root else []) + [
                        "unsquashfs", "-f", "-d", out_dir, "-o", str(offset), path
                    ]
                    self.log(f"  CMD: {' '.join(cmd2)}", tag="info")
                    r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=180)
                    for line in (r2.stdout + r2.stderr).splitlines()[:15]:
                        if line.strip(): self.log(f"    {line.strip()}", tag="info")
                    if os.path.isdir(out_dir):
                        self.log(f"  ✔ unsquashfs extracted to: {out_dir}", tag="success")
                        extract_dir = out_dir
                        for binary in ("busybox", "httpd", "uhttpd"):
                            target = self._find_binary(out_dir, binary)
                            if target:
                                self.log(f"  ✔ Auto-filled QEMU target: {target}", tag="success")
                                self.after(0, lambda b=target: self.qemu_entry.delete(0, "end"))
                                self.after(0, lambda b=target: self.qemu_entry.insert(0, b))
                                break
                else:
                    self.log("  ✘ No squashfs found — try manually: binwalk -e IoTGoat.img", tag="error")

            self.log("  Binwalk done.", tag="success")

        except FileNotFoundError:
            self.log("  ✘ binwalk not found — run: sudo apt install binwalk", tag="error")
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

            # Find whatever directory binwalk actually created
            # binwalk names it differently depending on version: _name.extracted or name.extracted
            actual_extract = None
            for entry in os.listdir(base_dir):
                full = os.path.join(base_dir, entry)
                if os.path.isdir(full) and fw_name.split(".")[0] in entry and "extract" in entry.lower():
                    actual_extract = full
                    break
            # Also try the underscore prefix pattern
            if not actual_extract:
                for entry in os.listdir(base_dir):
                    full = os.path.join(base_dir, entry)
                    if os.path.isdir(full) and entry.startswith("_") and fw_name.split(".")[0] in entry:
                        actual_extract = full
                        break

            # Build scan list — ONLY the firmware file itself + extracted dir
            # Never walk base_dir broadly (would scan your whole home folder)
            scan_targets = [path]   # scan the firmware binary itself
            if actual_extract:
                self.log(f"  Scanning extracted dir: {actual_extract}", tag="info")
                scan_dirs = [actual_extract]
            elif os.path.isdir(extract_dir):
                self.log(f"  Scanning extracted dir: {extract_dir}", tag="info")
                scan_dirs = [extract_dir]
            else:
                self.log("  ⚠ No extracted directory found — scanning firmware file only.", tag="warn")
                scan_dirs = []

            # Scan the firmware binary itself first
            for fpath in scan_targets:
                try:
                    matches = rules.match(fpath, timeout=30)
                    for m in matches:
                        fname = os.path.basename(fpath)
                        hits.append({"file": fpath, "rule": m.rule, "tags": ", ".join(m.tags) if m.tags else "—"})
                        self.log(f"  ⚠ YARA HIT [{m.rule}] in {fname}", tag="hit")
                except Exception:
                    pass

            # Scan extracted filesystem
            for scan_dir in scan_dirs:
                for root, _, files in os.walk(scan_dir):
                    for fname in files:
                        if self.stop_event.is_set():
                            break
                        fpath = os.path.join(root, fname)
                        # Skip symlinks and very large files (>50MB)
                        try:
                            if os.path.islink(fpath): continue
                            if os.path.getsize(fpath) > 50 * 1024 * 1024: continue
                        except Exception:
                            continue
                        try:
                            matches = rules.match(fpath, timeout=10)
                            for m in matches:
                                hits.append({"file": fpath, "rule": m.rule, "tags": ", ".join(m.tags) if m.tags else "—"})
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
    #  MODULE 6: QEMU DYNAMIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════

    # Arch string → qemu-user binary name
    QEMU_BINS = {
        "mips":    "qemu-mips",
        "mipsel":  "qemu-mipsel",
        "arm":     "qemu-arm",
        "aarch64": "qemu-aarch64",
        "x86_64":  "qemu-x86_64",
        "i386":    "qemu-i386",
        "ppc":     "qemu-ppc",
    }

    # Suspicious syscall / string patterns to watch for
    SUSPICIOUS_PATTERNS = [
        # ── NOT listed here: socket/bind/connect/listen → caught by NET filter ──
        "execve",                              # process execution
        "system(", "popen(",                   # shell invocation
        "/etc/passwd", "/etc/shadow",          # credential file access
        "/bin/sh", "/bin/bash",                # shell spawning
        "chmod(", "chown(",                    # permission changes
        "ptrace(",                             # debugger/anti-analysis
        "wget", "curl", "tftp",               # download tools
        "base64",                              # encoding (obfuscation)
        "/tmp/",                               # temp file drops
        "iotgoat", "backdoor", "exploit",      # IoTGoat-specific strings
    ]

    def _start_qemu(self):
        path = self.qemu_entry.get().strip()
        if not path or not os.path.exists(path):
            self.log("✘ Binary path not found. Enter path to an extracted ELF binary.", tag="warn")
            return
        arch    = self.qemu_arch.get()
        timeout = int(self.qemu_timeout.get().strip() or "30")
        self._spawn(self._qemu_worker, path, arch, timeout)

    def _qemu_worker(self, binary_path: str, arch: str, timeout: int):
        self.log(f"▸ QEMU dynamic analysis: {binary_path}", tag="system")
        self._set_status("Running QEMU emulation…")

        result = {
            "binary":     binary_path,
            "arch":       arch,
            "syscalls":   [],
            "network":    [],
            "suspicious": [],
            "stdout":     "",
            "stderr":     "",
            "strace_out": "",
        }

        try:
            # ── Step 1: Detect architecture ───────────────────────────────
            if arch == "auto-detect":
                arch = self._detect_arch(binary_path)
                self.log(f"  Detected architecture: {arch}", tag="info")
                result["arch"] = arch

            qemu_bin = self.QEMU_BINS.get(arch)
            if not qemu_bin:
                self.log(f"✘ Unsupported architecture: {arch}", tag="error")
                return

            # Check qemu is available
            if not self._which(qemu_bin):
                self.log(f"✘ {qemu_bin} not found. Install qemu-user or qemu-user-static.", tag="error")
                self.log( "  Ubuntu: sudo apt install qemu-user qemu-user-static", tag="info")
                self.log( "  macOS:  brew install qemu", tag="info")
                return

            # ── Step 2: Find sysroot (extracted rootfs from binwalk) ──────
            sysroot = self._find_sysroot(binary_path)
            if sysroot:
                self.log(f"  Sysroot found: {sysroot}", tag="info")
            else:
                self.log("  No sysroot found — running without (may get missing lib errors)", tag="warn")

            # ── Step 2b: Smart binary + args selection ────────────────────
            binary_name = os.path.basename(binary_path)
            extra_args  = []
            run_binary  = binary_path

            if binary_name == "busybox":
                root = sysroot or os.path.dirname(os.path.dirname(binary_path))
                # Prefer uhttpd — confirmed working with IoTGoat
                www_dir = os.path.join(root, "www")
                for daemon, args in [
                    ("uhttpd",   ["-f", "-p", "18080", "-h", www_dir if os.path.isdir(www_dir) else "/"]),
                    ("httpd",    ["-f", "-p", "18080"]),
                    ("telnetd",  ["-F", "-p", "12323"]),
                    ("dropbear", ["-F", "-p", "12222"]),
                ]:
                    found = self._find_binary(root, daemon)
                    if found:
                        run_binary = found
                        extra_args = args
                        self.log(f"  Switching to daemon: {daemon} {' '.join(args)}", tag="info")
                        break
                else:
                    # No daemon found — use busybox ls for syscall capture
                    extra_args = ["ls", "/"]
                    self.log("  No daemon found — running: busybox ls /", tag="info")

            # ── Step 3: Run with strace ───────────────────────────────────
            self.log(f"  Launching {qemu_bin} with strace (timeout={timeout}s) …", tag="info")
            strace_log = run_binary + ".strace"

            qemu_cmd = [qemu_bin]
            if sysroot:
                qemu_cmd += ["-L", sysroot]
            qemu_cmd += [run_binary] + extra_args

            cmd = ["strace", "-f", "-e", "trace=network,process,file,signal",
                   "-o", strace_log] + qemu_cmd

            self.log(f"  CMD: {' '.join(cmd)}", tag="info")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True   # puts process in its own group
                )

                def _kill_group():
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        proc.kill()
                timer = threading.Timer(timeout, _kill_group)
                try:
                    timer.start()
                    stdout, stderr = proc.communicate()
                finally:
                    timer.cancel()

                self.log(f"  Emulation ran for {timeout}s then was terminated.", tag="info")
                result["stdout"] = stdout[:2000]
                result["stderr"] = stderr[:2000]

                if stdout.strip():
                    self.log("  ── Binary stdout ──", tag="info")
                    for line in stdout.splitlines()[:20]:
                        self.log(f"    {line}", tag="info")
                if stderr.strip():
                    self.log("  ── Binary stderr ──", tag="warn")
                    for line in stderr.splitlines()[:10]:
                        self.log(f"    {line}", tag="warn")

            except FileNotFoundError:
                self.log("  strace not found — run: sudo apt install strace", tag="warn")
                strace_log = None

                bare_cmd = [qemu_bin]
                if sysroot: bare_cmd += ["-L", sysroot]
                bare_cmd += [run_binary] + extra_args
                try:
                    proc = subprocess.Popen(bare_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    timer = threading.Timer(timeout, proc.kill)
                    try:
                        timer.start()
                        stdout, stderr = proc.communicate()
                    finally:
                        timer.cancel()
                    result["stdout"] = stdout[:2000]
                    result["stderr"] = stderr[:2000]
                    for line in stdout.splitlines()[:20]:
                        self.log(f"    {line}", tag="info")
                except Exception as e:
                    self.log(f"  ✘ Emulation error: {e}", tag="error")

            # ── Step 4: Parse strace output ───────────────────────────────
            if strace_log and os.path.exists(strace_log):
                self.log("  Parsing strace output …", tag="info")
                with open(strace_log, "r", errors="ignore") as f:
                    strace_lines = f.readlines()

                result["strace_out"] = "".join(strace_lines[:500])
                syscall_counts = {}
                network_calls  = []
                suspicious     = []

                for line in strace_lines:
                    # Count syscalls
                    import re
                    m = re.match(r"\[?(?:\d+)?\]?\s*(\w+)\(", line)
                    if m:
                        sc = m.group(1)
                        syscall_counts[sc] = syscall_counts.get(sc, 0) + 1

                    # Flag network activity
                    if any(k in line for k in ("socket(", "bind(", "listen(", "connect(", "sendto(", "recvfrom(")):
                        is_noise = (
                            "sin6_port=htons(65535)" in line or    # QEMU interface probe
                            ("SOCK_DGRAM" in line and "65535" in line)
                        )
                        if not is_noise:
                            clean = line.strip()[:120]
                            network_calls.append(clean)
                            self.log(f"  [NET] {clean}", tag="hit")

                    # Flag suspicious — skip all QEMU host-side noise
                    is_qemu_noise = (
                        "qemu-arm" in line or
                        "qemu-mips" in line or
                        "/proc/sys/vm/mmap" in line or
                        "/proc/self" in line or
                        "/lib/x86_64-linux-gnu" in line or
                        "/etc/ld.so" in line or
                        "ld.so.cache" in line or
                        "libglib" in line or
                        "CLONE_VM" in line or
                        "rt_sigaction" in line or
                        "rt_sigprocmask" in line
                    )
                    if not is_qemu_noise:
                        for pattern in self.SUSPICIOUS_PATTERNS:
                            if pattern in line:
                                clean = line.strip()[:120]
                                if clean not in suspicious:
                                    suspicious.append(clean)
                                    self.log(f"  [⚠] {clean}", tag="hit")
                                break

                result["syscalls"] = syscall_counts
                result["network"]  = network_calls[:50]
                result["suspicious"] = suspicious[:50]

                # Summary
                self.log(f"  Syscalls seen: {len(syscall_counts)} unique types", tag="info")
                self.log(f"  Network calls: {len(network_calls)}", tag="warn" if network_calls else "info")
                self.log(f"  Suspicious:    {len(suspicious)}",   tag="hit"  if suspicious    else "info")

                # Top syscalls
                top = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                self.log(f"  Top syscalls: {', '.join(f'{k}({v})' for k,v in top)}", tag="info")

                os.remove(strace_log)   # clean up

        except Exception as e:
            self.log(f"✘ QEMU error: {e}", tag="error")
        finally:
            self.audit_data["qemu_analysis"].append(result)
            self.log("▸ QEMU analysis complete.", tag="success")
            self._set_status("Ready")

    @staticmethod
    def _find_squashfs_offset(path: str) -> int | None:
        """Use binwalk in scan mode to find squashfs offset."""
        try:
            result = subprocess.run(
                ["binwalk", path], capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                if "squashfs" in line.lower():
                    parts = line.split()
                    if parts:
                        try: return int(parts[0])
                        except ValueError: pass
        except Exception:
            pass
        return None

    @staticmethod
    def _find_binary(root_dir: str, name: str) -> str:
        """
        Search for a binary by name, prioritising standard executable dirs.
        Returns the first match in: usr/sbin → sbin → usr/bin → bin → anywhere.
        """
        priority_dirs = [
            os.path.join(root_dir, "usr", "sbin"),
            os.path.join(root_dir, "sbin"),
            os.path.join(root_dir, "usr", "bin"),
            os.path.join(root_dir, "bin"),
        ]
        # Check priority dirs first
        for d in priority_dirs:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate
        # Fall back to full walk
        for dirpath, dirs, files in os.walk(root_dir):
            # Skip non-executable dirs to avoid false matches
            dirs[:] = [d for d in dirs if d not in ("upgrade", "keep.d", "opkg", "tmp")]
            if name in files:
                full = os.path.join(dirpath, name)
                if os.path.isfile(full):
                    return full
        return ""

    def _detect_arch(self, path: str) -> str:
        """Use 'file' command or binwalk output to detect ELF architecture."""
        try:
            out = subprocess.run(["file", path], capture_output=True, text=True).stdout.lower()
            if "mips" in out:
                return "mipsel" if "little" in out else "mips"
            if "aarch64" in out or "arm64" in out:
                return "aarch64"
            if "arm" in out:
                return "arm"
            if "x86-64" in out or "x86_64" in out:
                return "x86_64"
            if "80386" in out or "i386" in out:
                return "i386"
            if "powerpc" in out or "ppc" in out:
                return "ppc"
        except Exception:
            pass

        # Fall back to binwalk output already captured
        bw = self.audit_data.get("binwalk_output", "").lower()
        if "mips" in bw:    return "mips"
        if "arm"  in bw:    return "arm"
        if "x86"  in bw:    return "x86_64"

        return "mips"   # most common IoT arch

    def _find_sysroot(self, binary_path: str) -> str:
        """
        Walk UP the directory tree from the binary to find the squashfs-root
        (the directory that contains lib/, usr/, bin/, etc.).
        e.g. binary = .../squashfs-root/bin/busybox → sysroot = .../squashfs-root
        """
        candidate = os.path.dirname(binary_path)
        while candidate and candidate != "/":
            has_lib = any(
                os.path.isdir(os.path.join(candidate, d))
                for d in ("lib", "usr", "bin", "etc")
            )
            if has_lib:
                return candidate
            candidate = os.path.dirname(candidate)
        return ""

    @staticmethod
    def _which(binary: str) -> bool:
        """Check if a binary exists on PATH."""
        import shutil
        return shutil.which(binary) is not None
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

        # QEMU dynamic analysis summary
        qemu_str = ""
        for q in d.get("qemu_analysis", []):
            qemu_str += f"\n  Binary : {q['binary']}\n"
            qemu_str += f"  Arch   : {q['arch']}\n"
            if q.get("syscalls"):
                top = sorted(q["syscalls"].items(), key=lambda x: x[1], reverse=True)[:10]
                qemu_str += f"  Top syscalls: {', '.join(f'{k}({v})' for k,v in top)}\n"
            if q.get("network"):
                qemu_str += f"  Network calls ({len(q['network'])}):\n"
                for nc in q["network"][:10]:
                    qemu_str += f"    {nc}\n"
            if q.get("suspicious"):
                qemu_str += f"  Suspicious activity ({len(q['suspicious'])}):\n"
                for s in q["suspicious"][:10]:
                    qemu_str += f"    {s}\n"
            if q.get("stdout"):
                qemu_str += f"  Stdout preview: {q['stdout'][:300]}\n"
        qemu_str = qemu_str or "  Not run."

        return f"""You are a senior IoT security forensics expert. Analyse the following audit data and produce a structured, comprehensive security report.

FORMAT:
1. Executive Summary
2. Network Topology & Exposed Devices
3. Port & Service Vulnerability Analysis
4. Network Traffic Observations
5. Firmware Analysis Findings
6. YARA Malware/Indicator Scan Results
7. Dynamic Analysis (QEMU Emulation) Findings
8. Risk Matrix (table: Finding | Severity | Recommendation)
9. Remediation Roadmap (prioritised steps)
10. Conclusion

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

QEMU DYNAMIC ANALYSIS:
{qemu_str}
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
        """Return nmap scanner using system PATH (Linux)."""
        return nmap.PortScanner()


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = ForensicSentinel()
    app.mainloop()
