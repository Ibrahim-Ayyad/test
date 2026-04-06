import customtkinter as ctk
import nmap
import serial
import serial.tools.list_ports
import yara
import threading
import os
import socket
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class IoTSentinel(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("IoT Sentinel: Tapo C100 Discovery & Audit")
        self.geometry("1100x700")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="IoT SENTINEL", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # --- NEW: Host Discovery Section ---
        self.discover_label = ctk.CTkLabel(self.sidebar, text="1. Network Discovery", font=ctk.CTkFont(weight="bold"))
        self.discover_label.grid(row=1, column=0, padx=20, pady=(10, 0))

        self.discover_btn = ctk.CTkButton(self.sidebar, text="Find Devices", command=self.start_discovery)
        self.discover_btn.grid(row=2, column=0, padx=20, pady=10)

        self.ip_menu = ctk.CTkOptionMenu(self.sidebar, values=["Select Target IP"])
        self.ip_menu.grid(row=3, column=0, padx=20, pady=10)

        # --- Audit Section ---
        self.audit_label = ctk.CTkLabel(self.sidebar, text="2. Security Audit", font=ctk.CTkFont(weight="bold"))
        self.audit_label.grid(row=4, column=0, padx=20, pady=(20, 0))

        self.scan_btn = ctk.CTkButton(self.sidebar, text="Run Vulnerability Scan", command=self.start_nmap)
        self.scan_btn.grid(row=5, column=0, padx=20, pady=10)

        # --- Hardware Section ---
        self.hw_label = ctk.CTkLabel(self.sidebar, text="3. Hardware Analysis", font=ctk.CTkFont(weight="bold"))
        self.hw_label.grid(row=6, column=0, padx=20, pady=(20, 0))

        self.com_ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_menu = ctk.CTkOptionMenu(self.sidebar, values=self.com_ports if self.com_ports else ["No COM Found"])
        self.port_menu.grid(row=7, column=0, padx=20, pady=10)

        self.serial_btn = ctk.CTkButton(self.sidebar, text="Start Serial Dump", fg_color="transparent", border_width=2, command=self.start_serial)
        self.serial_btn.grid(row=8, column=0, padx=20, pady=10)

        self.yara_btn = ctk.CTkButton(self.sidebar, text="Run YARA Static Analysis", fg_color="#A155B9", command=self.run_yara)
        self.yara_btn.grid(row=9, column=0, padx=20, pady=10)

        # --- MAIN TERMINAL ---
        self.textbox = ctk.CTkTextbox(self, font=("Courier New", 13))
        self.textbox.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

    def log(self, message):
        self.textbox.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.textbox.see("end")

    # --- FEATURE: Host Discovery Logic ---
    def start_discovery(self):
        self.log("Searching for devices on the local network...")
        threading.Thread(target=self.discovery_worker, daemon=True).start()

    def discovery_worker(self):
        try:
            # Get local IP range (e.g., 192.168.1.0/24)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            network_range = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            
            nm = nmap.PortScanner()
            self.log(f"Scanning range: {network_range}")
            # -sn is a Ping Scan (Host Discovery only)
            nm.scan(hosts=network_range, arguments='-sn')
            
            discovered_ips = [host for host in nm.all_hosts()]
            
            if discovered_ips:
                self.ip_menu.configure(values=discovered_ips)
                self.ip_menu.set(discovered_ips[0])
                self.log(f"SUCCESS: Found {len(discovered_ips)} active hosts.")
                for ip in discovered_ips:
                    vendor = nm[ip].get('vendor', {}).get(list(nm[ip].get('vendor', {}).keys())[0], "Unknown Vendor") if nm[ip].get('vendor') else "Unknown"
                    self.log(f"  > {ip} ({vendor})")
            else:
                self.log("No hosts found. Check your network connection.")
        except Exception as e:
            self.log(f"DISCOVERY ERROR: {e}")

    # --- Existing Vulnerability Scan ---
    def start_nmap(self):
        target = self.ip_menu.get()
        if target == "Select Target IP":
            self.log("ERROR: Please run Discovery or select an IP first.")
            return
        self.log(f"Starting Vulnerability Scan on {target}...")
        threading.Thread(target=self.nmap_worker, args=(target,), daemon=True).start()

    def nmap_worker(self, target):
        try:
            nm = nmap.PortScanner()
            # Targeted ports for Tapo C100
            nm.scan(target, '23,80,443,554,2020', arguments='-sV --script http-title,rtsp-methods')
            if target in nm.all_hosts():
                for port in nm[target]['tcp']:
                    self.log(f"PORT {port}: {nm[target]['tcp'][port]['state']} | {nm[target]['tcp'][port]['product']}")
            self.log("Scan Finished.")
        except Exception as e:
            self.log(f"SCAN ERROR: {e}")

    # --- Serial & YARA Logic (Same as before) ---
    def start_serial(self):
        port = self.port_menu.get()
        if "COM" not in port and "/dev/" not in port:
            self.log("ERROR: Select a valid Serial Port.")
            return
        threading.Thread(target=self.serial_worker, args=(port,), daemon=True).start()

    def serial_worker(self, port):
        try:
            with serial.Serial(port, 115200, timeout=1) as ser:
                with open("firmware_dump.bin", "ab") as f:
                    self.log(f"Connected to {port}. Dumping data...")
                    while True:
                        if ser.in_waiting: f.write(ser.read(ser.in_waiting))
        except Exception as e: self.log(f"SERIAL ERROR: {e}")

    def run_yara(self):
        if not os.path.exists("firmware_dump.bin"):
            self.log("ERROR: No dump file found.")
            return
        rules = yara.compile(source='rule TapoCheck { strings: $a = "TP-Link" $b = "admin" condition: any of them }')
        matches = rules.match("firmware_dump.bin")
        self.log(f"YARA Result: Found {len(matches)} suspicious patterns." if matches else "YARA Result: Clean.")

if __name__ == "__main__":
    app = IoTSentinel()
    app.mainloop()
