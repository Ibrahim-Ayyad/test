import customtkinter as ctk
import nmap
import serial
import yara
import threading
import os
from datetime import datetime

# --- SETTINGS & THEME ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class IoTSecuritySuite(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("IoT Sentinel: Tapo C100 Security Suite")
        self.geometry("900x600")

        # Layout Grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="IoT SENTINEL", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.target_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Target IP (e.g. 192.168.1.5)")
        self.target_entry.grid(row=1, column=0, padx=20, pady=10)

        self.scan_btn = ctk.CTkButton(self.sidebar, text="Run Dynamic Scan", command=self.start_nmap)
        self.scan_btn.grid(row=2, column=0, padx=20, pady=10)

        self.serial_btn = ctk.CTkButton(self.sidebar, text="Start Serial Dump", fg_color="transparent", border_width=2, command=self.start_serial)
        self.serial_btn.grid(row=3, column=0, padx=20, pady=10)

        self.yara_btn = ctk.CTkButton(self.sidebar, text="Analyze Firmware", fg_color="#A155B9", command=self.run_yara)
        self.yara_btn.grid(row=4, column=0, padx=20, pady=10)

        # --- MAIN TERMINAL ---
        self.textbox = ctk.CTkTextbox(self, font=("Courier New", 12))
        self.textbox.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

    def log(self, message):
        self.textbox.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.textbox.see("end")

    # --- DYNAMIC SCANNING LOGIC ---
    def start_nmap(self):
        target = self.target_entry.get()
        if not target:
            self.log("ERROR: Please enter a Target IP.")
            return
        
        self.log(f"Starting Nmap Audit on {target}...")
        threading.Thread(target=self.nmap_worker, args=(target,), daemon=True).start()

    def nmap_worker(self, target):
        nm = nmap.PortScanner()
        # Scanning common Tapo ports: 22, 23, 554, 2020, 80, 443, 8080
        nm.scan(target, '22,23,554,2020,80,443,8080', arguments='-sV --script rtsp-url-enumeration,http-title')
        
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                ports = nm[target][proto].keys()
                for port in ports:
                    state = nm[target][proto][port]['state']
                    service = nm[target][proto][port]['product']
                    self.log(f"FOUND: Port {port}/{proto} is {state} ({service})")
        else:
            self.log("Scan Complete: No open ports found.")

    # --- SERIAL DUMP LOGIC ---
    def start_serial(self):
        self.log("Opening Serial Port /dev/ttyUSB0...")
        threading.Thread(target=self.serial_worker, daemon=True).start()

    def serial_worker(self):
        try:
            # Adjust COM port for Windows or /dev/tty for Linux
            with serial.Serial('/dev/ttyUSB0', 115200, timeout=1) as ser:
                with open("dump_output.bin", "ab") as f:
                    self.log("Dumping data to dump_output.bin... (Press Stop to end)")
                    while True:
                        if ser.in_waiting:
                            data = ser.read(ser.in_waiting)
                            f.write(data)
        except Exception as e:
            self.log(f"SERIAL ERROR: {e}")

    # --- STATIC ANALYSIS (YARA) LOGIC ---
    def run_yara(self):
        if not os.path.exists("dump_output.bin"):
            self.log("ERROR: No firmware dump found. Run Serial Dump first.")
            return

        self.log("Compiling YARA rules for Tapo C100...")
        rules_str = """
        rule Tapo_Hardcoded_Strings {
            strings:
                $s1 = "TP-Link" nocase
                $s2 = "root:x:0:0"
                $s3 = "admin123"
            condition:
                any of them
        }
        """
        try:
            rules = yara.compile(source=rules_str)
            matches = rules.match("dump_output.bin")
            if matches:
                for m in matches:
                    self.log(f"CRITICAL: YARA Match Found -> {m.rule}")
            else:
                self.log("YARA: No suspicious signatures found in binary.")
        except Exception as e:
            self.log(f"YARA ERROR: {e}")

if __name__ == "__main__":
    app = IoTSecuritySuite()
    app.mainloop()
