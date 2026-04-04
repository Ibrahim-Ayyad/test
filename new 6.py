import subprocess
from datetime import datetime

TARGET = "127.0.0.1" 
PORTS = "2323,80,443,554,8080" # Telnet, HTTP, HTTPS, RTSP, Alt-HTTP
OUTPUT_FILE = "iot_audit_results.txt"

def run_nmap(command, title):
    print(f"[*] Executing {title}...")
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"\n{'='*80}\n{title}\n{'='*80}\n")
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n[STDERR]\n{result.stderr}")
            return result.stdout
        except subprocess.TimeoutExpired:
            f.write("\n[!] Error: Scan timed out.\n")
            return ""
        except Exception as e:
            f.write(f"\n[!] Error: {str(e)}\n")
            return ""

def main():
    # Setup the report file
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"IoT Camera Security Audit\nTarget: {TARGET}\nDate: {datetime.now()}\n\n")

    # STEP 1: Intensive Service & Version Discovery
    print(f"Starting audit on {TARGET}...")
    run_nmap(
        ["nmap", "-sV", "-p", PORTS, TARGET], 
        "STEP 1: Service and Version Discovery"
    )

    # STEP 2: Telnet Brute Force (Your original logic)
    run_nmap(
        ["nmap", "-p", "2323", "--script", "telnet-brute", TARGET],
        "STEP 2: Telnet Credential Audit"
    )

    # STEP 3: Web UI Vulnerability & Default Credentials
    # 'http-enum' finds interesting directories, 'http-default-accounts' checks logins
    run_nmap(
        ["nmap", "-p", "80,443,8080", "--script", "http-enum,http-default-accounts", TARGET],
        "STEP 3: Web Interface & Default Credential Audit"
    )

    # STEP 4: RTSP Video Stream Check
    # Determines if the camera video stream is accessible without a password
    run_nmap(
        ["nmap", "-p", "554", "--script", "rtsp-methods,rtsp-url-enumeration", TARGET],
        "STEP 4: RTSP Video Stream Analysis"
    )

    # STEP 5: Generic Vulnerability Scan (CVEs)
    # Using the 'vulners' script (requires internet for nmap to download DB usually)
    run_nmap(
        ["nmap", "-sV", "-p", PORTS, "--script", "vulners", TARGET],
        "STEP 5: Known CVE Vulnerability Scan"
    )

    print(f"\n[+] Audit Complete. Full report saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()