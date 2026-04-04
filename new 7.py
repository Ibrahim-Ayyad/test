import nmap
import argparse
import sys
from datetime import datetime

TELNET_PORTS = "23,2323,2324,2023"
WEB_PORTS = "80,443,8080,8081,81,88"
RTSP_PORTS = "554,8554,10554"

def run_audit(target_ip, output_file):
    nm = nmap.PortScanner()
    found_ports = {"telnet": [], "web": [], "rtsp": []}

    print(f"[*] Starting Audit: {target_ip}")
    print(f"[*] Step 1: Discovering active services...")

    
    all_ports = f"{TELNET_PORTS},{WEB_PORTS},{RTSP_PORTS}"
    nm.scan(target_ip, ports=all_ports, arguments="-sT -T4")

    if target_ip not in nm.all_hosts():
        print(f"[-] Error: Target {target_ip} appears to be offline.")
        return

    # Categorize 
    for port in nm[target_ip].all_tcp():
        state = nm[target_ip]['tcp'][port]['state']
        if state == 'open':
            p_str = str(port)
            if p_str in TELNET_PORTS: found_ports["telnet"].append(p_str)
            elif p_str in WEB_PORTS: found_ports["web"].append(p_str)
            elif p_str in RTSP_PORTS: found_ports["rtsp"].append(p_str)

    # Step 2:scripts ports
    print(f"[*] Step 2: Running vulnerability scripts on discovered ports...")
    
    with open(output_file, "w") as f:
        f.write(f"IoT Audit Report: {target_ip}\nGenerated: {datetime.now()}\n")
        f.write("="*50 + "\n\n")

        # 1.Telnet
        if found_ports["telnet"]:
            ports = ",".join(found_ports["telnet"])
            print(f"    [!] Auditing Telnet on: {ports}")
            nm.scan(target_ip, ports=ports, arguments="-sV --script telnet-brute")
            write_results(f, nm[target_ip], "Telnet")

        # 2.Web
        if found_ports["web"]:
            ports = ",".join(found_ports["web"])
            print(f"    [!] Auditing Web UI on: {ports}")
            nm.scan(target_ip, ports=ports, arguments="-sV --script http-default-accounts,http-title")
            write_results(f, nm[target_ip], "Web Interface")

        # 3.RTSP
        if found_ports["rtsp"]:
            ports = ",".join(found_ports["rtsp"])
            print(f"    [!] Auditing RTSP on: {ports}")
            nm.scan(target_ip, ports=ports, arguments="-sV --script rtsp-url-enumeration")
            write_results(f, nm[target_ip], "Video Stream")

    print(f"\n[+] Audit Complete. Report saved to: {output_file}")

def write_results(f, host_data, category):
    f.write(f"--- {category} Analysis ---\n")
    for port in host_data.all_tcp():
        port_info = host_data['tcp'][port]
        f.write(f"Port {port}: {port_info.get('product', 'Unknown')} {port_info.get('version', '')}\n")
        if 'script' in port_info:
            for sid, out in port_info['script'].items():
                f.write(f"  > {sid}:\n{out}\n")
    f.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated IoT Service Discovery & Audit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-o", "--output", help="Output file", default="audit_results.txt")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    run_audit(args.target, args.output)