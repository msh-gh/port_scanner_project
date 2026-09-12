# src/scanner.py

import socket
import threading
import argparse
import time
from datetime import datetime

print_lock = threading.Lock()
open_ports = []

# Common port-to-service mapping with risk insights
PORT_ANALYSIS = {
    21: ("FTP", "High", "Disable if unused. Use SFTP instead."),
    22: ("SSH", "Medium", "Use strong passwords and key authentication."),
    23: ("Telnet", "High", "Disable. Use SSH instead."),
    25: ("SMTP", "Medium", "Use authentication and secure mail transfer."),
    53: ("DNS", "Low", "Ensure DNS servers are patched."),
    80: ("HTTP", "Medium", "Use HTTPS. Ensure web server is up-to-date."),
    110: ("POP3", "High", "Use secure alternatives like POP3S."),
    135: ("RPC", "High", "Block if not needed. Can be exploited."),
    139: ("NetBIOS", "High", "Disable file sharing if unnecessary."),
    143: ("IMAP", "Medium", "Use secure version IMAPS."),
    443: ("HTTPS", "Low", "Keep certificates and server updated."),
    445: ("SMB", "High", "Disable if not needed. Vulnerable to ransomware."),
    3306: ("MySQL", "High", "Use firewalls and strong DB credentials."),
    3389: ("RDP", "High", "Use Network Level Authentication (NLA).")
}

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            with print_lock:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
        sock.close()
    except Exception:
        pass

def validate_target(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False

def analyze_ports():
    report_lines = []
    for port in open_ports:
        if port in PORT_ANALYSIS:
            service, risk, recommendation = PORT_ANALYSIS[port]
        else:
            service, risk, recommendation = "Unknown", "Unknown", "Investigate the purpose of this open port."

        report_lines.append({
            "port": port,
            "service": service,
            "risk": risk,
            "recommendation": recommendation
        })
    return report_lines

def save_report(report_data, args, duration):
    filename = args.output or f"reports/report_{args.target}_{int(time.time())}.txt"
    try:
        with open(filename, "w") as f:
            f.write("="*60 + "\n")
            f.write(f"PORT SCAN REPORT\nTarget: {args.target}\n")
            f.write(f"Port Range: {args.start}-{args.end}\n")
            f.write(f"Scan Time: {datetime.now()}\n")
            f.write(f"Scan Duration: {duration:.2f} seconds\n")
            f.write("="*60 + "\n\n")

            if not report_data:
                f.write("✅ No open ports detected.\n")
            else:
                for entry in report_data:
                    f.write(f"[+] Port {entry['port']} - {entry['service']}\n")
                    f.write(f"    Risk Level: {entry['risk']}\n")
                    f.write(f"    Recommendation: {entry['recommendation']}\n\n")

            f.write("="*60 + "\n")
            f.write("⚠️ Note: Open ports are potential attack surfaces.\n")
            f.write("Always follow security best practices.\n")
        print(f"\n📄 Professional report saved to: {filename}")
    except:
        print("⚠️ Failed to save the report.")

def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner with Vulnerability Report")
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-o", "--output", help="Output file for report")
    args = parser.parse_args()

    if not validate_target(args.target):
        print("❌ Invalid target. Please enter a valid IP or domain.")
        return

    print(f"\n🎯 Scanning {args.target} from port {args.start} to {args.end}")
    print("Scan started at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("-" * 60)

    start_time = time.time()

    threads = []
    for port in range(args.start, args.end + 1):
        t = threading.Thread(target=scan_port, args=(args.target, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    duration = time.time() - start_time

    print("\n✅ Scan complete!")
    print(f"🕐 Duration: {duration:.2f} seconds")

    report_data = analyze_ports()
    save_report(report_data, args, duration)

if __name__ == "__main__":
    main()
