"""
Simple Network Port Scanner
----------------------------
A beginner-friendly tool that scans a target IP address for open TCP ports.

How it works:
1. For each port in the given range, we try to open a TCP connection
   to the target using Python's 'socket' library.
2. If the connection succeeds -> the port is OPEN (something is listening).
3. If the connection fails/times out -> the port is CLOSED or filtered.

This demonstrates core networking + cybersecurity concepts:
- TCP handshake basics (connect_ex attempts a real TCP connect)
- Port scanning fundamentals (used in reconnaissance / network defense)
- Socket programming in Python

Author: Parth Shah
"""

import socket
from datetime import datetime

# A small list of well-known ports and what they're commonly used for.
# (Real scanners check all 65535 ports, but this keeps the demo fast.)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def scan_port(target_ip, port, timeout=0.5):
    """
    Try to connect to a single port on the target.
    Returns True if the port is open, False otherwise.
    """
    # AF_INET  -> we are using IPv4
    # SOCK_STREAM -> we are using TCP (not UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # connect_ex returns 0 if the connection succeeded (port is open)
    result = sock.connect_ex((target_ip, port))
    sock.close()

    return result == 0


def scan_target(target_ip, ports_to_scan):
    """
    Scan a list/range of ports on the target IP and print results.
    """
    print(f"\nStarting scan on {target_ip}")
    print(f"Time started: {datetime.now()}")
    print("-" * 45)

    open_ports = []

    for port in ports_to_scan:
        if scan_port(target_ip, port):
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"[OPEN]   Port {port:<6} ({service})")
            open_ports.append(port)
        else:
            # Comment this line out if you only want to see open ports
            print(f"[closed] Port {port}")

    print("-" * 45)
    print(f"Scan complete. {len(open_ports)} open port(s) found: {open_ports}")


if __name__ == "__main__":
    # 'localhost' / 127.0.0.1 is safe to scan — it's your own machine.
    # Only scan systems you own or have explicit permission to test —
    # scanning others' systems without permission is illegal.
    target = input("Enter target IP to scan (press Enter for localhost): ").strip()
    if target == "":
        target = "127.0.0.1"

    scan_target(target, COMMON_PORTS.keys())
