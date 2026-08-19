#!/usr/bin/env python3
"""
Generates a synthetic sample .pcap file so anyone cloning this repo can
run the analyzer immediately without needing live network access or
root privileges.

The synthetic traffic simulates a small internal banking network segment
and intentionally includes:
  - Normal HTTPS / DNS traffic
  - A plaintext HTTP login POST (credential leak)
  - Traffic to a suspicious port (Telnet, 23)
  - A simple port-scan pattern from a single source IP

Run:
    python3 generate_sample_pcap.py
Output:
    ../samples/demo_traffic.pcap
"""

from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, Raw
import random

packets = []

# Normal HTTPS traffic (encrypted, no payload of interest)
for _ in range(15):
    src = f"10.0.1.{random.randint(10, 50)}"
    packets.append(
        Ether() / IP(src=src, dst="172.16.0.10") /
        TCP(sport=random.randint(40000, 60000), dport=443, flags="PA") /
        Raw(load=b"\x17\x03\x03" + bytes(random.randint(20, 200)))
    )

# Normal DNS lookups
for domain in [b"internal-banking-portal.local", b"sap-erp.internal", b"outlook.office.com"]:
    packets.append(
        Ether() / IP(src="10.0.1.15", dst="10.0.0.1") /
        UDP(sport=53321, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain))
    )

# --- ANOMALY 1: Plaintext HTTP login (credential leak) ---
packets.append(
    Ether() / IP(src="10.0.1.22", dst="172.16.0.20") /
    TCP(sport=51000, dport=80, flags="PA") /
    Raw(load=b"POST /login HTTP/1.1\r\nHost: legacy-vendor-portal.local\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
             b"user=jsmith&password=Summer2024!")
)

# --- ANOMALY 2: Suspicious port (Telnet) ---
packets.append(
    Ether() / IP(src="10.0.1.30", dst="10.0.2.5") /
    TCP(sport=52000, dport=23, flags="S")
)
packets.append(
    Ether() / IP(src="10.0.1.30", dst="10.0.2.5") /
    TCP(sport=52000, dport=23, flags="PA") /
    Raw(load=b"login: admin\r\npassword: admin123\r\n")
)

# --- ANOMALY 3: Port scan pattern from one source ---
scanner_ip = "10.0.1.99"
target_ip = "10.0.2.10"
for port in [21, 22, 23, 25, 80, 135, 139, 445, 3389, 8080]:
    packets.append(
        Ether() / IP(src=scanner_ip, dst=target_ip) /
        TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
    )

random.shuffle(packets)

wrpcap("../samples/demo_traffic.pcap", packets)
print(f"[+] Wrote {len(packets)} synthetic packets to ../samples/demo_traffic.pcap")
