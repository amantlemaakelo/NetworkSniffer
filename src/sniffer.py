#!/usr/bin/env python3
"""
BankWatch — Network Traffic Visibility & Anomaly Sniffer
===========================================================

A packet capture and analysis tool built for CodeAlpha's Cyber Security
internship (Task 1: Basic Network Sniffer), extended and reframed as a
lightweight network visibility tool for a financial-services environment.

Core capabilities:
  - Live packet capture using scapy
  - Protocol breakdown (Ethernet / IP / TCP / UDP / ICMP / DNS / HTTP)
  - Human-readable, color-coded console output
  - Lightweight anomaly detection:
      * Plaintext credential submission over HTTP (login/password fields)
      * Suspicious / non-standard destination ports
      * Basic port-scan heuristic (many distinct ports from one source
        in a short time window)
  - Structured logging to CSV and JSON for downstream SIEM-style ingestion

Author: Amantle Maakelo
Repo:   CodeAlpha_NetworkSniffer
"""

import argparse
import csv
import json
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    from scapy.layers.inet import Ether
except ImportError:
    print("[!] scapy is required. Install with: pip install scapy --break-system-packages")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUSPICIOUS_PORTS = {
    23: "Telnet (unencrypted remote admin)",
    21: "FTP (unencrypted file transfer)",
    445: "SMB (common lateral-movement target)",
    3389: "RDP (common ransomware entry point)",
    135: "MS-RPC (common exploitation target)",
}

CREDENTIAL_KEYWORDS = [b"password=", b"passwd=", b"pwd=", b"login=", b"user="]

PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 8

# ---------------------------------------------------------------------------
# ANSI colors for console output
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"


class PacketAnalyzer:
    """Parses packets, flags anomalies, and manages structured output."""

    def __init__(self, csv_path=None, json_path=None, verbose=False):
        self.verbose = verbose
        self.records = []
        self.csv_path = csv_path
        self.json_path = json_path

        # source_ip -> deque[(timestamp, dest_port)] for port-scan heuristic
        self._recent_ports = defaultdict(deque)

        self.stats = {
            "total_packets": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "dns": 0,
            "alerts": 0,
        }

    # -- anomaly checks ----------------------------------------------------

    def _check_suspicious_port(self, dst_port):
        return SUSPICIOUS_PORTS.get(dst_port)

    def _check_plaintext_credentials(self, payload: bytes):
        if not payload:
            return False
        lowered = payload.lower()
        return any(keyword in lowered for keyword in CREDENTIAL_KEYWORDS)

    def _check_port_scan(self, src_ip, dst_port, ts):
        window = self._recent_ports[src_ip]
        window.append((ts, dst_port))
        # drop entries outside the time window
        while window and ts - window[0][0] > PORT_SCAN_WINDOW_SECONDS:
            window.popleft()
        unique_ports = {p for _, p in window}
        return len(unique_ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD

    # -- packet handling -----------------------------------------------------

    def handle(self, pkt):
        self.stats["total_packets"] += 1
        ts = time.time()
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "length": len(pkt),
            "alerts": [],
        }

        if IP in pkt:
            record["src_ip"] = pkt[IP].src
            record["dst_ip"] = pkt[IP].dst

            if TCP in pkt:
                self.stats["tcp"] += 1
                record["protocol"] = "TCP"
                record["src_port"] = pkt[TCP].sport
                record["dst_port"] = pkt[TCP].dport

                suspicious = self._check_suspicious_port(pkt[TCP].dport)
                if suspicious:
                    record["alerts"].append(f"Suspicious port: {suspicious}")

                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if self._check_plaintext_credentials(payload):
                        record["alerts"].append(
                            "Possible plaintext credentials in HTTP payload"
                        )

                if self._check_port_scan(pkt[IP].src, pkt[TCP].dport, ts):
                    record["alerts"].append(
                        f"Possible port scan from {pkt[IP].src} "
                        f"(>= {PORT_SCAN_UNIQUE_PORT_THRESHOLD} ports in "
                        f"{PORT_SCAN_WINDOW_SECONDS}s)"
                    )

            elif UDP in pkt:
                self.stats["udp"] += 1
                record["protocol"] = "UDP"
                record["src_port"] = pkt[UDP].sport
                record["dst_port"] = pkt[UDP].dport

                if DNS in pkt and pkt.haslayer(DNSQR):
                    self.stats["dns"] += 1
                    record["protocol"] = "DNS"
                    try:
                        qname = pkt[DNSQR].qname.decode(errors="ignore")
                    except Exception:
                        qname = "?"
                    record["dns_query"] = qname

            elif ICMP in pkt:
                self.stats["icmp"] += 1
                record["protocol"] = "ICMP"

        else:
            record["protocol"] = pkt.summary().split()[0] if pkt else "UNKNOWN"

        if record["alerts"]:
            self.stats["alerts"] += len(record["alerts"])

        self.records.append(record)
        self._print(record)
        return record

    # -- output --------------------------------------------------------------

    def _print(self, r):
        proto_color = {
            "TCP": C.CYAN, "UDP": C.GREEN, "ICMP": C.YELLOW, "DNS": C.GREEN,
        }.get(r["protocol"], C.GRAY)

        line = (
            f"{proto_color}[{r['protocol'] or 'RAW':5}]{C.RESET} "
            f"{r['src_ip'] or '-':>15}:{r['src_port'] or '-':<6} -> "
            f"{r['dst_ip'] or '-':<15}:{r['dst_port'] or '-':<6} "
            f"len={r['length']}"
        )
        if r.get("dns_query"):
            line += f"  query={r['dns_query']}"
        print(line)

        for alert in r["alerts"]:
            print(f"   {C.RED}{C.BOLD}[ALERT]{C.RESET} {C.RED}{alert}{C.RESET}")

    def print_summary(self):
        print(f"\n{C.BOLD}{'='*60}{C.RESET}")
        print(f"{C.BOLD}Capture Summary{C.RESET}")
        print(f"{'='*60}")
        for k, v in self.stats.items():
            print(f"  {k:>15}: {v}")
        print(f"{'='*60}\n")

    def export(self):
        if self.csv_path:
            self._export_csv(self.csv_path)
            print(f"[+] CSV log written to {self.csv_path}")
        if self.json_path:
            self._export_json(self.json_path)
            print(f"[+] JSON log written to {self.json_path}")

    def _export_csv(self, path):
        fieldnames = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "length", "dns_query", "alerts",
        ]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in self.records:
                row = {k: r.get(k, "") for k in fieldnames}
                row["alerts"] = "; ".join(r["alerts"])
                writer.writerow(row)

    def _export_json(self, path):
        with open(path, "w") as f:
            json.dump(self.records, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BankWatch — network traffic visibility & anomaly sniffer"
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff on")
    parser.add_argument("-r", "--read", help="Read from an existing .pcap file instead of live capture")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("--csv", default="capture_log.csv", help="Path to write CSV log")
    parser.add_argument("--json", default="capture_log.json", help="Path to write JSON log")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    analyzer = PacketAnalyzer(csv_path=args.csv, json_path=args.json, verbose=args.verbose)

    print(f"{C.BOLD}BankWatch Network Sniffer{C.RESET} — Ctrl+C to stop\n")

    try:
        if args.read:
            print(f"[*] Reading packets from {args.read}")
            packets = rdpcap(args.read)
            for pkt in packets:
                analyzer.handle(pkt)
        else:
            kwargs = {"prn": analyzer.handle, "store": False}
            if args.iface:
                kwargs["iface"] = args.iface
            if args.count:
                kwargs["count"] = args.count
            if args.filter:
                kwargs["filter"] = args.filter
            sniff(**kwargs)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("[!] Permission denied. Live capture requires root/administrator privileges.")
        sys.exit(1)

    analyzer.print_summary()
    analyzer.export()


if __name__ == "__main__":
    main()
