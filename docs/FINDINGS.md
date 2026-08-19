# Findings — Sample Capture Analysis

**Analyst:** Amantle Maakelo
**Capture file:** `samples/demo_traffic.pcap` (synthetic, 31 packets)
**Tool used:** `src/sniffer.py`

## Summary

The bundled synthetic capture simulates a small internal segment of a
financial-services network, mixing normal encrypted traffic (HTTPS, DNS)
with three intentionally-injected anomaly patterns. This document explains
each finding the way an analyst would document it during triage — what was
seen, why it matters, and what the recommended remediation would be.

---

### Finding 1 — Plaintext credentials over HTTP

- **Source:** `10.0.1.22` → **Destination:** `172.16.0.20:80`
- **Detection:** HTTP POST to `/login` containing `user=` and `password=`
  fields in cleartext
- **Risk:** Any device on the network path (or an attacker with ARP-spoofing
  capability) can read the credentials directly from the packet payload.
  This is a critical finding in any environment, and especially so where the
  destination resembles a legacy vendor portal — third-party integrations are
  a common blind spot in banking environments.
- **Recommendation:** Enforce HTTPS/TLS for all authentication endpoints; if
  the vendor portal cannot support TLS, isolate it on a segmented VLAN and
  treat it as a known-risk legacy system pending replacement.

### Finding 2 — Traffic to high-risk legacy ports

- **Source:** `10.0.1.30` → **Destination:** `10.0.2.5:23` (Telnet)
- **Detection:** A Telnet session including a cleartext `login:`/`password:`
  exchange
- **Risk:** Telnet transmits all session data, including credentials, in
  plaintext. Its presence usually indicates legacy network hardware
  (switches, older industrial/embedded devices) that hasn't been migrated to
  SSH.
- **Recommendation:** Disable Telnet at the device level where possible;
  where legacy hardware requires it, restrict access via ACLs to a
  management-only VLAN with no general network reachability.

### Finding 3 — Port scan pattern from a single source

- **Source:** `10.0.1.99` → **Destination:** `10.0.2.10`
- **Detection:** The tool's port-scan heuristic triggered after the source
  contacted 8+ distinct ports on the same destination within a 10-second
  window (21, 22, 23, 25, 80, 135, 139, 445, 3389, 8080 — a classic
  reconnaissance port list)
- **Risk:** This pattern is textbook reconnaissance — an attacker (or
  compromised internal host) probing for open services before attempting
  exploitation. The specific ports targeted (SMB, RDP, MS-RPC) are commonly
  associated with lateral movement and ransomware deployment.
- **Recommendation:** Investigate host `10.0.1.99` immediately — this could
  be a compromised endpoint, an unauthorized vulnerability scan, or
  misconfigured monitoring tooling. Isolate and inspect if unauthorized.

---

## Why this matters for a banking/financial context

Each of these three findings maps to a real, common initial-access or
lateral-movement pattern seen in financial-sector breaches:

| Finding | MITRE ATT&CK mapping (approx.) |
|---|---|
| Plaintext credentials | T1040 – Network Sniffing (adversary-side), enabled by weak transport security |
| Legacy insecure services (Telnet) | T1021 – Remote Services (abuse of insecure remote access) |
| Port scanning | T1046 – Network Service Discovery |

A tool like this one is not a replacement for a full IDS/SIEM stack, but it
demonstrates the same triage instinct: **turn raw traffic into a short list
of things a human needs to look at**, rather than an unreadable packet dump.
