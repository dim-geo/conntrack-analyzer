# Conntrack Flow & Event Analyzer with NAT Inspection

A lightweight, standalone Python tool designed for Linux routers (OpenWrt, DD-WRT, VyOS, Alpine, Debian/Ubuntu) to monitor netfilter connection tracking events in real time (`conntrack -E -o xml`), inspect and demystify Network Address Translation (NAT), filter events by firewall mark, and clearly identify the **final target destination** for every flow.

---

## Key Features

- **Real-Time Event Monitoring**: Directly streams and parses live popping events (`NEW`, `UPDATE`, `DESTROY`) from `conntrack -E -o xml`.
- **Zero External Dependencies**: Implemented using pure Python standard library (`xml.etree`, `subprocess`, `argparse`, `ipaddress`). Requires no `pip` packages; runs on routers with standard `python3`.
- **Full NAT Translation Understanding**:
  - **Destination NAT (DNAT)**: Detects port forwards and redirects, mapping original target requests (e.g., `WAN:80`) to their **Final Target Destination** (e.g., internal LAN host `192.168.1.100:8080`).
  - **Source NAT (SNAT)**: Detects outgoing masquerading, displaying both the original local client (`192.168.1.50:54321`) and the translated public endpoint (`203.0.113.15:40105`).
  - **Full-NAT / Hairpin NAT**: Accurately tracks connections where both source and destination are rewritten simultaneously.
  - **Direct / No-NAT**: Identifies routed, local, or VPN traffic traversing without translation.
- **Firewall Mark (connmark / fwmark) Filtering**:
  - Exact match in decimal (`16`) or hexadecimal (`0x10`).
  - Bitmask filtering (`0x10/0xff`, `0x100/0xff00`).
  - Range filtering (`100-200`, `0x10-0x20`).
  - Inverted / negated filtering (`!0x10` or `--invert-mark`).
  - Comma-separated rule combinations (`0x10,0x20/0xff,!0x5`).
- **Multiple Output Formats**:
  - **Standard**: Colorful, clean, live log stream emphasizing the final target destination.
  - **Verbose (`-v`)**: Multi-line block with full tuple details, packet/byte counters, TCP state, flags, and connection labels.
  - **JSON (`--json`)**: Single-line NDJSON format ready for `jq`, Fluentbit, Vector, or log collectors.
- **Interactive Statistics**: Summarizes total events, NAT distribution, top client IPs, and top final target destinations on `Ctrl+C`.

---

## How NAT Understanding Works

In Linux netfilter conntrack, every connection is tracked as two directional tuples:
1. **Original Tuple**: Packets sent by the connection initiator (`orig.src -> orig.dst`).
2. **Reply Tuple**: Packets expected in the reverse direction (`repl.src -> repl.dst`).

| NAT Type | Condition | What Happened | Final Target Destination |
| :--- | :--- | :--- | :--- |
| **DNAT** | `repl.src != orig.dst` | The destination was translated (e.g. port forward). | **`repl.src:repl.sport`** (Internal host/port receiving the traffic) |
| **SNAT** | `repl.dst != orig.src` | The source was translated (e.g. WAN Masquerade). | **`orig.dst:orig.dport`** (Untranslated remote server) |
| **FULL-NAT** | Both conditions met | Hairpin NAT: both source and destination translated. | **`repl.src:repl.sport`** (Internal destination host) |
| **NO-NAT** | Neither condition met | Direct routing across interfaces. | **`orig.dst:orig.dport`** |

---

## Installation & Requirements

### On Your Linux Router

Ensure `conntrack-tools` and `python3` are installed:

- **OpenWrt**:
  ```bash
  opkg update
  opkg install conntrack python3-light
  ```
- **Debian / Ubuntu / Raspberry Pi OS**:
  ```bash
  sudo apt update
  sudo apt install conntrack python3
  ```
- **Alpine Linux / PostmarketOS**:
  ```bash
  apk add conntrack-tools python3
  ```
- **VyOS**:
  Pre-installed by default.

Copy `conntrack_analyzer.py` to your router:
```bash
scp conntrack_analyzer.py root@router.lan:/usr/local/bin/conntrack_analyzer
chmod +x /usr/local/bin/conntrack_analyzer
```

---

## Usage Examples

### 1. Live Monitoring (Default)
Stream popping conntrack events as they occur:
```bash
sudo ./conntrack_analyzer.py
```

Sample output:
```text
[01:17:08.253] [NEW    ] TCP:SYN_SENT 192.168.1.105:54320 (snat: 203.0.113.15:40105) ==> [SNAT] Target: 142.250.190.46:443  [mark:0x10]
[01:17:08.253] [NEW    ] TCP:ESTABLISHED 198.51.100.25:39120 -> 203.0.113.15:80 ==> [DNAT] Target: 192.168.1.200:8080  [mark:0x100]
[01:17:08.253] [UPDATE ] TCP:ESTABLISHED 192.168.1.50:59123 (snat: 192.168.1.1:61000) -> 203.0.113.15:443 ==> [FULL-NAT] Target: 192.168.1.200:8443  [mark:0x2000]
[01:17:08.253] [DESTROY] TCP:TIME_WAIT 10.0.10.5:41234 ==> [NO-NAT] Target: 10.0.20.12:22  [mark:0x0]
```

### 2. Filtering by Firewall Mark
Firewall marks are used for policy routing, QoS, VPN steering, or firewall classifying:

- **Filter by exact mark** (hex or decimal):
  ```bash
  sudo ./conntrack_analyzer.py -m 0x10
  sudo ./conntrack_analyzer.py -m 16
  ```

- **Filter with bitmask** (check specific bit fields):
  ```bash
  sudo ./conntrack_analyzer.py -m 0x100/0xff00
  ```

- **Exclude / Invert mark** (show only unmarked or non-matching flows):
  ```bash
  sudo ./conntrack_analyzer.py -m 0 --invert-mark
  ```

- **Filter multiple marks or ranges**:
  ```bash
  sudo ./conntrack_analyzer.py -m 0x10,0x20,100-200
  ```

### 3. Inspecting Port Forwards (DNAT)
Identify which internal server actually receives incoming traffic forwarded from the WAN:
```bash
sudo ./conntrack_analyzer.py --dnat-only -v
```

Verbose output shows both the requested endpoint and the final internal server:
```text
──────────────────────────────────────────────────────────────────────────────
 [NEW    ] 2026-10-02 01:19:23.301  Protocol: TCP (ESTABLISHED)  Flow ID: 1002
──────────────────────────────────────────────────────────────────────────────
  NAT Mode:                [DNAT] (DNAT)
  Client Original:         198.51.100.25:39120
  Target Requested:        203.0.113.15:80
  FINAL TARGET DEST:       192.168.1.200:8080
  Firewall Mark:           0x00000100 (256)
  Timeout / Flags:         432000s  |  Assured: Yes  |  Unreplied: No
  Traffic Counters:        Orig: 1 pkts (64 B)  |  Repl: 1 pkts (64 B)
  Original Tuple:          src=198.51.100.25:39120 dst=203.0.113.15:80
  Reply Tuple:             src=192.168.1.200:8080 dst=198.51.100.25:39120
```

### 4. Reverse DNS Resolution in Summary (`-n`)
Resolve public, non-private IP addresses to hostnames in the summary statistics:
```bash
sudo ./conntrack_analyzer.py -n
```
*Summary output:*
```text
 Top Flows [original sources , Top final destinations]:
   • [10.0.10.5 , 10.0.20.12:22]
     Traffic: Down 28.8 KB / Up 12.1 KB (Total: 40.9 KB) | 1 events
   • [192.168.1.50 , 192.168.1.200:8443] [FULL-NAT]
     Traffic: Down 8.7 KB / Up 3.1 KB (Total: 11.8 KB) | 1 events
   • [2001:db8:1::10 , [2606:4700:4700::1111]:53 (one.one.one.one)]
     Traffic: Down 240 B / Up 180 B (Total: 420 B) | 1 events
   • [192.168.1.105 , 8.8.8.8 (dns.google)] [SNAT]
     Traffic: Down 84 B / Up 84 B (Total: 168 B) | 1 events
   • [198.51.100.25 , 192.168.1.200:8080] [DNAT]
     Traffic: Down 64 B / Up 64 B (Total: 128 B) | 1 events

 Top Downloaders [top clients, destinations]:
   • [10.0.10.5 , 10.0.20.12:22]
     Downloaded: 28.8 KB | Uploaded: 12.1 KB | 1 events
   • [192.168.1.50 , 192.168.1.200:8443]
     Downloaded: 8.7 KB | Uploaded: 3.1 KB | 1 events
   • [192.168.1.105 , 8.8.8.8 (dns.google)]
     Downloaded: 84 B | Uploaded: 144 B | 2 events
     ↳ Destinations: 8.8.8.8 (dns.google): 84 B, 142.250.190.46:443 (ord37s33-in-f14.1e100.net): 0 B

 Top Uploaders [top clients, destinations]:
   • [10.0.10.5 , 10.0.20.12:22]
     Uploaded: 12.1 KB | Downloaded: 28.8 KB | 1 events
   • [192.168.1.50 , 192.168.1.200:8443]
     Uploaded: 3.1 KB | Downloaded: 8.7 KB | 1 events
   • [192.168.1.105 , 8.8.8.8 (dns.google)]
     Uploaded: 144 B | Downloaded: 84 B | 2 events
     ↳ Destinations: 8.8.8.8 (dns.google): 84 B, 142.250.190.46:443 (ord37s33-in-f14.1e100.net): 60 B
```
> [!NOTE]
> - DNS lookups **never run during live event streaming**, ensuring zero packet/capture latency.
> - **Private IP addresses** (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `fc00::/7`, etc.) are automatically skipped and never queried.
> - Uses local command-line tools (`dig`, `nslookup`, `host`) when present, falling back to Python standard library `socket.gethostbyaddr`.

### 5. Filtering by IP, Subnet, or Port
- Filter by final target subnet:
  ```bash
  sudo ./conntrack_analyzer.py --target 192.168.1.0/24
  ```
- Filter by protocol and port:
  ```bash
  sudo ./conntrack_analyzer.py -p tcp --port 443
  ```

### 6. JSON Streaming for Automation
Output newline-delimited JSON (NDJSON) and pipe directly into `jq`:
```bash
sudo ./conntrack_analyzer.py --json | jq '{event: .event, proto: .protocol, mark: .mark_hex, target: .nat.final_target}'
```

### 7. Remote Monitoring from Local Machine via SSH
If you prefer not to keep scripts on the router, stream conntrack XML over SSH and analyze locally:
```bash
ssh root@router "conntrack -E -o xml" | ./conntrack_analyzer.py --stdin -n
```

### 8. Analyze Existing Table Snapshot (`-s / --snapshot`)
Inspect the current connection table once without waiting for new events:
```bash
sudo ./conntrack_analyzer.py -s -n
```
All existing filters (`-m`, `-p`, `--nat-only`, `--target`, etc.) remain fully valid:
```bash
sudo ./conntrack_analyzer.py -s -p tcp --dnat-only
```

---

### 9. Dual-Dump Interval Diff Mode (`-i / --interval SECONDS`)
Takes two snapshots (`conntrack -L -o xml`) separated by a user-specified time interval, computes throughput and delta traffic, and uncovers real-time network hogs:
- **Disappeared connections** from the first dump are **ignored** (no noise).
- **Brand new connections** established during the interval appear in a dedicated section.
- **Top Downloaders** and **Top Uploaders** are ranked by delta traffic and transfer rate (e.g. `MB/s`, `KB/s`).

```bash
# Compare 2 dumps 5 seconds apart with public DNS resolution
sudo ./conntrack_analyzer.py -i 5 -n
```

Sample diff output:
```text
══════════════════════════════════════════════════════════════════════════════
 Conntrack Dump Diff Analysis (Interval: 5.0s)
══════════════════════════════════════════════════════════════════════════════
 Dump 1 Flows: 42  |  Dump 2 Flows: 48
 Active Persistent: 40  |  Brand New: 8  |  Disappeared (Ignored): 2
 Interval Traffic:  Down 14.8 MB (3.0 MB/s) / Up 1.2 MB (240.0 KB/s)

 Top Downloaders [top clients, destinations]:
   • [192.168.1.105 , 142.250.190.46:443 (ord37s33-in-f14.1e100.net)]
     Downloaded: 12.4 MB (2.48 MB/s) | Uploaded: 450.2 KB (90.04 KB/s) | 5 active, 1 new flows
     ↳ Destinations: 142.250.190.46:443 (ord37s33-in-f14.1e100.net): 10.1 MB, 1.1.1.1:443 (one.one.one.one): 2.3 MB
   • [198.51.100.25 , 192.168.1.200:8080]
     Downloaded: 1.9 MB (380.0 KB/s) | Uploaded: 97.7 KB (19.5 KB/s) | 1 active flows

 Top Uploaders [top clients, destinations]:
   • [192.168.1.105 , 142.250.190.46:443 (ord37s33-in-f14.1e100.net)]
     Uploaded: 450.2 KB (90.04 KB/s) | Downloaded: 12.4 MB (2.48 MB/s) | 5 active, 1 new flows
   • [198.51.100.25 , 192.168.1.200:8080]
     Uploaded: 97.7 KB (19.5 KB/s) | Downloaded: 1.9 MB (380.0 KB/s) | 1 active flows

 Top Flows [original sources , Top final destinations]:
   • [192.168.1.105 , 142.250.190.46:443 (ord37s33-in-f14.1e100.net)] [SNAT]
     Traffic: Down 10.1 MB (2.02 MB/s) / Up 320.0 KB (64.00 KB/s) (Total: 10.4 MB) | 1 active flow(s)
   • [198.51.100.25 , 192.168.1.200:8080] [DNAT]
     Traffic: Down 1.9 MB (380.0 KB/s) / Up 97.7 KB (19.5 KB/s) (Total: 2.0 MB) | 1 active flow(s)

 Brand New Connections (8 appeared):
   • TCP   [192.168.1.105:55120 -> 1.1.1.1:443] -> Final: 1.1.1.1:443 (one.one.one.one) [SNAT] | Mark: 0x10 | Initial: 341.8 KB down / 24.4 KB up
   • UDP   [192.168.1.220:41200 -> 8.8.8.8:53] -> Final: 8.8.8.8:53 (dns.google) [SNAT] | Mark: 0x0 | Initial: 256 B down / 128 B up
══════════════════════════════════════════════════════════════════════════════
```

#### Offline Dump Diff (`--diff-files`)
Compare two saved XML snapshots without router access:
```bash
./conntrack_analyzer.py --diff-files dump1.xml dump2.xml -i 5 -n
```

---

## Command Reference

```text
usage: conntrack_analyzer.py [-h] [-s] [-i SECONDS] [--diff-files FILE1 FILE2]
                             [-f FILE] [--stdin]
                             [--conntrack-bin PATH] [--conntrack-args ARGS]
                             [-m MARK] [--invert-mark]
                             [-e {new,update,destroy,all}]
                             [-p PROTO] [--nat-only] [--dnat-only] [--snat-only]
                             [--src IP] [--dst IP] [--target IP]
                             [--port PORT] [--sport SPORT] [--dport DPORT]
                             [--target-port TARGET_PORT]
                             [-n] [-v] [--json] [--no-color] [-c COUNT] [--no-summary]

Operation Modes & Input Sources:
  -s, --snapshot, --dump       Snapshot mode: inspect connection table once (`conntrack -L -o xml`) and exit.
  -i, --interval SECONDS       Interval diff mode: compare 2 table dumps separated by SECONDS.
  --diff-files FILE1 FILE2     Compare two saved XML snapshot files offline.
  -f, --file FILE              Read XML from saved file.
  --stdin                      Read XML from standard input pipeline.
  --conntrack-bin PATH         Specify custom path to conntrack binary.
  --conntrack-args ARGS        Pass extra flags to conntrack command.

Filtering Options:
  -m, --mark MARK              Filter by mark (hex, decimal, mask, range, negation).
  --invert-mark                Invert mark filter match.
  -e, --event EVENT            Filter by event type: new, update, destroy.
  -p, --proto PROTO            Filter by protocol (tcp, udp, icmp, gre).
  --nat-only                   Show only flows where NAT occurred.
  --dnat-only                  Show only Destination NAT flows.
  --snat-only                  Show only Source NAT flows.
  --src IP[/MASK]              Filter by original source IP or CIDR.
  --dst IP[/MASK]              Filter by original destination IP or CIDR.
  --target IP[/MASK]           Filter by final target destination IP or CIDR.
  --port PORT                  Filter by any port.
  --sport SPORT                Filter by original source port.
  --dport DPORT                Filter by original destination port.
  --target-port PORT           Filter by final target port.

Output Formatting:
  -v, --verbose                Multi-line detailed flow inspection.
  --json                       Output parsed events or diff summary as JSON.
  --no-color                   Disable ANSI colors.
  -c, --count N                Stop after N matching events.
  -n, --resolve-names          Resolve public IPs to hostnames via local tools (dig/nslookup).
  --no-summary                 Do not print summary statistics on exit.
```
