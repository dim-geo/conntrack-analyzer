#!/usr/bin/env python3
"""
conntrack_analyzer.py - Real-Time Conntrack Event & Flow Analyzer with NAT Inspection.

Monitors netfilter connection tracking events via `conntrack -E -o xml`, parses the
live event stream, understands NAT translations (SNAT / DNAT / Full-NAT), filters
flows based on firewall marks, and highlights the final target destination of each connection.

Designed for Linux routers (OpenWrt, DD-WRT, VyOS, Alpine, Debian/Ubuntu, etc.).
Requires Python 3.6+ and the `conntrack` utility (conntrack-tools). No external
pip dependencies required.
"""

import sys
import os
import re
import time
import signal
import shutil
import socket
import argparse
import json
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, List, Dict, Tuple as PyTuple, Any, Generator


# ==============================================================================
# Terminal Colors & Styling
# ==============================================================================

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_DARK = "\033[40m"


def colorize(text: str, color_code: str, enable_color: bool = True) -> str:
    """Wrap text in ANSI color codes if color is enabled."""
    if not enable_color or not color_code:
        return text
    return f"{color_code}{text}{Colors.RESET}"


def format_endpoint(ip: Optional[str], port: Optional[int]) -> str:
    """Format an IP and port into a standard endpoint string (handles IPv6 brackets)."""
    if not ip:
        return "?"
    if port is None:
        return ip
    if ":" in ip:  # IPv6
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


# ==============================================================================
# Data Structures
# ==============================================================================

class FlowTuple:
    """Represents a directional half of a flow (original or reply)."""
    def __init__(
        self,
        direction: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        l3_proto: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        l4_proto: Optional[str] = None,
        packets: Optional[int] = None,
        bytes_count: Optional[int] = None,
        zone: Optional[int] = None,
    ):
        self.direction = direction
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.l3_proto = l3_proto
        self.src_port = src_port
        self.dst_port = dst_port
        self.l4_proto = l4_proto
        self.packets = packets
        self.bytes_count = bytes_count
        self.zone = zone

    @property
    def src_endpoint(self) -> str:
        return format_endpoint(self.src_ip, self.src_port)

    @property
    def dst_endpoint(self) -> str:
        return format_endpoint(self.dst_ip, self.dst_port)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "direction": self.direction,
            "src": self.src_ip,
            "dst": self.dst_ip,
            "l3proto": self.l3_proto,
            "sport": self.src_port,
            "dport": self.dst_port,
            "l4proto": self.l4_proto,
            "packets": self.packets,
            "bytes": self.bytes_count,
            "zone": self.zone,
        }


class NatAnalysis:
    """
    Analyzes NAT by comparing the original tuple with the reply tuple.

    In Netfilter:
    - The 'original' tuple contains packets as sent by the initial sender.
    - The 'reply' tuple contains packets expected in return.
      - If DNAT was performed, the destination was rewritten. The repl.src (the host
        actually replying) will NOT match orig.dst. repl.src is the FINAL TARGET.
      - If SNAT was performed, the source was rewritten. The repl.dst (where replies
        are sent back) will NOT match orig.src.
    """
    def __init__(self, orig: FlowTuple, repl: FlowTuple):
        self.orig = orig
        self.repl = repl

        self.is_dnat = False
        self.is_snat = False

        # Destination NAT Check:
        # Check if reply source IP or port differs from original destination IP/port.
        if repl.src_ip and orig.dst_ip and (repl.src_ip != orig.dst_ip):
            self.is_dnat = True
        elif repl.src_port is not None and orig.dst_port is not None and (repl.src_port != orig.dst_port):
            self.is_dnat = True

        # Source NAT Check:
        # Check if reply destination IP or port differs from original source IP/port.
        if repl.dst_ip and orig.src_ip and (repl.dst_ip != orig.src_ip):
            self.is_snat = True
        elif repl.dst_port is not None and orig.src_port is not None and (repl.dst_port != orig.src_port):
            self.is_snat = True

        # Classification
        if self.is_dnat and self.is_snat:
            self.nat_type = "FULL-NAT"
        elif self.is_dnat:
            self.nat_type = "DNAT"
        elif self.is_snat:
            self.nat_type = "SNAT"
        else:
            self.nat_type = "NO-NAT"

        # Determine Final Target Destination
        if self.is_dnat:
            self.final_target_ip = repl.src_ip or orig.dst_ip
            self.final_target_port = repl.src_port if repl.src_port is not None else orig.dst_port
        else:
            self.final_target_ip = orig.dst_ip
            self.final_target_port = orig.dst_port

        # Determine Translated Client Source (if SNAT)
        if self.is_snat:
            self.translated_client_ip = repl.dst_ip
            self.translated_client_port = repl.dst_port
        else:
            self.translated_client_ip = None
            self.translated_client_port = None

    @property
    def final_target_endpoint(self) -> str:
        return format_endpoint(self.final_target_ip, self.final_target_port)

    @property
    def translated_client_endpoint(self) -> Optional[str]:
        if self.translated_client_ip:
            return format_endpoint(self.translated_client_ip, self.translated_client_port)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.nat_type,
            "is_dnat": self.is_dnat,
            "is_snat": self.is_snat,
            "client_original": self.orig.src_endpoint,
            "client_translated": self.translated_client_endpoint,
            "target_requested": self.orig.dst_endpoint,
            "final_target": self.final_target_endpoint,
            "final_target_ip": self.final_target_ip,
            "final_target_port": self.final_target_port,
        }


class ConntrackEvent:
    """Represents a single conntrack event parsed from XML."""
    def __init__(
        self,
        event_type: str,
        orig: FlowTuple,
        repl: FlowTuple,
        mark: int = 0,
        secmark: Optional[int] = None,
        state: Optional[str] = None,
        timeout: Optional[int] = None,
        flow_id: Optional[int] = None,
        assured: bool = False,
        unreplied: bool = False,
        labels: Optional[List[str]] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.event_type = event_type.lower()
        self.orig = orig
        self.repl = repl
        self.mark = mark
        self.secmark = secmark
        self.state = state
        self.timeout = timeout
        self.flow_id = flow_id
        self.assured = assured
        self.unreplied = unreplied
        self.labels = labels or []
        self.timestamp = timestamp or datetime.now()

        # Perform NAT analysis
        self.nat = NatAnalysis(self.orig, self.repl)

    @property
    def protocol(self) -> str:
        return (self.orig.l4_proto or self.orig.l3_proto or "unknown").upper()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event": self.event_type,
            "protocol": self.protocol,
            "state": self.state,
            "mark": self.mark,
            "mark_hex": f"0x{self.mark:08x}",
            "secmark": self.secmark,
            "timeout": self.timeout,
            "id": self.flow_id,
            "assured": self.assured,
            "unreplied": self.unreplied,
            "labels": self.labels,
            "nat": self.nat.to_dict(),
            "original_tuple": self.orig.to_dict(),
            "reply_tuple": self.repl.to_dict(),
        }


# ==============================================================================
# Filtering Logic
# ==============================================================================

class MarkFilter:
    """
    Parses and matches conntrack marks.
    Supports:
      - Plain decimal (e.g. 10) or hex (e.g. 0x10)
      - Masked match: val/mask (e.g. 0x10/0xff or 0x100/0xff00)
      - Range match: low-high (e.g. 100-200 or 0x10-0x20)
      - Negation: !expr (e.g. !0x10 or !0x10/0xff)
      - Comma-separated list: 0x10,0x20/0xff,!0x5
    """
    def __init__(self, spec: str):
        self.raw_spec = spec
        self.rules: List[PyTuple[bool, Any]] = []

        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue

            negated = False
            if part.startswith("!"):
                negated = True
                part = part[1:].strip()

            if "/" in part:
                val_str, mask_str = part.split("/", 1)
                val = int(val_str.strip(), 0)
                mask = int(mask_str.strip(), 0)
                rule = (lambda m, v=val, k=mask: (m & k) == (v & k))
            elif "-" in part:
                low_str, high_str = part.split("-", 1)
                low = int(low_str.strip(), 0)
                high = int(high_str.strip(), 0)
                rule = (lambda m, l=low, h=high: l <= m <= h)
            else:
                val = int(part.strip(), 0)
                rule = (lambda m, v=val: m == v)

            self.rules.append((negated, rule))

    def matches(self, mark: int) -> bool:
        if not self.rules:
            return True

        has_positive = any(not neg for neg, _ in self.rules)
        matched_any_positive = False

        for negated, rule in self.rules:
            res = rule(mark)
            if negated and res:
                return False
            if not negated and res:
                matched_any_positive = True

        return matched_any_positive if has_positive else True


class EventFilter:
    """Filters ConntrackEvents based on CLI options."""
    def __init__(
        self,
        mark_filter: Optional[MarkFilter] = None,
        invert_mark: bool = False,
        event_types: Optional[List[str]] = None,
        protocol: Optional[str] = None,
        nat_only: bool = False,
        dnat_only: bool = False,
        snat_only: bool = False,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        port: Optional[int] = None,
        dport: Optional[int] = None,
        sport: Optional[int] = None,
        target_port: Optional[int] = None,
    ):
        self.mark_filter = mark_filter
        self.invert_mark = invert_mark
        self.event_types = {e.strip().lower() for e in event_types} if event_types else None
        self.protocol = protocol.lower() if protocol else None
        self.nat_only = nat_only
        self.dnat_only = dnat_only
        self.snat_only = snat_only
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.target_ip = target_ip
        self.port = port
        self.dport = dport
        self.sport = sport
        self.target_port = target_port

    @staticmethod
    def _ip_matches(ip_str: Optional[str], filter_str: Optional[str]) -> bool:
        if not filter_str:
            return True
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            if "/" in filter_str:
                net = ipaddress.ip_network(filter_str, strict=False)
                return ip in net
            else:
                target_addr = ipaddress.ip_address(filter_str)
                return ip == target_addr
        except ValueError:
            return ip_str == filter_str

    def matches(self, event: ConntrackEvent) -> bool:
        # Mark filter
        if self.mark_filter:
            mark_matched = self.mark_filter.matches(event.mark)
            if self.invert_mark:
                mark_matched = not mark_matched
            if not mark_matched:
                return False

        # Event type filter
        if self.event_types and "all" not in self.event_types:
            if event.event_type not in self.event_types:
                return False

        # Protocol filter
        if self.protocol:
            if self.protocol not in event.protocol.lower():
                return False

        # NAT filters
        if self.nat_only and event.nat.nat_type == "NO-NAT":
            return False
        if self.dnat_only and not event.nat.is_dnat:
            return False
        if self.snat_only and not event.nat.is_snat:
            return False

        # IP Address / CIDR filters
        if self.src_ip and not self._ip_matches(event.orig.src_ip, self.src_ip):
            return False
        if self.dst_ip and not self._ip_matches(event.orig.dst_ip, self.dst_ip):
            return False
        if self.target_ip and not self._ip_matches(event.nat.final_target_ip, self.target_ip):
            return False

        # Port filters
        if self.port is not None:
            ports = {event.orig.src_port, event.orig.dst_port, event.nat.final_target_port}
            if self.port not in ports:
                return False

        if self.sport is not None and event.orig.src_port != self.sport:
            return False

        if self.dport is not None and event.orig.dst_port != self.dport:
            return False

        if self.target_port is not None and event.nat.final_target_port != self.target_port:
            return False

        return True


# ==============================================================================
# XML Stream Parser
# ==============================================================================

class ConntrackXMLParser:
    """
    Parses a streaming sequence of XML chunks from `conntrack -E -o xml`.

    Uses a sliding string buffer to locate `<flow ...> ... </flow>` blocks.
    This guarantees immunity to missing document root tags, XML headers,
    split chunk boundaries, and prevents memory accumulation.
    """
    def __init__(self):
        self.buffer = ""

    def feed(self, chunk: str) -> Generator[ET.Element, None, None]:
        """Feed a string chunk and yield XML Element objects for each complete `<flow>`."""
        self.buffer += chunk

        while True:
            start_pos = self.buffer.find("<flow")
            if start_pos == -1:
                # Keep tail in case of partial '<flow' tag arriving
                self.buffer = self.buffer[-8:] if len(self.buffer) > 8 else self.buffer
                break

            end_tag = "</flow>"
            end_pos = self.buffer.find(end_tag, start_pos)
            if end_pos == -1:
                # Incomplete flow, keep buffer from start_pos
                self.buffer = self.buffer[start_pos:]
                break

            flow_xml = self.buffer[start_pos : end_pos + len(end_tag)]
            self.buffer = self.buffer[end_pos + len(end_tag) :]

            try:
                elem = ET.fromstring(flow_xml)
                yield elem
            except ET.ParseError:
                # Malformed chunk, continue
                continue

    @staticmethod
    def parse_tuple(elem: Optional[ET.Element], direction: str) -> FlowTuple:
        """Parses a <meta direction="..."> or <tuple direction="..."> element into a FlowTuple."""
        if elem is None:
            return FlowTuple(direction=direction)

        layer3 = elem.find("layer3")
        src_ip = layer3.findtext("src") if layer3 is not None else None
        dst_ip = layer3.findtext("dst") if layer3 is not None else None
        l3_proto = layer3.attrib.get("protoname") if layer3 is not None else None

        layer4 = elem.find("layer4")
        l4_proto = layer4.attrib.get("protoname") if layer4 is not None else None
        src_port_txt = layer4.findtext("sport") if layer4 is not None else None
        dst_port_txt = layer4.findtext("dport") if layer4 is not None else None

        src_port = int(src_port_txt) if src_port_txt and src_port_txt.isdigit() else None
        dst_port = int(dst_port_txt) if dst_port_txt and dst_port_txt.isdigit() else None

        counters = elem.find("counters")
        pkts_txt = counters.findtext("packets") if counters is not None else None
        bytes_txt = counters.findtext("bytes") if counters is not None else None

        packets = int(pkts_txt) if pkts_txt and pkts_txt.isdigit() else None
        bytes_count = int(bytes_txt) if bytes_txt and bytes_txt.isdigit() else None

        zone_txt = elem.findtext("zone")
        zone = int(zone_txt) if zone_txt and zone_txt.isdigit() else None

        return FlowTuple(
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            l3_proto=l3_proto,
            src_port=src_port,
            dst_port=dst_port,
            l4_proto=l4_proto,
            packets=packets,
            bytes_count=bytes_count,
            zone=zone,
        )

    def parse_flow_element(self, flow_elem: ET.Element) -> ConntrackEvent:
        """Constructs a ConntrackEvent from an XML `<flow>` element."""
        event_type = flow_elem.attrib.get("type", "flow")

        # Find original & reply meta/tuple elements (handles both libnetfilter schemas)
        orig_elem = flow_elem.find(".//meta[@direction='original']")
        if orig_elem is None:
            orig_elem = flow_elem.find(".//tuple[@direction='original']")

        repl_elem = flow_elem.find(".//meta[@direction='reply']")
        if repl_elem is None:
            repl_elem = flow_elem.find(".//tuple[@direction='reply']")

        orig_tuple = self.parse_tuple(orig_elem, "original")
        repl_tuple = self.parse_tuple(repl_elem, "reply")

        # Independent metadata
        indep_elem = flow_elem.find(".//meta[@direction='independent']")
        if indep_elem is None:
            indep_elem = flow_elem.find(".//independent")

        def get_meta_text(tag_name: str) -> Optional[str]:
            if indep_elem is not None:
                val = indep_elem.findtext(tag_name)
                if val:
                    return val
            # Fallback to direct search in flow
            return flow_elem.findtext(f".//{tag_name}")

        mark_txt = get_meta_text("mark")
        mark = int(mark_txt, 0) if mark_txt else 0

        secmark_txt = get_meta_text("secmark")
        secmark = int(secmark_txt, 0) if secmark_txt else None

        state = get_meta_text("state")

        timeout_txt = get_meta_text("timeout")
        timeout = int(timeout_txt) if timeout_txt and timeout_txt.isdigit() else None

        id_txt = get_meta_text("id")
        flow_id = int(id_txt) if id_txt and id_txt.isdigit() else None

        assured = False
        unreplied = False
        if indep_elem is not None:
            assured = indep_elem.find("assured") is not None
            unreplied = indep_elem.find("unreplied") is not None
        else:
            assured = flow_elem.find(".//assured") is not None
            unreplied = flow_elem.find(".//unreplied") is not None

        # Labels
        labels: List[str] = []
        labels_elem = flow_elem.find(".//labels")
        if labels_elem is not None:
            for lbl in labels_elem.findall("label"):
                if lbl.text:
                    labels.append(lbl.text.strip())

        return ConntrackEvent(
            event_type=event_type,
            orig=orig_tuple,
            repl=repl_tuple,
            mark=mark,
            secmark=secmark,
            state=state,
            timeout=timeout,
            flow_id=flow_id,
            assured=assured,
            unreplied=unreplied,
            labels=labels,
            timestamp=datetime.now(),
        )


# ==============================================================================
# Formatters & Visual Display
# ==============================================================================

def format_event_badge(event_type: str, use_color: bool) -> str:
    evt = event_type.upper()
    if evt == "NEW":
        return colorize(f"[{evt:<7}]", Colors.BOLD + Colors.GREEN, use_color)
    elif evt == "UPDATE":
        return colorize(f"[{evt:<7}]", Colors.BOLD + Colors.CYAN, use_color)
    elif evt == "DESTROY":
        return colorize(f"[{evt:<7}]", Colors.BOLD + Colors.RED, use_color)
    else:
        return colorize(f"[{evt:<7}]", Colors.BOLD + Colors.YELLOW, use_color)


def format_nat_badge(nat_type: str, use_color: bool) -> str:
    if nat_type == "DNAT":
        return colorize("[DNAT]", Colors.BOLD + Colors.MAGENTA, use_color)
    elif nat_type == "SNAT":
        return colorize("[SNAT]", Colors.BOLD + Colors.YELLOW, use_color)
    elif nat_type == "FULL-NAT":
        return colorize("[FULL-NAT]", Colors.BOLD + Colors.BRIGHT_RED, use_color)
    else:
        return colorize("[NO-NAT]", Colors.DIM, use_color)


def format_standard(event: ConntrackEvent, use_color: bool = True) -> str:
    """
    Renders a clear, human-readable terminal line highlighting the final target destination.
    """
    t_str = event.timestamp.strftime("%H:%M:%S.%f")[:-3]
    badge = format_event_badge(event.event_type, use_color)
    nat_badge = format_nat_badge(event.nat.nat_type, use_color)

    # Protocol & TCP state
    proto_info = event.protocol
    if event.state:
        proto_info += f":{event.state}"
    proto_str = colorize(f"{proto_info:<12}", Colors.BRIGHT_BLUE, use_color)

    # Firewall mark
    mark_str = colorize(f"mark:0x{event.mark:x}", Colors.CYAN, use_color)

    # Client
    client_str = colorize(event.orig.src_endpoint, Colors.WHITE, use_color)

    # Final Target Destination formatting
    final_target = colorize(
        event.nat.final_target_endpoint,
        Colors.BOLD + Colors.BRIGHT_GREEN + Colors.UNDERLINE,
        use_color,
    )

    # Flow string based on NAT type
    if event.nat.nat_type == "DNAT":
        orig_dst = colorize(event.orig.dst_endpoint, Colors.DIM, use_color)
        flow_details = f"{client_str} -> {orig_dst} ==> {nat_badge} Target: {final_target}"
    elif event.nat.nat_type == "SNAT":
        snat_str = colorize(f"(snat: {event.nat.translated_client_endpoint})", Colors.DIM, use_color)
        flow_details = f"{client_str} {snat_str} ==> {nat_badge} Target: {final_target}"
    elif event.nat.nat_type == "FULL-NAT":
        orig_dst = colorize(event.orig.dst_endpoint, Colors.DIM, use_color)
        snat_str = colorize(f"(snat: {event.nat.translated_client_endpoint})", Colors.DIM, use_color)
        flow_details = f"{client_str} {snat_str} -> {orig_dst} ==> {nat_badge} Target: {final_target}"
    else:
        flow_details = f"{client_str} ==> {nat_badge} Target: {final_target}"

    return f"[{t_str}] {badge} {proto_str} {flow_details}  [{mark_str}]"


def format_verbose(event: ConntrackEvent, use_color: bool = True) -> str:
    """
    Renders a comprehensive multi-line inspection block for the event.
    """
    badge = format_event_badge(event.event_type, use_color)
    nat_badge = format_nat_badge(event.nat.nat_type, use_color)
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    final_target_str = colorize(
        event.nat.final_target_endpoint,
        Colors.BOLD + Colors.BRIGHT_GREEN,
        use_color,
    )
    mark_display = colorize(
        f"0x{event.mark:08x} ({event.mark})",
        Colors.BOLD + Colors.CYAN,
        use_color,
    )

    proto_str = event.protocol
    if event.state:
        proto_str += f" ({event.state})"

    lines = [
        colorize("─" * 78, Colors.DIM, use_color),
        f" {badge} {colorize(timestamp, Colors.BOLD, use_color)}  "
        f"Protocol: {colorize(proto_str, Colors.BRIGHT_BLUE, use_color)}  "
        f"Flow ID: {event.flow_id or 'N/A'}",
        colorize("─" * 78, Colors.DIM, use_color),
        f"  {colorize('NAT Mode:', Colors.BOLD, use_color):<24} {nat_badge} ({event.nat.nat_type})",
        f"  {colorize('Client Original:', Colors.BOLD, use_color):<24} {event.orig.src_endpoint}",
    ]

    if event.nat.is_snat:
        lines.append(
            f"  {colorize('Client SNAT Translated:', Colors.BOLD, use_color):<24} "
            f"{colorize(event.nat.translated_client_endpoint or 'N/A', Colors.YELLOW, use_color)}"
        )

    if event.nat.is_dnat:
        lines.append(
            f"  {colorize('Target Requested:', Colors.BOLD, use_color):<24} {event.orig.dst_endpoint}"
        )

    lines.append(
        f"  {colorize('FINAL TARGET DEST:', Colors.BOLD + Colors.BRIGHT_WHITE, use_color):<24} {final_target_str}"
    )

    lines.append(
        f"  {colorize('Firewall Mark:', Colors.BOLD, use_color):<24} {mark_display}"
    )

    if event.timeout is not None:
        lines.append(
            f"  {colorize('Timeout / Flags:', Colors.BOLD, use_color):<24} "
            f"{event.timeout}s  |  Assured: {'Yes' if event.assured else 'No'}  |  "
            f"Unreplied: {'Yes' if event.unreplied else 'No'}"
        )

    if event.labels:
        lines.append(
            f"  {colorize('Connection Labels:', Colors.BOLD, use_color):<24} {', '.join(event.labels)}"
        )

    # Counters
    orig_pkts = event.orig.packets if event.orig.packets is not None else 0
    orig_bytes = event.orig.bytes_count if event.orig.bytes_count is not None else 0
    repl_pkts = event.repl.packets if event.repl.packets is not None else 0
    repl_bytes = event.repl.bytes_count if event.repl.bytes_count is not None else 0

    if orig_pkts or repl_pkts or orig_bytes or repl_bytes:
        lines.append(
            f"  {colorize('Traffic Counters:', Colors.BOLD, use_color):<24} "
            f"Orig: {orig_pkts} pkts ({orig_bytes} B)  |  "
            f"Repl: {repl_pkts} pkts ({repl_bytes} B)"
        )

    # Raw Tuples
    lines.append(
        f"  {colorize('Original Tuple:', Colors.DIM, use_color):<24} "
        f"src={event.orig.src_endpoint} dst={event.orig.dst_endpoint}"
    )
    lines.append(
        f"  {colorize('Reply Tuple:', Colors.DIM, use_color):<24} "
        f"src={event.repl.src_endpoint} dst={event.repl.dst_endpoint}"
    )

    return "\n".join(lines)


# ==============================================================================
# Reverse DNS Resolution (Summary Only, Non-Private IPs Only)
# ==============================================================================

class DNSResolver:
    """
    Reverse DNS resolver for non-private IP addresses in summary statistics.
    Leverages local tools (dig, nslookup, host) when available, with a fallback
    to socket.gethostbyaddr. Caches queries in-memory so identical IPs are resolved once.
    """
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self._cache: Dict[str, Optional[str]] = {}
        self._dig_bin = shutil.which("dig")
        self._nslookup_bin = shutil.which("nslookup")
        self._host_bin = shutil.which("host")

    @staticmethod
    def is_public_ip(ip_str: Optional[str]) -> bool:
        """Determines if an IP is a public (non-private/non-local) IP address."""
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            return False

    def resolve(self, ip_str: str) -> Optional[str]:
        """Resolves a public IP address to a hostname. Returns None for private/failed IPs."""
        if not ip_str or not self.is_public_ip(ip_str):
            return None

        if ip_str in self._cache:
            return self._cache[ip_str]

        hostname: Optional[str] = None

        # 1. Try local `dig -x <ip> +short`
        if self._dig_bin:
            try:
                res = subprocess.run(
                    [self._dig_bin, "-x", ip_str, "+short", "+time=1", "+tries=1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=self.timeout + 0.5,
                )
                out = res.stdout.strip()
                if out:
                    first = out.splitlines()[0].strip().rstrip(".")
                    if first and not first.startswith(";"):
                        hostname = first
            except Exception:
                pass

        # 2. Try local `nslookup <ip>` (handles both BIND and BusyBox formats)
        if not hostname and self._nslookup_bin:
            try:
                res = subprocess.run(
                    [self._nslookup_bin, ip_str],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=self.timeout + 0.5,
                )
                out = res.stdout.strip()
                # Standard BIND nslookup: 'name = hostname.'
                m = re.search(r"name\s*=\s*([^\s]+)", out, re.IGNORECASE)
                if m:
                    hostname = m.group(1).rstrip(".")
                else:
                    # BusyBox nslookup: 'Name: hostname'
                    m = re.search(r"Name:\s*([^\s]+)", out)
                    if m:
                        hostname = m.group(1).rstrip(".")
            except Exception:
                pass

        # 3. Try local `host <ip>`
        if not hostname and self._host_bin:
            try:
                res = subprocess.run(
                    [self._host_bin, "-W", "1", ip_str],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=self.timeout + 0.5,
                )
                out = res.stdout.strip()
                m = re.search(r"pointer\s+([^\s]+)", out)
                if m:
                    hostname = m.group(1).rstrip(".")
            except Exception:
                pass

        # 4. Fallback to Python standard library socket.gethostbyaddr
        if not hostname:
            orig_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.timeout)
                name, _, _ = socket.gethostbyaddr(ip_str)
                hostname = name.rstrip(".")
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                hostname = None
            finally:
                socket.setdefaulttimeout(orig_timeout)

        self._cache[ip_str] = hostname
        return hostname

    def batch_resolve(self, ip_list: List[str]) -> Dict[str, Optional[str]]:
        """Concurrently resolves a list of non-private IPs using a thread pool."""
        from concurrent.futures import ThreadPoolExecutor

        public_ips = [ip for ip in set(ip_list) if ip and self.is_public_ip(ip)]
        if not public_ips:
            return {}

        results: Dict[str, Optional[str]] = {}
        with ThreadPoolExecutor(max_workers=min(len(public_ips), 6)) as executor:
            future_to_ip = {executor.submit(self.resolve, ip): ip for ip in public_ips}
            for future in future_to_ip:
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception:
                    results[ip] = None
        return results


def format_bytes(b: int) -> str:
    """Formats byte counts into human-readable representation."""
    b = int(max(0, b))
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"


def format_rate(bytes_count: float, seconds: float) -> str:
    """Formats bytes per second into human-readable representation."""
    if seconds <= 0:
        return f"{format_bytes(int(bytes_count))}/s"
    rate = bytes_count / seconds
    return f"{format_bytes(int(rate))}/s"


# ==============================================================================
# Statistics Summary
# ==============================================================================

class StatsTracker:
    """Tracks metrics on analyzed flows for summary display upon exit."""
    def __init__(self):
        self.start_time = time.time()
        self.total_received = 0
        self.total_matched = 0
        self.by_event_type: Dict[str, int] = {}
        self.by_nat_type: Dict[str, int] = {}
        self.by_proto: Dict[str, int] = {}

        # Tracking for [original sources , Top final destinations]
        self.flow_records: Dict[PyTuple[str, str], Dict[str, Any]] = {}

        # Tracking for [top clients, destinations] to uncover downloaders & uploaders
        self.client_records: Dict[str, Dict[str, Any]] = {}

        # Compatibility fields
        self.top_targets: Dict[str, int] = {}
        self.top_clients: Dict[str, int] = {}

        self.endpoint_to_ip: Dict[str, str] = {}
        self.dns_resolver = DNSResolver()

    def record(self, event: ConntrackEvent, matched: bool):
        self.total_received += 1
        if not matched:
            return

        self.total_matched += 1
        self.by_event_type[event.event_type] = self.by_event_type.get(event.event_type, 0) + 1
        self.by_nat_type[event.nat.nat_type] = self.by_nat_type.get(event.nat.nat_type, 0) + 1
        self.by_proto[event.protocol] = self.by_proto.get(event.protocol, 0) + 1

        tgt = event.nat.final_target_endpoint
        self.top_targets[tgt] = self.top_targets.get(tgt, 0) + 1
        if event.nat.final_target_ip:
            self.endpoint_to_ip[tgt] = event.nat.final_target_ip

        client = event.orig.src_endpoint
        self.top_clients[client] = self.top_clients.get(client, 0) + 1
        if event.orig.src_ip:
            self.endpoint_to_ip[client] = event.orig.src_ip

        src_ip = event.orig.src_ip or "unknown"
        if event.orig.src_ip:
            self.endpoint_to_ip[src_ip] = event.orig.src_ip

        up_b = event.orig.bytes_count or 0
        down_b = event.repl.bytes_count or 0
        nat_type = event.nat.nat_type

        # Record flow conversation: [original source -> final target destination]
        flow_key = (src_ip, tgt)
        if flow_key not in self.flow_records:
            self.flow_records[flow_key] = {
                "src": src_ip,
                "dst": tgt,
                "nat": nat_type,
                "events": 0,
                "down": 0,
                "up": 0,
            }
        self.flow_records[flow_key]["events"] += 1
        self.flow_records[flow_key]["down"] += down_b
        self.flow_records[flow_key]["up"] += up_b

        # Record client activity: [top clients, destinations]
        if src_ip not in self.client_records:
            self.client_records[src_ip] = {
                "client": src_ip,
                "events": 0,
                "down": 0,
                "up": 0,
                "dests": {},
            }
        cr = self.client_records[src_ip]
        cr["events"] += 1
        cr["down"] += down_b
        cr["up"] += up_b

        if tgt not in cr["dests"]:
            cr["dests"][tgt] = {
                "events": 0,
                "down": 0,
                "up": 0,
                "nat": nat_type,
            }
        cr["dests"][tgt]["events"] += 1
        cr["dests"][tgt]["down"] += down_b
        cr["dests"][tgt]["up"] += up_b

    def print_summary(self, use_color: bool = True, resolve_names: bool = False):
        duration = max(time.time() - self.start_time, 0.001)
        rate = self.total_received / duration

        print("\n" + colorize("═" * 78, Colors.BOLD, use_color))
        print(colorize(f" Conntrack Flow Analysis Summary (Duration: {duration:.1f}s, {rate:.1f} ev/s)", Colors.BOLD + Colors.CYAN, use_color))
        print(colorize("═" * 78, Colors.BOLD, use_color))
        print(f" Total Events Received: {colorize(str(self.total_received), Colors.BOLD, use_color)}  |  "
              f"Matched Filter: {colorize(str(self.total_matched), Colors.BOLD + Colors.GREEN, use_color)}")

        if self.by_event_type:
            types_str = ", ".join(f"{k.upper()}: {v}" for k, v in sorted(self.by_event_type.items()))
            print(f" Event Types: {types_str}")

        if self.by_nat_type:
            nat_str = ", ".join(f"{k}: {v}" for k, v in sorted(self.by_nat_type.items()))
            print(f" NAT Types:   {colorize(nat_str, Colors.YELLOW, use_color)}")

        # Collect IPs for DNS resolution if enabled
        resolved_map: Dict[str, Optional[str]] = {}
        if resolve_names:
            ips_to_resolve = list(set(self.endpoint_to_ip.values()))
            resolved_map = self.dns_resolver.batch_resolve(ips_to_resolve)

        def fmt_dest(ep: str) -> str:
            ip = self.endpoint_to_ip.get(ep)
            h = resolved_map.get(ip) if ip else None
            return f"{ep} ({h})" if h else ep

        def fmt_client(cl: str) -> str:
            h = resolved_map.get(cl)
            return f"{cl} ({h})" if h else cl

        # Check if byte counters are available across captured flows
        has_bytes = any((f["down"] + f["up"]) > 0 for f in self.flow_records.values())

        # ----------------------------------------------------------------------
        # 1. Top Flows [original sources , Top final destinations]
        # ----------------------------------------------------------------------
        if self.flow_records:
            print("\n " + colorize("Top Flows [original sources , Top final destinations]:", Colors.BOLD, use_color))
            sorted_flows = sorted(
                self.flow_records.values(),
                key=lambda x: (x["down"] + x["up"] if has_bytes else 0, x["events"]),
                reverse=True,
            )[:5]

            for f in sorted_flows:
                client_str = colorize(fmt_client(f["src"]), Colors.WHITE, use_color)
                dest_str = colorize(fmt_dest(f["dst"]), Colors.GREEN, use_color)
                nat_badge = f" {format_nat_badge(f['nat'], use_color)}" if f["nat"] != "NO-NAT" else ""
                print(f"   {colorize('•', Colors.GREEN, use_color)} [{client_str} , {dest_str}]{nat_badge}")
                if has_bytes:
                    total_b = f["down"] + f["up"]
                    traffic_str = (
                        f"Down {colorize(format_bytes(f['down']), Colors.GREEN, use_color)} / "
                        f"Up {colorize(format_bytes(f['up']), Colors.YELLOW, use_color)} "
                        f"(Total: {colorize(format_bytes(total_b), Colors.BOLD, use_color)})"
                    )
                    print(f"     Traffic: {traffic_str} | {f['events']} events")
                else:
                    print(f"     Events: {colorize(str(f['events']), Colors.BOLD, use_color)} events")

        # ----------------------------------------------------------------------
        # 2. Top Downloaders [top clients, destinations]
        # ----------------------------------------------------------------------
        if self.client_records:
            print("\n " + colorize("Top Downloaders [top clients, destinations]:", Colors.BOLD, use_color))
            sorted_downloaders = sorted(
                self.client_records.values(),
                key=lambda x: (x["down"] if has_bytes else 0, x["events"]),
                reverse=True,
            )[:5]

            for c in sorted_downloaders:
                client_str = colorize(fmt_client(c["client"]), Colors.CYAN, use_color)
                top_dest_entry = sorted(
                    c["dests"].items(),
                    key=lambda x: (x[1]["down"] if has_bytes else 0, x[1]["events"]),
                    reverse=True,
                )[0]
                dest_str = colorize(fmt_dest(top_dest_entry[0]), Colors.GREEN, use_color)
                print(f"   {colorize('•', Colors.CYAN, use_color)} [{client_str} , {dest_str}]")
                if has_bytes:
                    print(
                        f"     Downloaded: {colorize(format_bytes(c['down']), Colors.BOLD + Colors.GREEN, use_color)} | "
                        f"Uploaded: {colorize(format_bytes(c['up']), Colors.YELLOW, use_color)} | "
                        f"{c['events']} events"
                    )
                    if len(c["dests"]) > 1:
                        dest_summary = ", ".join([
                            f"{fmt_dest(d)}: {format_bytes(info['down'])}"
                            for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["down"], reverse=True)[:3]
                        ])
                        print(f"     ↳ Destinations: {dest_summary}")
                else:
                    print(f"     Activity: {colorize(str(c['events']), Colors.BOLD, use_color)} events")

        # ----------------------------------------------------------------------
        # 3. Top Uploaders [top clients, destinations]
        # ----------------------------------------------------------------------
        if self.client_records:
            print("\n " + colorize("Top Uploaders [top clients, destinations]:", Colors.BOLD, use_color))
            sorted_uploaders = sorted(
                self.client_records.values(),
                key=lambda x: (x["up"] if has_bytes else 0, x["events"]),
                reverse=True,
            )[:5]

            for c in sorted_uploaders:
                client_str = colorize(fmt_client(c["client"]), Colors.YELLOW, use_color)
                top_dest_entry = sorted(
                    c["dests"].items(),
                    key=lambda x: (x[1]["up"] if has_bytes else 0, x[1]["events"]),
                    reverse=True,
                )[0]
                dest_str = colorize(fmt_dest(top_dest_entry[0]), Colors.GREEN, use_color)
                print(f"   {colorize('•', Colors.YELLOW, use_color)} [{client_str} , {dest_str}]")
                if has_bytes:
                    print(
                        f"     Uploaded: {colorize(format_bytes(c['up']), Colors.BOLD + Colors.YELLOW, use_color)} | "
                        f"Downloaded: {colorize(format_bytes(c['down']), Colors.GREEN, use_color)} | "
                        f"{c['events']} events"
                    )
                    if len(c["dests"]) > 1:
                        dest_summary = ", ".join([
                            f"{fmt_dest(d)}: {format_bytes(info['up'])}"
                            for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["up"], reverse=True)[:3]
                        ])
                        print(f"     ↳ Destinations: {dest_summary}")
                else:
                    print(f"     Activity: {colorize(str(c['events']), Colors.BOLD, use_color)} events")

        print(colorize("═" * 78, Colors.BOLD, use_color))


# ==============================================================================
# Dump Diff & Interval Analysis
# ==============================================================================

def get_flow_key(event: ConntrackEvent) -> PyTuple:
    """
    Returns a unique tuple key identifying the flow in netfilter conntrack.
    Netfilter guarantees uniqueness of the original tuple per zone.
    """
    return (
        event.orig.l3_proto or "",
        event.orig.l4_proto or "",
        event.orig.src_ip or "",
        event.orig.src_port or 0,
        event.orig.dst_ip or "",
        event.orig.dst_port or 0,
        event.orig.zone or 0,
    )


class DiffAnalyzer:
    """
    Analyzes differences between two conntrack table snapshots taken across a time interval.

    Rules:
      1. Connections that disappear from the first dump are ignored.
      2. Brand new connections appear in a dedicated 'Brand New Connections' section.
      3. Active persistent connections have delta traffic computed (delta_down, delta_up)
         to reveal Top Downloaders, Top Uploaders, and Top Flows over the interval.
    """
    def __init__(self, interval_seconds: float = 1.0):
        self.interval = max(interval_seconds, 0.001)
        self.dns_resolver = DNSResolver()

    def analyze(
        self,
        events_1: List[ConntrackEvent],
        events_2: List[ConntrackEvent],
    ) -> Dict[str, Any]:
        """Compares two dumps and computes persistent deltas and brand new connections."""
        # Index Dump 1 by flow tuple key
        map1: Dict[PyTuple, List[ConntrackEvent]] = {}
        for e1 in events_1:
            key = get_flow_key(e1)
            map1.setdefault(key, []).append(e1)

        active_flows: List[Dict[str, Any]] = []
        brand_new_flows: List[ConntrackEvent] = []

        # Match Dump 2 flows against Dump 1
        for e2 in events_2:
            key = get_flow_key(e2)
            candidates = map1.get(key, [])

            matched_idx = -1
            for idx, e1 in enumerate(candidates):
                # Verify if this is truly the exact same connection
                if e1.flow_id is not None and e2.flow_id is not None and e1.flow_id != e2.flow_id:
                    continue
                # If byte counters decreased, connection was reset/reopened
                if e1.orig.bytes_count is not None and e2.orig.bytes_count is not None and e2.orig.bytes_count < e1.orig.bytes_count:
                    continue
                if e1.repl.bytes_count is not None and e2.repl.bytes_count is not None and e2.repl.bytes_count < e1.repl.bytes_count:
                    continue
                matched_idx = idx
                break

            if matched_idx >= 0:
                e1 = candidates.pop(matched_idx)
                d_down = max(0, (e2.repl.bytes_count or 0) - (e1.repl.bytes_count or 0))
                d_up = max(0, (e2.orig.bytes_count or 0) - (e1.orig.bytes_count or 0))
                d_pkts_down = max(0, (e2.repl.packets or 0) - (e1.repl.packets or 0))
                d_pkts_up = max(0, (e2.orig.packets or 0) - (e1.orig.packets or 0))

                active_flows.append({
                    "event": e2,
                    "prev_event": e1,
                    "delta_down": d_down,
                    "delta_up": d_up,
                    "delta_pkts_down": d_pkts_down,
                    "delta_pkts_up": d_pkts_up,
                    "delta_total": d_down + d_up,
                })
            else:
                brand_new_flows.append(e2)

        # Disappeared flows from dump 1 are ignored per user instruction
        disappeared_count = sum(len(lst) for lst in map1.values())

        # Aggregate by client to uncover Top Downloaders and Top Uploaders
        client_records: Dict[str, Dict[str, Any]] = {}
        endpoint_to_ip: Dict[str, str] = {}

        def get_client(ip: str) -> Dict[str, Any]:
            if ip not in client_records:
                client_records[ip] = {
                    "client": ip,
                    "down": 0,
                    "up": 0,
                    "persistent_down": 0,
                    "persistent_up": 0,
                    "new_down": 0,
                    "new_up": 0,
                    "persistent_flows": 0,
                    "new_flows": 0,
                    "dests": {},
                }
            return client_records[ip]

        total_down = 0
        total_up = 0

        # Record active flows
        for flow in active_flows:
            e = flow["event"]
            client_ip = e.orig.src_ip or "unknown"
            tgt = e.nat.final_target_endpoint
            if e.orig.src_ip:
                endpoint_to_ip[client_ip] = e.orig.src_ip
            if e.nat.final_target_ip:
                endpoint_to_ip[tgt] = e.nat.final_target_ip

            d_down = flow["delta_down"]
            d_up = flow["delta_up"]
            total_down += d_down
            total_up += d_up

            cr = get_client(client_ip)
            cr["down"] += d_down
            cr["up"] += d_up
            cr["persistent_down"] += d_down
            cr["persistent_up"] += d_up
            cr["persistent_flows"] += 1

            if tgt not in cr["dests"]:
                cr["dests"][tgt] = {"down": 0, "up": 0, "flows": 0, "nat": e.nat.nat_type}
            cr["dests"][tgt]["down"] += d_down
            cr["dests"][tgt]["up"] += d_up
            cr["dests"][tgt]["flows"] += 1

        # Record brand new flows
        for e in brand_new_flows:
            client_ip = e.orig.src_ip or "unknown"
            tgt = e.nat.final_target_endpoint
            if e.orig.src_ip:
                endpoint_to_ip[client_ip] = e.orig.src_ip
            if e.nat.final_target_ip:
                endpoint_to_ip[tgt] = e.nat.final_target_ip

            n_down = e.repl.bytes_count or 0
            n_up = e.orig.bytes_count or 0
            total_down += n_down
            total_up += n_up

            cr = get_client(client_ip)
            cr["down"] += n_down
            cr["up"] += n_up
            cr["new_down"] += n_down
            cr["new_up"] += n_up
            cr["new_flows"] += 1

            if tgt not in cr["dests"]:
                cr["dests"][tgt] = {"down": 0, "up": 0, "flows": 0, "nat": e.nat.nat_type}
            cr["dests"][tgt]["down"] += n_down
            cr["dests"][tgt]["up"] += n_up
            cr["dests"][tgt]["flows"] += 1

        # Flow conversation records: [original sources , Top final destinations]
        flow_records: Dict[PyTuple[str, str], Dict[str, Any]] = {}
        for flow in active_flows:
            e = flow["event"]
            client_ip = e.orig.src_ip or "unknown"
            tgt = e.nat.final_target_endpoint
            fkey = (client_ip, tgt)
            if fkey not in flow_records:
                flow_records[fkey] = {
                    "src": client_ip,
                    "dst": tgt,
                    "nat": e.nat.nat_type,
                    "down": 0,
                    "up": 0,
                    "flows": 0,
                    "pkts": 0,
                }
            flow_records[fkey]["down"] += flow["delta_down"]
            flow_records[fkey]["up"] += flow["delta_up"]
            flow_records[fkey]["flows"] += 1
            flow_records[fkey]["pkts"] += flow["delta_pkts_down"] + flow["delta_pkts_up"]

        return {
            "interval_seconds": self.interval,
            "dump1_count": len(events_1),
            "dump2_count": len(events_2),
            "persistent_count": len(active_flows),
            "brand_new_count": len(brand_new_flows),
            "disappeared_count": disappeared_count,
            "total_down": total_down,
            "total_up": total_up,
            "active_flows": active_flows,
            "brand_new_flows": brand_new_flows,
            "client_records": client_records,
            "flow_records": flow_records,
            "endpoint_to_ip": endpoint_to_ip,
        }

    def print_diff_report(
        self,
        diff_data: Dict[str, Any],
        use_color: bool = True,
        resolve_names: bool = False,
        verbose: bool = False,
    ):
        """Displays the diff analysis report."""
        dt = diff_data["interval_seconds"]

        # Collect IPs for DNS resolution if enabled
        resolved_map: Dict[str, Optional[str]] = {}
        if resolve_names:
            ips_to_resolve = list(set(diff_data["endpoint_to_ip"].values()))
            resolved_map = self.dns_resolver.batch_resolve(ips_to_resolve)

        def fmt_dest(ep: str) -> str:
            ip = diff_data["endpoint_to_ip"].get(ep)
            h = resolved_map.get(ip) if ip else None
            return f"{ep} ({h})" if h else ep

        def fmt_client(cl: str) -> str:
            h = resolved_map.get(cl)
            return f"{cl} ({h})" if h else cl

        has_bytes = (diff_data["total_down"] + diff_data["total_up"]) > 0
        limit = 15 if verbose else 5

        print("\n" + colorize("═" * 78, Colors.BOLD, use_color))
        print(colorize(f" Conntrack Dump Diff Analysis (Interval: {dt:.1f}s)", Colors.BOLD + Colors.CYAN, use_color))
        print(colorize("═" * 78, Colors.BOLD, use_color))
        print(
            f" Dump 1 Flows: {colorize(str(diff_data['dump1_count']), Colors.BOLD, use_color)}  |  "
            f"Dump 2 Flows: {colorize(str(diff_data['dump2_count']), Colors.BOLD, use_color)}"
        )
        print(
            f" Active Persistent: {colorize(str(diff_data['persistent_count']), Colors.BOLD + Colors.GREEN, use_color)}  |  "
            f"Brand New: {colorize(str(diff_data['brand_new_count']), Colors.BOLD + Colors.YELLOW, use_color)}  |  "
            f"Disappeared (Ignored): {colorize(str(diff_data['disappeared_count']), Colors.DIM, use_color)}"
        )
        if has_bytes:
            down_str = f"Down {colorize(format_bytes(diff_data['total_down']), Colors.GREEN, use_color)} ({format_rate(diff_data['total_down'], dt)})"
            up_str = f"Up {colorize(format_bytes(diff_data['total_up']), Colors.YELLOW, use_color)} ({format_rate(diff_data['total_up'], dt)})"
            print(f" Interval Traffic:  {down_str} / {up_str}")

        clients = list(diff_data["client_records"].values())

        # ----------------------------------------------------------------------
        # 1. Top Downloaders [top clients, destinations]
        # ----------------------------------------------------------------------
        if clients:
            print("\n " + colorize("Top Downloaders [top clients, destinations]:", Colors.BOLD, use_color))
            sorted_down = sorted(
                clients,
                key=lambda x: (x["down"] if has_bytes else 0, x["persistent_flows"] + x["new_flows"]),
                reverse=True,
            )[:limit]

            for c in sorted_down:
                client_str = colorize(fmt_client(c["client"]), Colors.CYAN, use_color)
                top_dest_entry = sorted(
                    c["dests"].items(),
                    key=lambda x: (x[1]["down"] if has_bytes else 0, x[1]["flows"]),
                    reverse=True,
                )[0]
                dest_str = colorize(fmt_dest(top_dest_entry[0]), Colors.GREEN, use_color)
                print(f"   {colorize('•', Colors.CYAN, use_color)} [{client_str} , {dest_str}]")
                if has_bytes:
                    flows_info = f"{c['persistent_flows']} active"
                    if c["new_flows"] > 0:
                        flows_info += f", {c['new_flows']} new"
                    down_part = f"Downloaded: {colorize(format_bytes(c['down']), Colors.BOLD + Colors.GREEN, use_color)} ({format_rate(c['down'], dt)})"
                    up_part = f"Uploaded: {colorize(format_bytes(c['up']), Colors.YELLOW, use_color)} ({format_rate(c['up'], dt)})"
                    print(f"     {down_part} | {up_part} | {flows_info} flows")
                    if len(c["dests"]) > 1:
                        dests_summary = ", ".join([
                            f"{fmt_dest(d)}: {format_bytes(info['down'])}"
                            for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["down"], reverse=True)[:3]
                        ])
                        print(f"     ↳ Destinations: {dests_summary}")
                else:
                    print(f"     Activity: {c['persistent_flows']} active flows, {c['new_flows']} new flows")

        # ----------------------------------------------------------------------
        # 2. Top Uploaders [top clients, destinations]
        # ----------------------------------------------------------------------
        if clients:
            print("\n " + colorize("Top Uploaders [top clients, destinations]:", Colors.BOLD, use_color))
            sorted_up = sorted(
                clients,
                key=lambda x: (x["up"] if has_bytes else 0, x["persistent_flows"] + x["new_flows"]),
                reverse=True,
            )[:limit]

            for c in sorted_up:
                client_str = colorize(fmt_client(c["client"]), Colors.YELLOW, use_color)
                top_dest_entry = sorted(
                    c["dests"].items(),
                    key=lambda x: (x[1]["up"] if has_bytes else 0, x[1]["flows"]),
                    reverse=True,
                )[0]
                dest_str = colorize(fmt_dest(top_dest_entry[0]), Colors.GREEN, use_color)
                print(f"   {colorize('•', Colors.YELLOW, use_color)} [{client_str} , {dest_str}]")
                if has_bytes:
                    flows_info = f"{c['persistent_flows']} active"
                    if c["new_flows"] > 0:
                        flows_info += f", {c['new_flows']} new"
                    up_part = f"Uploaded: {colorize(format_bytes(c['up']), Colors.BOLD + Colors.YELLOW, use_color)} ({format_rate(c['up'], dt)})"
                    down_part = f"Downloaded: {colorize(format_bytes(c['down']), Colors.GREEN, use_color)} ({format_rate(c['down'], dt)})"
                    print(f"     {up_part} | {down_part} | {flows_info} flows")
                    if len(c["dests"]) > 1:
                        dests_summary = ", ".join([
                            f"{fmt_dest(d)}: {format_bytes(info['up'])}"
                            for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["up"], reverse=True)[:3]
                        ])
                        print(f"     ↳ Destinations: {dests_summary}")
                else:
                    print(f"     Activity: {c['persistent_flows']} active flows, {c['new_flows']} new flows")

        # ----------------------------------------------------------------------
        # 3. Top Active Flows [original sources , Top final destinations]
        # ----------------------------------------------------------------------
        flows = list(diff_data["flow_records"].values())
        if flows:
            print("\n " + colorize("Top Flows [original sources , Top final destinations]:", Colors.BOLD, use_color))
            sorted_flows = sorted(
                flows,
                key=lambda x: (x["down"] + x["up"] if has_bytes else 0, x["flows"]),
                reverse=True,
            )[:limit]

            for f in sorted_flows:
                client_str = colorize(fmt_client(f["src"]), Colors.WHITE, use_color)
                dest_str = colorize(fmt_dest(f["dst"]), Colors.GREEN, use_color)
                nat_badge = f" {format_nat_badge(f['nat'], use_color)}" if f["nat"] != "NO-NAT" else ""
                print(f"   {colorize('•', Colors.GREEN, use_color)} [{client_str} , {dest_str}]{nat_badge}")
                if has_bytes:
                    tot_b = f["down"] + f["up"]
                    flow_traffic = (
                        f"Down {colorize(format_bytes(f['down']), Colors.GREEN, use_color)} ({format_rate(f['down'], dt)}) / "
                        f"Up {colorize(format_bytes(f['up']), Colors.YELLOW, use_color)} ({format_rate(f['up'], dt)}) "
                        f"(Total: {colorize(format_bytes(tot_b), Colors.BOLD, use_color)})"
                    )
                    print(f"     Traffic: {flow_traffic} | {f['flows']} active flow(s)")
                else:
                    print(f"     Flows: {colorize(str(f['flows']), Colors.BOLD, use_color)} active flow(s)")

        # ----------------------------------------------------------------------
        # 4. Brand New Connections (Dedicated Section)
        # ----------------------------------------------------------------------
        brand_new = diff_data["brand_new_flows"]
        print("\n " + colorize(f"Brand New Connections ({len(brand_new)} appeared):", Colors.BOLD, use_color))
        if not brand_new:
            print(colorize("   None detected during this interval.", Colors.DIM, use_color))
        else:
            new_limit = len(brand_new) if verbose else min(10, len(brand_new))
            sorted_new = sorted(
                brand_new,
                key=lambda x: ((x.repl.bytes_count or 0) + (x.orig.bytes_count or 0)),
                reverse=True,
            )
            for e in sorted_new[:new_limit]:
                p = colorize(f"{e.protocol:<5}", Colors.CYAN, use_color)
                orig_src = e.orig.src_endpoint
                orig_dst = e.orig.dst_endpoint
                final_tgt = fmt_dest(e.nat.final_target_endpoint)
                nat_b = f" {format_nat_badge(e.nat.nat_type, use_color)}" if e.nat.nat_type != "NO-NAT" else ""
                mark_str = colorize(f"0x{e.mark:x}", Colors.MAGENTA, use_color)
                traffic_str = ""
                if (e.orig.bytes_count or 0) > 0 or (e.repl.bytes_count or 0) > 0:
                    traffic_str = f" | Initial: {format_bytes(e.repl.bytes_count or 0)} down / {format_bytes(e.orig.bytes_count or 0)} up"
                print(f"   {colorize('•', Colors.YELLOW, use_color)} {p} [{orig_src} -> {orig_dst}] -> Final: {colorize(final_tgt, Colors.GREEN, use_color)}{nat_b} | Mark: {mark_str}{traffic_str}")

            if len(brand_new) > new_limit:
                rem = len(brand_new) - new_limit
                print(colorize(f"   ... and {rem} more brand new connection(s) (use -v to display all)", Colors.DIM, use_color))

        print(colorize("═" * 78, Colors.BOLD, use_color))

    def to_dict(self, diff_data: Dict[str, Any]) -> Dict[str, Any]:
        """Converts diff analysis data to a structured dictionary for JSON export."""
        dt = diff_data["interval_seconds"]
        return {
            "mode": "diff",
            "interval_seconds": dt,
            "dump1_count": diff_data["dump1_count"],
            "dump2_count": diff_data["dump2_count"],
            "persistent_count": diff_data["persistent_count"],
            "brand_new_count": diff_data["brand_new_count"],
            "disappeared_count": diff_data["disappeared_count"],
            "interval_traffic": {
                "total_download_bytes": diff_data["total_down"],
                "total_upload_bytes": diff_data["total_up"],
                "download_rate_bytes_per_sec": diff_data["total_down"] / dt,
                "upload_rate_bytes_per_sec": diff_data["total_up"] / dt,
            },
            "top_downloaders": [
                {
                    "client": c["client"],
                    "download_bytes": c["down"],
                    "upload_bytes": c["up"],
                    "persistent_flows": c["persistent_flows"],
                    "new_flows": c["new_flows"],
                    "destinations": [
                        {"destination": d, "down": info["down"], "up": info["up"], "flows": info["flows"]}
                        for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["down"], reverse=True)
                    ],
                }
                for c in sorted(diff_data["client_records"].values(), key=lambda x: x["down"], reverse=True)
            ],
            "top_uploaders": [
                {
                    "client": c["client"],
                    "upload_bytes": c["up"],
                    "download_bytes": c["down"],
                    "persistent_flows": c["persistent_flows"],
                    "new_flows": c["new_flows"],
                    "destinations": [
                        {"destination": d, "down": info["down"], "up": info["up"], "flows": info["flows"]}
                        for d, info in sorted(c["dests"].items(), key=lambda x: x[1]["up"], reverse=True)
                    ],
                }
                for c in sorted(diff_data["client_records"].values(), key=lambda x: x["up"], reverse=True)
            ],
            "top_flows": [
                {
                    "client": f["src"],
                    "destination": f["dst"],
                    "nat": f["nat"],
                    "download_bytes": f["down"],
                    "upload_bytes": f["up"],
                    "active_flows": f["flows"],
                }
                for f in sorted(diff_data["flow_records"].values(), key=lambda x: x["down"] + x["up"], reverse=True)
            ],
            "brand_new_connections": [
                e.to_dict() for e in diff_data["brand_new_flows"]
            ],
        }


# ==============================================================================
# Process Execution & Stream Readers
# ==============================================================================

def find_conntrack_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """Finds the conntrack binary on the system or returns None."""
    if custom_path:
        if os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
            return custom_path
        return None

    found = shutil.which("conntrack")
    if found:
        return found

    # Check common router & system locations
    candidates = [
        "/usr/sbin/conntrack",
        "/sbin/conntrack",
        "/usr/local/sbin/conntrack",
        "/usr/bin/conntrack",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def stream_from_process(
    conntrack_bin: str,
    extra_args: Optional[List[str]] = None,
    event_mask: Optional[str] = None,
    dump_table: bool = False,
) -> Generator[str, None, None]:
    """
    Executes conntrack in a subprocess and yields stdout line-by-line in real time.
    """
    cmd = [conntrack_bin]
    if dump_table:
        cmd.extend(["-L", "-o", "xml"])
    else:
        cmd.extend(["-E", "-o", "xml"])
        if event_mask:
            cmd.extend(["-e", event_mask.upper()])

    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line-buffered
        )
    except PermissionError:
        sys.stderr.write("Error: Permission denied attempting to execute conntrack.\n")
        sys.stderr.write("Try running with sudo / as root.\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Error starting conntrack ({cmd}): {e}\n")
        sys.exit(1)

    # Register process for signal termination
    def cleanup_handler(signum, frame):
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except Exception:
            proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
                continue
            yield line
    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except Exception:
                proc.kill()

        if proc.returncode is not None and proc.returncode != 0:
            stderr_out = proc.stderr.read().strip()
            if "Operation not permitted" in stderr_out or "Permission denied" in stderr_out or "netlink socket" in stderr_out:
                sys.stderr.write(
                    f"\n[!] conntrack failed: {stderr_out}\n"
                    f"    Netfilter connection tracking requires root privileges (CAP_NET_ADMIN).\n"
                    f"    Please re-run this tool with: sudo {' '.join(sys.argv)}\n"
                )
            elif stderr_out:
                sys.stderr.write(f"\n[!] conntrack exited with error: {stderr_out}\n")


def stream_from_file(filepath: str) -> Generator[str, None, None]:
    """Reads XML from a file line-by-line."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line


def stream_from_stdin() -> Generator[str, None, None]:
    """Reads XML from standard input."""
    for line in sys.stdin:
        yield line


def collect_dump(
    stream_gen: Generator[str, None, None],
    flt: Optional[EventFilter] = None,
) -> List[ConntrackEvent]:
    """Reads all XML chunks from stream_gen and returns parsed ConntrackEvent list matching filter."""
    xml_parser = ConntrackXMLParser()
    events = []
    for chunk in stream_gen:
        for flow_elem in xml_parser.feed(chunk):
            event = xml_parser.parse_flow_element(flow_elem)
            if flt is None or flt.matches(event):
                events.append(event)
    return events


def run_diff_mode(args: argparse.Namespace, flt: EventFilter, use_color: bool):
    """Executes the two-dump interval diff analysis mode."""
    extra_args = args.conntrack_args.split() if args.conntrack_args else None

    if args.diff_files:
        file1, file2 = args.diff_files
        if not os.path.isfile(file1):
            sys.stderr.write(f"Error: Dump file 1 '{file1}' not found.\n")
            sys.exit(1)
        if not os.path.isfile(file2):
            sys.stderr.write(f"Error: Dump file 2 '{file2}' not found.\n")
            sys.exit(1)

        interval_sec = args.interval if args.interval is not None else 1.0
        if use_color and not args.json:
            print(colorize(f"[*] Analyzing diff between '{file1}' and '{file2}'...", Colors.BOLD + Colors.CYAN, True))

        events_1 = collect_dump(stream_from_file(file1), flt)
        events_2 = collect_dump(stream_from_file(file2), flt)

    else:
        conntrack_bin = find_conntrack_binary(args.conntrack_bin)
        if not conntrack_bin:
            sys.stderr.write(
                "Error: `conntrack` binary not found on this system.\n"
                "Please install conntrack-tools:\n"
                "  OpenWrt:       opkg update && opkg install conntrack\n"
                "  Debian/Ubuntu: sudo apt install conntrack\n"
                "  RHEL/CentOS:   sudo yum install conntrack-tools\n"
                "  Alpine:        apk add conntrack-tools\n"
                "Or specify the binary path using --conntrack-bin /path/to/conntrack\n"
                "Or compare saved dumps using: ./conntrack_analyzer.py --diff-files dump1.xml dump2.xml\n"
            )
            sys.exit(1)

        interval_sec = args.interval if args.interval is not None else 5.0

        if use_color and not args.json:
            print(colorize(f"[*] Capturing Dump 1 via `{conntrack_bin} -L -o xml`...", Colors.BOLD + Colors.CYAN, True))

        events_1 = collect_dump(
            stream_from_process(conntrack_bin=conntrack_bin, extra_args=extra_args, dump_table=True),
            flt,
        )

        if use_color and not args.json:
            print(colorize(f"[*] Dump 1 captured ({len(events_1)} matching flows). Waiting {interval_sec:.1f}s for Dump 2...", Colors.DIM, True))

        try:
            time.sleep(interval_sec)
        except KeyboardInterrupt:
            if use_color and not args.json:
                print(colorize("\n[!] Aborted waiting for Dump 2.", Colors.YELLOW, True))
            sys.exit(0)

        if use_color and not args.json:
            print(colorize(f"[*] Capturing Dump 2 via `{conntrack_bin} -L -o xml`...", Colors.BOLD + Colors.CYAN, True))

        events_2 = collect_dump(
            stream_from_process(conntrack_bin=conntrack_bin, extra_args=extra_args, dump_table=True),
            flt,
        )

    analyzer = DiffAnalyzer(interval_seconds=interval_sec)
    diff_data = analyzer.analyze(events_1, events_2)

    if args.json:
        print(json.dumps(analyzer.to_dict(diff_data)))
        sys.stdout.flush()
    elif not args.no_summary:
        analyzer.print_diff_report(
            diff_data=diff_data,
            use_color=use_color,
            resolve_names=args.resolve_names,
            verbose=args.verbose,
        )


# ==============================================================================
# Main CLI & Dispatcher
# ==============================================================================

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Conntrack Real-Time Event & Flow Analyzer with NAT Inspection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all popping events in real-time (calls `conntrack -E -o xml`)
  sudo ./conntrack_analyzer.py

  # Snapshot mode (-s): analyze existing conntrack table once and exit
  sudo ./conntrack_analyzer.py -s

  # Interval diff mode (-i): compare 2 dumps taken 5 seconds apart
  # (ignores disappeared connections, shows brand new connections, top downloaders/uploaders)
  sudo ./conntrack_analyzer.py -i 5

  # Interval diff mode with DNS resolution (-n) and mark filter (-m)
  sudo ./conntrack_analyzer.py -i 10 -n -m 0x10

  # Offline diff mode: compare two saved XML dump files
  ./conntrack_analyzer.py --diff-files dump1.xml dump2.xml -i 5 -n

  # Filter by firewall mark 0x10 (decimal 16)
  sudo ./conntrack_analyzer.py -m 0x10

  # Filter by mark with bitmask (e.g. mark matching 0x100 in mask 0xff00)
  sudo ./conntrack_analyzer.py -m 0x100/0xff00

  # Invert mark filter (show events that do NOT have mark 0)
  sudo ./conntrack_analyzer.py -m 0 --invert-mark

  # Show only Destination NAT (port forwards / redirects) and display final targets
  sudo ./conntrack_analyzer.py --dnat-only

  # Show only Source NAT (outgoing masqueraded traffic)
  sudo ./conntrack_analyzer.py --snat-only

  # Verbose inspection of TCP flows targeting internal subnet 192.168.1.0/24
  sudo ./conntrack_analyzer.py -p tcp --target 192.168.1.0/24 -v

  # Output as JSON streams for piping into jq or log aggregators
  sudo ./conntrack_analyzer.py --json | jq .

  # Analyze XML piped from stdin or file
  conntrack -E -o xml | ./conntrack_analyzer.py --stdin
  ./conntrack_analyzer.py -f capture.xml
        """,
    )

    # Operation modes & input source options
    input_group = parser.add_argument_group("Operation Modes & Input Sources")
    input_group.add_argument(
        "-s", "--snapshot", "--dump",
        dest="snapshot",
        action="store_true",
        help="Snapshot mode: inspect current connection table once (`conntrack -L -o xml`) and exit.",
    )
    input_group.add_argument(
        "-i", "--interval", "--diff-interval",
        dest="interval",
        type=float,
        metavar="SECONDS",
        help="Interval diff mode: take two conntrack table dumps separated by SECONDS, "
             "ignore disappeared connections, display brand new connections in a dedicated section, "
             "and rank top downloaders and uploaders.",
    )
    input_group.add_argument(
        "--diff-files",
        nargs=2,
        metavar=("FILE1", "FILE2"),
        help="Diff mode on saved XML files: compare FILE1 and FILE2 without running live conntrack.",
    )
    input_group.add_argument(
        "-f", "--file",
        help="Read and analyze XML from a saved file instead of live conntrack.",
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read XML from standard input (pipeline).",
    )
    input_group.add_argument(
        "--conntrack-bin",
        help="Custom path to conntrack executable (default: auto-detected in PATH / sbin).",
    )
    input_group.add_argument(
        "--conntrack-args",
        help="Additional raw arguments to pass directly to conntrack (e.g. \"-p tcp -b 1048576\").",
    )

    # Filtering options
    filter_group = parser.add_argument_group("Filtering Options")
    filter_group.add_argument(
        "-m", "--mark",
        help="Filter by conntrack mark. Accepts decimal (16), hex (0x10), mask (0x10/0xff), range (10-20), negation (!0x10), or list (10,0x20).",
    )
    filter_group.add_argument(
        "--invert-mark",
        action="store_true",
        help="Invert mark match (display events NOT matching --mark).",
    )
    filter_group.add_argument(
        "-e", "--event",
        help="Filter by event type: new, update, destroy, all (comma-separated, default: all).",
    )
    filter_group.add_argument(
        "-p", "--proto",
        help="Filter by layer4 protocol (tcp, udp, icmp, gre, etc.).",
    )
    filter_group.add_argument(
        "--nat-only",
        action="store_true",
        help="Show only flows where NAT occurred (SNAT, DNAT, or FULL-NAT).",
    )
    filter_group.add_argument(
        "--dnat-only",
        action="store_true",
        help="Show only flows where Destination NAT occurred.",
    )
    filter_group.add_argument(
        "--snat-only",
        action="store_true",
        help="Show only flows where Source NAT occurred.",
    )
    filter_group.add_argument(
        "--src",
        help="Filter by original source IP or CIDR (e.g. 192.168.1.50 or 192.168.1.0/24).",
    )
    filter_group.add_argument(
        "--dst",
        help="Filter by original destination IP or CIDR.",
    )
    filter_group.add_argument(
        "--target",
        help="Filter by FINAL target destination IP or CIDR.",
    )
    filter_group.add_argument(
        "--port",
        type=int,
        help="Filter by any port (source, destination, or target).",
    )
    filter_group.add_argument(
        "--sport",
        type=int,
        help="Filter by original client source port.",
    )
    filter_group.add_argument(
        "--dport",
        type=int,
        help="Filter by original destination port.",
    )
    filter_group.add_argument(
        "--target-port",
        type=int,
        help="Filter by FINAL target port.",
    )

    # Output formatting
    out_group = parser.add_argument_group("Output Formatting")
    out_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose multi-line output with complete tuple details, counters, flags, and marks.",
    )
    out_group.add_argument(
        "--json",
        action="store_true",
        help="Output parsed events as single-line JSON objects (NDJSON) or diff summary JSON.",
    )
    out_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes (automatically disabled if stdout is not a TTY).",
    )
    out_group.add_argument(
        "-c", "--count",
        type=int,
        help="Stop after displaying COUNT matching events.",
    )
    out_group.add_argument(
        "-n", "--resolve-names",
        action="store_true",
        help="Resolve public (non-private) IP addresses to hostnames in summary statistics using local tools (dig/nslookup).",
    )
    out_group.add_argument(
        "--no-summary",
        action="store_true",
        help="Do not display the statistics summary upon exit.",
    )

    return parser


def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    # Backwards compatibility alias
    args.dump = args.snapshot

    # Determine color output
    use_color = not args.no_color and sys.stdout.isatty() and not args.json

    # Build Mark Filter
    mark_filter = None
    if args.mark is not None:
        try:
            mark_filter = MarkFilter(args.mark)
        except Exception as e:
            sys.stderr.write(f"Error parsing --mark argument '{args.mark}': {e}\n")
            sys.exit(1)

    # Build Event Filter
    event_types = [x.strip() for x in args.event.split(",")] if args.event else None
    flt = EventFilter(
        mark_filter=mark_filter,
        invert_mark=args.invert_mark,
        event_types=event_types,
        protocol=args.proto,
        nat_only=args.nat_only,
        dnat_only=args.dnat_only,
        snat_only=args.snat_only,
        src_ip=args.src,
        dst_ip=args.dst,
        target_ip=args.target,
        port=args.port,
        dport=args.dport,
        sport=args.sport,
        target_port=args.target_port,
    )

    # Check for Interval Diff Mode
    is_diff_mode = (args.interval is not None) or (args.diff_files is not None)
    if is_diff_mode:
        if args.interval is not None and args.interval <= 0:
            parser.error("--interval must be greater than 0 seconds.")
        run_diff_mode(args, flt, use_color)
        return

    # Single Snapshot / Streaming mode
    # Determine input stream
    if args.file:
        if not os.path.exists(args.file):
            sys.stderr.write(f"Error: XML file '{args.file}' not found.\n")
            sys.exit(1)
        stream_gen = stream_from_file(args.file)
        source_desc = f"File '{args.file}'"
    elif args.stdin or (not sys.stdin.isatty() and not sys.stdout.isatty() and not args.snapshot and not args.file):
        stream_gen = stream_from_stdin()
        source_desc = "Standard Input (stdin)"
    else:
        conntrack_bin = find_conntrack_binary(args.conntrack_bin)
        if not conntrack_bin:
            sys.stderr.write(
                "Error: `conntrack` binary not found on this system.\n"
                "Please install conntrack-tools:\n"
                "  OpenWrt:       opkg update && opkg install conntrack\n"
                "  Debian/Ubuntu: sudo apt install conntrack\n"
                "  RHEL/CentOS:   sudo yum install conntrack-tools\n"
                "  Alpine:        apk add conntrack-tools\n"
                "Or specify the binary path using --conntrack-bin /path/to/conntrack\n"
                "Or pipe XML from another machine using: ssh router 'conntrack -E -o xml' | ./conntrack_analyzer.py --stdin\n"
            )
            sys.exit(1)

        extra_args = args.conntrack_args.split() if args.conntrack_args else None
        event_mask = args.event if args.event and args.event.lower() != "all" else None

        stream_gen = stream_from_process(
            conntrack_bin=conntrack_bin,
            extra_args=extra_args,
            event_mask=event_mask,
            dump_table=args.snapshot,
        )
        mode = "snapshot of connection table" if args.snapshot else "live popping events"
        source_desc = f"`{conntrack_bin}` ({mode})"

    # Print startup banner in interactive terminal
    if use_color and not args.json:
        filters_applied = []
        if args.mark:
            filters_applied.append(f"mark={args.mark}")
        if args.event:
            filters_applied.append(f"event={args.event}")
        if args.proto:
            filters_applied.append(f"proto={args.proto}")
        if args.nat_only:
            filters_applied.append("nat=only")
        if args.dnat_only:
            filters_applied.append("dnat=only")
        if args.snat_only:
            filters_applied.append("snat=only")
        if args.target:
            filters_applied.append(f"target={args.target}")
        if args.resolve_names:
            filters_applied.append("resolve-names=yes")

        filter_str = f" [Filters: {', '.join(filters_applied)}]" if filters_applied else ""
        if args.snapshot:
            print(colorize(f"[*] Analyzing Conntrack Table Snapshot from {source_desc}{filter_str}...\n", Colors.BOLD + Colors.CYAN, True))
        else:
            print(colorize(f"[*] Starting Conntrack Flow Analysis from {source_desc}{filter_str}...", Colors.BOLD + Colors.CYAN, True))
            print(colorize("[*] Press Ctrl+C to stop and view statistics summary.\n", Colors.DIM, True))

    xml_parser = ConntrackXMLParser()
    stats = StatsTracker()
    matched_count = 0

    try:
        for chunk in stream_gen:
            for flow_elem in xml_parser.feed(chunk):
                event = xml_parser.parse_flow_element(flow_elem)
                matched = flt.matches(event)
                stats.record(event, matched)

                if matched:
                    matched_count += 1
                    if args.json:
                        print(json.dumps(event.to_dict()))
                        sys.stdout.flush()
                    elif args.verbose:
                        print(format_verbose(event, use_color))
                        sys.stdout.flush()
                    else:
                        print(format_standard(event, use_color))
                        sys.stdout.flush()

                    if args.count and matched_count >= args.count:
                        break

            if args.count and matched_count >= args.count:
                break

    except KeyboardInterrupt:
        pass
    finally:
        if not args.json and not args.no_summary:
            stats.print_summary(use_color=use_color, resolve_names=args.resolve_names)


if __name__ == "__main__":
    main()
