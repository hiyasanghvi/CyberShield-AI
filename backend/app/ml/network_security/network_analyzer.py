
import io
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
)


MAX_CAPTURE_SIZE = 50 * 1024 * 1024
MAX_PACKETS = 50000


def analyze_network_capture(file_bytes: bytes, file_name: str) -> dict:
    if not file_bytes:
        raise ValueError("Uploaded capture file is empty.")

    if len(file_bytes) > MAX_CAPTURE_SIZE:
        raise ValueError("PCAP file exceeds the 50 MB limit.")

    try:
        packets = rdpcap(io.BytesIO(file_bytes))
    except Exception as error:
        raise ValueError(
            "Invalid or unsupported PCAP/PCAPNG file."
        ) from error

    if not packets:
        raise ValueError("No packets found in capture.")

    if len(packets) > MAX_PACKETS:
        raise ValueError(
            f"Capture contains more than {MAX_PACKETS} packets. "
            "Please upload a smaller capture."
        )

    flows = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "start": None,
        "end": None,
        "protocol": "OTHER",
        "syn": 0,
        "ack": 0,
    })

    source_ports = defaultdict(set)
    syn_counts = Counter()
    dns_queries = Counter()
    protocols = Counter()
    indicators = []
    evidence = []

    total_bytes = 0
    packet_count = 0
    http_count = 0
    dns_count = 0

    first_timestamp = None
    last_timestamp = None

    for packet in packets:
        packet_count += 1
        packet_size = len(packet)
        total_bytes += packet_size

        try:
            timestamp = float(packet.time)
        except Exception:
            timestamp = None

        if timestamp is not None:
            first_timestamp = (
                timestamp if first_timestamp is None
                else min(first_timestamp, timestamp)
            )
            last_timestamp = (
                timestamp if last_timestamp is None
                else max(last_timestamp, timestamp)
            )

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        else:
            continue

        src_port = None
        dst_port = None
        protocol = "OTHER"
        syn = False
        ack = False

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            protocol = "TCP"

            syn = bool(int(tcp.flags) & 0x02)
            ack = bool(int(tcp.flags) & 0x10)

            if syn and not ack:
                syn_counts[src_ip] += 1

            if syn:
                source_ports[src_ip].add(dst_port)

            if src_port == 80 or dst_port == 80:
                http_count += 1

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            protocol = "UDP"

            if src_port == 53 or dst_port == 53:
                dns_count += 1

                if packet.haslayer(DNS) and packet[DNS].qd:
                    try:
                        query = packet[DNSQR].qname.decode(
                            errors="ignore"
                        ).rstrip(".")
                        if query:
                            dns_queries[src_ip] += 1
                    except Exception:
                        pass

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        protocols[protocol] += 1

        flow_key = (
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        )

        flow = flows[flow_key]
        flow["packets"] += 1
        flow["bytes"] += packet_size
        flow["protocol"] = protocol

        if timestamp is not None:
            flow["start"] = (
                timestamp if flow["start"] is None
                else min(flow["start"], timestamp)
            )
            flow["end"] = (
                timestamp if flow["end"] is None
                else max(flow["end"], timestamp)
            )

        if syn:
            flow["syn"] += 1

        if ack:
            flow["ack"] += 1

    if packet_count == 0:
        raise ValueError("No IP packets found in capture.")

    duration = 0.0

    if first_timestamp is not None and last_timestamp is not None:
        duration = max(0.0, last_timestamp - first_timestamp)

    # Select the largest flow for the database's single-flow summary.
    largest_flow = None

    if flows:
        largest_key, largest_data = max(
            flows.items(),
            key=lambda item: item[1]["bytes"],
        )

        largest_flow = {
            "source_ip": largest_key[0],
            "destination_ip": largest_key[1],
            "protocol": largest_key[2],
            "source_port": largest_key[3],
            "destination_port": largest_key[4],
            "packets": largest_data["packets"],
            "bytes": largest_data["bytes"],
            "duration": (
                max(
                    0.0,
                    (largest_data["end"] or 0)
                    - (largest_data["start"] or 0),
                )
            ),
        }

    # Heuristic port scan indicator.
    port_scan_sources = []

    for source_ip, ports in source_ports.items():
        if len(ports) >= 15:
            port_scan_sources.append({
                "source_ip": source_ip,
                "unique_destination_ports": len(ports),
            })

    if port_scan_sources:
        indicators.append("POSSIBLE_PORT_SCAN")
        evidence.append({
            "type": "PORT_SCAN",
            "details": port_scan_sources,
            "description": (
                "A source contacted 15 or more distinct destination "
                "ports using TCP SYN packets."
            ),
        })

    # Heuristic SYN flood indicator.
    syn_flood_sources = []

    for source_ip, count in syn_counts.items():
        if count >= 100:
            syn_flood_sources.append({
                "source_ip": source_ip,
                "syn_packets_without_ack": count,
            })

    if syn_flood_sources:
        indicators.append("POSSIBLE_SYN_FLOOD")
        evidence.append({
            "type": "SYN_FLOOD",
            "details": syn_flood_sources,
            "description": (
                "A source generated at least 100 TCP SYN packets "
                "without ACK in this capture."
            ),
        })

    if dns_count:
        indicators.append("DNS_TRAFFIC_PRESENT")
        evidence.append({
            "type": "DNS",
            "query_packet_count": dns_count,
            "description": "DNS traffic was observed.",
        })

    if http_count:
        indicators.append("HTTP_TRAFFIC_PRESENT")
        evidence.append({
            "type": "HTTP",
            "packet_count": http_count,
            "description": (
                "Traffic using TCP port 80 was observed. "
                "This does not prove sensitive data was exposed."
            ),
        })

    if not indicators:
        indicators.append("NO_STRONG_NETWORK_INDICATORS")

    # Risk score based on observed heuristic evidence.
    risk_score = 0

    if port_scan_sources:
        risk_score += 40

    if syn_flood_sources:
        risk_score += 50

    if http_count:
        risk_score += 5

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        classification = "MALICIOUS"
        severity = "CRITICAL"
    elif risk_score >= 40:
        classification = "SUSPICIOUS"
        severity = "HIGH"
    elif risk_score >= 20:
        classification = "SUSPICIOUS"
        severity = "MEDIUM"
    else:
        classification = "LOW_RISK"
        severity = "LOW"

    attack_category = (
        ", ".join(
            item for item in indicators
            if item in {
                "POSSIBLE_PORT_SCAN",
                "POSSIBLE_SYN_FLOOD",
            }
        )
        or "NORMAL_OR_UNCLASSIFIED"
    )

    flow_rate = (
        total_bytes / duration
        if duration > 0
        else 0.0
    )

    explanation = (
        f"Analyzed {packet_count} packets across {len(flows)} flows. "
        f"Observed {dict(protocols)}. "
        f"Detected indicators: {', '.join(indicators)}. "
        f"Heuristic risk score: {risk_score}/100."
    )

    recommendation = (
        "Investigate the flagged source IPs and affected ports. "
        "Correlate with firewall and endpoint logs before taking action."
        if risk_score >= 40
        else
        "No strong attack pattern was detected by the current checks. "
        "Continue monitoring; this result does not guarantee the "
        "network traffic is safe."
    )

    return {
        "file_name": file_name,
        "total_packets": packet_count,
        "total_bytes": total_bytes,
        "total_flows": len(flows),
        "duration": round(duration, 3),
        "flow_rate": round(flow_rate, 3),
        "protocols": dict(protocols),
        "dns_packet_count": dns_count,
        "http_packet_count": http_count,
        "dns_query_sources": dict(dns_queries),
        "port_scan_sources": port_scan_sources,
        "syn_flood_sources": syn_flood_sources,
        "largest_flow": largest_flow,
        "indicators": indicators,
        "evidence": evidence,
        "attack_category": attack_category,
        "classification": classification,
        "risk_score": risk_score,
        "severity": severity,
        "explanation": explanation,
        "recommendation": recommendation,
    }
