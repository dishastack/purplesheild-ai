
from collections import Counter, defaultdict
from io import BytesIO

import pandas as pd
from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
)


class PacketAnalyzer:

    def __init__(self):
        self.packets = []
        self.packet_rows = []

    def load_capture(self, file_bytes):
        """Load packets from an uploaded PCAP or PCAPNG file."""

        self.packets = rdpcap(BytesIO(file_bytes))
        self.packet_rows = []

        for index, packet in enumerate(self.packets, start=1):

            source = "Unknown"
            destination = "Unknown"
            protocol = "Other"
            source_port = None
            destination_port = None
            tcp_flags = None
            dns_query = None
            packet_length = len(packet)

            if IP in packet:
                source = packet[IP].src
                destination = packet[IP].dst

            elif IPv6 in packet:
                source = packet[IPv6].src
                destination = packet[IPv6].dst

            elif ARP in packet:
                source = packet[ARP].psrc
                destination = packet[ARP].pdst
                protocol = "ARP"

            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)

            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            elif ICMP in packet:
                protocol = "ICMP"

            if DNS in packet:
                protocol = "DNS"

                if DNSQR in packet:
                    try:
                        dns_query = (
                            packet[DNSQR].qname.decode(
                                "utf-8", errors="ignore"
                            ).rstrip(".")
                        )
                    except Exception:
                        dns_query = None

            self.packet_rows.append({
                "Packet": index,
                "Source": source,
                "Destination": destination,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "TCP Flags": tcp_flags,
                "DNS Query": dns_query,
                "Length": packet_length,
            })

        return self.get_dataframe()

    def get_dataframe(self):
        return pd.DataFrame(self.packet_rows)

    def protocol_statistics(self):
        return dict(
            Counter(
                row["Protocol"]
                for row in self.packet_rows
            )
        )

    def top_source_ips(self, limit=10):
        counts = Counter(
            row["Source"]
            for row in self.packet_rows
            if row["Source"] != "Unknown"
        )

        return counts.most_common(limit)

    def top_destination_ips(self, limit=10):
        counts = Counter(
            row["Destination"]
            for row in self.packet_rows
            if row["Destination"] != "Unknown"
        )

        return counts.most_common(limit)

    def dns_investigation(self):
        return [
            row for row in self.packet_rows
            if row["DNS Query"]
        ]

    def tcp_handshake_analysis(self):
        connections = defaultdict(
            lambda: {
                "SYN": 0,
                "SYN_ACK": 0,
                "ACK": 0,
                "Other": 0,
            }
        )

        for row in self.packet_rows:

            if row["Protocol"] != "TCP":
                continue

            flags = row["TCP Flags"] or ""

            connection = (
                row["Source"],
                row["Source Port"],
                row["Destination"],
                row["Destination Port"],
            )

            if "S" in flags and "A" not in flags:
                connections[connection]["SYN"] += 1

            elif "S" in flags and "A" in flags:
                connections[connection]["SYN_ACK"] += 1

            elif "A" in flags:
                connections[connection]["ACK"] += 1

            else:
                connections[connection]["Other"] += 1

        return dict(connections)

    def packet_summary(self):
        total = len(self.packet_rows)

        protocols = self.protocol_statistics()

        return {
            "total_packets": total,
            "protocol_count": len(protocols),
            "unique_sources": len({
                row["Source"]
                for row in self.packet_rows
                if row["Source"] != "Unknown"
            }),
            "dns_queries": len(self.dns_investigation()),
            "tcp_packets": protocols.get("TCP", 0),
            "udp_packets": protocols.get("UDP", 0),
        }
