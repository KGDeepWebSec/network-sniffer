#!/usr/bin/env python3
"""
Basic Network Sniffer - A simple tool to capture and analyze network packets
"""
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
import sys
import time
from datetime import datetime

captured_packets = []  # Store captured packets for saving

def get_packet_details(packet):
    """Extract and return relevant details from a packet"""
    details = {
        "timestamp": datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f'),
        "summary": packet.summary(),
        "length": len(packet),
        "layers": [],
    }

    # Add layer information
    if ARP in packet:
        details["layers"].append({
            "type": "ARP",
            "op": "Request" if packet[ARP].op == 1 else "Reply",
            "src_mac": packet[ARP].hwsrc,
            "src_ip": packet[ARP].psrc,
            "dst_mac": packet[ARP].hwdst,
            "dst_ip": packet[ARP].pdst
        })

    if IP in packet:
        details["layers"].append({
            "type": "IP",
            "version": packet[IP].version,
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "ttl": packet[IP].ttl,
            "proto": packet[IP].proto
        })

    if TCP in packet:
        details["layers"].append({
            "type": "TCP", 
            "sport": packet[TCP].sport,
            "dport": packet[TCP].dport,
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "flags": packet[TCP].flags
        })

    if UDP in packet:
        details["layers"].append({
            "type": "UDP",
            "sport": packet[UDP].sport,
            "dport": packet[UDP].dport,
            "len": packet[UDP].len
        })

    if ICMP in packet:
        details["layers"].append({
            "type": "ICMP",
            "type_id": packet[ICMP].type,
            "code": packet[ICMP].code
        })

    return details

def packet_callback(packet):
    """Process each captured packet"""
    captured_packets.append(packet)
    details = get_packet_details(packet)

    # Print packet information
    print(f"\n{'='*80}")
    print(f"TIME: {details['timestamp']}")
    print(f"PACKET: {details['summary']}")
    print(f"LENGTH: {details['length']} bytes")

    # Print layer details
    for layer in details["layers"]:
        layer_type = layer.pop("type")
        print(f"\n[{layer_type} Layer]")
        for key, value in layer.items():
            print(f"  {key}: {value}")
    print(f"{'='*80}")

def main():
    """Main function to start the network sniffer"""

    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-c", "--count", type=int, default=0, 
                        help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", default="", 
                        help="BPF filter to apply (e.g., 'tcp port 80')")

    args = parser.parse_args()

    try:
        print(f"Starting packet capture on {args.interface or 'default interface'}")
        if args.filter:
            print(f"Using filter: {args.filter}")
        print(f"Capturing {args.count if args.count > 0 else 'infinite'} packets...")
        print("Press Ctrl+C to stop capture\n")

        # Capture and store packets
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=args.count if args.count > 0 else None
        )

        # Save packets to a file
        timestamp = int(time.time())
        filename = f"captured_packets_{timestamp}.pcap"
        wrpcap(filename, packets)
        print(f"\nSaved {len(packets)} packets to {filename}")

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")
        sys.exit(0)
    except PermissionError:
        print("\nError: Insufficient permissions. Try running with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

    try:
        print(f"Starting packet capture on {args.interface or 'default interface'}")
        if args.filter:
            print(f"Using filter: {args.filter}")
        print(f"Capturing {args.count if args.count > 0 else 'infinite'} packets...")
        print("Press Ctrl+C to stop capture\n")

        # Start packet capture
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=args.count if args.count > 0 else None
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except PermissionError:
        print("\nError: Insufficient permissions. Try running with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
    finally:
        if captured_packets:
            filename = f"captured_packets_{int(time.time())}.pcap"
            wrpcap(filename, captured_packets)
            print(f"\nSaved {len(captured_packets)} packets to {filename}")

if __name__ == "__main__":
    main()
