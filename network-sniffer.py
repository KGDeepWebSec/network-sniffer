import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
import sys
import time
from datetime import datetime

# Log packet details to a file
def log_packet_details(packet_details, filename="packet_capture.log"):
    """Log packet details to a log file"""
    with open(filename, 'a') as log_file:
        log_file.write(f"{packet_details['timestamp']} - {packet_details['summary']}\n")

# Extract packet details
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
    # Add more layers like IP, TCP, UDP, ICMP
    # (Same as your previous code...)

    return details

# Callback for processing each packet
def packet_callback(packet):
    """Process each captured packet"""
    details = get_packet_details(packet)
    
    # Log the packet details to a file
    log_packet_details(details)

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

# Main function to start the network sniffer
def main():
    """Main function to start the network sniffer"""
    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter to apply (e.g., 'tcp port 80')")
    parser.add_argument("-e", "--export", choices=["csv", "json"], help="Export captured packets to CSV or JSON")

    args = parser.parse_args()

    try:
        print(f"Starting packet capture on {args.interface or 'default interface'}")
        if args.filter:
            print(f"Using filter: {args.filter}")
        print(f"Capturing {args.count if args.count > 0 else 'infinite'} packets...")
        print("Press Ctrl+C to stop capture\n")

        # Capture packets
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

        # Export packets to CSV or JSON if selected
        if args.export == "csv":
            export_to_csv(packets)
            print(f"Exported packets to captured_packets.csv")
        elif args.export == "json":
            export_to_json(packets)
            print(f"Exported packets to captured_packets.json")

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")
        sys.exit(0)
    except PermissionError:
        print("\nError: Insufficient permissions. Try running with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

# Run the script
if __name__ == "__main__":
    main()
