import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
import sys
import time
from datetime import datetime

# Log packet summary to a log file
def log_packet_details(packet_details, filename="packet_capture.log"):
    with open(filename, 'a') as log_file:
        log_file.write(f"{packet_details['timestamp']} - {packet_details['summary']}\n")

# Extract and structure packet details
def get_packet_details(packet):
    details = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
        "summary": packet.summary(),
        "length": len(packet),
        "layers": []
    }

    # Add ARP Layer
    if ARP in packet:
        details["layers"].append({
            "type": "ARP",
            "Operation": "Request" if packet[ARP].op == 1 else "Reply",
            "Source MAC": packet[ARP].hwsrc,
            "Source IP": packet[ARP].psrc,
            "Destination MAC": packet[ARP].hwdst,
            "Destination IP": packet[ARP].pdst
        })

    # Add IP Layer
    if IP in packet:
        details["layers"].append({
            "type": "IP",
            "Source IP": packet[IP].src,
            "Destination IP": packet[IP].dst,
            "TTL": packet[IP].ttl
        })

    # Add TCP Layer
    if TCP in packet:
        details["layers"].append({
            "type": "TCP",
            "Source Port": packet[TCP].sport,
            "Destination Port": packet[TCP].dport,
            "Flags": packet[TCP].flags
        })

    # Add UDP Layer
    if UDP in packet:
        details["layers"].append({
            "type": "UDP",
            "Source Port": packet[UDP].sport,
            "Destination Port": packet[UDP].dport
        })

    # Add ICMP Layer
    if ICMP in packet:
        details["layers"].append({
            "type": "ICMP",
            "Type": packet[ICMP].type,
            "Code": packet[ICMP].code
        })

    return details

# Callback function for each captured packet
def packet_callback(packet):
    details = get_packet_details(packet)
    log_packet_details(details)

    print("\n" + "-"*60)
    print(f"[Time]     {details['timestamp']}")
    print(f"[Length]   {details['length']} bytes")
    print(f"[Summary]  {details['summary']}")

    for layer in details["layers"]:
        print(f"\n>> {layer['type']} Layer:")
        for key, value in layer.items():
            if key != "type":
                print(f"   {key}: {value}")
    print("-"*60)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Interface to capture from")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="", help="Capture filter (e.g. 'tcp', 'icmp')")
    parser.add_argument("-e", "--export", choices=["csv", "json"], help="Export packets to CSV or JSON")

    args = parser.parse_args()

    try:
        print(f"\nStarting capture on interface: {args.interface or 'default'}")
        if args.filter:
            print(f"Using filter: {args.filter}")
        print(f"Capturing {args.count if args.count > 0 else '∞'} packets. Press Ctrl+C to stop.\n")

        sniff_count = args.count if args.count > 0 else 0
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=sniff_count
        )

        # Save as PCAP
        filename = f"captured_packets_{int(time.time())}.pcap"
        wrpcap(filename, packets)
        print(f"\n✅ Saved {len(packets)} packets to: {filename}")

        # Export to CSV or JSON
        if args.export == "csv":
            export_to_csv(packets)
            print("✅ Exported packets to captured_packets.csv")
        elif args.export == "json":
            export_to_json(packets)
            print("✅ Exported packets to captured_packets.json")

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user.")
        sys.exit(0)
    except PermissionError:
        print("\n🚫 Permission Denied. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

# Optional export functions (placeholder if needed)
def export_to_csv(packets):
    # Add export to CSV logic here
    pass

def export_to_json(packets):
    # Add export to JSON logic here
    pass

if __name__ == "__main__":
    main()
