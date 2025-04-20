# Network Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic. This tool helps understand how data flows on a network and how packets are structured.

## Features
- Captures packets from specified network interfaces
- Analyzes and displays packet structure in readable format
- Parses common protocols (IP, TCP, UDP, ICMP, ARP)
- Supports BPF filtering syntax for targeted captures

## Requirements
- Python 3.x
- Scapy library

## Installation
```bash
pip install scapy


Usage

sudo python3 network_sniffer.py -i eth0 -c 10 -f "tcp"

Command Line Options

-i INTERFACE: Network interface to capture packets from
-c COUNT: Number of packets to capture (0 for infinite)
-f FILTER: BPF filter to apply (e.g., 'tcp port 80')


Examples
Capture 5 ICMP packets:

sudo python3 network_sniffer.py -i eth0 -c 5 -f "icmp"

Monitor HTTP traffic:

sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"

Security Notice
This tool is for educational purposes only. Always ensure you have proper authorization before capturing network traffic.
