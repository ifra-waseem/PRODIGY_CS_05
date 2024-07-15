This Python script utilizes the Scapy library to create a packet sniffer that captures and analyzes network packets. Here's a description of its functionality:

Description of the Packet Sniffer Script
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

def packet_callback(packet):
    # Print a timestamp
    print(f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        # Display the source and destination IP addresses
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        # Determine the protocol and display relevant information
        if proto == 6:  # TCP
            print("Protocol: TCP")
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                payload = packet[TCP].payload
                print(f"Source Port: {sport}")
                print(f"Destination Port: {dport}")
                print(f"Payload: {payload}")
        elif proto == 17:  # UDP
            print("Protocol: UDP")
            if UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                payload = packet[UDP].payload
                print(f"Source Port: {sport}")
                print(f"Destination Port: {dport}")
                print(f"Payload: {payload}")
        else:
            print(f"Protocol: Other ({proto})")
            print(f"Payload: {packet[IP].payload}")
Packet Callback Function (packet_callback): This function is called for each packet captured by sniff. It prints a timestamp and extracts and displays relevant information from the packet:
Timestamp: Current time when the packet is captured.
IP Layer: Extracts source (ip_src) and destination (ip_dst) IP addresses, and protocol (proto) type.
Protocol Handling: Depending on the protocol (proto), it identifies TCP (6) or UDP (17) and prints source and destination ports (sport, dport) along with payload data (payload). For other protocols, it prints the protocol number and payload.
# Start sniffing
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
Starting Sniffing: Initiates the packet sniffing process using Scapy's sniff function:
prn=packet_callback: Specifies the callback function (packet_callback) to process each captured packet.
store=0: Disables storing packets in memory, which is useful for long-term sniffing.
Summary
This script serves as a basic packet sniffer that captures and analyzes network traffic in real-time. It's capable of handling TCP, UDP, and other IP-based protocols, providing insights into source and destination addresses, ports, and payload data. This tool is valuable for network monitoring, troubleshooting, and educational purposes, with the ability to extend functionality for specific network analysis tasks.
