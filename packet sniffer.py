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

# Start sniffing
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
