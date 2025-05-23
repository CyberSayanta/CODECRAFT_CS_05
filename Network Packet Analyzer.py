from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import datetime

def packet_callback(packet):
    """Process each captured packet"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"\n[{timestamp}] Packet: {src_ip} -> {dst_ip}")
        print(f"Protocol: {protocol} ({get_protocol_name(protocol)})")
        
        if packet.haslayer(TCP):
            print(f"TCP - Source Port: {packet[TCP].sport} | Dest Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP - Source Port: {packet[UDP].sport} | Dest Port: {packet[UDP].dport}")
        
       
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:100]
            print(f"Payload (truncated): {payload}")

def get_protocol_name(proto_num):
    """Convert protocol number to name"""
    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        
    }
    return protocol_names.get(proto_num, "Unknown")

def main():
    print("Simple Network Packet Analyzer (Educational Purposes Only)")
    print("Press Ctrl+C to stop capturing...")
    print("Sniffing network traffic...\n")
    
    try:
        
        sniff(prn=packet_callback, store=0, iface=None)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    main()