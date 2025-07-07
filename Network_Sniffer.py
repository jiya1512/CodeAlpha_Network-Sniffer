#!/usr/bin/env python3
"""
Network Packet Capture Tool
"""

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """Process each captured packet"""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine protocol
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            proto = "Other"
            src_port = dst_port = None
        
        # Display packet information
        print(f"[+] Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port} ({proto})")
        
        # Display payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:50]  # Show first 50 bytes
            if len(payload) > 50:
                payload += "..."
            print(f"    Payload: {payload}")

def main():
    """Main execution"""
    print("[*] Starting packet capture...")
    try:
        # Capture packets indefinitely
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped.")

if __name__ == "__main__":
    main()