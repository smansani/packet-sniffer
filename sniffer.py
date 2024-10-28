from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

suspicious_ips = ["172.18.220.6", "10.0.0.5"]  # Add any suspicious IPs you want to monitor

def log_packet(packet, protocol):
    with open(f"{protocol}_packets_log.txt", "a") as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        ttl = packet[IP].ttl
        flags = packet[IP].flags if hasattr(packet[IP], 'flags') else "N/A"
        f.write(f"[{timestamp}] Protocol: {protocol}, Source: {src}, Destination: {dst}, Size: {size} bytes, TTL: {ttl}, Flags: {flags}\n")

def log_suspicious_packet(packet):
    with open("suspicious_packets_log.txt", "a") as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = packet[IP].proto
        f.write(f"[{timestamp}] Suspicious Packet: Source: {src}, Destination: {dst}, Protocol: {protocol}, Size: {len(packet)} bytes\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        print("\nPacket Captured:")
        print(f"Source: {src_ip}")
        print(f"Destination: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"TTL: {packet[IP].ttl}")
        print(f"Packet Size: {len(packet)} bytes")

        if src_ip in suspicious_ips:
            print(f"Alert! Suspicious activity detected from {src_ip}")
            log_suspicious_packet(packet)  # Log suspicious packet
            return  # Continue sniffing
            
        if packet.haslayer(TCP):
            print(f"TCP Packet Captured: {src_ip} -> {dst_ip}")
            log_packet(packet, "TCP")
        elif packet.haslayer(UDP):
            print(f"UDP Packet Captured: {src_ip} -> {dst_ip}")
            log_packet(packet, "UDP")
        else:
            print(f"IP Packet Captured: {src_ip} -> {dst_ip}")
            log_packet(packet, "IP")
    else:
        print("\nNon-IP Packet Captured:")
        print(packet.summary())

print("Sniffing packets... Press Ctrl+C to stop.")
try:
    sniff(filter="ip", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nSniffing stopped by user.")
