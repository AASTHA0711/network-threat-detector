from scapy.all import sniff, IP, DNS, wrpcap
from collections import defaultdict
from datetime import datetime

# Dictionary to count packets from each IP
ip_counter = defaultdict(int)

# List to store captured packets
captured_packets = []

# Log alert to a file
def log_alert(message):
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()} - ALERT: {message}\n")
    print(f"[ALERT] {message}")

# Log normal packets to a file
def log_packet_info(packet):
    with open("packets.log", "a") as f:
        f.write(f"{datetime.now()} - {packet.summary()}\n")

# Process each sniffed packet
def process_packet(packet):
    captured_packets.append(packet)  # Save for pcap file

    # Log the packet info
    log_packet_info(packet)

    # Check if it's a DNS packet
    if packet.haslayer(DNS):
        print(f"[DNS] Packet: {packet.summary()}")

    # Check for suspicious IPs
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1

        if ip_counter[src_ip] > 20:
            log_alert(f"Suspicious IP detected: {src_ip} sent {ip_counter[src_ip]} packets")

# Start sniffing
print("[*] Starting packet sniffing... Press Ctrl+C to stop.")
try:
    sniff(prn=process_packet, count=100, store=0)  # You can remove 'count=100' for infinite sniffing
except KeyboardInterrupt:
    print("\n[!] Sniffing stopped by user.")

# Save captured packets to .pcap file
wrpcap("captured_packets.pcap", captured_packets)
print("[*] Packets saved to captured_packets.pcap")

from scapy.all import sniff, IP, TCP
from datetime import datetime

alert_log_file = "alerts.log"
packet_log_file = "packets.log"

def log_alert(message):
    with open(alert_log_file, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] ALERT: {message}\n")
        print(f"[{timestamp}] ALERT: {message}")

ip_count = {}
syn_count = {}
suspicious_ports = [4444, 1337, 23]
keywords = ["malware", "exploit", "shellcode"]

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src

        # Packet Logging
        with open(packet_log_file, "a") as f:
            f.write(f"{datetime.now()} - {src_ip}\n")

        # Repeated IP detection
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
        if ip_count[src_ip] > 20:
            log_alert(f"Multiple packets from {src_ip}")

        # SYN Flood Detection
        if TCP in packet and packet[TCP].flags == "S":
            syn_count[src_ip] = syn_count.get(src_ip, 0) + 1
            if syn_count[src_ip] > 15:
                log_alert(f"Potential SYN Flood from {src_ip}")

        # Suspicious Ports
        if TCP in packet:
            if packet[TCP].dport in suspicious_ports:
                log_alert(f"Suspicious port access from {src_ip} to port {packet[TCP].dport}")

        # Suspicious Payload
        if packet.haslayer(TCP) and hasattr(packet[TCP], 'payload'):
            try:
                payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                for keyword in keywords:
                    if keyword in payload:
                        log_alert(f"Suspicious keyword '{keyword}' found in packet from {src_ip}")
            except Exception:
                pass

print("🔍 Sniffing started... Press Ctrl+C to stop.")
sniff(filter="ip", prn=analyze_packet, store=0)
