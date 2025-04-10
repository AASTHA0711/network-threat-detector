from scapy.all import sniff

# Har packet pe yeh function chalega
def packet_callback(packet):
    print(packet.summary())  # Basic info of the packet

# 10 packets sniff karega (safe start)
sniff(count=10, prn=packet_callback)
