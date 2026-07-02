from scapy.all import sniff, IP
from datetime import datetime

def packet_callback(packet):
    if packet.haslayer(IP):
        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"

        elif protocol == 17:
            protocol_name = "UDP"

        else:
            protocol_name = "Other"

        print("====================== New Packet ======================")
        print("Time           :", datetime.now().strftime("%H:%M:%S"))
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)
        print(f"Protocol       : {protocol} ({protocol_name})")
        print("Packet Length  :", len(packet), "bytes")
        print("Summary        :", packet.summary())
        
        

print("Packet Sniffer Started...")

sniff(prn=packet_callback, count=5)