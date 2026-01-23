from scapy.all import sniff

def process_packet(packet):
    print("Packet reveived!")
    print(packet)


sniff(iface="H2-eth0", prn=process_packet)