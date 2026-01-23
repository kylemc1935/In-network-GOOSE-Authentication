from scapy.all import sendp, rdpcap

packets = rdpcap("sample_goose_packets.pcap")

for packet in packets:
    sendp(packet, "H1-eth0")
