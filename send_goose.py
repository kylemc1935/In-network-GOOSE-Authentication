from scapy.all import rdpcap, sendp, Ether

# file is only for quick and easy testing on mininet, is later to be replaced by a .c file

SEND_IFACE = "H1-eth0"
MAGIC = b"\xCA\xFE"

packets = rdpcap("switch_controls/sample_goose_packets.pcap")
for pkt in packets:
    pkt[Ether].dst = "00:00:00:00:00:02"
    pkt[Ether].src = "00:00:00:00:00:01"
    sendp(pkt, iface=SEND_IFACE, verbose=False)

print("Done sending")
