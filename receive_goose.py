from scapy.all import sniff

RECV_IFACE = "H2-eth0"
def on_pkt(pkt):
    print("Goose packet received")

sniff(iface=RECV_IFACE, prn=on_pkt, store=False)
