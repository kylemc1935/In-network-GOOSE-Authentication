import csv
from pathlib import Path
from scapy.all import sniff

IN_IFACE  = "S2-eth1"
OUT_IFACE = "S2-eth2"

SWAP_TAG_DIRECTION = False # default way is unauthenticated packet in, authenticated packet out

MAX_MATCHES = 100
OUT_CSV = Path("../data/s1_latency_pairs.csv")

FILTER = "ether[12:2] = 0x88b8"  # GOOSE


def extract_seq_in(pkt) -> int:
    # extract 4 last bytes to get the sequence number
    raw = bytes(pkt)
    if len(raw) < 4:
        return -1
    return int.from_bytes(raw[-4:], "big", signed=False)

MARKER = b"\xAA\xFF" #marker to find the seq no
def extract_seq_out(pkt) -> int:
    raw = bytes(pkt)

    # find the last occurence
    idx = raw.rfind(MARKER)
    if idx == -1:
        return -1

    # need 4 bytes after CA FE
    if idx + 2 + 4 > len(raw):
        return -1

    return int.from_bytes(raw[idx + 2: idx + 6], "big", signed=False)



def main():
    tin = {}   # seq -> timestamp
    tout = {}  # seq -> timestamp
    matched = 0

    with open(OUT_CSV, "w", newline="") as f: # opne file and format csv
        w = csv.writer(f)
        w.writerow(["seq", "tin", "tout", "delta_ms"])

        def on_pkt(pkt): # comp on every GOOSE packet
            nonlocal matched
            iface = getattr(pkt, "sniffed_on", None) # get interface
            ts = float(pkt.time)

            if iface == IN_IFACE: # switch between incoming auth or non auth
                if SWAP_TAG_DIRECTION:
                    seq = extract_seq_out(pkt)
                else:
                    seq = extract_seq_in(pkt)
                if seq == -1:
                    return
                tin.setdefault(seq, ts)

            elif iface == OUT_IFACE:
                if SWAP_TAG_DIRECTION:
                    seq = extract_seq_in(pkt)
                else:
                    seq = extract_seq_out(pkt)
                if seq == -1:
                    return
                tout.setdefault(seq, ts)

            else:
                return

            # match + compute difference
            if seq in tin and seq in tout:
                delta_ms = (tout[seq] - tin[seq]) * 1e3

                w.writerow([seq, f"{tin[seq]:.6f}", f"{tout[seq]:.6f}", f"{delta_ms:.6f}"])
                f.flush()
                print(seq)
                print(f"{delta_ms:.6f}")

                matched += 1
                tin.pop(seq, None)
                tout.pop(seq, None)

        def should_stop(_pkt) -> bool:
            return matched >= MAX_MATCHES

        sniff(iface=[IN_IFACE, OUT_IFACE], filter=FILTER, prn=on_pkt, store=False, top_filter=should_stop)


if __name__ == "__main__":
    main()
