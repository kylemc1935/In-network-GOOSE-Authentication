"""
    Current design is capable to calculate the total time spend on a switch (can write to a file and decide later
    what to do with this data)

    And is also capable of calculating the througput of a system, ie from one port  to the other

"""

import argparse
import csv
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import List, Tuple, Optional

from scapy.all import PcapReader

from dataclasses import dataclass

@dataclass
class PcapStats:
    total_pkts: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    unique_seqs: int = 0
    min_seq: int | None = None
    max_seq: int | None = None

GOOSE_ETHERTYPE = 0x88B8
output_csv = Path("latency.csv")
DEFAULT_BUFSIZE_KB = 16384
pcap_dir = Path("./pcaps")

# marker used on authenticated packets
DEFAULT_MARKER_HEX = "AAFF"

# profiles to stop trying long commands
PROFILES = {
    "auth": {
        "mode": "auth",
        "in_iface": "H1-eth0",
        "out_iface": "H1-eth1",
        "default_duration": 10.0,
        "default_max": 1000,
    },
    "verify": {
        "mode": "verify",
        "in_iface": "S2-eth1",
        "out_iface": "S2-eth2",
        "default_duration": 10.0,
        "default_max": 1000,
    },
    "listen" : {
        "mode": "verify",
        "in_iface": "H1-eth0",
        "out_iface": "H2-eth0",
        "default_duration": 10.0,
        "default_max": 1000,
    }
}


def is_goose(frame_bytes: bytes) -> bool:
    eth_type = int.from_bytes(frame_bytes[12:14], "big")
    if eth_type == GOOSE_ETHERTYPE:
        return True
    return False

def extract_seq(raw: bytes, *, mode: int, marker: bytes) -> int:
    if mode == 0: # appended to the end
        if len(raw) < 4:
            return -1
        return int.from_bytes(raw[-4:], "big", signed=False)

    if mode == 1: # not appended to the end and need to find
        idx = raw.rfind(marker)
        if idx == -1:
            return -1
        start = idx + len(marker)
        if start + 4 > len(raw):
            return -1
        return int.from_bytes(raw[start:start+4], "big", signed=False)

    raise ValueError(f"Unknown seq extract mode: {mode}")

# reads pcap file and returrs a list of (seq, timestamp)
def read_pairs(pcap_path: Path, *, mode: str, marker: bytes) -> tuple[List[Tuple[int, float]], PcapStats]:
    out: List[Tuple[int, float]] = [] # start with an empty list and open pcap file to read in

    stats = PcapStats()
    seen = set()
    with PcapReader(str(pcap_path)) as rd:
        for pkt in rd:
            try:
                raw = bytes(pkt)
                ts = float(pkt.time)
            except Exception:
                continue

            if not is_goose(raw):
                continue

            seq = extract_seq(raw, mode=mode, marker=marker)
            if seq != -1:
                out.append((seq, ts))

                # stats for througput
                # calulates basing on the first packet received and the last packet sent
                stats.total_pkts += 1
                stats.total_bytes += len(raw)
                if stats.first_ts is None or ts < stats.first_ts:
                    stats.first_ts = ts
                if stats.last_ts is None or ts > stats.last_ts:
                    stats.last_ts = ts

                # count unique sequence numbers to count number of packets handled
                if seq not in seen:
                    seen.add(seq)
                    stats.unique_seqs += 1

                if stats.min_seq is None or seq < stats.min_seq:
                    stats.min_seq = seq
                if stats.max_seq is None or seq > stats.max_seq:
                    stats.max_seq = seq
    return out, stats

# given 2 lists will reuturn a list of matched rsequence nubers
def merge_join(ins: List[Tuple[int, float]], outs: List[Tuple[int, float]], max_matches: int,
               ) -> List[Tuple[int, float, float, float]]:
    # sort by sequnence and timestamp
    ins.sort(key=lambda x: (x[0], x[1]))
    outs.sort(key=lambda x: (x[0], x[1]))

    i = j = 0 # two pointers for merge join
    rows: List[Tuple[int, float, float, float]] = []

    while i < len(ins) and j < len(outs) and len(rows) < max_matches:
        seq_i, tin = ins[i] # look at current element in each list
        seq_j, tout = outs[j]

        if seq_i == seq_j: # if sequence numbers match ....
            rows.append((seq_i, tin, tout, (tout - tin) * 1e3))
            i += 1
            j += 1
        elif seq_i < seq_j: # else continue searching
            i += 1
        else:
            j += 1

    print(f"in total: {len(ins)}, out_total: {len(outs)}, matched = {len(rows)}")

    return rows

# start tcpdump in its own process, that writes into pcap_path
def _start_tcpdump(iface: str, pcap_path: Path, filter: str) -> subprocess.Popen:
    cmd = ["tcpdump", "-i", iface, "-U", "-B", str(DEFAULT_BUFSIZE_KB), "-s", "0",
        "-w", str(pcap_path), filter]
    print("CMD:", " ".join(cmd))
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, # hide output
        stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

# similarly stop, tcpdump
def _stop_tcpdump(proc: subprocess.Popen, timeout_s: float = 2.0) -> None:
    if proc.poll() is not None: # ensure process still running
        return
    try: # try to interrupt process
        os.killpg(proc.pid, signal.SIGINT)
        proc.wait(timeout=timeout_s)
    except Exception: # else force stop
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass

def capture_two_pcaps(in_iface: str, out_iface: str, in_pcap: Path, out_pcap: Path, *,
                      duration_s: float, filter: str) -> None:
    # ensure output dir exists
    in_pcap.parent.mkdir(parents=True, exist_ok=True)

    # delete old files
    if in_pcap.exists():
        in_pcap.unlink()
    if out_pcap.exists():
        out_pcap.unlink()

    p_in = _start_tcpdump(in_iface, in_pcap, filter)
    p_out = _start_tcpdump(out_iface, out_pcap, filter)

    # give tcpdump a moment to start (and fail if it’s going to)
    time.sleep(0.25)

    # if either exited, print why
    if p_in.poll() is not None:
        raise RuntimeError(f"tcpdump died immediately on {in_iface} (exit={p_in.returncode})")
    if p_out.poll() is not None:
        raise RuntimeError(f"tcpdump died immediately on {out_iface} (exit={p_out.returncode})")

    try:
        start = time.time()
        while time.time() - start < duration_s:
            if p_in.poll() is not None or p_out.poll() is not None:
                break
            time.sleep(0.05)
    finally:
        print("stopping both tcpdumps\n")
        _stop_tcpdump(p_in)
        _stop_tcpdump(p_out)

    # After stopping, verify files exist and are non-empty
    for pcap in (in_pcap, out_pcap):
        if not pcap.exists():
            raise FileNotFoundError(f"tcpdump did not create pcap: {pcap}")
        if pcap.stat().st_size == 0:
            raise RuntimeError(f"pcap exists but is empty (no packets captured?): {pcap}")


# write to csv, need to come back and sort ##################
def write_csv(csv_path: Path, rows: List[Tuple[int, float, float, float]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "tin", "tout", "delta_ms"])
        for seq, tin, tout, dms in rows:
            w.writerow([seq, f"{tin:.6f}", f"{tout:.6f}", f"{dms:.6f}"])

# this is for time stats, not througput
def print_stats(rows: List[Tuple[int, float, float, float]]) -> None:
    if not rows:
        print("No matches")
        return

    deltas = [r[3] for r in rows]
    deltas_sorted = sorted(deltas)

    n = len(deltas_sorted)
    avg = sum(deltas_sorted) / n
    p50 = deltas_sorted[n // 2]
    p95 = deltas_sorted[max(0, int(n * 0.95) - 1)]
    p99 = deltas_sorted[max(0, int(n * 0.99) - 1)] # unsure what to keep

    print(f"Matched {n} packets.")
    print(f"avg={avg:.3f} ms, p50={p50:.3f} ms, p95={p95:.3f} ms, p99~={p99:.3f} ms")

def print_system_throughput(rows: List[Tuple[int, float, float, float]]) -> None:
    if not rows:
        print("No matched packets")
        return

    first_tin = rows[0][1]
    last_tout = rows[-1][2]

    duration = max(1e-9, last_tout - first_tin)

    delivered = len(rows)
    pps = delivered / duration

    print("Throuput stats:\n")
    print(f"duration: {duration:.6f} s")
    print(f"delivered packets: {delivered}")
    print(f"throughput: {pps:.1f} pkt/s")


def main():
    ap = argparse.ArgumentParser(description="Capture (optional) + offline correlate by seq (sort + merge-join).")
    ap.add_argument("--profile", required=True, choices=PROFILES.keys(), help="Use a predefined profile (auth/verify).")
    ap.add_argument("--duration", type=float, help="Capture duration in seconds")
    ap.add_argument("--max", type=int, default=1000, help="Max matched pairs to write")

    args = ap.parse_args()

    p = PROFILES[args.profile]
    mode = p["mode"]
    in_iface = p["in_iface"]
    out_iface = p["out_iface"]

    duration = args.duration or p["default_duration"]
    max_matches = args.max or p["default_max"]

    marker = bytes.fromhex(DEFAULT_MARKER_HEX)

    # decide extraction modes based on switch mode
    if mode == "auth":
        in_mode = 0
        out_mode = 1
    else:  # verify
        in_mode = 1
        out_mode = 0

    ts = time.strftime("%Y%m%d_%H%M%S") # create unique pcap files
    pcap_dir.mkdir(parents=True, exist_ok=True)
    in_pcap = pcap_dir / f"in_{in_iface}_{ts}.pcap"
    out_pcap = pcap_dir / f"out_{out_iface}_{ts}.pcap"

    # tcpdump filter for GOOSE only
    filter = "ether proto 0x88b8"

    # run experiment
    capture_two_pcaps(in_iface, out_iface, in_pcap, out_pcap,
            duration_s=duration, filter=filter,)

    print(f"Captured:\n  IN : {in_pcap}\n  OUT: {out_pcap}")

    # parse in files and match timestamps
    print("reading in files and matching\n")
    ins, in_stats = read_pairs(in_pcap, mode=in_mode, marker=marker)
    outs, out_stats = read_pairs(out_pcap, mode=out_mode, marker=marker)


    rows = merge_join(ins, outs, max_matches=max_matches)

    print_system_throughput(rows)
    print("writing results to csv\n")
    write_csv(output_csv, rows)
    print_stats(rows)


if __name__ == "__main__":
    main()
