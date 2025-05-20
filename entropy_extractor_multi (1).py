#!/usr/bin/env python3
"""
entropy_extractor_mp.py
Parallel entropy extractor for folders of *.pcap / *.pcap.gz traces.

Run:
    python entropy_extractor_mp.py --pcap_dir  /path/to/top \
                                   --outfile   entropies.csv \
                                   --workers   8
"""
# --------------------------------------------------------------------
import argparse, csv, gzip, math, socket, os
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import dpkt
# --------------------------------------------------------------------
# ----------------- generic helpers ----------------------------------

def list_pcaps(root: str):
    paths = []
    for pat in ('*.pcap', '*.pcap.gz'):
        paths.extend(Path(root).rglob(pat))
    return sorted(paths)

def ip_to_int(addr: bytes) -> int:
    if len(addr) == 4:
        return int.from_bytes(addr, 'big')
    return hash(addr) & 0xFFFFFFFF

def msb_k(x: int, k: int) -> int:
    return x >> (32 - k)

def port_bucket(p: int) -> str:
    if p <= 1023:  return 'system'
    if p <= 49151: return 'user'
    return 'ephemeral'

def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c/total) * math.log2(c/total) for c in counter.values())

# ----------------- window structure ---------------------------------

def empty_state(ks):
    return {
        'ports': {'count': defaultdict(int), 'bytes': defaultdict(int)},
        'saddr': {k: {'count': defaultdict(int), 'bytes': defaultdict(int)} for k in ks},
        'daddr': {k: {'count': defaultdict(int), 'bytes': defaultdict(int)} for k in ks},
    }

def merge_state(dst, src):
    """Add counters from *src* into *dst* (same nested structure)."""
    # ports
    for metric in ('count', 'bytes'):
        for key, val in src['ports'][metric].items():
            dst['ports'][metric][key] += val
    # ip tables
    for tag in ('saddr', 'daddr'):
        for k in src[tag]:
            for metric in ('count', 'bytes'):
                for key, val in src[tag][k][metric].items():
                    dst[tag][k][metric][key] += val

# ----------------- per-file worker ----------------------------------

def process_single_pcap(pcap_path: str, ks, win_lens):
    """Run in a worker process; returns its own windows dict."""
    windows = {wl: {} for wl in win_lens}               # local counters
    opener = gzip.open if pcap_path.endswith('.gz') else open
    with opener(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                size = len(buf)
                src = ip_to_int(ip.src); dst = ip_to_int(ip.dst)
                sport = dport = 0
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    sport = ip.data.sport; dport = ip.data.dport
            except Exception:
                continue

            for wl in win_lens:
                start = int(ts // wl) * wl
                w = windows[wl].setdefault(start, empty_state(ks))
                # -- ports
                for p in (sport, dport):
                    b = port_bucket(p)
                    w['ports']['count'][b] += 1
                    w['ports']['bytes'][b] += size
                # -- IP buckets
                for k in ks:
                    w['saddr'][k]['count'][msb_k(src, k)] += 1
                    w['saddr'][k]['bytes'][msb_k(src, k)] += size
                    w['daddr'][k]['count'][msb_k(dst, k)] += 1
                    w['daddr'][k]['bytes'][msb_k(dst, k)] += size
    return windows

# ----------------- main ---------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcap_dir', required=True)
    ap.add_argument('--outfile',  default='entropies.csv')
    ap.add_argument('--workers',  type=int, default=os.cpu_count(),
                    help='parallel processes (default: #cores)')
    args = ap.parse_args()

    ks         = (3,4,5,6)
    win_lens   = (300, 600, 900)           # sec
    global_win = {wl: {} for wl in win_lens}

    pcaps = list_pcaps(args.pcap_dir)
    print(f'Found {len(pcaps)} pcaps  →  spawning {args.workers} workers\n')

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        fut_to_pcap = {pool.submit(process_single_pcap, str(p), ks, win_lens): p
                       for p in pcaps}
        for fut in as_completed(fut_to_pcap):
            p = fut_to_pcap[fut]
            try:
                local_win = fut.result()
                # merge into global
                for wl in win_lens:
                    for start, state in local_win[wl].items():
                        merged = global_win[wl].setdefault(start, empty_state(ks))
                        merge_state(merged, state)
                print(f'✓ {p.name}')
            except Exception as e:
                print(f'✗ {p.name}: {e}')

    # -------- write CSV ---------------------------------------------
    with open(args.outfile, 'w', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['window_start','window_length','entropy_type','k',
                     'metric','value'])
        for wl, win_map in global_win.items():
            for start, state in win_map.items():
                start_dt = datetime.utcfromtimestamp(start)
                # ports
                for metric in ('count','bytes'):
                    wr.writerow([start_dt, wl, 'ports', '', metric,
                                 entropy(state['ports'][metric])])
                # ip
                for k in ks:
                    for tag in ('saddr','daddr'):
                        for metric in ('count','bytes'):
                            wr.writerow([start_dt, wl, tag, k, metric,
                                         entropy(state[tag][k][metric])])

    print(f'\nAll done → {args.outfile}')

if __name__ == '__main__':
    main()

