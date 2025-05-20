#!/usr/bin/env python3
"""
plot_entropies.py
Read entropies.csv (as produced by entropy_extractor_mp.py) and emit
time-series plots with matplotlib—one chart per series, no subplots.

Usage
-----
python plot_entropies.py --csv     entropies.csv \
                         --outdir  plots
"""
# --------------------------------------------------------------------
import argparse, os
import pandas as pd
import matplotlib.pyplot as plt

SERIES_ORDER = [("ports",  "",  "count"),
                ("ports",  "",  "bytes"),
                ("saddr",  3,   "count"),
                ("saddr",  3,   "bytes"),
                ("daddr",  3,   "count"),
                ("daddr",  3,   "bytes")]
# --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv',     required=True, help='entropies.csv')
    ap.add_argument('--outdir',  default='plots', help='output directory')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    df = pd.read_csv(args.csv, parse_dates=['window_start'])
    # There are three window lengths (300,600,900).  Iterate over them.
    for wl, group in df.groupby('window_length'):
        # build a pivot for cleaner filtering
        for etype, k, metric in SERIES_ORDER:
            mask = (group['entropy_type'] == etype)      & \
                   (group['metric']       == metric)     & \
                   (group['k'].fillna('').astype(str) == ('' if k == "" else str(k)))

            g = group.loc[mask].sort_values('window_start')
            if g.empty:
                continue

            plt.figure()
            plt.plot(g['window_start'], g['value'])
            title = f"{etype}-{metric}"
            if k != "":            # saddr/daddr include k
                title = f"{etype}(k={k})-{metric}"
            plt.title(f"{title}  –  window {wl//60} min")
            plt.xlabel("Time (UTC)")
            plt.ylabel("Shannon entropy (bits)")
            plt.tight_layout()

            fname = f"{title}_win{wl}s.png".replace('(', '').replace(')', '')
            plt.savefig(os.path.join(args.outdir, fname))
            plt.close()
            print(f"✓ {fname}")

if __name__ == '__main__':
    main()

