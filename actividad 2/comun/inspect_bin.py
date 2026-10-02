#!/usr/bin/env python3
"""Revisa rapidamente si traza.bin calza con el formato de 24 bytes supuesto en swsketch.cpp.

  ./inspect_bin.py data/traza.bin [--ts-hz 1000000]

Que mirar: el tiempo debe crecer y caer en la fecha de la traza (2018-12-03 ~14:00 UTC
para la traza de referencia); las IPs deben verse como IPs reales. Si el tiempo sale
absurdo, probar --ts-double o otro --ts-hz; si las IPs salen "al reves" (p. ej. el
ultimo octeto siempre bajo), usar --ip-swap en swsketch.
"""
import argparse
import datetime as dt

import numpy as np

# Mismo registro de 24 bytes que pcap2bin.cpp / inject_attack.py
REC = np.dtype([("ts", "<u8"), ("src", "<u4"), ("dst", "<u4"), ("sport", "<u2"),
                ("dport", "<u2"), ("len", "<u2"), ("proto", "u1"), ("flags", "u1")])


def ip(x):
    x = int(x)
    return f"{x >> 24}.{(x >> 16) & 255}.{(x >> 8) & 255}.{x & 255}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--ts-hz", type=float, default=1e6)
    ap.add_argument("-n", type=int, default=8)
    a = ap.parse_args()
    r = np.fromfile(a.trace, dtype=REC)
    print(f"{len(r)} registros")
    as_double = r["ts"][: a.n].view("<f8")
    for k in range(a.n):
        t = r["ts"][k] / a.ts_hz
        try:
            when = dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat()
        except (OverflowError, ValueError, OSError):
            when = "fuera de rango"
        print(f"ts={int(r['ts'][k])} ({when}) | como double: {as_double[k]:.6f} | "
              f"src={ip(r['src'][k])} dst={ip(r['dst'][k])} sport={r['sport'][k]} dport={r['dport'][k]} "
              f"proto={r['proto'][k]} flags={r['flags'][k]} len={r['len'][k]}")
    ts = r["ts"].astype(np.int64)
    print(f"monotono: {(np.diff(ts) >= 0).mean() * 100:.3f}% de pares en orden; "
          f"duracion = {(ts[-1] - ts[0]) / a.ts_hz:.1f} s (con --ts-hz {a.ts_hz:g})")
    print(f"flags distintos de 0: {(r['flags'] != 0).sum()} paquetes")


if __name__ == "__main__":
    main()
