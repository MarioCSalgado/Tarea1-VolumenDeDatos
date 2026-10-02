#!/usr/bin/env python3
"""Referencia exacta independiente (numpy), con la misma convencion de ventanas.

Sirve para verificar swsketch cuando no se tiene exact_hh, y como segunda
referencia cuando si se tiene. Salida: j,tau_rel,N,T,f,hh,delta

  ./exact_ref.py traza.bin --key dst --query 1.2.3.4 -W 60 --delta 10 --phi 0.01 --out ref.csv
"""
import argparse

import numpy as np
import pandas as pd

# Mismo registro de 24 bytes que pcap2bin.cpp / inject_attack.py
REC = np.dtype([("ts", "<u8"), ("src", "<u4"), ("dst", "<u4"), ("sport", "<u2"),
                ("dport", "<u2"), ("len", "<u2"), ("proto", "u1"), ("flags", "u1")])


def parse_ip(s):
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--key", choices=["src", "dst"], required=True)
    ap.add_argument("--query", required=True)
    ap.add_argument("-W", type=int, default=60)
    ap.add_argument("--delta", type=int, default=10)
    ap.add_argument("--phi", default="0.01")
    ap.add_argument("--ts-hz", type=int, default=1_000_000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    rec = np.fromfile(a.trace, dtype=REC)
    ts = rec["ts"].astype(np.int64)
    t0 = ts[0]
    P = a.delta * a.ts_hz
    m = a.W // a.delta
    dt = ts - t0
    q = np.where(dt <= 0, 0, (dt + P - 1) // P)          # subventana (t0+(q-1)p, t0+qp]; ts==t0 -> 0 (fuera)
    qmax = int(dt[-1] // P)                                # ultima tau_j <= ultimo paquete
    q = np.minimum(q, qmax + 1)
    nsub = np.bincount(q, minlength=qmax + 2)
    key = rec[a.key]
    fsub = np.bincount(q[key == np.uint32(parse_ip(a.query))], minlength=qmax + 2)
    nsub[0] = fsub[0] = 0
    cN, cF = np.cumsum(nsub), np.cumsum(fsub)
    qt = np.arange(m, qmax + 1)                            # q_tau de cada evaluacion
    N = cN[qt] - cN[qt - m]
    F = cF[qt] - cF[qt - m]
    T = np.maximum(1, np.ceil(float(a.phi) * N.astype(np.float64)).astype(np.int64))   # igual que exact_hh
    delta = np.diff(np.concatenate([[0], F]))
    df = pd.DataFrame({"j": qt - m, "tau_rel": qt * a.delta, "N": N, "T": T, "f": F,
                       "hh": (F >= T).astype(int), "delta": delta})
    df.to_csv(a.out, index=False)
    print(f"exact_ref: {len(df)} ventanas, max f={F.max()} -> {a.out}")


if __name__ == "__main__":
    main()
