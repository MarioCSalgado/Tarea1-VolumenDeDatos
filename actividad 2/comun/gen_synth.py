#!/usr/bin/env python3
"""Traza sintetica para PROBAR el codigo sin la traza MAWI.

Imita el formato de 24 bytes supuesto en swsketch.cpp y la interfaz de
inject_attack.py (ddos / scan). NO reemplaza a la traza real en el informe.

  ./gen_synth.py base --out base.bin --duration 900 --pps 10000 --seed 1
  ./gen_synth.py ddos --base base.bin --out ddos.bin --gt gt_ddos.json \
        --start 300 --duration 30 --pps 400 --sources 4000 --seed 7
  ./gen_synth.py scan --base base.bin --out scan.bin --gt gt_scan.json \
        --start 300 --duration 30 --pps 300 --dst-count 60000 --seed 7
"""
import argparse
import json

import numpy as np

# Mismo registro de 24 bytes que pcap2bin.cpp / inject_attack.py
REC = np.dtype([("ts", "<u8"), ("src", "<u4"), ("dst", "<u4"), ("sport", "<u2"),
                ("dport", "<u2"), ("len", "<u2"), ("proto", "u1"), ("flags", "u1")])
assert REC.itemsize == 24

TS_HZ = 1_000_000
T0 = 1543845600 * TS_HZ + 123_457          # 2018-12-03 14:00:00.123457 UTC (no alineado)


def ip_str(x):
    x = int(x)
    return f"{x >> 24}.{(x >> 16) & 255}.{(x >> 8) & 255}.{x & 255}"


def zipf_ranks(rng, n_items, s, size):
    p = np.arange(1, n_items + 1, dtype=np.float64) ** (-s)
    cdf = np.cumsum(p)
    cdf /= cdf[-1]
    return np.searchsorted(cdf, rng.random(size), side="right")


def random_ips(rng, n):
    # IPs publicas "razonables" (evita 0.x, 10.x, 127.x, >= 224.x)
    ips = rng.integers(0x0B000000, 0xDF000000, size=n, dtype=np.uint64).astype(np.uint32)
    return ips


def cmd_base(a):
    rng = np.random.default_rng(a.seed)
    n_target = int(a.pps * a.duration)
    # tasa variable (1 +/- 0.15) para que N_j cambie entre ventanas
    cand = rng.uniform(0, a.duration, size=int(n_target * 1.25))
    rate = 1.0 + 0.15 * np.sin(2 * np.pi * cand / 300.0) + 0.05 * np.sin(2 * np.pi * cand / 47.0)
    keep = rng.random(cand.size) < rate / 1.2
    t = np.sort(cand[keep])
    t[0] = 0.0                                          # el primer paquete define t0
    n = t.size
    src_pool = random_ips(rng, a.n_src)
    dst_pool = random_ips(rng, a.n_dst)
    rec = np.zeros(n, dtype=REC)
    rec["ts"] = T0 + np.round(t * TS_HZ).astype(np.uint64)
    rec["src"] = src_pool[zipf_ranks(rng, a.n_src, a.zipf_src, n)]
    rec["dst"] = dst_pool[zipf_ranks(rng, a.n_dst, a.zipf_dst, n)]
    rec["sport"] = rng.integers(1024, 65535, n)
    rec["dport"] = rng.choice(np.array([80, 443, 53, 22, 8080], dtype=np.uint16), n)
    rec["proto"] = rng.choice(np.array([6, 17], dtype=np.uint8), n, p=[0.85, 0.15])
    rec["len"] = rng.integers(40, 1500, n)
    # algunos paquetes exactamente en bordes de subventana, para probar (a, b]
    for k in range(1, int(a.duration // 10)):
        i = np.searchsorted(rec["ts"], T0 + k * 10 * TS_HZ)
        if i < n:
            rec["ts"][i] = T0 + k * 10 * TS_HZ
    rec.tofile(a.out)
    print(f"base: {n} paquetes, {a.duration} s, t0={T0} -> {a.out}")


def inject(a, kind):
    base = np.fromfile(a.base, dtype=REC)
    t0 = int(base["ts"][0])
    rng = np.random.default_rng(a.seed)
    n = int(a.pps * a.duration)
    # paquetes del ataque en (t0 + start, t0 + start + duration]
    off = rng.uniform(0, a.duration, size=n)
    off = np.sort(a.duration - off)                      # en (0, duration]
    atk = np.zeros(n, dtype=REC)
    atk["ts"] = t0 + int(a.start * TS_HZ) + np.maximum(1, np.round(off * TS_HZ)).astype(np.uint64)
    atk["sport"] = rng.integers(1024, 65535, n)
    atk["len"] = 60
    atk["proto"] = 6
    existing = set(np.unique(base["dst"]).tolist()) | set(np.unique(base["src"]).tolist())
    def fresh_ip():
        while True:
            x = int(random_ips(rng, 1)[0])
            if x not in existing:
                return x
    if kind == "ddos":
        victim = fresh_ip()
        srcs = random_ips(rng, a.sources)
        atk["src"] = srcs[rng.integers(0, a.sources, n)]
        atk["dst"] = victim
        atk["dport"] = 80
        atk["flags"] = 0x11   # SYN | SINTETICO
        info = {"tipo": "ddos", "victima": ip_str(victim), "fuentes": a.sources}
    else:
        attacker = fresh_ip()
        dsts = random_ips(rng, a.dst_count)
        atk["src"] = attacker
        atk["dst"] = dsts[np.arange(n) % a.dst_count]
        atk["dport"] = rng.integers(1, 1024, n)
        atk["flags"] = 0x11
        info = {"tipo": "scan", "atacante": ip_str(attacker), "destinos": a.dst_count}
    allr = np.concatenate([base, atk])
    allr = allr[np.argsort(allr["ts"], kind="stable")]
    allr.tofile(a.out)
    gt = {"ataque": info, "semilla": a.seed, "traza_base": a.base, "sintetico": True,
          "ventana_ataque_rel_s": [a.start, a.start + a.duration], "paquetes_inyectados": n}
    with open(a.gt, "w") as f:
        json.dump(gt, f, indent=2)
    print(f"{kind}: +{n} paquetes -> {a.out}; gt -> {a.gt}: {info}")


def cmd_pcap(a):
    """Convierte un .bin a pcap clasico (Ethernet + IPv4 + TCP/UDP), para probar pcap2bin."""
    rec = np.fromfile(a.bin, dtype=REC)
    pk = np.dtype([("ts_sec", "<u4"), ("ts_usec", "<u4"), ("caplen", "<u4"), ("wirelen", "<u4"),
                   ("eth_dst", "V6"), ("eth_src", "V6"), ("ethertype", ">u2"),
                   ("ver_ihl", "u1"), ("tos", "u1"), ("tot_len", ">u2"), ("ip_id", ">u2"), ("frag", ">u2"),
                   ("ttl", "u1"), ("proto", "u1"), ("ip_csum", ">u2"), ("src", ">u4"), ("dst", ">u4"),
                   ("sport", ">u2"), ("dport", ">u2"), ("seq", ">u4"), ("ack", ">u4"),
                   ("off", "u1"), ("tflags", "u1"), ("win", ">u2"), ("csum", ">u2"), ("urg", ">u2")])
    assert pk.itemsize == 16 + 54
    with open(a.out, "wb") as f:
        f.write(np.array([0xa1b2c3d4], "<u4").tobytes() + np.array([2, 4], "<u2").tobytes()
                + np.array([0, 0, 65535, 1], "<u4").tobytes())
        for s in range(0, len(rec), 1 << 20):
            r = rec[s:s + (1 << 20)]
            o = np.zeros(len(r), dtype=pk)
            o["ts_sec"] = r["ts"] // TS_HZ
            o["ts_usec"] = r["ts"] % TS_HZ
            o["caplen"] = 54
            o["wirelen"] = np.maximum(r["len"], 54)
            o["ethertype"] = 0x0800
            o["ver_ihl"] = 0x45
            o["tot_len"] = o["wirelen"] - 14
            o["ttl"] = 64
            o["proto"] = r["proto"]
            o["src"] = r["src"]
            o["dst"] = r["dst"]
            o["sport"] = r["sport"]
            o["dport"] = r["dport"]
            o["off"] = 0x50
            syn = (r["flags"] & 1) != 0
            o["tflags"] = np.where(syn, 0x02, 0x10)
            f.write(o.tobytes())
    print(f"pcap: {len(rec)} paquetes -> {a.out}")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("pcap")
    c.add_argument("--bin", required=True)
    c.add_argument("--out", required=True)
    b = sp.add_parser("base")
    b.add_argument("--out", required=True)
    b.add_argument("--duration", type=float, default=900)
    b.add_argument("--pps", type=float, default=10000)
    b.add_argument("--n-src", type=int, default=300000)
    b.add_argument("--n-dst", type=int, default=200000)
    b.add_argument("--zipf-src", type=float, default=1.0)
    b.add_argument("--zipf-dst", type=float, default=1.05)
    b.add_argument("--seed", type=int, default=1)
    for k in ("ddos", "scan"):
        c = sp.add_parser(k)
        c.add_argument("--base", required=True)
        c.add_argument("--out", required=True)
        c.add_argument("--gt", required=True)
        c.add_argument("--start", type=float, default=300)
        c.add_argument("--duration", type=float, default=30)
        c.add_argument("--pps", type=float, required=True)
        c.add_argument("--seed", type=int, default=7)
        if k == "ddos":
            c.add_argument("--sources", type=int, default=4000)
        else:
            c.add_argument("--dst-count", type=int, default=60000)
    a = ap.parse_args()
    if a.cmd == "base":
        cmd_base(a)
    elif a.cmd == "pcap":
        cmd_pcap(a)
    else:
        inject(a, a.cmd)


if __name__ == "__main__":
    main()
