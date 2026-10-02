#!/usr/bin/env python3
"""Actividad 1: error absoluto y relativo de CMS y CS en la traza sin ataques + memoria.

Usa las salidas de swsketch corridas con --with-exact y varias claves
(--query-top / --query-random). Cada archivo: <prefijo>_w<W>_s<SEED>.csv (+ .json).

  ./validate_act1.py results/base_w*_s*.csv --out results/act1
"""
import argparse
import glob
import os

import numpy as np
import pandas as pd

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "comun"))
from common import load_exact, load_meta, runs_from_glob


def band(row):
    if row.f_exact >= row["T"]:
        return "f >= T (heavy hitter)"
    if row.f_exact >= 0.1 * row["T"]:
        return "0,1T <= f < T"
    return "f < 0,1T"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--out", default="results/act1")
    ap.add_argument("--exact", help="CSV de exact_hh --out-query con varias --query (referencia oficial)")
    a = ap.parse_args()
    ex = load_exact(a.exact) if a.exact else None
    paths = sorted(set(p for pat in a.csv for p in glob.glob(pat)))
    runs = runs_from_glob(paths)
    rows, band_rows = [], []
    for (w, seed), df in sorted(runs.items()):
        meta_path = [p for p in paths if p.endswith(f"_w{w}_s{seed}.csv")][0][:-4] + ".json"
        meta = load_meta(meta_path) if os.path.exists(meta_path) else {}
        if ex is not None:
            df["tau_rel"] = df.tau_rel.round(3)
            mg = df.merge(ex[["tau_rel", "key", "N", "f"]], on=["tau_rel", "key"], suffixes=("", "_hh"))
            n_bad_n = int((mg.N != mg.N_hh).sum())
            n_bad_f = int((mg.f_exact.notna() & (mg.f_exact != mg.f)).sum())
            print(f"w={w} s={seed}: {len(mg)} pares (clave, ventana) cruzados con exact_hh; "
                  f"N distinto: {n_bad_n}; f exacta propia distinta de exact_hh: {n_bad_f}")
            mg["f_exact"] = mg["f"]                     # la referencia es exact_hh
            df = mg
        df = df[df.f_exact > 0].copy()
        df["band"] = df.apply(band, axis=1)
        for sk, col in (("CMS", "f_cms"), ("CS", "f_cs")):
            err = df[col] - df.f_exact
            rel = err.abs() / df.f_exact
            rec = {
                "sketch": sk, "w": w, "seed": seed,
                "pares (clave, ventana)": len(df),
                "claves": df.key.nunique(),
                "error abs. medio": err.abs().mean(),
                "error abs. mediano": err.abs().median(),
                "error abs. max": err.abs().max(),
                "sesgo medio": err.mean(),
                "error rel. medio": rel.mean(),
                "error rel. mediano": rel.median(),
                "error abs. / N (%)": 100 * (err.abs() / df.N).mean(),
                "subestimaciones (%)": 100 * (err < 0).mean(),
                "memoria sketch (KB)": meta.get("bytes_per_sketch", np.nan) / 1024,
                "memoria anillo+A (KB)": meta.get("bytes_ring_plus_aggregate", np.nan) / 1024,
            }
            if sk == "CMS":
                bound = 2.0 / w * df.N            # epsilon N con epsilon = 2/w
                rec["dentro de cota 2N/w (%)"] = 100 * (err <= bound).mean()
            rows.append(rec)
            for b, g in df.groupby("band"):
                e = (g[col] - g.f_exact)
                band_rows.append({"sketch": sk, "w": w, "seed": seed, "banda": b, "pares": len(g),
                                  "error abs. medio": e.abs().mean(),
                                  "error rel. medio": (e.abs() / g.f_exact).mean()})
    res = pd.DataFrame(rows)
    bands = pd.DataFrame(band_rows)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    res.to_csv(a.out + "_por_semilla.csv", index=False)
    # promedio sobre semillas
    num = [c for c in res.columns if c not in ("sketch", "w", "seed")]
    agg = res.groupby(["sketch", "w"])[num].mean().reset_index()
    agg.to_csv(a.out + ".csv", index=False)
    bagg = bands.groupby(["sketch", "w", "banda"])[["pares", "error abs. medio", "error rel. medio"]].mean().reset_index()
    bagg.to_csv(a.out + "_bandas.csv", index=False)
    cols = ["sketch", "w", "error abs. medio", "error rel. medio", "error rel. mediano", "error abs. / N (%)",
            "sesgo medio", "subestimaciones (%)", "memoria sketch (KB)", "memoria anillo+A (KB)"]
    if "dentro de cota 2N/w (%)" in agg:
        cols.append("dentro de cota 2N/w (%)")
    with open(a.out + ".md", "w") as f:
        f.write(agg[cols].to_markdown(index=False, floatfmt=".3g"))
        f.write("\n\n")
        f.write(bagg.to_markdown(index=False, floatfmt=".3g"))
        f.write("\n")
    print(agg[cols].to_string(index=False, float_format=lambda x: f"{x:.4g}"))
    print()
    print(bagg.to_string(index=False, float_format=lambda x: f"{x:.4g}"))


if __name__ == "__main__":
    main()
