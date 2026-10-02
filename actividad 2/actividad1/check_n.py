#!/usr/bin/env python3
"""Autoverificacion obligatoria: N_j del anillo == columna N de la referencia exacta.

  ./check_n.py results/base_w1024_s1.csv exact_base.csv [--meta results/base_w1024_s1.json]
Sale con codigo 1 si alguna ventana difiere.
"""
import argparse
import sys

import pandas as pd

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "comun"))
from common import load_exact, load_meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sketch_csv")
    ap.add_argument("exact_csv")
    ap.add_argument("--meta")
    a = ap.parse_args()
    s = pd.read_csv(a.sketch_csv).drop_duplicates("j")[["j", "tau_rel", "N", "T"]]
    t0 = None
    if a.meta:
        m = load_meta(a.meta)
        t0 = m["t0_ticks"] / m["ts_hz"]
    e = load_exact(a.exact_csv, t0_s=t0).drop_duplicates("tau_rel")
    s["tau_rel"] = s["tau_rel"].round(3)
    cols = ["tau_rel", "N"] + (["T"] if "T" in e else [])
    mg = s.merge(e[cols], on="tau_rel", how="outer", suffixes=("_ring", "_exact"), indicator=True)
    both = mg[mg["_merge"] == "both"]
    bad = both[both["N_ring"] != both["N_exact"]]
    if "T_exact" in both:
        nbt = int((both["T_ring"] != both["T_exact"]).sum())
        print(f"umbral T distinto en {nbt} ventanas")
    only_s = (mg["_merge"] == "left_only").sum()
    only_e = (mg["_merge"] == "right_only").sum()
    print(f"ventanas comparadas: {len(both)}; distintas: {len(bad)}; solo en sketch: {only_s}; solo en exacta: {only_e}")
    if len(bad):
        print(bad.head(20).to_string(index=False))
        print("ERROR: el anillo esta desalineado; los demas resultados no son validos.")
        sys.exit(1)
    if only_s or only_e:
        print("aviso: distinto numero de ventanas (revisar la ultima subventana: --no-eval-last)")
    print("OK: N_j coincide en todas las ventanas comunes.")


if __name__ == "__main__":
    main()
