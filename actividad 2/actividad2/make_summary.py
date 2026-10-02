#!/usr/bin/env python3
"""Tabla resumen final (error, memoria y latencia) para el informe.

  ./make_summary.py --act1 results/act1_dst.csv --attacks results/ddos_resumen.csv results/scan_resumen.csv \
      --out results/tabla_resumen
"""
import argparse

import numpy as np
import pandas as pd


def fmt_lat(v):
    return "no detecta" if pd.isna(v) else f"{v:.0f} s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--act1", required=True)
    ap.add_argument("--attacks", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    act1 = pd.read_csv(a.act1)
    att = pd.concat([pd.read_csv(p) for p in a.attacks], ignore_index=True)
    rows = []
    for _, r in att.iterrows():
        v = act1[(act1.sketch == r.sketch) & (act1.w == r.w)]
        e1 = v["error rel. medio"].iloc[0] if len(v) else np.nan
        ab = v["error abs. / N (%)"].iloc[0] if len(v) else np.nan
        sd = "" if pd.isna(r["MRE desv."]) else f" ± {r['MRE desv.']:.3f}"
        diff = r["ventanas de diferencia"]
        rel = "igual" if diff == 0 else ("no detecta" if pd.isna(diff) else f"{diff:+.1f} ventanas")
        rows.append({
            "Ataque": r.ataque, "Sketch": r.sketch, "w": int(r.w),
            "Memoria sketch (KB)": f"{r['memoria (KB)']:.0f}",
            "Memoria anillo+A (KB)": f"{7 * r['memoria (KB)']:.0f}",
            "Err. abs./N sin ataque (%)": f"{ab:.3f}",
            "Err. rel. sin ataque": f"{e1:.3f}",
            "MRE ataque": f"{r['MRE media']:.3f}{sd}",
            "Latencia exacta": fmt_lat(r["latencia exacta (s)"]),
            "Latencia sketch": fmt_lat(r["latencia sketch (s)"]),
            "vs. exacto": rel,
            "FP / FN": f"{r['FP en rango']:.1f} / {r['FN en rango']:.1f}",
        })
    t = pd.DataFrame(rows)
    t.to_csv(a.out + ".csv", index=False)
    with open(a.out + ".md", "w") as f:
        f.write(t.to_markdown(index=False) + "\n")
    print(t.to_string(index=False))


if __name__ == "__main__":
    main()
