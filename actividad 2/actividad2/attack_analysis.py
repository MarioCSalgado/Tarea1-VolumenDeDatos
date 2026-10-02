#!/usr/bin/env python3
"""Actividad 2 y seccion 6.3: deteccion de un ataque con CMS y CS, MRE, latencia,
falsos positivos/negativos y cambio de frecuencia Delta f.

  ./attack_analysis.py --attack ddos --gt gt_ddos.json --exact exact_ddos.csv \
      --runs 'results/ddos_w*_s*.csv' --out results/ddos --figdir figs

Las corridas de swsketch se nombran <prefijo>_w<W>_s<SEED>.csv (con su .json).
La figura usa la semilla mas chica; las tablas promedian sobre semillas.
"""
import argparse
import glob
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter
import numpy as np
import pandas as pd

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "comun"))
from common import (BASE, CMSMED_COLOR, CS_COLOR, GRID, INK, INK2, MUTED, W_COLORS, load_exact, load_gt,
                    load_meta, runs_from_glob, style_axes)

NAMES = {"ddos": ("DDoS", "víctima", "IP de destino", "de la"), "scan": ("Scan", "atacante", "IP de origen", "del")}
thousands = FuncFormatter(lambda v, _: f"{v:,.0f}".replace(",", "."))


def first_detection(df, col, start):
    d = df[(df.tau_rel > start) & (df[col] == 1)]
    return float(d.tau_rel.iloc[0]) if len(d) else np.nan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", choices=["ddos", "scan"], required=True)
    ap.add_argument("--gt", required=True)
    ap.add_argument("--exact", required=True, help="CSV de exact_hh --out-query (o exact_ref.py)")
    ap.add_argument("--runs", required=True, help="glob de CSV de swsketch")
    ap.add_argument("--start", type=float, help="inicio del ataque en s desde t0 (si el JSON no lo trae)")
    ap.add_argument("--duration", type=float)
    ap.add_argument("-W", type=int, default=60)
    ap.add_argument("--delta", type=int, default=10)
    ap.add_argument("--out", required=True)
    ap.add_argument("--figdir", default="figs")
    ap.add_argument("--label", default="", help="texto extra para el titulo (p. ej. 'traza sintética')")
    a = ap.parse_args()
    W, p = a.W, a.delta
    nm, rol, keyname, art = NAMES[a.attack]

    key, start, dur, _ = load_gt(a.gt, a.start, a.duration)
    paths = sorted(glob.glob(a.runs))
    runs = runs_from_glob(paths)
    if not runs:
        raise SystemExit("sin corridas para " + a.runs)
    meta = load_meta(paths[0][:-4] + ".json")
    t0 = meta["t0_ticks"] / meta["ts_hz"]
    ex = load_exact(a.exact, t0_s=t0, W=W, p=p)

    lo, hi = start - W, start + dur + W
    rows, perwin, delta_rows = [], [], []
    merged = {}
    for (w, seed), df in sorted(runs.items()):
        df = df[df.key == key].copy()
        if df.empty:
            raise SystemExit(f"la clave {key} no esta en las corridas (use --query {key})")
        df["tau_rel"] = df.tau_rel.round(3)
        m = df.merge(ex[["tau_rel", "N", "f", "delta"]], on="tau_rel", suffixes=("", "_ex"))
        m["dN"] = m.N.diff().fillna(m.N)            # cambio del trafico total entre ventanas
        if (m.N != m.N_ex).any():
            print(f"AVISO w={w} s={seed}: N distinto a la referencia en {(m.N != m.N_ex).sum()} ventanas")
        m["hh_ex"] = (m.f >= m["T"]).astype(int)
        merged[(w, seed)] = m
        J = m[(m.tau_rel > start) & (m.tau_rel - W < start + dur) & (m.f > 0)]
        t_ex = first_detection(m, "hh_ex", start)
        R = m[(m.tau_rel >= lo) & (m.tau_rel <= hi)]
        for sk, col, hcol in (("CMS", "f_cms", "hh_cms"), ("CS", "f_cs", "hh_cs")):
            rel = (J[col] - J.f).abs() / J.f
            t_sk = first_detection(m, hcol, start)
            pre = m[(m.tau_rel <= start) & (m[hcol] == 1)]
            rows.append({
                "ataque": nm, "sketch": sk, "w": w, "seed": seed,
                "memoria (KB)": meta["bytes_per_sketch"] / meta["w"] * w / 1024,
                "|J|": len(J), "MRE": rel.mean(),
                "latencia exacta (s)": t_ex - start, "latencia sketch (s)": t_sk - start,
                "ventanas de diferencia": (t_sk - t_ex) / p,
                "FP en rango": int(((R[hcol] == 1) & (R.hh_ex == 0)).sum()),
                "FN en rango": int(((R[hcol] == 0) & (R.hh_ex == 1)).sum()),
                "alarmas antes del ataque": len(pre),
            })
            for _, r in J.iterrows():
                perwin.append({"ataque": nm, "sketch": sk, "w": w, "seed": seed, "tau_rel": r.tau_rel,
                               "t_desde_inicio": r.tau_rel - start, "f": r.f, "f_hat": r[col],
                               "T": r["T"], "err_rel": abs(r[col] - r.f) / r.f})
        # Delta f
        D = R.copy()
        inc = D.nlargest(3, "delta")
        dec = D.nsmallest(3, "delta")
        pred = (D.dN - D.delta) / w                   # sesgo teorico de CMS-mediana: (dN - df)/w
        for est, col in (("CS", "df_cs"), ("CMS-mediana", "df_cms_med")):
            e = D[col] - D.delta
            delta_rows.append({
                "ataque": nm, "estimador": est, "w": w, "seed": seed,
                "MAE en rango": e.abs().mean(),
                "sesgo en incrementos": (inc[col] - inc.delta).mean(),
                "sesgo en decrementos": (dec[col] - dec.delta).mean(),
                "error max": e.abs().max(),
                "sesgo medio": e.mean(),
                "sesgo teorico medio (dN-df)/w": pred.mean(),
                "corr(error, (dN-df)/w)": np.corrcoef(e, pred)[0, 1] if e.std() > 0 and pred.std() > 0 else np.nan,
            })

    res = pd.DataFrame(rows)
    pw = pd.DataFrame(perwin)
    dr = pd.DataFrame(delta_rows)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    res.to_csv(a.out + "_por_semilla.csv", index=False)
    pw.to_csv(a.out + "_error_por_ventana.csv", index=False)
    dr.to_csv(a.out + "_delta_por_semilla.csv", index=False)

    agg = res.groupby(["ataque", "sketch", "w"]).agg(
        **{"memoria (KB)": ("memoria (KB)", "first"), "|J|": ("|J|", "first"),
           "MRE media": ("MRE", "mean"), "MRE desv.": ("MRE", "std"),
           "MRE min": ("MRE", "min"), "MRE max": ("MRE", "max"),
           "latencia exacta (s)": ("latencia exacta (s)", "first"),
           "latencia sketch (s)": ("latencia sketch (s)", "mean"),
           "ventanas de diferencia": ("ventanas de diferencia", "mean"),
           "FP en rango": ("FP en rango", "mean"), "FN en rango": ("FN en rango", "mean"),
           "alarmas antes del ataque": ("alarmas antes del ataque", "mean"),
           "semillas": ("seed", "count")}).reset_index()
    agg.to_csv(a.out + "_resumen.csv", index=False)
    dagg = dr.groupby(["ataque", "estimador", "w"])[["MAE en rango", "sesgo medio", "sesgo teorico medio (dN-df)/w",
                                                      "corr(error, (dN-df)/w)", "sesgo en incrementos",
                                                      "sesgo en decrementos", "error max"]].mean().reset_index()
    dagg.to_csv(a.out + "_delta_resumen.csv", index=False)
    with open(a.out + "_resumen.md", "w") as f:
        f.write(agg.to_markdown(index=False, floatfmt=".3g") + "\n\n" + dagg.to_markdown(index=False, floatfmt=".3g") + "\n")
    print(agg.to_string(index=False, float_format=lambda x: f"{x:.4g}"))
    print()
    print(dagg.to_string(index=False, float_format=lambda x: f"{x:.4g}"))

    # ---------------- figuras (semilla principal) ----------------
    os.makedirs(a.figdir, exist_ok=True)
    seed0 = min(s for (_, s) in runs)
    widths = sorted({w for (w, _) in runs})
    title_extra = f" — {a.label}" if a.label else ""

    # Figura 1: frecuencia exacta vs estimada (CMS | CS), 3 anchos por panel
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.9), sharey=True, dpi=200)
    for ax, (sk, col) in zip(axes, (("Count-Min Sketch (mínimo)", "f_cms"), ("CountSketch (mediana)", "f_cs"))):
        style_axes(ax)
        ax.axvspan(0, dur, color="#f0efec", zorder=0)
        any_m = merged[(widths[0], seed0)]
        R = any_m[(any_m.tau_rel >= lo) & (any_m.tau_rel <= hi)]
        x = R.tau_rel - start
        ax.plot(x, R["T"], color=MUTED, lw=1.0, ls=(0, (4, 3)), zorder=2)
        for w in widths:
            m = merged[(w, seed0)]
            Rw = m[(m.tau_rel >= lo) & (m.tau_rel <= hi)]
            ax.plot(Rw.tau_rel - start, Rw[col], color=W_COLORS.get(w, CS_COLOR), lw=1.6, marker="o", ms=3.2,
                    zorder=3)
        ax.plot(x, R.f, color=INK, lw=2.0, marker="o", ms=3.6, zorder=4)
        ax.set_title(sk, fontsize=10, color=INK, loc="left")
        ax.set_xlabel("tiempo desde el inicio del ataque (s), fin de cada ventana de 60 s", fontsize=8, color=INK2)
        ax.yaxis.set_major_formatter(thousands)
        ax.set_xticks(np.arange(-W, dur + W + 1, 20))
        ax.text(dur / 2, ax.get_ylim()[1] * 0.98 if ax.get_ylim()[1] > 0 else 1, "ataque", ha="center", va="top",
                fontsize=7.5, color=INK2)
    axes[0].set_ylabel(f"paquetes en la ventana con {keyname} = {rol}", fontsize=8, color=INK2)
    handles = [Line2D([], [], color=INK, lw=2, marker="o", ms=3.6, label="exacta")]
    handles += [Line2D([], [], color=W_COLORS.get(w, CS_COLOR), lw=1.6, marker="o", ms=3.2, label=f"w = {w}")
                for w in widths]
    handles += [Line2D([], [], color=MUTED, lw=1, ls=(0, (4, 3)), label="umbral T = ⌈0,01·N⌉"),
                Patch(color="#f0efec", label="intervalo del ataque")]
    fig.suptitle(f"{nm}: frecuencia {art} {rol} ({keyname}), d = 5{title_extra}", fontsize=10.5, color=INK,
                 x=0.01, ha="left", y=0.985)
    fig.legend(handles=handles, loc="upper left", ncol=len(handles), frameon=False, fontsize=7.5,
               bbox_to_anchor=(0.005, 0.925), handlelength=2.2, columnspacing=1.4)
    fig.tight_layout(rect=(0, 0, 1, 0.86))
    fig.savefig(os.path.join(a.figdir, f"{a.attack}_frecuencia.png"))
    plt.close(fig)

    # Figura 2: Delta f exacto vs CS vs CMS-mediana (fila 1) y su error (fila 2), un panel por w
    fig, axes = plt.subplots(2, len(widths), figsize=(10, 5.2), dpi=200, sharex=True,
                             gridspec_kw={"height_ratios": [2.2, 1]})
    axes = np.atleast_2d(axes)
    for k, w in enumerate(widths):
        m = merged[(w, seed0)]
        R = m[(m.tau_rel >= lo) & (m.tau_rel <= hi)]
        x = R.tau_rel - start
        ax = axes[0, k]
        style_axes(ax)
        ax.axhline(0, color=BASE, lw=0.8)
        ax.bar(x, R.delta, width=6, color="#d6d5cd", zorder=1)
        ax.plot(x, R.df_cs, color=CS_COLOR, lw=1.5, marker="o", ms=3.5, zorder=3)
        ax.plot(x, R.df_cms_med, color=CMSMED_COLOR, lw=1.5, marker="s", ms=3.2, zorder=3)
        ax.set_title(f"w = {w}", fontsize=9.5, color=INK, loc="left")
        ax.yaxis.set_major_formatter(thousands)
        ax2 = axes[1, k]
        style_axes(ax2)
        ax2.axhline(0, color=BASE, lw=0.8)
        ax2.plot(x, R.df_cs - R.delta, color=CS_COLOR, lw=1.3, marker="o", ms=3)
        ax2.plot(x, R.df_cms_med - R.delta, color=CMSMED_COLOR, lw=1.3, marker="s", ms=2.8)
        ax2.axvspan(0, dur, color="#f0efec", zorder=0)
        ax.axvspan(0, dur, color="#f0efec", zorder=0)
        ax2.set_xticks(np.arange(-W, dur + W + 1, 30))
        ax2.set_xlabel("tiempo desde el inicio (s)", fontsize=8, color=INK2)
        ax2.yaxis.set_major_formatter(thousands)
    axes[0, 0].set_ylabel(r"$\Delta f_j = f_j - f_{j-1}$", fontsize=8, color=INK2)
    axes[1, 0].set_ylabel(r"error $\widehat{\Delta f}_j - \Delta f_j$", fontsize=8, color=INK2)
    handles = [Patch(color="#d6d5cd", label="Δf exacto"),
               Line2D([], [], color=CS_COLOR, lw=1.5, marker="o", ms=3.5, label="CountSketch (mediana con signo)"),
               Line2D([], [], color=CMSMED_COLOR, lw=1.5, marker="s", ms=3.2, label="CMS-mediana (sin signo)"),
               Patch(color="#f0efec", label="intervalo del ataque")]
    fig.suptitle(f"{nm}: cambio de frecuencia entre ventanas consecutivas{title_extra}", fontsize=10.5, color=INK,
                 x=0.01, ha="left", y=0.985)
    fig.legend(handles=handles, loc="upper left", ncol=4, frameon=False, fontsize=7.5, bbox_to_anchor=(0.005, 0.95))
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.savefig(os.path.join(a.figdir, f"{a.attack}_delta.png"))
    plt.close(fig)
    print(f"figuras -> {a.figdir}/{a.attack}_frecuencia.png, {a.figdir}/{a.attack}_delta.png")


if __name__ == "__main__":
    main()
