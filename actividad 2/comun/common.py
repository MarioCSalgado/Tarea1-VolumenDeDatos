"""Utilidades compartidas: lectura de CSV de swsketch, de la referencia exacta y del JSON."""
import json
import re

import numpy as np
import pandas as pd

# Paleta (validada, fondo claro). Anchos de w: una rampa azul, de claro (w chico) a oscuro.
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASE = "#c3c2b7"
W_COLORS = {256: "#86b6ef", 1024: "#2a78d6", 4096: "#104281"}
CS_COLOR = "#2a78d6"     # slot 1
CMSMED_COLOR = "#eb6834"  # slot 2


def style_axes(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(BASE)
    ax.tick_params(colors=INK2, labelsize=8)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def load_gt(path, start=None, duration=None):
    """Devuelve (clave, inicio_rel_s, duracion_s, dict) desde el JSON de inject_attack.py.

    El JSON real trae ataque.victima (ddos) o ataque.atacante (scan). El nombre del
    campo de inicio/duracion puede variar: se buscan varios y se pueden forzar con
    --start / --duration (segundos relativos a t0).
    """
    with open(path) as f:
        gt = json.load(f)
    at = gt.get("ataque", gt)
    key = at.get("victima") or at.get("atacante")
    if key is None:
        raise SystemExit(f"{path}: no encuentro ataque.victima ni ataque.atacante")
    if (start is None or duration is None) and "ventana_ataque_rel_s" in gt:
        a0, a1 = gt["ventana_ataque_rel_s"]
        start = float(a0) if start is None else start
        duration = float(a1) - float(a0) if duration is None else duration
    if start is None:
        for k in ("inicio_rel_s", "start", "inicio", "start_s", "t_start"):
            if k in at:
                start = float(at[k])
                break
    if duration is None:
        for k in ("duracion_s", "duration", "duracion", "duration_s"):
            if k in at:
                duration = float(at[k])
                break
    if start is None or duration is None:
        raise SystemExit(f"{path}: no encuentro inicio/duracion; use --start y --duration")
    return key, start, duration, gt


_ALIASES = {
    "tau_rel": ["tau_rel", "t_rel_s", "tau", "t", "time", "ventana_fin", "window_end", "end"],
    "N": ["N", "n", "total", "n_total", "packets"],
    "f": ["exact_f", "f", "freq", "f_exact", "exact", "count", "frecuencia", "fj"],
    "delta": ["exact_delta", "delta", "df", "delta_f", "dfreq", "cambio"],
    "hh": ["exact_hh", "hh", "heavy", "is_hh", "hh_exact"],
    "T": ["threshold", "T", "umbral"],
    "key": ["key", "clave", "ip"],
    "j": ["win", "j", "window", "ventana", "idx"],
}


def load_exact(path, t0_s=None, W=60, p=10):
    """Lee la referencia exacta (exact_hh --out-query o exact_ref.py).

    Normaliza columnas a j, tau_rel, N, f, delta (y hh si existe). Si el tiempo viene
    absoluto (epoch), se pasa a relativo con t0_s; si no hay columna de tiempo, se
    asume que las filas son tau_0, tau_1, ... (tau_j = W + j p).
    """
    df = pd.read_csv(path)
    low = {c.lower().strip(): c for c in df.columns}
    out = pd.DataFrame()
    for std, names in _ALIASES.items():
        for n in names:
            if n.lower() in low:
                out[std] = df[low[n.lower()]]
                break
    if "N" not in out or "f" not in out:
        raise SystemExit(f"{path}: columnas no reconocidas {list(df.columns)}; ajuste _ALIASES en common.py")
    if "tau_rel" in out:
        tau = out["tau_rel"].astype(float)
        if tau.median() > 1e6:          # epoch en segundos
            if t0_s is None:
                raise SystemExit("tiempo absoluto en la referencia: se necesita t0 (meta.json de swsketch)")
            tau = tau - t0_s
        out["tau_rel"] = np.round(tau, 3)
    else:
        out["tau_rel"] = W + p * np.arange(len(out))
    if "j" not in out:
        out["j"] = np.round((out["tau_rel"] - W) / p).astype(int)
    if "delta" not in out:
        out["delta"] = np.nan
    # exact_hh deja vacio el delta de la primera ventana: se toma f_0 - 0
    if "key" in out and out["key"].nunique() > 1:      # varias claves: delta por clave
        out["delta"] = out["delta"].fillna(out.groupby("key")["f"].diff()).fillna(out["f"])
    else:
        out["delta"] = out["delta"].fillna(out["f"].diff()).fillna(out["f"])
    return out


def load_meta(path):
    with open(path) as f:
        return json.load(f)


def runs_from_glob(paths):
    """Agrupa CSV de swsketch por (w, seed) usando el nombre *_w<W>_s<SEED>.csv."""
    runs = {}
    for p in paths:
        m = re.search(r"_w(\d+)_s(\d+)\.csv$", p)
        if not m:
            continue
        runs[(int(m.group(1)), int(m.group(2)))] = pd.read_csv(p)
    return runs
