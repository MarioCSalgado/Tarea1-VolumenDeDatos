#!/usr/bin/env python3
"""Actividad 1: error y memoria de CMS y CountSketch frente al conteo exacto.

Lee los CSV generados por experimentos.sh en resultados/ y produce:
  - resultados/resumen.csv   una fila por (sketch, w) con error, memoria y decisiones HH
  - resultados/por_ip.csv    error relativo medio por IP y configuracion
  - resultados/tablas.md     las mismas tablas en Markdown, listas para el informe

Uso:
    python3 analisis.py [carpeta_resultados]

Solo usa la libreria estandar de Python.
"""

import csv
import os
import sys

D = 5
ANCHOS = [256, 1024, 4096]
SKETCHES = ["cms", "cs"]
NOMBRE = {"cms": "CMS", "cs": "CS"}
M = 6  # subventanas en el anillo; con el agregado son M + 1 sketches
BYTES_CONTADOR = 4  # int32_t


def leer_exacto(ruta):
    """(win, ip) -> (N, umbral, f_exacta, hh_exacto), desde exact_hh --out-query."""
    exacto = {}
    with open(ruta, newline="") as f:
        for fila in csv.DictReader(f):
            clave = (int(fila["win"]), fila["key"])
            exacto[clave] = (int(fila["N"]), int(fila["threshold"]), int(fila["exact_f"]),
                             fila["exact_hh"] == "1")
    return exacto


def leer_sketch(ruta):
    """(win, ip) -> (N, umbral, f_estimada, hh_sketch), desde ventana --out.

    N y el umbral los calcula el propio programa con su anillo de contadores escalares.
    """
    est = {}
    with open(ruta, newline="") as f:
        for fila in csv.DictReader(f):
            est[(int(fila["win"]), fila["key"])] = (int(fila["N"]), int(fila["umbral"]),
                                                    int(fila["est"]), fila["hh"] == "1")
    return est


def analizar(exacto, est):
    """Compara estimaciones con el valor exacto para todas las (ventana, IP)."""
    if set(exacto) != set(est):
        raise SystemExit("las ventanas o IPs del sketch no coinciden con exact_hh")

    abs_err, rel_err = [], []
    sub = fp = fn = hh_exactos = 0
    por_ip = {}
    for clave, (n_ex, umbral_ex, f, hh_ex) in exacto.items():
        n_sk, umbral_sk, f_est, hh_sk = est[clave]
        # El N_j y el umbral del anillo deben coincidir con los de exact_hh
        if n_sk != n_ex:
            raise SystemExit(f"N distinto en ventana {clave[0]}: {n_sk} vs {n_ex}")
        if umbral_sk != umbral_ex:
            raise SystemExit(f"umbral distinto en ventana {clave[0]}: {umbral_sk} vs {umbral_ex}")

        e = abs(f_est - f)
        abs_err.append(e)
        if f > 0:
            r = e / f
            rel_err.append(r)
            por_ip.setdefault(clave[1], []).append(r)
        if f_est < f:
            sub += 1

        # Decision de heavy hitter del sketch (umbral calculado con su propio N_j)
        # frente a la decision exacta de exact_hh
        hh_exactos += hh_ex
        fp += hh_sk and not hh_ex
        fn += hh_ex and not hh_sk

    n = len(abs_err)
    return {
        "consultas": n,
        "err_abs_medio": sum(abs_err) / n,
        "err_abs_max": max(abs_err),
        "err_rel_medio": sum(rel_err) / len(rel_err),
        "err_rel_max": max(rel_err),
        "subestimaciones": sub,
        "hh_exactos": hh_exactos,
        "falsos_pos": fp,
        "falsos_neg": fn,
        "rel_por_ip": {ip: sum(v) / len(v) for ip, v in por_ip.items()},
    }


def main():
    carpeta = sys.argv[1] if len(sys.argv) > 1 else "resultados"
    exacto = leer_exacto(os.path.join(carpeta, "exacto.csv"))

    # Frecuencia exacta media por IP, para ordenar la tabla por IP
    suma, cuenta = {}, {}
    for (_, ip), (_, _, f, _) in exacto.items():
        suma[ip] = suma.get(ip, 0) + f
        cuenta[ip] = cuenta.get(ip, 0) + 1
    f_media = {ip: suma[ip] / cuenta[ip] for ip in suma}
    ips = sorted(f_media, key=f_media.get, reverse=True)

    filas = []
    for sk in SKETCHES:
        for w in ANCHOS:
            r = analizar(exacto, leer_sketch(os.path.join(carpeta, f"{sk}_w{w}.csv")))
            r["sketch"], r["w"] = sk, w
            r["mem_bytes"] = (M + 1) * D * w * BYTES_CONTADOR
            filas.append(r)

    # ---------------------------------------------------------------- resumen.csv
    campos = ["sketch", "d", "w", "mem_bytes", "consultas", "err_abs_medio", "err_abs_max",
              "err_rel_medio", "err_rel_max", "subestimaciones", "hh_exactos", "falsos_pos",
              "falsos_neg"]
    with open(os.path.join(carpeta, "resumen.csv"), "w", newline="") as f:
        out = csv.writer(f)
        out.writerow(campos)
        for r in filas:
            out.writerow([NOMBRE[r["sketch"]], D, r["w"], r["mem_bytes"], r["consultas"],
                          f"{r['err_abs_medio']:.1f}", r["err_abs_max"],
                          f"{r['err_rel_medio']:.6f}", f"{r['err_rel_max']:.6f}",
                          r["subestimaciones"], r["hh_exactos"], r["falsos_pos"], r["falsos_neg"]])

    # ----------------------------------------------------------------- por_ip.csv
    with open(os.path.join(carpeta, "por_ip.csv"), "w", newline="") as f:
        out = csv.writer(f)
        out.writerow(["ip", "f_media"] + [f"{NOMBRE[r['sketch']]}_w{r['w']}" for r in filas])
        for ip in ips:
            out.writerow([ip, f"{f_media[ip]:.0f}"] + [f"{r['rel_por_ip'][ip]:.6f}" for r in filas])

    # ----------------------------------------------------------------- tablas.md
    lineas = []
    lineas.append(f"## Error y memoria (d = {D}, {filas[0]['consultas']} consultas = "
                  f"{len(ips)} IPs x {filas[0]['consultas'] // len(ips)} ventanas)\n")
    lineas.append("| Sketch | w | Memoria (7 sketches) | Error abs. medio | Error abs. max | "
                  "Error rel. medio | Error rel. max | Subestima | HH FP | HH FN |")
    lineas.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in filas:
        lineas.append(
            f"| {NOMBRE[r['sketch']]} | {r['w']} | {r['mem_bytes'] / 1024:.0f} KB | "
            f"{r['err_abs_medio']:,.0f} | {r['err_abs_max']:,} | {100 * r['err_rel_medio']:.2f} % | "
            f"{100 * r['err_rel_max']:.1f} % | {r['subestimaciones']} | {r['falsos_pos']} | "
            f"{r['falsos_neg']} |")
    lineas.append(f"\nHH: decision de heavy hitter del sketch (f_est >= techo(0,01 N_j), con N_j del "
                  f"anillo) comparada con la de exact_hh; hay {filas[0]['hh_exactos']} pares "
                  f"(ventana, IP) que son HH exactos.\n")

    lineas.append("## Error relativo medio por IP\n")
    lineas.append("| IP | f media | " + " | ".join(
        f"{NOMBRE[r['sketch']]} w={r['w']}" for r in filas) + " |")
    lineas.append("|---|---|" + "---|" * len(filas))
    for ip in ips:
        lineas.append(f"| {ip} | {f_media[ip]:,.0f} | " + " | ".join(
            f"{100 * r['rel_por_ip'][ip]:.2f} %" for r in filas) + " |")

    texto = "\n".join(lineas) + "\n"
    with open(os.path.join(carpeta, "tablas.md"), "w") as f:
        f.write(texto)
    print(texto)


if __name__ == "__main__":
    main()
