# Tarea 1 2026: Count-Min Sketch y CountSketch en ventanas deslizantes

**Tópicos en Grandes Volúmenes de Datos, Universidad de Concepción**
Franco Ponce Chacana y Mario Salgado Orellana

Implementamos Count-Min Sketch (CMS) y CountSketch (CS) sobre una ventana deslizante de 60 s que avanza cada 10 s. La ventana se mantiene por linealidad, con un anillo de 6 sub-sketches y un agregado: `A ← A − S_expira + S_nueva`. La usamos para detectar un DDoS (clave = IP de destino) y un scan (clave = IP de origen) inyectados sobre la traza MAWI, y para estimar el cambio de frecuencia Δf entre ventanas.

## Estructura

| Carpeta | Contenido |
| --- | --- |
| `datos/` | Herramientas del curso: `pcap2bin.cpp`, `exact_hh.cpp`, `inject_attack.py`, `Makefile`. La traza `.pcap` va aquí, pero no se sube al repositorio. |
| `actividad1/` | Implementación (`swsketch.cpp`): CMS, CS, anillo de 6 sub-sketches, agregado A, anillo de N_j y ΔA. También la validación contra `exact_hh` (`validate_act1.py`), la autoverificación de N_j (`check_n.py`) y una referencia exacta independiente (`exact_ref.py`). |
| `actividad1/resultados/` | Error absoluto y relativo, sesgo y memoria en la traza sin ataques (`act1_dst.md`, `act1_src.md`), verificación de N_j, estadísticas de la traza y claves usadas. En `corridas/` está cada corrida. |
| `actividad2/` | Análisis de los ataques (`attack_analysis.py`): MRE, latencia, falsos positivos y negativos, Δf. También la tabla resumen (`make_summary.py`). |
| `actividad2/resultados/` | `ddos_resumen.md`, `scan_resumen.md`, `tabla_resumen.md` (error, memoria y latencia), resúmenes de Δf, error por ventana, referencia exacta y *ground truth* de los ataques. |
| `actividad2/figuras/` | Frecuencia exacta vs. estimada (una figura por ataque, con CMS y CS para los 3 anchos) y Δf exacto vs. CS y CMS-mediana. |
| `comun/` | Utilidades compartidas, generador del informe y de la presentación, e inspector y generador de trazas de prueba. |
| `run_all.sh` | Reproduce todo. |
| `organizar.sh` | Copia los resultados a las carpetas de cada actividad. |

## Reproducir

Requisitos: Linux o WSL, `g++`, `make`, `python3` con `numpy`, `pandas`, `matplotlib` y `tabulate`. Para generar el informe en PDF también hace falta `latexmk`.

```bash
# 1. Bajar la traza a datos/ (unos 10 GB)
curl -L -C - -o datos/201812031400.pcap.gz https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz

# 2. Correr todo
PCAP=datos/201812031400.pcap.gz DDOS_PPS=4000 SCAN_PPS=4000 bash run_all.sh
```

`run_all.sh` hace lo siguiente:
1. Compila las herramientas.
2. Convierte la traza con `pcap2bin`.
3. Inyecta los ataques con `inject_attack.py`.
4. Calcula la referencia exacta con `exact_hh`.
5. Corre los sketches con d = 5, w ∈ {256, 1024, 4096} y semillas de hash 1, 2 y 3.
6. Verifica que N_j coincida con `exact_hh` en todas las ventanas.
7. Deja los resultados en `actividad1/` y `actividad2/`.

Para probar el código sin la traza MAWI hay un modo con traza sintética (unos 2 minutos): `MODE=synth bash run_all.sh`.

**Parámetros usados**

| Parámetro | Valor |
| --- | --- |
| Traza | <https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz> |
| Ataques | `--start 300 --duration 30` |
| DDoS | `--pps 4000 --sources 4000` (`DDOS_PPS=4000`) |
| Scan | `--pps 4000 --dst-count 60000` (`SCAN_PPS=4000`) |
| Semilla de los ataques | 7 |
| Semillas de hash | 1, 2 y 3 |

Con los valores del enunciado (10000 y 8000 paq/s) el ataque supera varias veces el umbral y las curvas de los anchos mayores se superponen con la exacta, así que bajamos la intensidad a 4000 paq/s, como sugiere la sección 2 del enunciado.

## Diseño

**Registro.** Es idéntico al de `pcap2bin.cpp`: 24 B, little-endian (`ts_us`, `src`, `dst`, `sport`, `dport`, `len`, `proto`, `flags`).

**Hashing.** Cada fila usa ((a·x + b) mod (2⁶¹ − 1)) mod w, una familia de Carter–Wegman 2-independiente, con semilla fija. CMS y CS comparten las funciones de posición, así que ven las mismas colisiones. CS agrega funciones de signo independientes. Los 6 sub-sketches y A usan las mismas funciones, por eso se pueden sumar y restar.

**Ventana.**
- La subventana q cubre (t₀ + (q−1)p, t₀ + qp] y va en la ranura (q−1) mod 6.
- Se evalúa en τ_j = t₀ + 60 + 10j.
- Cada paquete actualiza la ranura actual y A.
- Al avanzar, primero se resta la ranura que expira de A y se limpia; después se cargan los paquetes nuevos.
- Hay precarga: τ₀ ya tiene S₁…S₆, cada uno en su ranura.
- Cada avance toca 2dw contadores, sin importar cuántos paquetes tenga la ventana.

Una sola plantilla, `SlidingSketch<Ops>`, sirve para ambos sketches; sólo cambian `update` y `estimate`.

**N_j y umbral.** N_j se lleva con un anillo de 6 contadores escalares. El umbral es T = ⌈φN⌉, calculado igual que en `exact_hh`.

**ΔA_j = S_entra − S_sale.** Se mantiene en un arreglo D. Al rotar se hace D ← −S_sale antes de limpiar la ranura, y cada paquete nuevo también se suma en D. Sobre D se aplican dos estimadores: la mediana de CS y la variante experimental CMS-mediana.

**Autoverificaciones.**
- A = Σ anillo en cada evaluación.
- D = A_j − A_{j−1}.
- N_j y T_j coinciden con `exact_hh` (`actividad1/resultados/verificacion_Nj.txt`).
- El conteo exacto propio coincide con `exact_hh` en todas las claves de validación.
