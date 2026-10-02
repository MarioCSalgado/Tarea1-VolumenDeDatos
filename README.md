# Tarea 1 - Tópico en el Manejo de Grandes Volúmenes de Datos

**Universidad de Concepción — 2026-2**

## Integrantes

- Franco Ponce Chacana
- Mario Salgado Orellana

## Datos

- Traza: https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz (no se sube al repositorio)
- Semilla de los ataques: **7**
- Ataques: `--start 300 --duration 30 --pps 4000` (DDoS con `--sources 4000`, scan con `--dst-count 60000`)
- Sketches: d = 5, w ∈ {256, 1024, 4096}, φ = 0,01

## Estructura

- `actividad 1/`: ventana deslizante con CMS y CS, y validación contra `exact_hh` en la traza sin ataques.
- `actividad 2/`: detección de DDoS y scan, Δf con CountSketch y CMS-mediana, figuras (`actividad2/figuras/`) y tabla resumen (`actividad2/resultados/tabla_resumen.md`).

## Reproducir

```bash
cd "actividad 1" && ./experimentos.sh ruta/a/traza.bin && python3 analisis.py
cd "actividad 2" && DDOS_PPS=4000 SCAN_PPS=4000 bash run_all.sh
```