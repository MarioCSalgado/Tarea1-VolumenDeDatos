#!/usr/bin/env bash
# Reproduce todos los experimentos de la Tarea 1.
#
#   PCAP=datos/201812031400.pcap INTEGRANTES="..." bash run_all.sh
#   MODE=synth bash run_all.sh            # traza sintetica (solo para probar el codigo)
#
# Variables: PCAP, DDOS_PPS, SCAN_PPS, ATK_SEED, WIDTHS, SEEDS, D, START, DUR, TRACE_URL
#
# Codigo:   datos/ (herramientas del curso), actividad1/ (sketches + ventana + validacion),
#           actividad2/ (deteccion de ataques), comun/ (utilidades)
# Salidas:  actividad1/resultados, actividad2/resultados, actividad2/figuras.
#           data/ y trabajo/ son temporales (no van al repositorio).
set -euo pipefail
cd "$(dirname "$0")"

MODE=${MODE:-real}
TOOLS=datos
TRACE_URL=${TRACE_URL:-https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz}
WIDTHS=${WIDTHS:-"256 1024 4096"}
SEEDS=${SEEDS:-"1 2 3"}
D=${D:-5}
START=${START:-300}
DUR=${DUR:-30}
ATK_SEED=${ATK_SEED:-7}
NTOP=${NTOP:-20}
NRAND=${NRAND:-80}
if [ "$MODE" = synth ]; then
  DDOS_PPS=${DDOS_PPS:-400}; SCAN_PPS=${SCAN_PPS:-300}; LABEL=${LABEL:-"traza sintética"}
else
  DDOS_PPS=${DDOS_PPS:-10000}; SCAN_PPS=${SCAN_PPS:-8000}; LABEL=${LABEL:-"MAWI 2018-12-03 14:00"}
fi
W=trabajo            # resultados intermedios
mkdir -p data $W/figs
echo "== compilando"
make -C datos >/dev/null
make -C actividad1 >/dev/null
SK=./actividad1/swsketch

# ------------------------------------------------------------------ 1. traza base
if [ ! -f data/traza.bin ]; then
  if [ "$MODE" = synth ]; then
    python3 comun/gen_synth.py base --out data/synth_base.bin --duration 900 --pps 10000 --seed 1
    python3 comun/gen_synth.py pcap --bin data/synth_base.bin --out data/synth.pcap
    PCAP=data/synth.pcap
  else
    if [ -z "${PCAP:-}" ]; then
      for c in datos/201812031400.pcap datos/201812031400.pcap.gz; do [ -f "$c" ] && PCAP=$c && break; done
    fi
    if [ -z "${PCAP:-}" ]; then
      echo "== descargando $TRACE_URL"
      curl -L -C - -o datos/201812031400.pcap.gz "$TRACE_URL"
      PCAP=datos/201812031400.pcap.gz
    fi
  fi
  echo "== pcap2bin $PCAP"
  case "$PCAP" in
    *.gz) zcat "$PCAP" | "$TOOLS/pcap2bin" > data/traza.bin.tmp ;;
    *)    "$TOOLS/pcap2bin" -i "$PCAP" -o data/traza.bin.tmp ;;
  esac
  mv data/traza.bin.tmp data/traza.bin
fi

# ------------------------------------------------------------------ 2. ataques
echo "== inyectando ataques (semilla $ATK_SEED)"
python3 "$TOOLS/inject_attack.py" ddos --base data/traza.bin --out data/traza_ddos.bin --gt $W/gt_ddos.json \
    --start "$START" --duration "$DUR" --pps "$DDOS_PPS" --sources 4000 --seed "$ATK_SEED"
python3 "$TOOLS/inject_attack.py" scan --base data/traza.bin --out data/traza_scan.bin --gt $W/gt_scan.json \
    --start "$START" --duration "$DUR" --pps "$SCAN_PPS" --dst-count 60000 --seed "$ATK_SEED"
VICTIMA=$(python3 -c "import json;print(json.load(open('$W/gt_ddos.json'))['ataque']['victima'])")
ATACANTE=$(python3 -c "import json;print(json.load(open('$W/gt_scan.json'))['ataque']['atacante'])")
echo "   victima DDoS = $VICTIMA ; atacante scan = $ATACANTE"

# ------------------------------------------------------------------ 3. referencia exacta
echo "== exact_hh"
"$TOOLS/exact_hh" data/traza.bin --stats --key dst > $W/stats_dst.txt
"$TOOLS/exact_hh" data/traza.bin --stats --key src > $W/stats_src.txt
"$TOOLS/exact_hh" data/traza_ddos.bin --key dst -W 60 --delta 10 --phi 0.01 \
    --query "$VICTIMA" --out-query $W/exact_ddos.csv --out-windows $W/windows_ddos.csv > /dev/null
"$TOOLS/exact_hh" data/traza_scan.bin --key src -W 60 --delta 10 --phi 0.01 \
    --query "$ATACANTE" --out-query $W/exact_scan.csv > /dev/null
for k in dst src; do
  $SK data/traza.bin --key $k -w 64 --query-top "$NTOP" --query-random "$NRAND" --query-min 50 \
      --query-seed 1 --save-queries "$W/claves_$k.txt" --out /dev/null 2>/dev/null
  QARGS=$(sed 's/^/--query /' "$W/claves_$k.txt" | tr '\n' ' ')
  # shellcheck disable=SC2086
  "$TOOLS/exact_hh" data/traza.bin --key $k -W 60 --delta 10 --phi 0.01 $QARGS \
      --out-query "$W/exact_base_$k.csv" > /dev/null
done

# ------------------------------------------------------------------ 4. sketches
echo "== sketches: w en {$WIDTHS}, semillas {$SEEDS}"
: > $W/swsketch.log
for w in $WIDTHS; do
  for s in $SEEDS; do
    for k in dst src; do
      $SK data/traza.bin --key $k -d "$D" -w "$w" --seed "$s" --query-file "$W/claves_$k.txt" \
          --with-exact --selfcheck --out "$W/base_${k}_w${w}_s${s}.csv" --meta "$W/base_${k}_w${w}_s${s}.json" \
          2>> $W/swsketch.log
    done
    $SK data/traza_ddos.bin --key dst -d "$D" -w "$w" --seed "$s" --query "$VICTIMA" \
        --with-exact --selfcheck --out "$W/ddos_w${w}_s${s}.csv" --meta "$W/ddos_w${w}_s${s}.json" 2>> $W/swsketch.log
    $SK data/traza_scan.bin --key src -d "$D" -w "$w" --seed "$s" --query "$ATACANTE" \
        --with-exact --selfcheck --out "$W/scan_w${w}_s${s}.csv" --meta "$W/scan_w${w}_s${s}.json" 2>> $W/swsketch.log
  done
done
grep -h "autoverificacion" $W/swsketch.log | sort | uniq -c

# ------------------------------------------------------------------ 5. verificacion y analisis
FW=$(echo $WIDTHS | awk '{print $1}'); FS=$(echo $SEEDS | awk '{print $1}')
echo "== autoverificacion N_j contra exact_hh"
{
  for x in base_dst ddos scan; do
    case $x in base_dst) ref=$W/exact_base_dst.csv ;; *) ref=$W/exact_$x.csv ;; esac
    echo "-- $x"
    python3 actividad1/check_n.py "$W/${x}_w${FW}_s${FS}.csv" "$ref" --meta "$W/${x}_w${FW}_s${FS}.json"
  done
} | tee $W/verificacion_Nj.txt
echo "== Actividad 1"
python3 actividad1/validate_act1.py "$W/base_dst_w*_s*.csv" --exact $W/exact_base_dst.csv --out $W/act1_dst
python3 actividad1/validate_act1.py "$W/base_src_w*_s*.csv" --exact $W/exact_base_src.csv --out $W/act1_src
echo "== Actividad 2"
python3 actividad2/attack_analysis.py --attack ddos --gt $W/gt_ddos.json --exact $W/exact_ddos.csv \
    --runs "$W/ddos_w*_s*.csv" --out $W/ddos --figdir $W/figs --label "$LABEL"
python3 actividad2/attack_analysis.py --attack scan --gt $W/gt_scan.json --exact $W/exact_scan.csv \
    --runs "$W/scan_w*_s*.csv" --out $W/scan --figdir $W/figs --label "$LABEL"
python3 actividad2/make_summary.py --act1 $W/act1_dst.csv \
    --attacks $W/ddos_resumen.csv $W/scan_resumen.csv --out $W/tabla_resumen
# ------------------------------------------------------------------ 6. ordenar por actividad
bash organizar.sh "$W"
echo "Listo: actividad1/resultados, actividad2/resultados, actividad2/figuras"