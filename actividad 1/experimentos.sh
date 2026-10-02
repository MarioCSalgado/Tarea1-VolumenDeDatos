#!/usr/bin/env bash
# Actividad 1: validacion de CMS y CountSketch contra exact_hh sobre la traza sin ataques.
#
# Uso:
#   ./experimentos.sh [ruta/a/traza.bin]
#
# Por defecto usa ~/trazas/traza.bin. Traza utilizada:
#   https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
#   zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin
#
# Genera en resultados/:
#   exacto.csv            frecuencia exacta de cada IP de ips.txt por ventana (exact_hh)
#   ventanas_exacto.csv   N exacto por ventana (exact_hh)
#   n_anillo.csv          N del anillo (main_n), para la verificacion de alineacion
#   {cms,cs}_w{W}.csv     estimaciones de cada sketch con d=5 y ancho W
#   {cms,cs}_w{W}.log     resumen de memoria y tiempo de cada ejecucion
set -euo pipefail
cd "$(dirname "$0")"

TRAZA="${1:-$HOME/trazas/traza.bin}"
D=5
ANCHOS="256 1024 4096"
SALIDA=resultados

if [ ! -f "$TRAZA" ]; then
    echo "no se encontro la traza: $TRAZA" >&2
    exit 1
fi
mkdir -p "$SALIDA"

echo "== compilando"
make -s pcap2bin exact_hh
g++ -O2 -std=c++17 -Wall -Wextra -o main_n main_n.cpp
g++ -O2 -std=c++17 -Wall -Wextra -c main.cpp -o main.o
g++ -O2 -std=c++17 -c MurmurHash3.cpp -o MurmurHash3.o
g++ main.o MurmurHash3.o -o ventana

echo "== verificacion de N_j (anillo vs exact_hh)"
./main_n "$TRAZA" > "$SALIDA/n_anillo.csv"
./exact_hh "$TRAZA" --key src -W 60 --delta 10 --phi 0.01 \
    --out-windows "$SALIDA/ventanas_exacto.csv" > /dev/null
if diff <(cut -d, -f1-3 "$SALIDA/ventanas_exacto.csv") "$SALIDA/n_anillo.csv" > /dev/null; then
    echo "   N_j IDENTICO en todas las ventanas"
else
    echo "   ERROR: N_j distinto, el anillo esta desalineado" >&2
    exit 1
fi

echo "== frecuencias exactas de las IPs de ips.txt"
QUERIES=""
while read -r ip; do
    [ -n "$ip" ] && QUERIES="$QUERIES --query $ip"
done < ips.txt
# shellcheck disable=SC2086
./exact_hh "$TRAZA" --key src -W 60 --delta 10 --phi 0.01 $QUERIES \
    --out-query "$SALIDA/exacto.csv" > /dev/null

for sk in cms cs; do
    for w in $ANCHOS; do
        echo "== $sk  d=$D  w=$w"
        ./ventana "$TRAZA" --sketch "$sk" --d "$D" --w "$w" --key src \
            --query-file ips.txt --out "$SALIDA/${sk}_w${w}.csv" 2> "$SALIDA/${sk}_w${w}.log"
        grep "tiempo total" "$SALIDA/${sk}_w${w}.log"
    done
done

echo "== listo. Analisis: python3 analisis.py"
