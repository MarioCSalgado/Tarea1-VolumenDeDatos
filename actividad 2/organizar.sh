#!/usr/bin/env bash
# Copia los resultados de una corrida a las carpetas de cada actividad.
#
#   bash organizar.sh trabajo            # lo usa run_all.sh al final
#   bash organizar.sh ../real/results    # resultados de una corrida hecha con la version anterior
#
# Busca los archivos en ORIGEN, en ORIGEN/figs, en ORIGEN/../figs y en ORIGEN/../data.
set -euo pipefail
cd "$(dirname "$0")"
O=${1:?uso: bash organizar.sh CARPETA_CON_RESULTADOS}
A1=actividad1/resultados
A2=actividad2/resultados
F2=actividad2/figuras
mkdir -p "$A1/corridas" "$A2/corridas" "$F2"

copy() {  # copy DESTINO archivos...
  local dest=$1; shift
  for f in "$@"; do [ -e "$f" ] && cp -f "$f" "$dest/"; done
  return 0
}

shopt -s nullglob
# ---- Actividad 1: validacion sin ataques, verificacion del anillo, caracterizacion de la traza
copy "$A1" "$O"/act1_* "$O"/stats_*.txt "$O"/claves_*.txt "$O"/exact_base_*.csv "$O"/verificacion_Nj.txt
copy "$A1/corridas" "$O"/base_*_w*_s*.csv "$O"/base_*_w*_s*.json
# ---- Actividad 2: deteccion, MRE, latencia, delta f, tabla resumen
copy "$A2" "$O"/ddos_resumen.* "$O"/scan_resumen.* "$O"/ddos_por_semilla.csv "$O"/scan_por_semilla.csv \
     "$O"/*_error_por_ventana.csv "$O"/*_delta_*.csv "$O"/*_delta_*.md "$O"/tabla_resumen.* \
     "$O"/exact_ddos.csv "$O"/exact_scan.csv "$O"/windows_ddos.csv "$O"/gt_*.json "$O"/../data/gt_*.json
copy "$A2/corridas" "$O"/ddos_w*_s*.csv "$O"/ddos_w*_s*.json "$O"/scan_w*_s*.csv "$O"/scan_w*_s*.json
copy "$F2" "$O"/figs/*.png "$O"/../figs/*.png
# ---- registro de la corrida, si existe
for log in "$O"/swsketch.log "$O"/../real.log "$O"/../prueba.log; do
  [ -e "$log" ] && cp -f "$log" "$A1/" || true
done
echo "resultados ordenados en $A1, $A2 y $F2"
