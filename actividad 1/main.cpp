#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "traza.hpp"
#include "ventana.hpp"
#include "sketches.hpp"

// Ventana deslizante con Count-Min Sketch o CountSketch sobre la traza.
// Para cada ventana y cada IP consultada escribe:
//     win,tau_us,N,umbral,key,est,hh
// N es el numero exacto de paquetes de la ventana (anillo de contadores escalares),
// umbral = techo(phi * N) y hh = 1 si est >= umbral (decision de heavy hitter del sketch).
// win, tau_us y N tienen el mismo formato que exact_hh, de modo que se pueden
// cruzar por "win" con la salida de exact_hh --out-query (columna exact_f).
//
// Compilacion:
//   g++ -O2 -std=c++17 -o ventana main.cpp MurmurHash3.cpp
//
// Ejemplo:
//   ./ventana ~/trazas/traza.bin --sketch cms --d 5 --w 1024 --key src
//             --query 203.83.117.211 --query 202.12.82.146 --out cms_w1024.csv

// Muestra las opciones por stderr
static void uso(const char* prog) {
    fprintf(stderr,
            "uso: %s traza.bin [opciones]\n"
            "  --sketch cms|cs     sketch a usar (def. cms)\n"
            "  --d D               filas del sketch (def. 5)\n"
            "  --w W               columnas del sketch (def. 1024)\n"
            "  --key src|dst       clave: IP de origen o de destino (def. src)\n"
            "  --phi F             umbral de heavy hitter (def. 0.01)\n"
            "  --query IP          IP a consultar; puede repetirse\n"
            "  --query-file ARCH   archivo con una IP por linea\n"
            "  --out ARCH          CSV de salida (def. salida estandar)\n",
            prog);
}

// "a.b.c.d" -> entero a<<24 | b<<16 | c<<8 | d (mismo orden que exact_hh)
static bool texto_a_ip(const char* s, uint32_t* ip) {
    unsigned a, b, c, d;
    char extra; // detecta texto sobrante despues de la IP
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

// Entero -> "a.b.c.d", el mismo formato que imprime exact_hh
static std::string ip_a_texto(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof buf, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return buf;
}

// Umbral de heavy hitter T_j = phi * N_j. Igual que exact_hh se usa el techo, porque
// f >= 3.7 sobre enteros equivale a f >= 4, y como minimo 1.
static uint64_t umbral_hh(uint64_t N, double phi) {
    uint64_t t = (uint64_t)std::ceil(phi * (double)N);
    return t == 0 ? 1 : t;
}

// Recorre la traza con la ventana y escribe una linea por (ventana, IP consultada).
template <class Sketch>
static void ejecutar(const char* ruta, const Sketch& prototipo, bool usar_dst, double phi,
                     const std::vector<uint32_t>& consultas, FILE* salida) {
    const uint64_t W = 60000000, p = 10000000;  // 60 s y 10 s en microsegundos
    VentanaDeslizante<Sketch> ventana(W, p, prototipo);

    size_t ventanas = 0;
    // Se llama en cada evaluacion tau_j: estima cada IP consultada sobre el agregado
    auto evaluar = [&](const VentanaDeslizante<Sketch>& v, uint64_t tau) {
        ventanas++;
        uint64_t umbral = umbral_hh(v.N(), phi);  // a partir del N_j exacto del anillo
        for (uint32_t ip : consultas) {
            int64_t est = v.agregado().estimar(ip);  // f_j(x) estimada
            fprintf(salida, "%llu,%llu,%llu,%llu,%s,%lld,%d\n", (unsigned long long)v.indice_ventana(tau),
                    (unsigned long long)tau, (unsigned long long)v.N(), (unsigned long long)umbral,
                    ip_a_texto(ip).c_str(), (long long)est, est >= (int64_t)umbral ? 1 : 0);
        }
    };

    fprintf(salida, "win,tau_us,N,umbral,key,est,hh\n");
    auto inicio = std::chrono::steady_clock::now(); // para medir el tiempo total

    LeerTraza lector(ruta);
    Record r;
    uint64_t ultimo = 0, paquetes = 0;
    while (lector.next(r)) { // cada paquete actualiza su sub-sketch y el agregado
        ventana.push(r.ts_us, usar_dst ? r.dst : r.src, evaluar);
        ultimo = r.ts_us;
        paquetes++;
    }
    ventana.terminar(ultimo, evaluar); // ultima ventana, si corresponde

    double segundos = std::chrono::duration<double>(std::chrono::steady_clock::now() - inicio).count();

    // Resumen por stderr, para no mezclarlo con el CSV
    size_t mem_uno = prototipo.memoria_bytes();
    fprintf(stderr, "d = %d, w = %d\n", prototipo.filas(), prototipo.columnas());
    fprintf(stderr, "paquetes procesados : %llu\n", (unsigned long long)paquetes);
    fprintf(stderr, "ventanas evaluadas  : %zu\n", ventanas);
    fprintf(stderr, "memoria por sketch  : %zu bytes\n", mem_uno);
    // 7 sketches: 6 del anillo + el agregado
    fprintf(stderr, "memoria total (m+1) : %zu bytes (%.2f KB)\n", mem_uno * 7, mem_uno * 7 / 1024.0);
    fprintf(stderr, "tiempo total        : %.2f s\n", segundos);
}

int main(int argc, char** argv) {
    if (argc < 2 || argv[1][0] == '-') {
        uso(argv[0]);
        return 2;
    }

    // Valores por defecto
    std::string sketch = "cms", clave = "src";
    int d = 5, w = 1024;
    double phi = 0.01;
    const char* ruta_salida = nullptr;
    std::vector<uint32_t> consultas; // IPs a consultar

    // Lectura de opciones (argv[1] es la traza)
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto siguiente = [&]() -> const char* { // valor de la opcion actual
            if (i + 1 >= argc) {
                fprintf(stderr, "falta el valor de %s\n", a.c_str());
                exit(2);
            }
            return argv[++i];
        };

        if (a == "--sketch") sketch = siguiente();
        else if (a == "--d") d = atoi(siguiente());
        else if (a == "--w") w = atoi(siguiente());
        else if (a == "--key") clave = siguiente();
        else if (a == "--phi") phi = atof(siguiente());
        else if (a == "--out") ruta_salida = siguiente();
        else if (a == "--query") {
            const char* s = siguiente();
            uint32_t ip;
            if (!texto_a_ip(s, &ip)) {
                fprintf(stderr, "IP invalida: %s\n", s);
                return 2;
            }
            consultas.push_back(ip);
        } else if (a == "--query-file") {
            const char* ruta = siguiente();
            FILE* f = fopen(ruta, "r");
            if (!f) {
                perror(ruta);
                return 2;
            }
            char linea[64];
            while (fgets(linea, sizeof linea, f)) {
                linea[strcspn(linea, "\r\n")] = 0;  // quitar el salto de linea
                if (linea[0] == 0) continue;        // ignorar lineas vacias
                uint32_t ip;
                if (!texto_a_ip(linea, &ip)) {
                    fprintf(stderr, "IP invalida en %s: %s\n", ruta, linea);
                    return 2;
                }
                consultas.push_back(ip);
            }
            fclose(f);
        } else {
            fprintf(stderr, "opcion desconocida: %s\n", a.c_str());
            uso(argv[0]);
            return 2;
        }
    }

    // Validacion de opciones
    if (sketch != "cms" && sketch != "cs") {
        fprintf(stderr, "--sketch debe ser cms o cs\n");
        return 2;
    }
    if (clave != "src" && clave != "dst") {
        fprintf(stderr, "--key debe ser src o dst\n");
        return 2;
    }
    if (!(phi > 0 && phi < 1)) {
        fprintf(stderr, "--phi debe estar en (0, 1)\n");
        return 2;
    }
    if (consultas.empty()) {
        fprintf(stderr, "aviso: no hay IPs para consultar (use --query o --query-file)\n");
    }

    FILE* salida = ruta_salida ? fopen(ruta_salida, "w") : stdout;
    if (!salida) {
        perror(ruta_salida);
        return 1;
    }

    // Misma ventana, solo cambia el tipo de sketch
    bool usar_dst = (clave == "dst");
    if (sketch == "cms") ejecutar(argv[1], CountMin(d, w), usar_dst, phi, consultas, salida);
    else ejecutar(argv[1], CountSketch(d, w), usar_dst, phi, consultas, salida);

    if (salida != stdout) fclose(salida);
    return 0;
}
