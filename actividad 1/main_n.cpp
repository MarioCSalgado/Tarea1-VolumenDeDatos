#include <cstdio>
#include <string>
#include "traza.hpp"
#include "ventana.hpp"
// Verificacion del anillo: imprime win,tau_us,N para cada ventana,
// en el mismo formato que las tres primeras columnas de exact_hh --out-windows.
int main(int argc, char** argv) {
    if (argc < 2) {
       // %s se reemplaza por argv[0], el nombre del programa
       // src,dst entre corchetes indica que ese argumento es opcional
        fprintf(stderr, "uso: %s traza.bin [src|dst]\n", argv[0]);//Imprime en stderr con salida de errores
        return 2; //Si no le pasaste la traza, muestra cómo se usa y termina
    }
    bool usar_dst = (argc > 2 && std::string(argv[2]) == "dst"); //Decide qué IP usar como clave
    const uint64_t W = 60000000, p = 10000000;  // 60 s y 10 s en microsegundos
    VentanaDeslizante<SketchNulo> ventana(W, p, SketchNulo()); // sketch vacio: solo cuenta N_j
    // Se llama en cada evaluacion: imprime una linea del CSV por ventana
    auto evaluar = [](const VentanaDeslizante<SketchNulo>& v, uint64_t tau) {
        printf("%llu,%llu,%llu\n", (unsigned long long)v.indice_ventana(tau),
               (unsigned long long)tau, (unsigned long long)v.N());
    };
    printf("win,tau_us,N\n"); // encabezado, igual al de exact_hh
    LeerTraza lector(argv[1]);
    Record r;
    uint64_t ultimo = 0; // hora del ultimo paquete, para terminar()
    while (lector.next(r)) { // recorre todos los paquetes de la traza
        ventana.push(r.ts_us, usar_dst ? r.dst : r.src, evaluar);
        ultimo = r.ts_us;
    }
    ventana.terminar(ultimo, evaluar); // evalua la ultima ventana, si corresponde
    return 0;
}
