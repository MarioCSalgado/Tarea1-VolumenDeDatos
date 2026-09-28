// countmin_cu.hpp
//
// Implementacion de la estructura CountMin-CU (Conservative Update),
// siguiendo el pseudocodigo de la guia:
//
//   Insertar(x):
//       Paso 1: encontrar el minimo actual entre los d contadores mapeados
//       Paso 2: incrementar solo los contadores que sean iguales a ese minimo
//   Estimar(x): identica a CountMin (minimo de los d contadores mapeados)
//
// La diferencia con CountMin (normal) esta unicamente en Insertar: en vez de
// incrementar los d contadores siempre, solo se incrementan los que ya
// estan en el valor minimo, evitando sobreestimacion innecesaria en los
// contadores que ya estaban mas altos por colisiones de otros elementos.
//
// Usa MurmurHash3_x86_32 (MurmurHash3.h / MurmurHash3.cpp) igual que
// countmin.hpp. Requiere compilar tambien MurmurHash3.cpp:
//   g++ -O2 -std=c++17 tu_programa.cpp MurmurHash3.cpp -o tu_programa

#pragma once


#include <vector>       // Estructura std::vector
#include <string>       // Manejo de std::string
#include <cstdint>      // Tipos de datos (uint32_t, ...)
#include <limits>       // Límite máximo para representar infinito
#include <random>       // Generador aleatorios
#include <algorithm>    // std::min y std::max 
#include <stdexcept>    // Manejo de errores (invalid_argument,...)


#include "MurmurHash3.h"

class CountMinCU {
public:
    // d: numero de filas (funciones hash), w: numero de columnas (contadores por fila)
    CountMinCU(int d, int w) : d_(d), w_(w) {
        if (d_ <= 0 || w_ <= 0) {
            throw std::invalid_argument("d y w deben ser positivos");
        }

        // Matriz de contadores C[1..d][1..w], inicializada en 0
        C_.assign(d_, std::vector<long long>(w_, 0));

        // Generar d semillas distintas para simular d hashes independientes
        semillas_.resize(d_);
        std::mt19937_64 rng(12345); // semilla fija -> reproducibilidad
        std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());
        for (int i = 0; i < d_; i++) {
            semillas_[i] = dist(rng);
        }
    }

    // Insertar(x): actualizacion conservadora
    void insertar(const std::string& x, long long c = 1) {
        // Paso 1: encontrar el minimo actual entre los d contadores mapeados
        std::vector<uint32_t> posiciones(d_);
        long long minimo = std::numeric_limits<long long>::max();

        for (int j = 0; j < d_; j++) {
            posiciones[j] = hash_j(x, j);
            minimo = std::min(minimo, C_[j][posiciones[j]]);
        }

        // Paso 2: incremento conservador
        long long nuevo_minimo = minimo + c;
        for (int j = 0; j < d_; j++) {
            C_[j][posiciones[j]] = std::max(C_[j][posiciones[j]], nuevo_minimo);
        }
    }

    // Estimar(x): identica a CountMin
    long long estimar(const std::string& x) const {
        long long freq_est = std::numeric_limits<long long>::max();
        for (int j = 0; j < d_; j++) {
            uint32_t pos = hash_j(x, j);
            freq_est = std::min(freq_est, C_[j][pos]);
        }
        return freq_est;
    }

    int filas() const { return d_; }
    int columnas() const { return w_; }

private:
    int d_;
    int w_;
    std::vector<std::vector<long long>> C_;
    std::vector<uint32_t> semillas_;

    // Mapea x a una columna [0, w_) en la fila j, usando MurmurHash3_x86_32
    // con la semilla de esa fila
    uint32_t hash_j(const std::string& x, int j) const {
        uint32_t h;
        MurmurHash3_x86_32(x.data(), static_cast<int>(x.size()), semillas_[j], &h);
        return h % static_cast<uint32_t>(w_);
    }
};