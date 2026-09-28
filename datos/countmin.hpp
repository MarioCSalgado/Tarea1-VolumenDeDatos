// countmin.hpp
//
// Implementacion de la estructura CountMin (version estandar, sin
// actualizacion conservadora), siguiendo el pseudocodigo de la guia:
//
//   Insertar(x, c=1): incrementa los d contadores mapeados por x
//   Estimar(x):       retorna el minimo de los d contadores mapeados por x
//
// Usa MurmurHash3_x86_32 (archivo MurmurHash3.h / MurmurHash3.cpp, dominio
// publico) parametrizada por semilla para simular las d funciones hash
// independientes, en vez de reimplementar el hash dentro de esta clase.
//
// Requiere compilar tambien MurmurHash3.cpp, por ejemplo:
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

class CountMin {
public:
    // d: numero de filas (funciones hash), w: numero de columnas (contadores por fila)
    CountMin(int d, int w) : d_(d), w_(w) {
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

    // Insertar(x, c): incrementa los d contadores mapeados por x
    void insertar(const std::string& x, long long c = 1) {
        for (int j = 0; j < d_; j++) {
            uint32_t pos = posicion(x, j);
            C_[j][pos] += c;
        }
    }

    // Estimar(x): retorna el minimo de los d contadores mapeados por x
    long long estimar(const std::string& x) const {
        long long freq_est = std::numeric_limits<long long>::max();
        for (int j = 0; j < d_; j++) {
            uint32_t pos = posicion(x, j);
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
    uint32_t posicion(const std::string& x, int j) const {
        uint32_t h;
        MurmurHash3_x86_32(x.data(), static_cast<int>(x.size()), semillas_[j], &h);
        return h % static_cast<uint32_t>(w_);
    }
};