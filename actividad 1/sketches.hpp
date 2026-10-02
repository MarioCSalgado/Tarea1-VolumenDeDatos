#pragma once
#include <algorithm>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <vector>
#include "MurmurHash3.h"

// Count-Min Sketch y CountSketch 
//
// Ambos comparten la misma tabla C de d x w contadores y las mismas operaciones
// lineales (add, sub, clear), que son las que usa VentanaDeslizante.
// Solo cambian update() y estimar().
//
// Requiere compilar tambien MurmurHash3.cpp:
//   g++ -O2 -std=c++17 main.cpp MurmurHash3.cpp -o ventana

// Parte comun: tabla de contadores, semillas de hash y operaciones lineales.
class SketchLineal {
public:
    SketchLineal(int d_, int w_) : d(d_), w(w_), C((size_t)d_ * w_, 0), semilla_pos(d_), semilla_signo(d_) {
        if (d <= 0 || w <= 0 || d > 64) throw std::invalid_argument("se requiere 0 < d <= 64 y w > 0");
        // Semilla fija: todas las copias (anillo y agregado) usan las mismas funciones hash,
        // y los resultados son reproducibles entre ejecuciones.
        std::mt19937_64 rng(12345);
        for (int j = 0; j < d; j++) {
            semilla_pos[j] = (uint32_t)rng();
            semilla_signo[j] = (uint32_t)rng();
        }
    }

    // Linealidad: el sketch de la union es la suma casilla a casilla.
    void add(const SketchLineal& o) {
        for (size_t i = 0; i < C.size(); i++) C[i] += o.C[i];
    }
    void sub(const SketchLineal& o) {
        for (size_t i = 0; i < C.size(); i++) C[i] -= o.C[i];
    }
    void clear() { std::fill(C.begin(), C.end(), 0); }

    int filas() const { return d; }
    int columnas() const { return w; }
    size_t memoria_bytes() const { return C.size() * sizeof(int32_t); }  // solo los contadores

protected:
    // h_j(x): columna de la clave x en la fila j, en [0, w)
    uint32_t pos(uint32_t clave, int j) const {
        uint32_t h;
        MurmurHash3_x86_32(&clave, sizeof(clave), semilla_pos[j], &h);
        return h % (uint32_t)w;
    }
    // s_j(x): signo de la clave x en la fila j, en {-1, +1}. Usa un hash independiente de h_j.
    int signo(uint32_t clave, int j) const {
        uint32_t h;
        MurmurHash3_x86_32(&clave, sizeof(clave), semilla_signo[j], &h);
        return (h & 1) ? 1 : -1;
    }
    // Contador C[j, col], con la tabla guardada fila por fila en un solo vector
    int32_t& celda(int j, uint32_t col) { return C[(size_t)j * w + col]; }
    int32_t celda(int j, uint32_t col) const { return C[(size_t)j * w + col]; }

    int d, w;
    std::vector<int32_t> C;  // con signo: CountSketch puede tener contadores negativos
    std::vector<uint32_t> semilla_pos, semilla_signo;
};

// Count-Min Sketch (5.1)
//   update:  C[j, h_j(x)] <- C[j, h_j(x)] + 1,   j = 1..d
//   estimar: f(x) = min_j C[j, h_j(x)]           (sobreestima por colisiones)
class CountMin : public SketchLineal {
public:
    CountMin(int d_, int w_) : SketchLineal(d_, w_) {}

    void update(uint32_t clave) {
        for (int j = 0; j < d; j++) celda(j, pos(clave, j)) += 1;
    }

    int64_t estimar(uint32_t clave) const {
        int64_t minimo = INT64_MAX;
        for (int j = 0; j < d; j++) minimo = std::min<int64_t>(minimo, celda(j, pos(clave, j)));
        return minimo;
    }
};

// CountSketch (5.2)
//   update:  C[j, h_j(x)] <- C[j, h_j(x)] + s_j(x)
//   fila j:  z_j(x) = s_j(x) * C[j, h_j(x)]      (deshace el signo)
//   estimar: f(x) = mediana_j z_j(x), truncada a 0 si es negativa
class CountSketch : public SketchLineal {
public:
    CountSketch(int d_, int w_) : SketchLineal(d_, w_) {}

    void update(uint32_t clave) {
        for (int j = 0; j < d; j++) celda(j, pos(clave, j)) += signo(clave, j);
    }

    int64_t estimar(uint32_t clave) const {
        int64_t z[64];
        for (int j = 0; j < d; j++) z[j] = (int64_t)signo(clave, j) * celda(j, pos(clave, j));
        std::sort(z, z + d);
        // Con d impar la mediana es el elemento central; con d par, el promedio de los dos centrales.
        int64_t mediana = (d % 2 == 1) ? z[d / 2] : (z[d / 2 - 1] + z[d / 2]) / 2;
        return mediana < 0 ? 0 : mediana;
    }
};
