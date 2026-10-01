#pragma once
#include <cstdint>
#include <vector>

// Ventana deslizante mediante un anillo de m sub-sketches y un sketch agregado A.
//Convencion (seccion 4 del enunciado):
//t0 = marca de tiempo del primer paquete.
// La subventana q cubre (t0 + (q-1)p, t0 + qp], con q >= 1.
//Un paquete justo en un borde pertenece a la subventana que TERMINA ahi.
// La ranura del anillo es (q-1) mod m.
//Las evaluaciones ocurren en tau_j = t0 + W + j*p, y en tau_j el agregado
//contiene exactamente las subventanas q_tau-m+1,., q_tau, con q_tau = (tau_j - t0)/p.
// El parametro Sketch debe tener: update(clave), add(otro), sub(otro), clear().
// Sketch vacio, que sirve para probar solo el anillo y N_j, sin sketches reales.
struct SketchNulo {
    void update(uint32_t) {}
    void add(const SketchNulo&) {}
    void sub(const SketchNulo&) {}
    void clear() {} //estos son los requisitos de la ventana, por ahora vacios eso si
};

template <class Sketch> //creamos la clase
class VentanaDeslizante {
public:
    //W_us y p_us en microsegundos. prototipo: sketch vacio que se copia m+1 veces,
    // asi todos comparten las mismas funciones hash (si no, sumar/restar no tiene sentido).
    VentanaDeslizante(uint64_t W_us, uint64_t p_us, const Sketch& prototipo)
        : p(p_us), m(W_us / p_us), A(prototipo), anillo(m, prototipo), n(m, 0) {}
    // Procesa un paquete. Los paquetes deben llegar ordenados por tiempo.
    // evaluar(ventana, tau_us) se llama en cada instante de evaluacion tau_j.
    template <class Evaluar>
    void push(uint64_t ts, uint32_t clave, Evaluar&& evaluar) {
        if (!iniciada) {
            t0 = ts;
            iniciada = true;
        }
        if (ts <= t0) return;  // ts == t0 da q = 0 no pertenece a ninguna subventana
        uint64_t q = (ts - t0 + p - 1) / p;  // techo de (ts - t0)/p
        // Avanzar subventana por subventana hasta la del paquete
        // (tambien recorre las subventanas vacias, si las hubiera).
        while (q_tau < q) {
            if (q_tau >= m) evaluar(*this, tau(q_tau));  // la subventana q_tau termina: evaluar
            avanzar();    // luego expirar la mas antigua
        }
        size_t r = (q - 1) % m;
        anillo[r].update(clave);  // sub-sketch de la subventana actual
        A.update(clave); // y el agregado, simultaneamente
        n[r]++;
        N_++;
    }
    // Llamar al final con la marca de tiempo del ultimo paquete, para evaluar
    // la ultima ventana si su borde tau coincide con o es anterior al final de la traza.
    template <class Evaluar>
    void terminar(uint64_t t_fin, Evaluar&& evaluar) {
        if (iniciada && q_tau >= m && tau(q_tau) <= t_fin) evaluar(*this, tau(q_tau));
    }
    const Sketch& agregado() const { return A; }
    uint64_t N() const { return N_; }
    uint64_t t_inicial() const { return t0; }
    // Numero de ventana j a partir de tau_j: j = q_tau - m
    uint64_t indice_ventana(uint64_t tau_us) const { return (tau_us - t0) / p - m; }
private:
    // Instante en que termina la subventana q: tau = t0 + q*p
    uint64_t tau(uint64_t q) const { return t0 + q * p; }
    // Pasa a la siguiente subventana. Si el anillo ya estaba lleno, primero expira
    // la mas antigua: comparte ranura con la que entra, (q-1) mod m = (q-m-1) mod m.
    void avanzar() {
        q_tau++;
        if (q_tau > m) {
            size_t r = (q_tau - 1) % m;
            A.sub(anillo[r]);  // A <- A - S_expira (linealidad)
            N_ -= n[r];
            anillo[r].clear();// la ranura se limpia y se reutiliza
            n[r] = 0;
        }
    }
    uint64_t p, m;
    uint64_t t0 = 0;
    uint64_t q_tau = 0;  // subventana mas nueva cargada
    uint64_t N_ = 0; // paquetes exactos en la ventana activa
    bool iniciada = false;
    Sketch A;        // sketch agregado de la ventana
    std::vector<Sketch> anillo;// m sub-sketches
    std::vector<uint64_t> n;// m contadores escalares (para N_j exacto)
};
