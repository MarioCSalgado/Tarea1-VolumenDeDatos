// swsketch.cpp
// Count-Min Sketch y CountSketch sobre una ventana deslizante mantenida por
// linealidad: anillo de m sub-sketches + agregado A (A <- A - S_expira + S_nueva).
//
// Tarea 1 2026 - Topicos en Grandes Volumenes de Datos (UdeC)
//
// Compilar:  g++ -O2 -march=native -std=c++17 -o swsketch swsketch.cpp
// Uso:       ./swsketch traza.bin --key dst -d 5 -w 1024 --query 1.2.3.4 --out salida.csv
//            ./swsketch --help
//
// Convenciones (seccion 4 del enunciado):
//   * La subventana q (q = 1, 2, ...) cubre (t0 + (q-1)p, t0 + q p]; ranura (q-1) mod m.
//     Los paquetes con ts == t0 no caen en ningun intervalo y no se cuentan
//     (exact_hh hace lo mismo: salen en tau_0 porque ts <= tau_0 - W).
//   * Se evalua tau_j mientras tau_j <= ts del ultimo paquete (igual que exact_hh).
//   * Evaluaciones en tau_j = t0 + W + j p; el agregado contiene q_tau-m+1 .. q_tau.
//   * En cada avance: primero se expira la ranura mas antigua (se resta de A y se
//     limpia), despues se cargan los paquetes de la subventana nueva.
//   * Precarga: en tau_0 las m subventanas ya estan llenas, cada una en su ranura.
//   * N_j se mantiene exacto con un anillo de m contadores escalares.
//   * Delta A_j = A_j - A_{j-1} = S_entra - S_sale se mantiene en un arreglo D:
//     al rotar, D <- -S_sale (antes de limpiar la ranura) y cada paquete nuevo
//     tambien se suma en D.

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

using std::string;
using std::vector;

// ============================================================================
// FORMATO DEL REGISTRO DE 24 BYTES (identico a pcap2bin.cpp / exact_hh.cpp)
// ----------------------------------------------------------------------------
//   offset 0  : uint64  ts_us  microsegundos desde epoch
//   offset 8  : uint32  src    IPv4 origen en orden de host (1.2.3.4 = 0x01020304)
//   offset 12 : uint32  dst    IPv4 destino
//   offset 16 : uint16  sport
//   offset 18 : uint16  dport
//   offset 20 : uint16  len
//   offset 22 : uint8   proto
//   offset 23 : uint8   flags  (bit 4 = paquete sintetico, lo marca inject_attack.py)
// ============================================================================
static const size_t REC_SIZE = 24;
static const size_t OFF_TS = 0, OFF_SRC = 8, OFF_DST = 12, OFF_FLAGS = 23;

struct Rec {
    int64_t ts;   // ticks
    uint32_t src, dst;
    uint8_t flags;
};

static bool g_ts_double = false;
static bool g_ip_swap = false;
static int64_t g_ts_hz = 1000000;  // ticks por segundo

static inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

static inline void decode(const uint8_t* p, Rec& r) {
    if (g_ts_double) {
        double s;
        std::memcpy(&s, p + OFF_TS, 8);
        r.ts = (int64_t)std::llround(s * (double)g_ts_hz);
    } else {
        uint64_t t;
        std::memcpy(&t, p + OFF_TS, 8);
        r.ts = (int64_t)t;
    }
    std::memcpy(&r.src, p + OFF_SRC, 4);
    std::memcpy(&r.dst, p + OFF_DST, 4);
    if (g_ip_swap) { r.src = bswap32(r.src); r.dst = bswap32(r.dst); }
    r.flags = p[OFF_FLAGS];
}

// ----------------------------------------------------------------------------
// IPs
// ----------------------------------------------------------------------------
static bool parse_ip(const string& s, uint32_t& out) {
    unsigned a, b, c, d;
    char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4 && a < 256 && b < 256 &&
        c < 256 && d < 256) {
        out = (a << 24) | (b << 16) | (c << 8) | d;
        return true;
    }
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (end && *end == 0 && v <= 0xFFFFFFFFull) { out = (uint32_t)v; return true; }
    return false;
}

static string ip_str(uint32_t x) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", x >> 24, (x >> 16) & 255, (x >> 8) & 255, x & 255);
    return buf;
}

// ----------------------------------------------------------------------------
// Hashing: familia de Carter-Wegman ((a x + b) mod p), p = 2^61 - 1.
// Es 2-independiente sobre [p]; al reducir mod w la prob. de colision es ~1/w.
// ----------------------------------------------------------------------------
static const uint64_t MP = (1ULL << 61) - 1;

struct CWHash {
    uint64_t a = 1, b = 0;
    inline uint64_t operator()(uint32_t x) const {
        __uint128_t t = (__uint128_t)a * x + b;
        uint64_t r = (uint64_t)(t & MP) + (uint64_t)(t >> 61);
        if (r >= MP) r -= MP;
        return r;
    }
};

// d funciones de posicion h_j (compartidas por CMS y CS: las mismas colisiones)
// y d funciones de signo s_j (solo CS), todas independientes entre si.
struct HashFamily {
    int d = 0;
    uint32_t w = 0;
    vector<CWHash> pos, sgn;
    void init(int d_, uint32_t w_, uint64_t seed) {
        d = d_;
        w = w_;
        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<uint64_t> A(1, MP - 1), B(0, MP - 1);
        pos.resize(d);
        sgn.resize(d);
        for (int j = 0; j < d; j++) { pos[j].a = A(rng); pos[j].b = B(rng); }
        for (int j = 0; j < d; j++) { sgn[j].a = A(rng); sgn[j].b = B(rng); }
    }
    // columnas y signos de una clave (se calculan una sola vez por paquete)
    inline void locate(uint32_t x, uint32_t* col, int32_t* s) const {
        for (int j = 0; j < d; j++) {
            col[j] = (uint32_t)(pos[j](x) % w);
            s[j] = (sgn[j](x) & 1) ? +1 : -1;
        }
    }
};

static const int DMAX = 32;

// ----------------------------------------------------------------------------
// Matriz d x w de contadores (con signo: CS y Delta A los necesitan)
// ----------------------------------------------------------------------------
using Cnt = int32_t;

struct Matrix {
    int d = 0;
    uint32_t w = 0;
    vector<Cnt> c;
    void init(int d_, uint32_t w_) { d = d_; w = w_; c.assign((size_t)d * w, 0); }
    inline Cnt& at(int j, uint32_t col) { return c[(size_t)j * w + col]; }
    inline Cnt at(int j, uint32_t col) const { return c[(size_t)j * w + col]; }
    void clear() { std::fill(c.begin(), c.end(), 0); }
    size_t bytes() const { return c.size() * sizeof(Cnt); }
    bool operator==(const Matrix& o) const { return c == o.c; }
};

static inline int64_t median_inplace(int64_t* v, int n) {
    std::nth_element(v, v + n / 2, v + n);
    int64_t hi = v[n / 2];
    if (n % 2) return hi;
    int64_t lo = *std::max_element(v, v + n / 2);
    // d par: promedio de los dos centrales (redondeado hacia -inf)
    int64_t s = lo + hi;
    return (s >= 0) ? s / 2 : -((-s + 1) / 2);
}

// ----------------------------------------------------------------------------
// Operaciones propias de cada estimador. La ventana es la misma para ambos.
// ----------------------------------------------------------------------------
struct CMSOps {
    static constexpr const char* name = "CMS";
    // C[j, h_j(x)] += c
    static inline void update(Matrix& M, const uint32_t* col, const int32_t*, Cnt c) {
        for (int j = 0; j < M.d; j++) M.at(j, col[j]) += c;
    }
    // f^ = min_j C[j, h_j(x)]   (valido solo con frecuencias >= 0)
    static inline int64_t estimate(const Matrix& M, const uint32_t* col, const int32_t*) {
        int64_t m = INT64_MAX;
        for (int j = 0; j < M.d; j++) m = std::min<int64_t>(m, M.at(j, col[j]));
        return m;
    }
    // Delta f^ (CMS-mediana, experimental): mediana_r Delta A[r, h_r(x)]
    static inline int64_t estimate_signed(const Matrix& M, const uint32_t* col, const int32_t*) {
        int64_t v[DMAX];
        for (int j = 0; j < M.d; j++) v[j] = M.at(j, col[j]);
        return median_inplace(v, M.d);
    }
};

struct CSOps {
    static constexpr const char* name = "CS";
    // C[j, h_j(x)] += s_j(x) c
    static inline void update(Matrix& M, const uint32_t* col, const int32_t* s, Cnt c) {
        for (int j = 0; j < M.d; j++) M.at(j, col[j]) += s[j] * c;
    }
    // f^ = mediana_j s_j(x) C[j, h_j(x)]
    static inline int64_t estimate(const Matrix& M, const uint32_t* col, const int32_t* s) {
        int64_t v[DMAX];
        for (int j = 0; j < M.d; j++) v[j] = (int64_t)s[j] * M.at(j, col[j]);
        return median_inplace(v, M.d);
    }
    // Sobre Delta A se usa el mismo estimador habitual
    static inline int64_t estimate_signed(const Matrix& M, const uint32_t* col, const int32_t* s) {
        return estimate(M, col, s);
    }
};

// ----------------------------------------------------------------------------
// Ventana deslizante generica: anillo de m sub-sketches + agregado A + diferencias D
// ----------------------------------------------------------------------------
template <class Ops>
struct SlidingSketch {
    int m = 0;
    vector<Matrix> ring;  // S_q en la ranura (q-1) mod m
    Matrix A;             // agregado de la ventana activa
    Matrix D;             // Delta A_j = S_entra - S_sale
    void init(int m_, int d, uint32_t w) {
        m = m_;
        ring.assign(m, Matrix());
        for (auto& S : ring) S.init(d, w);
        A.init(d, w);
        D.init(d, w);
    }
    // Llega un paquete de la subventana actual: se actualiza S, A y D a la vez.
    inline void add(int slot, const uint32_t* col, const int32_t* s) {
        Ops::update(ring[slot], col, s, +1);
        Ops::update(A, col, s, +1);
        Ops::update(D, col, s, +1);
    }
    // Expira la ranura: D <- -S_sale (antes de limpiar), A <- A - S_sale, S_sale <- 0.
    // Toca 2 d w contadores (3 d w contando D), independiente de los paquetes.
    void expire(int slot) {
        Cnt* S = ring[slot].c.data();
        Cnt* a = A.c.data();
        Cnt* dd = D.c.data();
        const size_t n = A.c.size();
        for (size_t i = 0; i < n; i++) {
            dd[i] = -S[i];
            a[i] -= S[i];
            S[i] = 0;
        }
    }
    // Antes de la primera rotacion D acumula todo (Delta A_0 = A_0 - 0).
    int64_t estimate(const uint32_t* col, const int32_t* s) const { return Ops::estimate(A, col, s); }
    int64_t estimate_delta(const uint32_t* col, const int32_t* s) const {
        return Ops::estimate_signed(D, col, s);
    }
    // Autoverificacion de linealidad: A == suma del anillo
    bool check_aggregate() const {
        vector<int64_t> sum(A.c.size(), 0);
        for (auto& S : ring)
            for (size_t i = 0; i < sum.size(); i++) sum[i] += S.c[i];
        for (size_t i = 0; i < sum.size(); i++)
            if (sum[i] != A.c[i]) return false;
        return true;
    }
    size_t bytes_per_sketch() const { return A.bytes(); }
};

// ----------------------------------------------------------------------------
// phi como fraccion exacta para T = ceil(phi N) sin errores de punto flotante
// ----------------------------------------------------------------------------
struct Fraction {
    int64_t num = 1, den = 100;
};
static Fraction parse_phi(const string& s) {
    Fraction f;
    size_t dot = s.find('.');
    if (dot == string::npos) { f.num = std::stoll(s); f.den = 1; return f; }
    string ip = s.substr(0, dot), fp = s.substr(dot + 1);
    int64_t den = 1;
    for (size_t i = 0; i < fp.size(); i++) den *= 10;
    f.num = (ip.empty() ? 0 : std::stoll(ip)) * den + (fp.empty() ? 0 : std::stoll(fp));
    f.den = den;
    return f;
}
static inline int64_t ceil_phi(const Fraction& f, int64_t N) { return (N * f.num + f.den - 1) / f.den; }
// Umbral tal como lo calcula exact_hh: ceil(phi * N) en double, y al menos 1.
// (Para phi = 0.01 coincide con el techo exacto para todo N < 2e7.)
static inline int64_t threshold(double phi_d, const Fraction& f, int64_t N) {
    int64_t t = (int64_t)std::ceil(phi_d * (double)N);
    (void)f;
    return t < 1 ? 1 : t;
}

// ----------------------------------------------------------------------------
// Opciones
// ----------------------------------------------------------------------------
struct Opts {
    string trace, out, meta;
    bool key_src = false;
    int d = 5;
    uint32_t w = 1024;
    int64_t W = 60, p = 10;
    string phi = "0.01";
    uint64_t seed = 12345;
    vector<string> queries;
    string query_file;
    int query_top = 0, query_random = 0;
    int64_t query_min = 1;
    bool with_exact = false;
    bool selfcheck = false;
    uint64_t query_seed = 1;
    string save_queries;
};

static void usage() {
    std::fprintf(stderr,
                 "Uso: swsketch TRAZA.bin [opciones]\n"
                 "  --key src|dst        clave: IP de origen (scan) o de destino (ddos)   [dst]\n"
                 "  -d N                 filas del sketch                                  [5]\n"
                 "  -w N                 ancho del sketch                                  [1024]\n"
                 "  -W S                 ancho de la ventana en segundos                   [60]\n"
                 "  --delta S            paso p en segundos (W/p subventanas)              [10]\n"
                 "  --phi F              umbral de heavy hitter (T = ceil(phi N))          [0.01]\n"
                 "  --seed N             semilla de las funciones hash                     [12345]\n"
                 "  --query IP           clave a consultar (se puede repetir)\n"
                 "  --query-file F       archivo con una IP por linea\n"
                 "  --query-top K        agrega las K claves mas frecuentes de la traza (pre-pasada)\n"
                 "  --query-random R     agrega R claves al azar entre las vistas (pre-pasada)\n"
                 "  --query-min C        frecuencia global minima para --query-random      [1]\n"
                 "  --with-exact         cuenta exacta de las claves consultadas (referencia propia)\n"
                 "  --selfcheck          verifica A == suma del anillo y D == A_j - A_{j-1}\n"
                 "  --query-seed N       semilla para elegir las claves al azar            [1]\n"
                 "  --save-queries F     guarda las claves elegidas (para reusarlas con --query-file)\n"
                 "  --out F.csv          salida por ventana y clave                        [stdout]\n"
                 "  --meta F.json        memoria, tiempos y verificaciones\n"
                 "  --ts-hz N            ticks por segundo del campo de tiempo             [1000000]\n"
                 "  --ts-double          el tiempo viene como double en segundos\n"
                 "  --ip-swap            las IPs vienen en orden de red (invertir bytes)\n");
}

static bool parse_args(int argc, char** argv, Opts& o) {
    for (int i = 1; i < argc; i++) {
        string a = argv[i];
        auto need = [&](const char* name) -> string {
            if (i + 1 >= argc) { std::fprintf(stderr, "falta valor para %s\n", name); std::exit(2); }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") { usage(); std::exit(0); }
        else if (a == "--key") { string k = need("--key"); if (k == "src") o.key_src = true; else if (k == "dst") o.key_src = false; else { std::fprintf(stderr, "--key debe ser src o dst\n"); return false; } }
        else if (a == "-d") o.d = std::stoi(need("-d"));
        else if (a == "-w") o.w = (uint32_t)std::stoul(need("-w"));
        else if (a == "-W") o.W = std::stoll(need("-W"));
        else if (a == "--delta") o.p = std::stoll(need("--delta"));
        else if (a == "--phi") o.phi = need("--phi");
        else if (a == "--seed") o.seed = std::stoull(need("--seed"));
        else if (a == "--query") o.queries.push_back(need("--query"));
        else if (a == "--query-file") o.query_file = need("--query-file");
        else if (a == "--query-top") o.query_top = std::stoi(need("--query-top"));
        else if (a == "--query-random") o.query_random = std::stoi(need("--query-random"));
        else if (a == "--query-min") o.query_min = std::stoll(need("--query-min"));
        else if (a == "--with-exact") o.with_exact = true;
        else if (a == "--selfcheck") o.selfcheck = true;
        else if (a == "--query-seed") o.query_seed = std::stoull(need("--query-seed"));
        else if (a == "--save-queries") o.save_queries = need("--save-queries");
        else if (a == "--out") o.out = need("--out");
        else if (a == "--meta") o.meta = need("--meta");
        else if (a == "--ts-hz") g_ts_hz = std::stoll(need("--ts-hz"));
        else if (a == "--ts-double") g_ts_double = true;
        else if (a == "--ip-swap") g_ip_swap = true;
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "opcion desconocida: %s\n", a.c_str()); return false; }
        else if (o.trace.empty()) o.trace = a;
        else { std::fprintf(stderr, "argumento extra: %s\n", a.c_str()); return false; }
    }
    if (o.trace.empty()) { usage(); return false; }
    if (o.d < 1 || o.d > DMAX) { std::fprintf(stderr, "d debe estar en [1, %d]\n", DMAX); return false; }
    if (o.w < 1) { std::fprintf(stderr, "w debe ser >= 1\n"); return false; }
    if (o.p <= 0 || o.W <= 0 || o.W % o.p != 0) { std::fprintf(stderr, "W debe ser multiplo de --delta\n"); return false; }
    return true;
}

// ----------------------------------------------------------------------------
// Lectura por bloques
// ----------------------------------------------------------------------------
struct Reader {
    FILE* f = nullptr;
    vector<uint8_t> buf;
    size_t n = 0, i = 0;
    explicit Reader(const string& path) : buf(REC_SIZE * (1 << 16)) {
        f = std::fopen(path.c_str(), "rb");
        if (!f) { std::perror(path.c_str()); std::exit(1); }
    }
    ~Reader() { if (f) std::fclose(f); }
    inline bool next(Rec& r) {
        if (i == n) {
            n = std::fread(buf.data(), REC_SIZE, buf.size() / REC_SIZE, f);
            i = 0;
            if (n == 0) return false;
        }
        decode(buf.data() + REC_SIZE * i++, r);
        return true;
    }
};

// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    Opts o;
    if (!parse_args(argc, argv, o)) return 2;
    const int m = (int)(o.W / o.p);
    const int64_t P = o.p * g_ts_hz;  // largo de subventana en ticks
    const Fraction phi = parse_phi(o.phi);
    const double phi_d = std::stod(o.phi);

    // ---- claves a consultar --------------------------------------------------
    vector<uint32_t> qkeys;
    auto add_key = [&](uint32_t k) {
        if (std::find(qkeys.begin(), qkeys.end(), k) == qkeys.end()) qkeys.push_back(k);
    };
    for (auto& s : o.queries) {
        uint32_t k;
        if (!parse_ip(s, k)) { std::fprintf(stderr, "IP invalida: %s\n", s.c_str()); return 2; }
        add_key(k);
    }
    if (!o.query_file.empty()) {
        std::ifstream in(o.query_file);
        string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            uint32_t k;
            if (parse_ip(line, k)) add_key(k);
        }
    }
    if (o.query_top > 0 || o.query_random > 0) {
        // Pre-pasada solo para ELEGIR claves de validacion; no es parte del algoritmo.
        std::unordered_map<uint32_t, int64_t> cnt;
        cnt.reserve(1 << 20);
        Reader rd(o.trace);
        Rec r;
        while (rd.next(r)) cnt[o.key_src ? r.src : r.dst]++;
        vector<std::pair<int64_t, uint32_t>> v;
        v.reserve(cnt.size());
        for (auto& kv : cnt) v.push_back({kv.second, kv.first});
        std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.first != b.first ? a.first > b.first : a.second < b.second; });
        for (int i = 0; i < o.query_top && i < (int)v.size(); i++) add_key(v[i].second);
        vector<uint32_t> pool;
        for (auto& e : v)
            if (e.first >= o.query_min) pool.push_back(e.second);
        std::sort(pool.begin(), pool.end());
        std::mt19937_64 rng(o.query_seed);
        std::shuffle(pool.begin(), pool.end(), rng);
        int added = 0;
        for (size_t i = 0; i < pool.size() && added < o.query_random; i++) {
            size_t before = qkeys.size();
            add_key(pool[i]);
            if (qkeys.size() > before) added++;
        }
    }
    if (qkeys.empty()) std::fprintf(stderr, "aviso: sin claves de consulta; solo se reporta N\n");
    if (!o.save_queries.empty()) {
        FILE* qf = std::fopen(o.save_queries.c_str(), "w");
        if (!qf) { std::perror(o.save_queries.c_str()); return 1; }
        for (uint32_t k : qkeys) std::fprintf(qf, "%s\n", ip_str(k).c_str());
        std::fclose(qf);
    }
    const int nq = (int)qkeys.size();

    // posiciones y signos de cada clave consultada (fijos: mismas hash para todo)
    HashFamily H;
    H.init(o.d, o.w, o.seed);
    vector<uint32_t> qcol((size_t)nq * o.d);
    vector<int32_t> qsgn((size_t)nq * o.d);
    for (int k = 0; k < nq; k++) H.locate(qkeys[k], &qcol[(size_t)k * o.d], &qsgn[(size_t)k * o.d]);

    // ---- estructuras -----------------------------------------------------------
    SlidingSketch<CMSOps> cms;
    SlidingSketch<CSOps> cs;
    cms.init(m, o.d, o.w);
    cs.init(m, o.d, o.w);
    vector<int64_t> Nsub(m, 0);  // anillo de m contadores escalares
    int64_t N = 0;

    // referencia exacta propia (solo para las claves consultadas)
    std::unordered_map<uint32_t, int> qidx;
    for (int k = 0; k < nq; k++) qidx[qkeys[k]] = k;
    vector<int64_t> exsub(o.with_exact ? (size_t)m * nq : 0, 0), exwin(o.with_exact ? nq : 0, 0);
    vector<int64_t> exprev(o.with_exact ? nq : 0, 0);

    // autoverificacion de Delta A: celdas de A en la evaluacion anterior
    vector<int64_t> prevA_cms((size_t)nq * o.d, 0), prevA_cs((size_t)nq * o.d, 0);
    int64_t check_agg_fail = 0, check_delta_fail = 0, check_evals = 0;

    // ---- salida ----------------------------------------------------------------
    FILE* out = stdout;
    if (!o.out.empty()) {
        out = std::fopen(o.out.c_str(), "w");
        if (!out) { std::perror(o.out.c_str()); return 1; }
    }
    std::fprintf(out,
                 "j,tau_rel,tau_abs,key,N,T,f_exact,df_exact,f_cms,f_cs,f_cs_raw,df_cms_med,df_cs,"
                 "hh_exact,hh_cms,hh_cs\n");

    int64_t t0 = 0, cur = 1, packets = 0, late = 0, evals = 0, rotations = 0, at_t0 = 0, t_last = 0;
    double rot_seconds = 0.0;

    auto evaluate = [&](int64_t qtau) {
        const int64_t j = qtau - m;
        const int64_t tau_rel_ticks = qtau * P;  // tau_j - t0 = W + j p
        const double tau_rel = (double)tau_rel_ticks / (double)g_ts_hz;
        const double tau_abs = (double)(t0 + tau_rel_ticks) / (double)g_ts_hz;
        const int64_t T = threshold(phi_d, phi, N);
        evals++;
        if (o.selfcheck) {
            check_evals++;
            if (!cms.check_aggregate() || !cs.check_aggregate()) check_agg_fail++;
        }
        if (nq == 0) {
            std::fprintf(out, "%" PRId64 ",%.6f,%.6f,,%" PRId64 ",%" PRId64 ",,,,,,,,,,\n", j, tau_rel, tau_abs, N, T);
            return;
        }
        for (int k = 0; k < nq; k++) {
            const uint32_t* col = &qcol[(size_t)k * o.d];
            const int32_t* s = &qsgn[(size_t)k * o.d];
            const int64_t f_cms = cms.estimate(col, s);
            const int64_t f_cs_raw = cs.estimate(col, s);
            const int64_t f_cs = std::max<int64_t>(0, f_cs_raw);  // truncado a 0 al reportar
            const int64_t df_cms = cms.estimate_delta(col, s);   // CMS-mediana sobre Delta A
            const int64_t df_cs = cs.estimate_delta(col, s);     // CS sobre Delta A
            if (o.selfcheck) {
                // D debe ser exactamente A_j - A_{j-1} en las celdas consultadas
                for (int r = 0; r < o.d; r++) {
                    int64_t a1 = cms.A.at(r, col[r]), a2 = cs.A.at(r, col[r]);
                    int64_t &p1 = prevA_cms[(size_t)k * o.d + r], &p2 = prevA_cs[(size_t)k * o.d + r];
                    if (cms.D.at(r, col[r]) != a1 - p1 || cs.D.at(r, col[r]) != a2 - p2) check_delta_fail++;
                    p1 = a1;
                    p2 = a2;
                }
            }
            string fe = "", dfe = "", hhe = "";
            if (o.with_exact) {
                fe = std::to_string(exwin[k]);
                dfe = std::to_string(exwin[k] - exprev[k]);
                hhe = (exwin[k] >= T) ? "1" : "0";
                exprev[k] = exwin[k];
            }
            std::fprintf(out,
                         "%" PRId64 ",%.6f,%.6f,%s,%" PRId64 ",%" PRId64 ",%s,%s,%" PRId64 ",%" PRId64 ",%" PRId64
                         ",%" PRId64 ",%" PRId64 ",%s,%d,%d\n",
                         j, tau_rel, tau_abs, ip_str(qkeys[k]).c_str(), N, T, fe.c_str(), dfe.c_str(), f_cms, f_cs,
                         f_cs_raw, df_cms, df_cs, hhe.c_str(), f_cms >= T ? 1 : 0, f_cs >= T ? 1 : 0);
        }
    };

    auto rotate_to = [&](int64_t qnew) {
        // qnew entra; si qnew > m, la subventana qnew - m sale y comparte ranura con qnew
        const int slot = (int)((qnew - 1) % m);
        if (qnew > m) {
            auto t1 = std::chrono::steady_clock::now();
            cms.expire(slot);
            cs.expire(slot);
            N -= Nsub[slot];
            Nsub[slot] = 0;
            if (o.with_exact)
                for (int k = 0; k < nq; k++) {
                    exwin[k] -= exsub[(size_t)slot * nq + k];
                    exsub[(size_t)slot * nq + k] = 0;
                }
            rot_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - t1).count();
            rotations++;
        }
    };

    auto wall0 = std::chrono::steady_clock::now();
    {
        Reader rd(o.trace);
        Rec r;
        bool first = true;
        uint32_t col[DMAX];
        int32_t sg[DMAX];
        while (rd.next(r)) {
            if (first) { t0 = r.ts; first = false; }
            packets++;
            t_last = r.ts;
            const int64_t dt = r.ts - t0;
            if (dt <= 0 && cur == 1) { at_t0++; continue; }  // ts == t0: fuera de toda subventana
            int64_t q = (dt <= 0) ? 1 : (dt + P - 1) / P;  // techo(dt/p)
            if (q < cur) { late++; q = cur; }               // paquete fuera de orden: se asigna a la actual
            while (q > cur) {                                // cierra subventanas (aunque esten vacias)
                if (cur >= m) evaluate(cur);                 // ventana = cur-m+1 .. cur
                cur++;
                rotate_to(cur);                              // primero expirar ...
            }
            const int slot = (int)((cur - 1) % m);           // ... despues cargar
            const uint32_t key = o.key_src ? r.src : r.dst;
            H.locate(key, col, sg);
            cms.add(slot, col, sg);
            cs.add(slot, col, sg);
            Nsub[slot]++;
            N++;
            if (o.with_exact) {
                auto it = qidx.find(key);
                if (it != qidx.end()) { exsub[(size_t)slot * nq + it->second]++; exwin[it->second]++; }
            }
        }
        if (packets == 0) { std::fprintf(stderr, "traza vacia\n"); return 1; }
        // la ultima subventana se evalua solo si su borde no supera al ultimo paquete
        if (cur >= m && t0 + cur * P <= t_last) evaluate(cur);
    }
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    if (out != stdout) std::fclose(out);

    const size_t bps = cms.bytes_per_sketch();
    std::fprintf(stderr,
                 "[swsketch] key=%s d=%d w=%u seed=%" PRIu64 " paquetes=%" PRId64 " ventanas=%" PRId64
                 " rotaciones=%" PRId64 " fuera_de_orden=%" PRId64 " en_t0=%" PRId64 "\n"
                 "[swsketch] memoria por sketch=%zu B, anillo+A=%zu B por tipo, +D=%zu B; tiempo=%.2fs "
                 "(%.1f Mpkt/s), rotaciones=%.4fs (%.1f us c/u)\n",
                 o.key_src ? "src" : "dst", o.d, o.w, o.seed, packets, evals, rotations, late, at_t0, bps, bps * (m + 1),
                 bps * (m + 2), wall, packets / wall / 1e6, rot_seconds,
                 rotations ? 1e6 * rot_seconds / rotations : 0.0);
    if (o.selfcheck)
        std::fprintf(stderr, "[swsketch] autoverificacion: A==suma(anillo) fallas=%" PRId64 "/%" PRId64
                             ", D==A_j-A_{j-1} fallas=%" PRId64 "\n",
                     check_agg_fail, check_evals, check_delta_fail);

    if (!o.meta.empty()) {
        FILE* mf = std::fopen(o.meta.c_str(), "w");
        if (mf) {
            std::fprintf(mf,
                         "{\n  \"trace\": \"%s\",\n  \"key\": \"%s\",\n  \"d\": %d,\n  \"w\": %u,\n  \"W\": %" PRId64
                         ",\n  \"p\": %" PRId64 ",\n  \"m\": %d,\n  \"phi\": \"%s\",\n  \"seed\": %" PRIu64
                         ",\n  \"t0_ticks\": %" PRId64 ",\n  \"ts_hz\": %" PRId64 ",\n  \"packets\": %" PRId64
                         ",\n  \"evaluations\": %" PRId64 ",\n  \"rotations\": %" PRId64
                         ",\n  \"late_packets\": %" PRId64 ",\n  \"counter_bytes\": %zu,\n  \"bytes_per_sketch\": %zu"
                         ",\n  \"bytes_ring_plus_aggregate\": %zu,\n  \"bytes_with_delta\": %zu"
                         ",\n  \"seconds_total\": %.4f,\n  \"seconds_rotations\": %.6f"
                         ",\n  \"selfcheck\": %s,\n  \"selfcheck_aggregate_failures\": %" PRId64
                         ",\n  \"selfcheck_delta_failures\": %" PRId64 "\n}\n",
                         o.trace.c_str(), o.key_src ? "src" : "dst", o.d, o.w, o.W, o.p, m, o.phi.c_str(), o.seed, t0,
                         g_ts_hz, packets, evals, rotations, late, sizeof(Cnt), bps, bps * (m + 1), bps * (m + 2), wall,
                         rot_seconds, o.selfcheck ? "true" : "false", check_agg_fail, check_delta_fail);
            std::fclose(mf);
        }
    }
    return (o.selfcheck && (check_agg_fail || check_delta_fail)) ? 3 : 0;
}
