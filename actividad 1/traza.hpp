#pragma once //compliador incluye una vez el archivo
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
// 1 para que los campos de las estructuras sean a 1 byte, y no hayarellenos o padding
#pragma pack(push,1) //push para apilarlos internamente
struct Record{
    uint64_t ts_us; //hora en microsegundos
    uint32_t src, dst; //ip de origen y destino
    uint16_t sport, dport, len; //puertos de origen y destino y largo de paquete en bytes
    uint8_t proto, flags; //protocolos y flags
};
//cabe mencionar que la estructura suma 24 bytes
#pragma pack(pop) // restaura la confg para que en paack con el 1 solo aafcte a record
static_assert(sizeof(Record) == 24, "24 bytes tiene que ser"); //como bien dijimos las estructura suma 24 bytes
class LeerTraza{ // clase que lee la traza
    public:
    explicit LeerTraza(const char* path) : buff(1 << 16){ // el constructor crea buffer
        fx = fopen(path, "rb"); //abre archivo para leer en binario
        if(!fx){
            perror("fopen"); //si no se puede abrir lanza error
            exit(1);
        }
    }
    ~LeerTraza(){ //destructor de leer traza y cierra el archivo
        if(fx){
            fclose(fx);
        }
    }
    bool next(Record& r){ //true si hay para entregar un siguiente paquete y false, si se terminó la traza
        //referenciamos para que el resultado de la funcion se guarde en r
        if(pos == n){ //si se ocuparon todos los registros del buffer
            //procedemoa a leer otro bloque, lee hasta 65536 registros de 24 bytes para guardar e el buffer
            n = fread(buff.data(), sizeof(Record), buff.size(), fx); //retorna los que efectivamente se leyeron
            pos = 0; //reinicia poscicion dentro de el buffer
            if(n == 0){
                return false; // si no se lee nada
            }
        }
        r = buff[pos++];
        return true;
    }
    private: //datos privados
    FILE* fx = nullptr;
    std::vector<Record> buff;
    size_t pos = 0;
    size_t n = 0;
};