#ifndef M4ASM_H
#define M4ASM_H

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

#include "label.h"
#include <ctype.h>
#define STRTOLOWER(v) for (int i=0;i<strlen(v);i++) v[i]=tolower(v[i]);

#define l16(x) (htonl(x)&0xFFFF0000)>>16
#define u16(x) (htonl(x)&0xFFFF)

struct assembled_insn_t assemble_insn(int opcode, uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3);
struct assembled_insn_t parse_and_assemble_insn(char* data, struct le_context *lctx);
void print_assembled_insn(struct assembled_insn_t in);
struct parsed_int_t getintval(char* f);
struct parsed_param_t parse_param(char* p, struct le_context *lctx);

struct parsed_param_t {
    int code; // 0 = no error
    char type; // R = register, N = word, F = dword, n = [near address], f = [far address]
    uint32_t value;
};

#define OUTFMT_BINARY 0
#define OUTFMT_LOGISIM 1

#endif