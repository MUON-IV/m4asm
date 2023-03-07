#ifndef INSNS_H
#define INSNS_H

// NOP
#define OPC_NOP 0x00

// JMP
#define OPC_JMP_FAR 0x02
#define OPC_JMP_NEAR 0x37

// MOV
// I2R      = INDIRECT MOV LOAD
// R2A      = register to A register
// V2R      = immediate Value to register
// V2A      = immediate Value to A register
// D2R/R2D  = mov rX, [AD] or similar. TBD.
#define OPC_MOV_I2R_NEAR 0x03
#define OPC_MOV_I2R_FAR 0x04
#define OPC_MOV_R2M_FAR 0x05
#define OPC_MOV_R2M_NEAR 0x06
#define OPC_MOV_R2R 0x07
#define OPC_MOV_R2A 0x2F
#define OPC_MOV_V2R 0x35
#define OPC_MOV_V2A 0x36
#define OPC_MOV_D2R 0x08
#define OPC_MOV_R2D 0x0E

// ADD
#define OPC_ADD_RR 0x09
#define OPC_ADD_RI 0x0C
#define OPC_ADC_RR 0x0D // ADC

// SUB
#define OPC_SUB_RR 0x0F
#define OPC_SUB_RI 0x12
#define OPC_SUC_RR 0x13 // SUC

// Rotates
#define OPC_SHR_RI 0x14
#define OPC_SHL_RI 0x15
#define OPC_ROR_RI 0x16
#define OPC_ROL_RI 0x17

// NOT, INC
#define OPC_NOT_R 0x18
#define OPC_INC_R 0x30

// 2-operand logic.
#define OPC_AND_RR 0x19
#define OPC_AND_RI 0x1A
#define OPC_OR_RR 0x1B
#define OPC_OR_RI 0x1C
#define OPC_XOR_RR 0x1D
#define OPC_XOR_RI 0x1E
#define OPC_XNOR_RR 0x1F
#define OPC_XNOR_RI 0x20
#define OPC_NOR_RR 0x21
#define OPC_NOR_RI 0x22
#define OPC_NAND_RR 0x23
#define OPC_NAND_RI 0x24

// PUSH
#define OPC_PUSHB_FAR 0x25
#define OPC_PUSHW_FAR 0x27
#define OPC_PUSHW_NEAR 0x3A
#define OPC_PUSH_REG 0x2A

// SSP
#define OPC_SSP 0x29

// POP
#define OPC_POP_REG 0x2B
#define OPC_POP_FAR 0x2C
#define OPC_POP_AD 0x2E
#define OPC_POP_NEAR 0x3C

// CALL
#define OPC_CALL_FAR 0x31
#define OPC_CALL_NEAR 0xE0

// RET
#define OPC_RET 0x33

// IEN
#define OPC_IEN 0x3E

// SINT
#define OPC_SINT 0x34

// MMOV
#define OPC_MMOV_ST 0x40
#define OPC_MMOV_LD 0x41

// IMOV
#define OPC_IMOV_LD 0x4A
#define OPC_IMOV_ST 0x4B
#define OPC_IMOV_ST_IMM 0x4C

// BRCH
#define OPC_BRCH_FLG_FAR 0x42
#define OPC_BRCH_FLG_NEAR 0x44
#define OPC_BRCH_IV_FAR 0x46
#define OPC_BRCH_IV_NEAR 0x48

// Special T,T+1 MOVs
#define OPC_MOV_RSA 0x4F
#define OPC_IMOV_RSA 0x4E

// SPECIAL ASSEMBLER-SPECIFIC
#define OPC_DW 0x10FF

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct assembled_insn_t {
    uint16_t data[16];
    int length;
};

struct parsed_int_t {
    int code;
    int strlength;
    unsigned long value;
};

#define PTYPE_REGISTER 'R' // rX
#define PTYPE_WORD_IMM 'W' // 0xF00D
#define PTYPE_DWORD_IMM 'D'// d0xDEADBEEF
#define PTYPE_NEAR_PTR 'n' // (0xF00D)
#define PTYPE_FAR_PTR 'f'  // [0xDEADBEEF]

#include <stddef.h>

struct insn_def_t {
    const char *mnemonic;
    unsigned short opcode;
    int length;
    int cycles;
    const char *params; // R = register, W = word, D = dword, n = (near address), f = [far address]
};

static struct insn_def_t insns[] = {
    {"nop"  , OPC_NOP           , 1, 1, ""},

    {"jmp"  , OPC_JMP_FAR       , 3, 4, "D"},
    {"jmp"  , OPC_JMP_NEAR      , 2, 4, "W"},

    {"mov"  , OPC_MOV_I2R_NEAR  , 2, 4, "Rn"},
    {"mov"  , OPC_MOV_I2R_FAR   , 3, 4, "Rf"},
    {"mov"  , OPC_MOV_R2M_FAR   , 3, 4, "fR"},
    {"mov"  , OPC_MOV_R2M_NEAR  , 2, 4, "nR"},
    {"mov"  , OPC_MOV_R2R       , 1, 1, "RR"},
    {"mov"  , OPC_MOV_R2A       , 1, 1, "R"},
    {"mov"  , OPC_MOV_V2R       , 2, 2, "RW"},
    {"mova" , OPC_MOV_V2A       , 2, 1, "W"},
    {"ldfa" , OPC_MOV_D2R       , 1, 2, "R"},
    {"stfa" , OPC_MOV_R2D       , 1, 2, "R"},

    {"add"  , OPC_ADD_RR        , 1, 1, "RR"},
    {"add"  , OPC_ADD_RI        , 2, 2, "RW"},
    {"adc"  , OPC_ADC_RR        , 1, 1, "RR"},
    
    {"sub"  , OPC_SUB_RR        , 1, 1, "RR"},
    {"sub"  , OPC_SUB_RI        , 2, 2, "RW"},
    {"suc"  , OPC_SUC_RR        , 1, 1, "RR"},

    {"shr"  , OPC_SHR_RI        , 1, 1, "RW"},
    {"shl"  , OPC_SHL_RI        , 1, 1, "RW"},
    {"ror"  , OPC_ROR_RI        , 1, 1, "RW"},
    {"rol"  , OPC_ROL_RI        , 1, 1, "RW"},

    {"not"  , OPC_NOT_R         , 1, 1, "R"},
    {"inc"  , OPC_INC_R         , 1, 1, "R"},

    {"and"  , OPC_AND_RR        , 1, 1, "RR"},
    {"or"   , OPC_OR_RR         , 1, 1, "RR"},
    {"nor"  , OPC_NOR_RR        , 1, 1, "RR"},
    {"xor"  , OPC_XOR_RR        , 1, 1, "RR"},
    {"nand" , OPC_NAND_RR       , 1, 1, "RR"},
    {"xnor" , OPC_XNOR_RR       , 1, 1, "RR"},

    {"and"  , OPC_AND_RI        , 2, 2, "RW"},
    {"or"   , OPC_OR_RI         , 2, 2, "RW"},
    {"nor"  , OPC_NOR_RI        , 2, 2, "RW"},
    {"xor"  , OPC_XOR_RI        , 2, 2, "RW"},
    {"nand" , OPC_NAND_RI       , 2, 2, "RW"},
    {"xnor" , OPC_XNOR_RI       , 2, 2, "RW"},

    {"pushb", OPC_PUSHB_FAR     , 3, 5, "f"},
    {"push" , OPC_PUSHW_FAR     , 3, 5, "f"},
    {"push" , OPC_PUSHW_NEAR    , 2, 5, "n"},
    {"push" , OPC_PUSH_REG      , 1, 2, "R"},

    {"ssp"  , OPC_SSP           , 3, 3, "D"},

    {"pop"  , OPC_POP_REG       , 1, 3, "R"},
    {"pop"  , OPC_POP_FAR       , 3, 6, "f"},
    {"popad", OPC_POP_AD        , 4, 1, ""},
    {"pop"  , OPC_POP_NEAR      , 6, 2, "n"},

    {"call" , OPC_CALL_FAR      , 3, 5, "D"},
    {"call" , OPC_CALL_NEAR     , 2, 5, "W"},

    {"ret"  , OPC_RET           , 1, 6, ""},

    {"ien"  , OPC_IEN           , 1, 1, ""},

    {"sint" , OPC_SINT          , 1, 1, ""},

    {"mmov" , OPC_MMOV_ST       , 3, 4, "fR"},
    {"mmov" , OPC_MMOV_LD       , 3, 4, "Rf"},

    {"imov" , OPC_IMOV_LD       , 3, 4, "Rf"},
    {"imov" , OPC_IMOV_ST       , 3, 4, "fR"},
    {"imov" , OPC_IMOV_ST_IMM   , 4, 6, "fW"},

    {"brchf", OPC_BRCH_FLG_FAR  , 3, 5, "DW"},
    {"brchf", OPC_BRCH_FLG_NEAR , 2, 5, "WW"},
    {"brchi", OPC_BRCH_IV_FAR   , 3, 5, "DW"},
    {"brchi", OPC_BRCH_IV_NEAR  , 2, 5, "WW"},

    {"emov" , OPC_MOV_RSA       , 1, 4, "RR"},
    {"iemov", OPC_IMOV_RSA      , 1, 4, "RR"},

    {"dw"   , OPC_DW            , 1, 1, "W"},

    {(char*)NULL, 0, 0, 0, (char*)NULL}, // terminator
};

#endif