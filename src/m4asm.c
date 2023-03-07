#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock.h>
#include "getopt/getopt.h"
#include "strsep/strsep.h"
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#endif
#include "label.h"
#include "m4asm.h"
#include "insns.h"

void usage(char** argv) {
    fprintf(stderr, "Usage: %s [-i file] [-o file] [-f binary/logisim]\n", argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv) {
    printf("m4asm (C) Charlie Camilleri 2023\n");
    printf("Version 0.9\n\n");

    char *infile = NULL;
    char *outfile = NULL;
    int opt;
    int outformat = OUTFMT_BINARY;

    while ((opt = getopt(argc, argv, "i:o:f:")) != -1) {
        switch (opt) {
        case 'i': 
            infile = strdup(optarg);
            break;
        case 'o': 
            outfile = strdup(optarg);
            break;
        case 'f':
            if (strcmp(optarg,"logisim") == 0) {
                outformat = OUTFMT_LOGISIM;
            } else if (strcmp(optarg, "binary") == 0) {
                outformat = OUTFMT_BINARY;
            } else {
                usage(argv);
            }
            break;
        default:
            usage(argv);
        }
    }

    if (infile == NULL || outfile == NULL) {
        usage(argv);
    }

    printf("Reading %s\n", infile);
    FILE* fp = fopen(infile, "r");
    if (fp == NULL) {
        perror("fopen()");
        exit(-errno);
    }
    char *line = (char*)malloc(32768);

    struct le_context lctx = le_init_context();

    fseek(fp, 0, SEEK_SET);
    while (fgets(line, 32768, fp)) {
        if (ferror(fp)) {
            fclose(fp);
            perror("Reading file");
            exit(-errno);
        }
        line[strcspn(line, "\r\n")] = 0;
        le_initial_count(line, &lctx);
    }
    le_allocate_labels(&lctx);

    fseek(fp, 0, SEEK_SET);
    int insns = 0;
    uint32_t addr = 0;
    while (fgets(line, 32768, fp)) {
        if (ferror(fp)) {
            fclose(fp);
            perror("Reading file");
            exit(-errno);
        }
        line[strcspn(line, "\r\n")] = 0;
        if ((memcmp(line, "$ORG ", 5) == 0 || memcmp(line, "$org ", 5) == 0) && strlen(line)>5) {
            struct parsed_int_t pp = getintval(line + 5);
            if (pp.code != 0) {
                fprintf(stderr, "Error: Invalid origin specified: %s\n", line);
                exit(EXIT_FAILURE);
            }
            addr = pp.value&0xFFFFFFFF;
        } else {
            if (strlen(line) > 2 && le_parse_label(line, addr, &lctx, 1)) {
                struct assembled_insn_t asi = parse_and_assemble_insn(line, &lctx);
                if (asi.length > 0) insns ++;
                addr += asi.length*2;
            }
        }
    }

    fseek(fp, 0, SEEK_SET);
    lctx.stage = 1;

    struct assembled_insn_t *assembled = (struct assembled_insn_t*)malloc(sizeof(struct assembled_insn_t) * insns);
    int c = 0;
    while (fgets(line, 32768, fp)) {
        if (ferror(fp)) {
            fclose(fp);
            perror("Reading file");
            exit(-errno);
        }
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 2 && !le_valid_label(line) && memcmp(line, "$org ",5)!=0 && memcmp(line, "$org ",5)!=0) { 
            struct assembled_insn_t asi = parse_and_assemble_insn(line, &lctx);
            if (asi.length > 0) {
                assembled[c] = asi;
                c++;
            }
        }
    }

    fclose(fp);

    fp = fopen(outfile, "wb");
    if (fp == NULL) {
        perror("Opening output file");
        exit(-errno);
    }

    if (outformat == OUTFMT_BINARY) {
        for (int i=0;i<insns;i++) {
            if (fwrite(assembled[i].data, 2, assembled[i].length, fp) != assembled[i].length) {
                perror("fwrite");
                exit(-errno);
            }
            if (ferror(fp)) {
                exit(-errno);
            }
        }
    } else if (outformat == OUTFMT_LOGISIM) {
        char* hdr = "v3.0 hex words addressed\n";
        if (fwrite(hdr, 1, strlen(hdr), fp) != (strlen(hdr))) {
            perror("fwrite");
            exit(-errno);
        }

        uint32_t a = 0;
        for (int i=0;i<insns;i++) {
            // 01234567: abcd dead f00d
            char* outline = (char*)malloc(10 + (5 * assembled[i].length) + 2);
            memset(outline, 0, 10 + (5 * assembled[i].length) + 2);
            snprintf(outline, 10 + (5 * assembled[i].length) + 1, "%08X: ", a);
            for (int j=0;j<assembled[i].length;j++) {
                char buf[6];
                snprintf(buf, 6, "%04x ",htons(assembled[i].data[j]));
                memcpy(outline + 10 + (5*j), buf, 5);
            }
            outline[strlen(outline)-1] = '\n';
            if (fwrite(outline, 1, strlen(outline), fp) != (strlen(outline))) {
                perror("fwrite");
                exit(-errno);
            }

            free(outline);
            a += assembled[i].length;
        }
    }

    fclose(fp);
    free(assembled);
    free(infile);
    free(outfile);
    le_free_labels(&lctx);
}

void print_assembled_insn(struct assembled_insn_t in) {
    printf("INSN LEN=%d\n", in.length);
    for (int i=0;i<in.length;i++) {
        printf("   WORD %d\t0x%02X%02X\n",i, ((unsigned char*)&in.data[i])[0], ((unsigned char*)&in.data[i])[1]);
    }
} 

struct assembled_insn_t parse_and_assemble_insn(char* data, struct le_context *lctx) {
    struct assembled_insn_t ret;
    memset(&ret, 0, sizeof(ret));

    char* token, *mustfree, *dup;
    mustfree = dup = strdup(data);
    int numflds = 0;
    char* values[16];
    while ((token = strsep(&dup, " ")) && numflds < 16) {
        values[numflds] = (char*)malloc(strlen(token) +1);
        strcpy(values[numflds], token);
        numflds++;
    }

    char ptypes[17];
    struct parsed_param_t pvs[16];
    memset(ptypes,0,17);
    memset(pvs, 0, sizeof(struct parsed_param_t) * 16);

    for (int i=1;i<numflds;i++) {
        struct parsed_param_t pp = parse_param(values[i], lctx);
        if (pp.code != 0) {
            fprintf(stderr, "Error parsing parameter: %s\n", values[i]);
            exit(EXIT_FAILURE);
        }
        ptypes[i-1] = pp.type;
        pvs[i-1] = pp;
    }

    STRTOLOWER(values[0]);
    int c = 0;
    struct insn_def_t cd, best;
    best.cycles = 999;
    while ((cd = insns[c]).mnemonic != NULL) {
        c++;
        if (strcmp(values[0], cd.mnemonic)!=0) continue;
        if (strcmp(ptypes, cd.params)) continue;

        if (cd.cycles < best.cycles) best = cd;
    }

    if (best.cycles == 999) {
        fprintf(stderr, "Error: Cannot find instruction with mnemonic %s and ptypes [%s]\n", values[0], ptypes);
        exit(EXIT_FAILURE);
    }

    int p0 = pvs[0].value;
    int p1 = pvs[1].value;
    int p2 = pvs[2].value;
    int p3 = pvs[3].value;

    for (int i=0;i<numflds;i++) free(values[i]);
    free(mustfree);
    return assemble_insn(best.opcode, p0, p1, p2, p3);
}

struct assembled_insn_t assemble_insn(int opcode, uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3) {
    struct assembled_insn_t ret;
    memset(&ret, 0, sizeof(ret));
    switch (opcode) {
        case OPC_NOP: // NO PARAMS
            ret.length = 1;
            ret.data[0] = htons(OPC_NOP);
            break;

        // Jumps
        case OPC_JMP_FAR: // p0: full address
            ret.length = 3;
            ret.data[0] = htons(OPC_JMP_FAR);
            ret.data[2] = l16(p0);
            ret.data[1] = u16(p0);
            break;
        case OPC_JMP_NEAR: // p0: near address
            ret.length = 2;
            ret.data[0] = htons(OPC_JMP_NEAR);
            ret.data[1] = l16(p0);
            break;

        // MOVs
        case OPC_MOV_I2R_NEAR: // p0: register to move value to, p1: near address to load from
            ret.length = 2;
            ret.data[0] = htons(OPC_MOV_I2R_NEAR) | htons((p0&0xF)<<8);
            ret.data[1] = l16(p1);
            break;
        case OPC_MOV_I2R_FAR: // p0: register to move value to, p1: far address to load 
            ret.length = 3;
            ret.data[0] = htons(OPC_MOV_I2R_FAR) | htons((p0&0xF)<<8);
            ret.data[1] = u16(p1);
            ret.data[2] = l16(p1);
            break;
        case OPC_MOV_R2M_FAR: // p0: far dest address, p1: src register
            ret.length = 3;
            ret.data[0] = htons(OPC_MOV_R2M_FAR) | htons((p1&0xF)<<8);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_MOV_R2M_NEAR: // p0: near dest address, p1: src register
            ret.length = 2;
            ret.data[0] = htons(OPC_MOV_R2M_NEAR) | htons((p1&0xF)<<8);
            ret.data[1] = l16(p0);
            break;
        case OPC_MOV_R2R: // p0: dest reg, p1: src reg
            ret.length = 1;
            ret.data[0] = htons(OPC_MOV_R2R) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;
        case OPC_MOV_R2A: // p0: src reg
            ret.length = 1;
            ret.data[0] = htons(OPC_MOV_R2A) | htons((p0&0xF)<<12);
            break;
        case OPC_MOV_V2R: // p0: dest reg, p1: 16-bit value
            ret.length = 2;
            ret.data[0] = htons(OPC_MOV_V2R) | htons((p0&0xF)<<8);
            ret.data[1] = l16(p1);
            break;
        case OPC_MOV_V2A: // p0: 16-bit value
            ret.length = 2;
            ret.data[0] = htons(OPC_MOV_V2A);
            ret.data[1] = l16(p0);
            break;
        case OPC_MOV_D2R: // p0: dest register
            ret.length = 1;
            ret.data[0] = htons(OPC_MOV_D2R) | htons((p0&0xF)<<8);
            break;
        case OPC_MOV_R2D: // p0: src register
            ret.length = 1;
            ret.data[0] = htons(OPC_MOV_R2D) | htons((p0&0xF)<<8);
            break;

        // ADD
        case OPC_ADD_RR: // p0: register, p1: r with number to add to p0
            ret.length = 1;
            ret.data[0] = htons(OPC_ADD_RR) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;
        case OPC_ADD_RI: // p0: register, p1: imm value
            ret.length = 2;
            ret.data[0] = htons(OPC_ADD_RI) | htons((p0&0xF)<<8);
            ret.data[1] = l16(p1);
            break;
        case OPC_ADC_RR: // p0: register, p1: r with number to add to p0 with carry
            ret.length = 1;
            ret.data[0] = htons(OPC_ADC_RR) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;

        // SUB
        case OPC_SUB_RR: // p0: register, p1: r with number to sub from p0
            ret.length = 1;
            ret.data[0] = htons(OPC_SUB_RR) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;
        case OPC_SUB_RI: // p0: register, p1: imm value
            ret.length = 2;
            ret.data[0] = htons(OPC_SUB_RI) | htons((p0&0xF)<<8);
            ret.data[1] = l16(p1);
            break;
        case OPC_SUC_RR: // p0: register, p1: r with number to sub from p0 with carry/borrow
            ret.length = 1;
            ret.data[0] = htons(OPC_SUC_RR) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;

        // Rotates
        case OPC_SHL_RI:
        case OPC_SHR_RI:
        case OPC_ROL_RI:
        case OPC_ROR_RI: // p0: affected register, p1: number of shifts or rotates
            ret.length = 1;
            ret.data[0] = htons(opcode) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;

        // 1-operand logic
        case OPC_NOT_R: // p0: register to invert
        case OPC_INC_R:
            ret.length = 1;
            ret.data[0] = htons(opcode) | htons((p0&0xF)<<8);
            break;

        // R+R logic
        case OPC_AND_RR:
        case OPC_OR_RR:
        case OPC_XOR_RR:
        case OPC_XNOR_RR:
        case OPC_NOR_RR:
        case OPC_NAND_RR: // p0: affected register, p1: second operand (reg)
            ret.length = 1;
            ret.data[0] = htons(opcode) | htons((p0&0xF)<<8) | htons((p1&0xF)<<12);
            break;

        // R+I logic
        case OPC_AND_RI:
        case OPC_OR_RI:
        case OPC_XOR_RI:
        case OPC_XNOR_RI:
        case OPC_NOR_RI:
        case OPC_NAND_RI: // p0: affected register, p1: second operand (imm)
            ret.length = 2;
            ret.data[0] = htons(opcode) | htons((p0&0xF)<<8);
            ret.data[1] = l16(p1);
            break;

        // PUSH
        case OPC_PUSHB_FAR: // p0: address to fetch byte from
            ret.length = 3;
            ret.data[0] = htons(OPC_PUSHB_FAR);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_PUSHW_FAR: // p0: address to fetch word from
            ret.length = 3;
            ret.data[0] = htons(OPC_PUSHW_FAR);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_PUSHW_NEAR: // p0: near address to fetch word from
            ret.length = 2;
            ret.data[0] = htons(OPC_PUSHW_NEAR);
            ret.data[1] = l16(p0);
            break;
        case OPC_PUSH_REG: // p0: reg ID
            ret.length = 1;
            ret.data[0] = htons(OPC_PUSH_REG) | htons((p0&0xF)<<8);
            break;
        
        // SSP
        case OPC_SSP: // p0: address to put stack
            ret.length = 3;
            ret.data[0] = htons(OPC_SSP);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;

        // POP
        case OPC_POP_REG: // p0: regid
            ret.length = 1;
            ret.data[0] = htons(OPC_POP_REG) | htons((p0&0xF)<<8);
            break;
        case OPC_POP_FAR: // p0: far address
            ret.length = 3;
            ret.data[0] = htons(OPC_POP_FAR);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_POP_AD: // popad
            ret.length = 1;
            ret.data[0] = htons(OPC_POP_AD);
            break;
        case OPC_POP_NEAR: // p0: near address
            ret.length = 2;
            ret.data[0] = htons(OPC_POP_NEAR);
            ret.data[1] = l16(p0);
            break;

        // CALL
        case OPC_CALL_FAR: // p0: far address
            ret.length = 3;
            ret.data[0] = htons(OPC_CALL_FAR);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_CALL_NEAR: // p0: near address
            ret.length = 2;
            ret.data[0] = htons(OPC_CALL_NEAR);
            ret.data[1] = l16(p0);
            break;

        // RET
        case OPC_RET:
            ret.length = 1;
            ret.data[0] = htons(OPC_RET);
            break;

        // IEN
        case OPC_IEN:
            ret.length = 1;
            ret.data[0] = htons(OPC_IEN);
            break;

        // SINT
        case OPC_SINT:
            ret.length = 1;
            ret.data[0] = htons(OPC_SINT);
            break;

        // MMOV
        case OPC_MMOV_ST: // p0: destination mgmt addr, p1: source reg
            ret.length = 3;
            ret.data[0] = htons(OPC_MMOV_ST) | htons((p1&0xF)<<8);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_MMOV_LD: // p0: dest reg, p1: source mgmt addr
            ret.length = 3;
            ret.data[0] = htons(OPC_MMOV_LD) | htons((p0&0xF)<<8);
            ret.data[1] = u16(p1);
            ret.data[2] = l16(p1);
            break;

        // IMOV
        case OPC_IMOV_LD: // p0: dest reg, p1: source addr
            ret.length = 3;
            ret.data[0] = htons(OPC_IMOV_LD) | htons((p0&0xF)<<8);
            ret.data[1] = u16(p1);
            ret.data[2] = l16(p1);
            break;
        case OPC_IMOV_ST: // p0: dest addr, p1: source reg
            ret.length = 3;
            ret.data[0] = htons(OPC_IMOV_ST) | htons((p1&0xF)<<8);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_IMOV_ST_IMM: // p0: dest addr, p1: imm value
            ret.length = 4;
            ret.data[0] = htons(OPC_IMOV_ST_IMM);
            ret.data[1] = l16(p1);
            ret.data[2] = u16(p0);
            ret.data[3] = l16(p0);
            break;

        // BRCH
        case OPC_BRCH_FLG_FAR: // p0: addr, p1: flags to test
            ret.length = 3;
            ret.data[0] = htons(OPC_BRCH_FLG_FAR) | htons((p1&0xF)<<12);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_BRCH_FLG_NEAR: // p0: addr, p1: flags to test
            ret.length = 2;
            ret.data[0] = htons(OPC_BRCH_FLG_FAR) | htons((p1&0xF)<<12);
            ret.data[1] = l16(p0);
            break;
        case OPC_BRCH_IV_FAR: // p0: addr, p1: IV to test
            ret.length = 3;
            ret.data[0] = htons(OPC_BRCH_IV_FAR) | htons((p1&0xFF)<<8);
            ret.data[1] = u16(p0);
            ret.data[2] = l16(p0);
            break;
        case OPC_BRCH_IV_NEAR: // p0: addr, p1: IV to test
            ret.length = 2;
            ret.data[0] = htons(OPC_BRCH_IV_FAR) | htons((p1&0xFF)<<8);
            ret.data[1] = l16(p0);
            break;

        // EMOV (IO and otherwise), see docs. RSA=Register specified address. p0 = T, p1 = R
        case OPC_IMOV_RSA:
        case OPC_MOV_RSA:
            ret.length = 1;
            ret.data[0] = htons(opcode) | htons((p0&0xF)<<12) | htons((p1&0xF)<<8);
            break;

        // Special (assemblers-specific)
        case OPC_DW: // p0: binary data
            ret.length = 1;
            ret.data[0] = l16(p0);
            break;

        default:
            fprintf(stderr, "ERROR: Illegal instruction opcode=0x%04X\n",opcode);
            exit(EXIT_FAILURE);
    }

    return ret;
}

struct parsed_int_t getintval(char* f) {
    struct parsed_int_t ret;
    ret.code = 1;
    ret.strlength = strlen(f);
    if (strspn(f, "0123456789") == strlen(f)) {ret.code = 0; ret.value=strtol(f, NULL, 10);};
    if (strncmp(f, "0x", 2) == 0 && strspn(f+2, "0123456789abcdefABCDEF") == strlen(f)-2) {ret.code = 0; ret.value=strtol(f+2, NULL, 16);}
    if (strncmp(f, "0b", 2) == 0 && strspn(f+2, "01") == strlen(f)-2) {ret.code = 0; ret.value=strtol(f+2, NULL, 2);}

    return ret;
}

struct parsed_param_t parse_param(char* p, struct le_context *lctx) {
    char* cpy = strdup(p);
    if (cpy[strlen(cpy)-1] == ',') cpy[strlen(cpy)-1] = 0;
    struct parsed_param_t ret;
    ret.type = 'X';
    ret.code = 1;
    if (cpy[0] == '[' && p[strlen(cpy) - 1] == ']') { // FAR pointer [0xDEADBEEF]
        cpy[strlen(cpy) - 1] = 0;
        ret.code = 0;
        struct parsed_int_t iv = getintval(cpy+1);
        if (iv.code != 0 || iv.value > 0xFFFFFFFF) {
            //fprintf(stderr, "Error: Invalid parameter value (PTYPE_FAR_PTR): %s\n", p);
            //exit(EXIT_FAILURE);
            ret.value = le_get_label_addr(cpy+1, lctx);
            ret.type = PTYPE_FAR_PTR;
        } else {
            ret.value = iv.value&0xFFFFFFFF;
            ret.type = PTYPE_FAR_PTR;
        }
    } else if (cpy[0] == '(' && p[strlen(cpy) - 1] == ')') { // NEAR pointer (0xF00D)
        cpy[strlen(cpy) - 1] = 0;
        ret.code = 0;
        struct parsed_int_t iv = getintval(cpy+1);
        if (iv.code != 0 || iv.value > 0xFFFF) {
            //fprintf(stderr, "Error: Invalid parameter value (PTYPE_NEAR_PTR): %s\n", p);
            //exit(EXIT_FAILURE);
            ret.value = le_get_label_addr(cpy+1, lctx)&0xFFFF;
            ret.type = PTYPE_NEAR_PTR;
        } else {
            ret.value = iv.value&0xFFFF;
            ret.type = PTYPE_NEAR_PTR;
        }
    } else if (cpy[0] == 'r') { // REGISTER r?
        ret.code = 0;
        struct parsed_int_t iv = getintval(cpy+1);
        if (iv.code != 0 || iv.value > 0xF) {
            fprintf(stderr, "Error: Invalid parameter value (PTYPE_REGISTER): %s\n", p);
            exit(EXIT_FAILURE);
        }
        ret.value = iv.value&0xF;
        ret.type = PTYPE_REGISTER;
    } else if (cpy[0] == 'd') { // DWORD IMM
        ret.code = 0;
        struct parsed_int_t iv = getintval(cpy+1);
        if (iv.code != 0 || iv.value > 0xFFFFFFFF) {
            fprintf(stderr, "Error: Invalid parameter value (PTYPE_DWORD_IMM): %s\n", p);
            exit(EXIT_FAILURE);
        }
        ret.value = iv.value&0xFFFFFFFF;
        ret.type = PTYPE_DWORD_IMM;
    } else {
        ret.code = 0;
        struct parsed_int_t iv = getintval(cpy);
        if (iv.code != 0 || iv.value > 0xFFFFFFFF) {
            //fprintf(stderr, "Error: Invalid parameter value (PTYPE_WORD_IMM): %s\n", p);
            //exit(EXIT_FAILURE);
            ret.value = le_get_label_addr(cpy, lctx);
            ret.type = PTYPE_DWORD_IMM;
        } else {
            if (iv.value > 0xFFFF) {
                ret.value = iv.value&0xFFFFFFFF;
                ret.type = PTYPE_DWORD_IMM;
            } else {
                ret.value = iv.value;
                ret.type = PTYPE_WORD_IMM;
            }
        }
    }

    free(cpy);
    return ret;
}