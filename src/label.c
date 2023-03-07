#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "m4asm.h"
#include "label.h"

struct le_context le_init_context() {
    struct le_context ret;
    ret.idx = 0;
    ret.labels = NULL;
    ret.nlabels = 0;
    ret.stage = 0;
    return ret;
}

void le_initial_count(char* str, struct le_context *ctx) {
    if (str[strlen(str)-1] == ':') {
        ctx->nlabels++;
    }
}

void le_allocate_labels(struct le_context *ctx) {
    ctx->labels = (struct label*)malloc(sizeof(struct label) * ctx->nlabels);
}

void le_free_labels(struct le_context *ctx) {
    if(ctx->labels != NULL) free(ctx->labels);
}

int le_parse_label(char* line, uint32_t addr, struct le_context *ctx, int apply) {
    if (ctx->idx >= ctx->nlabels) return 1;
    if (line[strlen(line)-1] != ':') return 1;

    if (!apply) return 0;

    char* s = strdup(line);
    s[strlen(s)-1] = 0;

    strncpy(ctx->labels[ctx->idx].name, s, 32);
    ctx->labels[ctx->idx].address = addr;
    ctx->idx++;

    free(s);
    return 0;
}

int le_valid_label(char* line) {
    if (line[strlen(line)-1] != ':') return 0;
    return 1;
}

uint32_t le_get_label_addr(char* labelname, struct le_context *ctx) {
    for (int i=0;i<ctx->nlabels;i++) {
        if (strcmp(ctx->labels[i].name, labelname) != 0) continue;

        return ctx->labels[i].address;
    }
    if (ctx->stage == 1) {fprintf(stderr, "[LE] Error: Label not found: %s\n", labelname);exit(EXIT_FAILURE);}
    return 0;
}