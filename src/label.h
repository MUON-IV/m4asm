#ifndef LABEL_H
#define LABEL_H

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct label {
    char name[33];
    uint32_t address;
};

struct le_context {
    int nlabels;
    int idx;
    struct label *labels;
    int stage;
};

struct le_context le_init_context();
void le_initial_count(char* str, struct le_context *context);
void le_allocate_labels(struct le_context *context);
void le_free_labels(struct le_context *ctx);
int le_parse_label(char* line, uint32_t addr, struct le_context *ctx, int apply);
uint32_t le_get_label_addr(char* labelname, struct le_context *ctx);
int le_valid_label(char* line);

#endif