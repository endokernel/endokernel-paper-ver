#ifndef _APP_H_
#define _APP_H_

#include <mt.h>
typedef struct {
    void* code_begin, *code_end;
    void* data_begin, *data_end;
    void* func_begin, *func_end;
    void* stub;
    void* iv_domain_mark; // size=8192
} iv_encapslation_v1_t;


typedef enum box_e {
    SAND,
    SAFE,
    UN,
    RESERVED,
    FRIEND,
} box_t;

typedef struct {
    void* code_begin, *code_end;
    void* data_begin, *data_end;
    void* func_begin, *func_end;
    void* stub_begin, *stub_end;
    void* iv_domain_mark; // size=8192
    box_t box_type;
} iv_encapslation_t;


void app_alloc_stack(iv_tls_t* tls);

int install_app(char* buf, int domain_id, box_t safe);

int app_allow_outer_promote(int domain_id);

int install_app2(int domain_id, char* _link[], int* domain_id_addr[]);

void app_update_tls(int domain_id, box_t boxtype);

extern int id_allocated[16];
extern box_t id_box[16];

#endif