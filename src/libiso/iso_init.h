#ifndef ISONAME
#error "Define ISO Name as your namespace"
#endif
#if __INCLUDE_LEVEL__ != 1
#error "#include <iso.h> directly in your c file"
#endif

// need to update this id
#ifndef ISO_SCALL_ID
#define ISO_SCALL_ID 333
#endif

#ifndef CONCAT3
#define _CONCAT2(x,y) x##y
#define CONCAT2(x,y) _CONCAT2(x,y)
#define _CONCAT3(x,y,z) x##y##z
#define CONCAT3(x,y,z) _CONCAT3(x,y,z)
#define _CONCAT4(x,y,z,q) x##y##z##q
#define CONCAT4(x,y,z,q) _CONCAT4(x,y,z,q)
#endif
#ifndef ISO_EXTERN
#define ISO_EXTERN \
extern char CONCAT2(__start_iv_code_,name), CONCAT2(__stop_iv_code_,name); \
extern char CONCAT2(__start_iv_data_,name), CONCAT2(__stop_iv_data_,name); \
extern char CONCAT2(__start_iv_functable_,name), CONCAT2(__stop_iv_functable_,name);
ISO_EXTERN(ISONAME)
#endif

#define INIT_STUB(name)  \
ISO_HIDDEN __attribute__((section("iv_stub_"STR(name)))) __attribute__((aligned(4096), naked)) void CONCAT2(_xcall_stub_, name)(){ \
    __asm__ (".fill 8192, 1, 0xcc"); \
} \
struct { \
    void* code_begin, *code_end; \
    void* data_begin, *data_end; \
    void* func_begin, *func_end; \
    void* stub, *iv_domain_mark; \
} CONCAT2(iv_encapslation_, name) = { \
    &CONCAT2(__start_iv_code_, name), &CONCAT2(__stop_iv_code_, name), \
    &CONCAT2(__start_iv_data_, name), &CONCAT2(__stop_iv_data_, name), \
    &CONCAT2(__start_iv_functable_, name), &CONCAT2(__stop_iv_functable_, name), \
    &CONCAT2(_xcall_stub_,name), &CONCAT2(iv_domain_, name), \
}; \
void __attribute__((constructor)) CONCAT2(_iv_init_, name)(){ \
    CONCAT2(iv_encapslation_, name).code_end = (unsigned long)(CONCAT2(iv_encapslation_, name).code_end) & ~4095ul;\
    CONCAT2(iv_encapslation_, name).data_end = (unsigned long)(CONCAT2(iv_encapslation_, name).data_end) & ~4095ul;\
    syscall(ISO_SCALL_ID + 1 - ISOSAFE, &CONCAT2(iv_encapslation_, name)); \
}

INIT_STUB(ISONAME)

#define INIT_DATASTUB(name) \
static __attribute__((section("iv_data_"STR(ISONAME)))) __attribute__((aligned(4096), used)) unsigned long CONCAT2(iv_data_placeholder_, name) = {0}; 

#define INIT_CODESTUB(name) \
static __attribute__((section("iv_code_"STR(ISONAME)))) __attribute__((aligned(4096), used, naked)) void CONCAT2(iv_func_placeholder_, name)(){};

INIT_DATASTUB(ISONAME)

INIT_CODESTUB(ISONAME)
