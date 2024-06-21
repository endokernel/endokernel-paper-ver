#ifndef ISONAME
#error "Define ISO Name as your namespace"
#endif
#if __INCLUDE_LEVEL__ != 1
#error "#include <iso.h> directly in your c file"
#endif

#define INIT_DATAALIGN(name) \
static unsigned long __attribute__((section("iv_data_"STR(ISONAME)))) __attribute__((aligned(4096), used)) CONCAT2(iv_data_placeholder1_, name) = {0}; 

#define INIT_CODEALIGN(name) \
static void __attribute__((section("iv_code_"STR(ISONAME)))) __attribute__((aligned(4096), used, naked)) CONCAT2(iv_func_placeholder1_, name)(){};

INIT_DATAALIGN(ISONAME)

INIT_CODEALIGN(ISONAME)
