#include <stdio.h>
#define ISONAME iv_test
#define ISOSAFE 1
#include "iso.h"
#include "isoalloc.h"
struct iv { 
    void* code_begin, *code_end; 
    void* data_begin, *data_end; 
    void* func_begin, *func_end; 
    void* stub;
};
int fake_syscall(int id, struct iv* addr) {
    for (unsigned long* b = addr->func_begin; b!=addr->func_end; b++) {
        printf("%p %p\n", b, *b);
    }
    return 3;
}

void* ISO_CODE test_func (int t) {
    char* mem = iso_mem(1024);
    mem[0] = 0xaa;
    mem[1] = 0xbb;
    mem[2] = t;
    return mem;
}

int ISO_CODE test_read(char* c) {
    return c[2];
}

ISO_ENTRY(test_func);
ISO_ENTRY(test_read);

#include "iso_init.h"

#include "iso_align.h"
#include "iso_end.h"

#include "iso_xcall.h"

int main(){
    printf("%p ~ %p\n", &__start_iv_code_iv_test, &__stop_iv_code_iv_test);
    printf("%p ~ %p\n", &__start_iv_data_iv_test, &__stop_iv_data_iv_test);
    printf("%p ~ %p\n", &__start_iv_functable_iv_test, &__stop_iv_functable_iv_test);
    fflush(stdout);
    //printf("%p ~ %p\n", &__start_iv_iv_test_code, &__stop_iv_iv_test_code);
    char *c = xcall(iv_test, test_func, 123);
    printf("read=%d\n", xcall(iv_test, test_read, c));
    fflush(stdout);
    printf("======should failed when intravirt loaded=========\n");
    printf("pkey_mprotect=%d\n", pkey_mprotect((unsigned long)c&~0xffful, 4096, PROT_READ | PROT_WRITE, 2));
    printf("read=%d\n", c[2]);
}