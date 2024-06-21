#include <stdio.h>
#define ISONAME iv_test
#define ISOSAFE 0
#include "iso.h"
extern unsigned long iv_domain_iv_test;
struct iv { 
    void* code_begin, *code_end; 
    void* data_begin, *data_end; 
    void* func_begin, *func_end; 
    void* stub;
};

int ISO_CODE times(int x, int y) {
    return x * y;
}
int ISO_CODE times_s(int x, int y) {
    syscall(1, 1, "Writing\n", 8);
    return x * y;
}
int outer;
int ISO_CODE times_c(int x, int y) {
    outer = x*y;
    return outer;
}

ISO_ENTRY(times);
ISO_ENTRY(times_s);
ISO_ENTRY(times_c);

#include "iso_init.h"

#include "iso_align.h"
#include "iso_end.h"

#include "iso_xcall.h"

int main(){
    printf("%p ~ %p\n", &__start_iv_code_iv_test, &__stop_iv_code_iv_test);
    printf("%p ~ %p\n", &__start_iv_data_iv_test, &__stop_iv_data_iv_test);
    printf("%p ~ %p\n", &__start_iv_functable_iv_test, &__stop_iv_functable_iv_test);
    fflush(stdout);
    printf("Now I'm calling a normal sandbox function.\n");
    fflush(stdout);
    //printf("%p ~ %p\n", &__start_iv_iv_test_code, &__stop_iv_iv_test_code);
    printf("A function that has no syscall  should return without problem: 4*5=%d\n", xcall(iv_test, times, 4,5));
    fflush(stdout);
    printf("A function that has no syscall  should return without problem: 4*5=%d\n", xcall(iv_test, times, 4,5));
    fflush(stdout);
    printf("------------------- crash should happen --------------\n");
    xcall(iv_test, times_c, 6,6);
}