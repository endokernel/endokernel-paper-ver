#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/syscall.h>
#include <asm/unistd.h>

#include <temporal.h>

#define _GNU_SOURCE
#include <sys/mman.h>
#define _APP
#include <mt.h>

#define ISONAME test
#define ISOSAFE 1

#include <iso.h>
int iv_domain_test;
struct x {
    int n;
    int tid;
    char*mems[2];
};

int ISO_CODE test_subdomain(void* x) {
    printf("Current Domain = %lld\n", get_tls()->current_domain);
    struct x* xx = (struct x*)x;
    printf("%s\n", xx->mems[xx->n]);
}

char* ISO_CODE test_create_new_mem(void* x) {
    printf("Current Domain = %lld\n", get_tls()->current_domain);
    struct x* xx = (struct x*)x;
    xx->mems[xx->n] = temporal_alloc(xx->tid, 4096);
    printf("create mem %p\n", xx->mems[xx->n]);
    strcpy(xx->mems[xx->n], "tid1's secret");
    xx->mems[xx->n][3] = xx->tid + '0';
    return xx->mems[xx->n];
}

void ISO_CODE test_main12(int tid1, int tid2, int n) {
    char* tid1_mem = temporal_alloc(tid1, 4096);
    char* tid2_mem = temporal_alloc(tid2, 4096);
    strcpy(tid1_mem, "tid1's secret");
    strcpy(tid2_mem, "tid2's secret");
    struct x data1;
    if (n == 1)
        data1.n = 0;
    if (n == 2)
        data1.n = 1;
    data1.tid = tid1;
    data1.mems[0] = tid1_mem;
    data1.mems[1] = tid2_mem;
    temporal_call(test, tid1, test_subdomain, &data1);
    struct x data2;
    if (n == 1)
        data1.n = 0;
    if (n == 2)
        data1.n = 1;
    data2.tid = tid2;
    data2.mems[0] = tid2_mem;
    data2.mems[1] = tid1_mem;
    temporal_call(test, tid2, test_subdomain, &data2);
}

void ISO_CODE test_main3(int tid1, int tid2, int n) {
    struct x data1;
    data1.tid = tid1;
    data1.n = 0;
    char* mem1 = temporal_call(test, tid1, test_create_new_mem, &data1);
    printf("mem1 = %s\n", mem1);
    
    struct x data2;
    data2.tid = tid2;
    data2.n = 0;
    char* mem2 = temporal_call(test, tid2, test_create_new_mem, &data2);
    printf("mem2 = %s\n", mem2);
    //*((unsigned long*)get_tls()->app_stack[0])
    if (n == 1) {
        temporal_call(test, tid1, test_subdomain, &data1);
        temporal_call(test, tid2, test_subdomain, &data2);
    }

    if (n == 2) {
        temporal_call(test, tid1, test_subdomain, &data2);
        temporal_call(test, tid2, test_subdomain, &data1);
    }
}

int ISO_CODE test_forbidcall(void* x) {
    struct x* xx = (struct x*)x;
    if (xx->n != 0) {
        printf("I'm domain %d, calling %d\n", xx->tid, xx->n);
        xx->n = 0;
        temporal_call(test, xx->n, test_forbidcall, x);
    } else {
        printf("failed, you should not call me. domain=%lld\n", get_tls()->current_domain);
    }
}

void ISO_CODE test_main4(int tid1, int tid2, int n) {
    struct x data1;
    data1.tid = tid1;
    data1.n = tid2;
    temporal_call(test, data1.tid, test_forbidcall, &data1);
    data1.tid = tid2;
    data1.n = tid1;
    temporal_call(test, data1.tid, test_forbidcall, &data1);
}


int ISO_CODE empty_xcall() {
    return 0;
}

ISO_ENTRY(empty_xcall);
ISO_ENTRY(test_main12);
ISO_ENTRY(test_main3);
ISO_ENTRY(test_main4);
ISO_ENTRY(test_subdomain);
ISO_ENTRY(test_create_new_mem);
ISO_ENTRY(test_forbidcall);

#include <iso_init.h>
#include <iso_align.h>
#include <iso_end.h>

#undef ISONAME
#define ISONAME nested
#define ISOSAFE 1

#include <iso.h>

int iv_domain_nested;
int ISO_CODE proxy(int(*func)(int,int), int tid1, int tid2) {
    return func(tid1, tid2);
}
ISO_ENTRY(proxy);

#include <iso_init.h>
#include <iso_align.h>
#include <iso_end.h>

#include <iso_xcall.h>


int access_own_data(int tid1, int tid2){
    printf("Test 1: Tcall without changing sid\n");
    xcall(test, test_main12, tid1, tid2, 1);
}

int access_others_data(int tid1, int tid2){
    printf("Test 2: Tcall without changing sid, violation\n");
    xcall(test, test_main12, tid1, tid2, 2);
}

int create_memory_in_domain(int tid1, int tid2){
    printf("Test 3: Tcall without changing sid, create memory in temporal domain\n");
    xcall(test, test_main3, tid1, tid2, 0);
}

int access_owm_mem_created_in_domain(int tid1, int tid2){
    printf("Test 4: Tcall without changing sid, create memory in temporal domain and access after that\n");
    xcall(test, test_main3, tid1, tid2, 1);
}

int access_others_mem_created_in_domain(int tid1, int tid2){
    printf("Test 5: Tcall without changing sid, create memory in temporal domain and access others memory after that; violation\n");
    xcall(test, test_main3, tid1, tid2, 2);
}

int call_another_domain_in_domain0(int tid1, int tid2){
    printf("Test 6: Tcall without changing sid, Call another domain; violation\n");
    xcall(test, test_main4, tid1, tid2, 0);
}

static __inline__ unsigned long long rdtsc(void){
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#define run(n, fmt) \
_Pragma("GCC ivdep") \
_Pragma("GCC unroll 2") \
for (unsigned long start = rdtsc(), end = 0; end == 0; end = printf(fmt, (double)(rdtsc() - start) / n)) \
_Pragma("GCC unroll 32") \
_Pragma("GCC ivdep") \
    for (unsigned long i = 0; i < n; i++) 
int call_cost(int tid1, int tid2){
    //printf("Test 7: call costs\n");
    #define syscall_iv_empty 339
    #define syscall_iv_force_getppid 340
    {
        run(100000, "%f\n") {
            syscall(syscall_iv_empty);
        }
    }
    
    {
        run(100000, "%f\n") {
            syscall(__NR_getppid);
        }
    }
    {
        run(10000000, "%f\n") {
            syscall(340);
        }
    }
    
    {
        run(10000000, "%f\n") {
            xcall(test, empty_xcall);
        }
    }
    {
        run(10000000, "%f\n") {
            temporal_call(test, tid2, empty_xcall, 0);
        }
    }
    char* tid1_mem = temporal_alloc(tid1, 4096);
    {
        run(10000, "%f\n") {
            temporal_call(test, tid1, empty_xcall, 0);
        }
    }
}

int(*funcs[])(int, int) = {
    access_own_data, access_others_data, 
    create_memory_in_domain, access_owm_mem_created_in_domain, access_others_mem_created_in_domain, 
    call_another_domain_in_domain0,call_cost
};

int main(int argc, char** argv){
    //printf("iv_domain_test = %d\n", iv_domain_test);
    //printf("iv_domain_nested = %d\n", iv_domain_nested);
    //printf("Two tids created %d %d\n", tid1, tid2);
    if (argc == 2) {
        int nTest = atoi(argv[1]) - 1;
        int maxTest = sizeof(funcs) / sizeof(funcs[0]);
        int tid1 = 0, tid2 = 0;
        temporal_init();
        tid1 = temporal_create(0);
        tid2 = temporal_create(0);
        if (nTest >= 0 && nTest < maxTest) 
            funcs[nTest](tid1, tid2);
        else {
            nTest -= maxTest;
            if (nTest >= 0 && nTest < maxTest) 
                xcall(nested, proxy, funcs[nTest], tid1 ,tid2);
        }
    }

}
