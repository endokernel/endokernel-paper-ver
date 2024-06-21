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
#include <sys/stat.h>

#define ISONAME test
#define ISOSAFE 1

#include <iso.h>
int iv_domain_test;

int SYSFILTER startsWith(const char *pre, const char *str) {
    for (int i = 0; ; i++) {
        if (pre[i] == 0)
            return 1;
        if (pre[i] != str[i])
            return 0;
        if (str[i] == 0)
            return 0;
    }
}

int SYSFILTER syscall_callback_pre_1(temporal_ctx_t* ctx, int syscall_no, syscall_req_t *syscall_args) {
    if (syscall_no == SYS_open || syscall_no == SYS_openat) {
        const char *pathname = NULL;
        if (syscall_no == SYS_open) pathname = (const char *)syscall_args->args[0];
        if (syscall_no == SYS_openat) pathname = (const char *)syscall_args->args[1];
        
        if (startsWith("/tmp/disallow1/", pathname)) {
            syscall_args->ret = -13;
            return 1;
        }
    }
    return 0;
}

int SYSFILTER syscall_callback_pre_2(temporal_ctx_t* ctx, int syscall_no, syscall_req_t *syscall_args) {
    if (syscall_no == SYS_open || syscall_no == SYS_openat) {
        const char *pathname = NULL;
        if (syscall_no == SYS_open) pathname = (const char *)syscall_args->args[0];
        if (syscall_no == SYS_openat) pathname = (const char *)syscall_args->args[1];
        if (startsWith("/tmp/disallow2/", pathname)) {
            syscall_args->ret = -13;
            return 1;
        }
    }
    return 0;
}

const syscall_cb_t syscall_cbs[] = {
    syscall_callback_pre_1, // 1
    syscall_callback_pre_2, // 2
    0
};

int ISO_CODE test_nesteddomain(void* x) {
    tid_t tid = (tid_t) x;
    printf("[test_subdomain] Current Domain = %lld, tid = %lld\n", get_tls()->current_domain, tid);
    temporal_set_pre_syscall_cb(2); // nested domain cannot access /tmp/disallow2/
    FILE* f1 = fopen("/tmp/disallow1/file1", "r");
    FILE* f2 = fopen("/tmp/disallow2/file1", "r");
    if (f1 == NULL) {
        printf("* PASS: f1 == NULL\n");
    } else {
        printf("* FAILED: f1 != NULL\n");
        fclose(f1);
    }
    if (f2 == NULL) {
        printf("* PASS: f2 == NULL\n");
    } else {
        printf("* FAILED: f2 != NULL\n");
        fclose(f2);
    }
    return 0;
}

int ISO_CODE test_subdomain(void* x) {
    tid_t tid = (tid_t) x;
    printf("[test_subdomain] Current Domain = %lld, tid = %lld\n", get_tls()->current_domain, tid);
    temporal_set_pre_syscall_cb(1); // subdomain cannot access /tmp/disallow1/
    FILE* f1 = fopen("/tmp/disallow1/file1", "r");
    FILE* f2 = fopen("/tmp/disallow2/file1", "r");
    if (f1 == NULL) {
        printf("* PASS: f1 == NULL\n");
    } else {
        printf("* FAILED: f1 != NULL\n");
        fclose(f1);
    }
    if (f2 != NULL) {
        printf("* PASS: f2 != NULL\n");
        fclose(f2);
    } else {
        printf("* FAILED: f2 == NULL\n");
    }
    tid_t nested = temporal_create(tid);
    temporal_call(test, nested, test_nesteddomain, (void*) nested);
    return 0;
}

void ISO_CODE test_main(tid_t tid1) {
    temporal_call(test, tid1, test_subdomain, (void*) tid1);
}

ISO_ENTRY(test_main);
ISO_ENTRY(test_subdomain);
ISO_ENTRY(test_nesteddomain);

#include <iso_init.h>
#include <iso_align.h>
#include <iso_end.h>

#include <iso_xcall.h>

int main(int argc, char** argv){
    int syscalls[3] = {SYS_open, SYS_openat, SYS_connect};

    struct stat st = {0};
    if (stat("/tmp/disallow1/", &st) == -1) {
        mkdir("/tmp/disallow1/", 0700);
    }
    if (stat("/tmp/disallow2/", &st) == -1) {
        mkdir("/tmp/disallow2/", 0700);
    }
    FILE* f1 = fopen("/tmp/disallow1/file1", "w");
    fprintf(f1, "Hello World\n");
    FILE* f2 = fopen("/tmp/disallow2/file1", "w");
    fprintf(f2, "Bye World\n");
    fclose(f1); fclose(f2);
    
    temporal_init_ex(2, syscalls, syscall_cbs, 0,0);

    tid_t tid1 = temporal_create(0);
    xcall(test, test_main, tid1);
}
