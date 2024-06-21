
#ifndef BENCHMARK_H
#define BENCHMARK_H

typedef struct task_s {
    // function pointer
    const char* name;
    long long tid;
    int (*init)(struct task_s*);
    int (*done)(struct task_s*);
    int (*test_main)(struct task_s*);
    int (*secondary_main)(struct task_s*);
    int n_main, n_secondary, n_run, n_cur, global;
    int fd, mem;
} __attribute__((packed))  task_t;

//put into a section
#define REG_TASK_INSIDE(name_, init_, done_) \
    task_t task_##name_ = { \
        .name = #name_, \
        .tid = 1, \
        .init = init_, \
        .done = done_, \
        .test_main = test_main, \
        .secondary_main = name_, \
        .n_main = 1, \
        .n_secondary = 0, \
        .n_run = 1, \
        .n_cur = 0, \
        .global = 0, \
        .mem = 0, \
    }; \
    task_t* __attribute__((section("temporal_tasks"))) task_##name_##_ptr = &task_##name_;

#define REG_TASK_INSIDEN(name_, mem_, init_, done_) \
    task_t task_##name_ = { \
        .name = #name_, \
        .tid = 1, \
        .init = init_, \
        .done = done_, \
        .test_main = test_main, \
        .secondary_main = name_, \
        .n_main = 1, \
        .n_secondary = 0, \
        .n_run = 1, \
        .n_cur = 0, \
        .global = 0, \
        .mem = mem_, \
    }; \
    task_t* __attribute__((section("temporal_tasks"))) task_##name_##_ptr = &task_##name_;

#define REG_TASK_CALL(name_, n_main_, n_run_, init_, done_) \
    task_t task_##name_ = { \
        .name = #name_, \
        .tid = 1, \
        .init = init_, \
        .done = done_, \
        .test_main = 0, \
        .secondary_main = 0, \
        .n_main = n_main_, \
        .n_secondary = 0, \
        .n_run = n_run_, \
        .n_cur = 0, \
        .global = 0, \
        .mem = 0, \
    }; \
    task_t* __attribute__((section("temporal_tasks"))) task_##name_##_ptr = &task_##name_;

#define REG_TASK_GLOBAL(name_) \
    task_t task_##name_ = { \
        .name = #name_, \
        .tid = 1, \
        .init = 0, \
        .done = 0, \
        .test_main = name_, \
        .secondary_main = 0, \
        .n_main = 0, \
        .n_secondary = 0, \
        .n_run = 0, \
        .n_cur = 0, \
        .global = 1, \
        .mem = 0, \
    }; \
    task_t* __attribute__((section("temporal_tasks"))) task_##name_##_ptr = &task_##name_;

static __inline__ unsigned long long rdtsc(void){
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#define run(n, fmt) \
_Pragma("GCC ivdep") \
_Pragma("GCC unroll 2") \
for (unsigned long long start = rdtsc(), end = 0; end == 0; end = printf(fmt, (double)(rdtsc() - start) / (double)(n)), 1) \
_Pragma("GCC unroll 32") \
_Pragma("GCC ivdep") \
    for (unsigned long long i = 0; i < n; i++) 

#define run1(n, fmt) \
_Pragma("GCC ivdep") \
_Pragma("GCC unroll 2") \
for (unsigned long long start = rdtsc(), end = 0; end == 0; end = printf(fmt, rdtsc() - start, (n)), 1) \
_Pragma("GCC unroll 32") \
_Pragma("GCC ivdep") \
    for (unsigned long long i = 0; i < n; i++) 

#define syscall_iv_empty 339
#endif