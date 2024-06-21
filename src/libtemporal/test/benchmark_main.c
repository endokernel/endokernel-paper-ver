#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/syscall.h>
#include <asm/unistd.h>

#define _GNU_SOURCE
#include <sys/mman.h>

#include "benchmark.h"


#ifdef HAS_TEMPORAL

#include <temporal.h>

#define _APP
#include <mt.h>

#define ISONAME test
#define ISOSAFE 1

#include <iso.h>
int iv_domain_test;

int ISO_CODE test_main(task_t* task) {
    task->secondary_main(task);
}

int ISO_CODE test_empty(task_t* task) {
    // task->secondary_main(task);
    return 0;
}

int ISO_CODE test_init(task_t* task) {
    if (task->init)
        task->init(task);
}

int ISO_CODE test_done(task_t* task) {
    if (task->done)
        task->done(task);
}

int ISO_CODE empty_xcall() {
    return 0;
}

ISO_ENTRY(empty_xcall);
ISO_ENTRY(test_main);
ISO_ENTRY(test_init);
ISO_ENTRY(test_done);
ISO_ENTRY(test_empty);

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

#else

int test_main(task_t* task) {
    // printf("task_main\n");
    task->secondary_main(task);
}

int test_empty(task_t* task) {
    // task->secondary_main(task);
    return 0;
}

int test_init(task_t* task) {
    if (task->init)
        task->init(task);
}

int test_done(task_t* task) {
    if (task->done)
        task->done(task);
}

#pragma GCC push_options
#pragma GCC optimize ("O0")

int volatile __attribute__((noinline)) empty_xcall() {
    asm volatile ("": : :"memory");
    return 0;
}

#pragma GCC pop_options
#endif

#include "cases.h"

extern task_t* __start_temporal_tasks[];
extern task_t* __stop_temporal_tasks[];

#ifdef HAS_TEMPORAL

int fds[4096];
int open_test = 0;
// syscall_cb_t
int syscall_cb_pre(temporal_ctx_t* ctx, int syscall_no, syscall_req_t *syscall_args) {
    if (SYS_open == syscall_no) {
        // check if open file is /dev/null
        if (strcmp(syscall_args->args[0], "/dev/null") == 0) {
            // open /dev/null
            syscall_args->args[0] = "/dev/null";
            //asm("int3");
            return 0;
        } else {
            // not allow
            asm("int3");
            syscall_args->ret = -1;
            return 1;
        }
    }
}

int syscall_cb_post(temporal_ctx_t* ctx, int syscall_no, syscall_req_t *syscall_args) {
    switch (syscall_no) {
        case SYS_open:
            if (syscall_args->ret >= 0 && syscall_args->ret < 4096) {
                fds[syscall_args->ret] = 1;
            }
            break;
        case SYS_close:
            if (syscall_args->args[0] >= 0 && syscall_args->args[0] < 4096) {
                fds[syscall_args->args[0]] = 0;
            }
            break;
    }
    return 0;
}

// fd callback
int fd_cb(temporal_ctx_t* ctx, int fd, int op, void* buf, size_t count) {
    // sleep by loop
    //return 1;
    if (!open_test)
        return 1;
    
    if (fd == 0 || fd == 1)
        return 1;
    
    if (fds[fd] == 0) {
        asm("int3");
        return 0;
    } else {
        return 1;
    }
}

tid_t tid_main = 0;
tid_t tid_syscall = 0;
#else
long long tid_main = 0, tid_syscall = 0;
#endif

unsigned long fuck1, fuck2;

int main(int argc, char** argv) {
    fuck1 = (unsigned long) __stop_temporal_tasks;
    fuck2 = (unsigned long) __start_temporal_tasks;
    int num_tasks = (fuck1 - fuck2) / sizeof(task_t*);
    int tmode = 0;
    //printf("task start = %p, task end = %p, num_tasks = %d\n", fuck2, fuck1, num_tasks / sizeof(task_t));
    //return 0;
    task_t* tasks = malloc(sizeof(task_t) * num_tasks);
    
    for (int i = 0; i < num_tasks; i++) {
        memcpy(&tasks[i], __start_temporal_tasks[i], sizeof(task_t));
    }

    if (argc == 1) {
        // print task list
        printf("Task list: \n");
        for (int i = 0; i < num_tasks; i++) {
            printf("%d: %s %d\n", i, tasks[i].name, tasks[i].mem);
        }
        return 0;
    }

    int start_id = 0;
    int end_id = num_tasks;

    if (argc == 2 || argc == 3) {
        int task_id = -1;
        if (argc == 3) {
            tmode = 1;
            printf("!Temporal Policy mode\n");
        }
        for (int j = 0; j < num_tasks; j++) {
            if (strcmp(tasks[j].name, argv[1]) == 0) {
                task_id = j;
                break;
            }
        }
        if (task_id != -1) {
            start_id = task_id;
            end_id = task_id + 1;
        } else {
            printf("Task %s not found\n", argv[1]);
            return 0;
        }
    } /* else if (argc == 3) {
        int start_id = atoi(argv[1]);
        int end_id = atoi(argv[2]);
    } */ else {
        printf("Usage: %s [task_id] -- [task_id]\n", argv[0]);
        printf("If task_id is -1, run all tasks\n");
        return 0;
    }

    // init temporal
    #ifdef HAS_TEMPORAL
    printf("!Init temporal\n");
    static int syscalls[] = {
        SYS_open, 
        SYS_close
    };
    static syscall_cb_t syscall_cbs[] = { 
        syscall_cb_pre, syscall_cb_post, fd_cb, NULL
    };
    if (tmode == 1)
        temporal_init_ex(2, syscalls, syscall_cbs, NULL, NULL);
    else
        temporal_init();
    //temporal_init_ex(2, (int*){SYS_open, SYS_close, NULL}, (syscall_cb_t*){syscall_cb_post, syscall_cb_pre, fd_cb, NULL}, 0, 0);
    printf("!Init temporal done\n");
    tid_main = temporal_create(0);
    //tid_syscall = temporal_create(0);
    //printf("tid_main = %d, tid_syscall = %d\n", tid_main, tid_syscall);
    
    if (tmode == 1)
        temporal_set_cb_tid(tid_main, 1, 2, 3);
        
    //printf("tid_main = %d, tid_syscall = %d\n", tid_main, tid_syscall);
    #endif
    // init tasks
    for (int i = start_id; i < end_id; i++) {
        printf(">Task %d: %s Start\n", i, tasks[i].name);
        tasks[i].tid = tid_main;
        if (tasks[i].global) {
            tasks[i].test_main(&tasks[i]);
            printf(">Task %d: %s End\n\n", i, tasks[i].name);
            continue;
        }
        for (int j = 0; j < tasks[i].n_main; j++) {
            tasks[i].n_cur = j;
            //tasks[i].init(&tasks[i]);
            #ifdef HAS_TEMPORAL
            temporal_call(test, tid_main, test_init, &tasks[i]);
            tid_t tid = tasks[i].tid;
            #else
            test_init(&tasks[i]);
            #endif
            // rdtsc
            long long start, end;
            if (tasks[i].test_main == NULL) {
                start = rdtsc();
                for (int k = 0; k < tasks[i].n_run; k++) {
                    #ifdef HAS_TEMPORAL
                    temporal_call(test, tid, test_empty, &tasks[i]);
                    #else
                    test_empty(&tasks[i]);
                    #endif
                }
                end = rdtsc();

            } else {
                #ifdef HAS_TEMPORAL
               // printf("Main! %d\n", tid);
                #endif
                start = rdtsc();
                for (int k = 0; k < tasks[i].n_run; k++) {
                    #ifdef HAS_TEMPORAL
                    temporal_call(test, tid, test_main, &tasks[i]);
                    #else
                    test_main(&tasks[i]);
                    #endif
                }
                end = rdtsc();

            }
            #ifdef HAS_TEMPORAL
            temporal_call(test, tid, test_done, &tasks[i]);
            #else
            test_done(&tasks[i]);
            #endif
            printf("%s_call[%d]: %lld / %d\n", tasks[i].name, j, end - start, tasks[i].n_run);
        }
        printf(">Task %d: %s End\n\n", i, tasks[i].name);
    }

    #ifdef HAS_TEMPORAL
    temporal_destroy(tid_main);
    temporal_destroy(tid_syscall);
    #endif

    return 0;
}