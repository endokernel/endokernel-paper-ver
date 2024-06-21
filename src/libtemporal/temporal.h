#ifndef _ISO_TEMPORAL_H_
#define _ISO_TEMPORAL_H_
#include <stdint.h>
#include <stddef.h>
typedef uint64_t tid_t;
typedef struct mempool mempool_t; 
typedef struct acl_s acl_t;
typedef struct temporal_ctx temporal_ctx_t;

typedef long(*iv_syscall_t)(void);

typedef struct syscall_req {
    uint64_t args[6];
    uint64_t ret;
    iv_syscall_t* syscall_table;
} syscall_req_t;

typedef int(*syscall_cb_t)(temporal_ctx_t* ctx, int syscall_no, syscall_req_t *syscall_args);
typedef int(*fd_cb_t)(temporal_ctx_t* ctx, int syscall_no, int fd, iv_syscall_t* syscall_table);

struct temporal_ctx {
    tid_t tid;
    tid_t parent; // child domain allocate memory from its parent
    mempool_t* memory_pool;
    temporal_ctx_t* borrowed_ctx;
    unsigned long used;
    void* userdata;
    
    // used by IV
    int pre_syscall_cb_n;
    int post_syscall_cb_n;
    int fd_cb_n;
    //

    int parent_memory;
    int called;
    int freetag;
};

#ifndef CONCAT3

#define CONCAT2(x,y) x##y
#define CONCAT3(x,y,z) x##y##z
#define CONCAT4(x,y,z,q) x##y##z##q

#endif

#ifndef SYSCALLFILTER

tid_t temporal_create(tid_t);
tid_t temporal_create_ex(tid_t parent, int parent_memory);
void* temporal_alloc(tid_t, size_t);
int temporal_free(tid_t, void*);
int temporal_init();
int temporal_init_ex(int enable_syscall_filter, int *syscalls, syscall_cb_t* syscall_cbs, void* st, void* ed);
int temporal_destroy(tid_t);
unsigned long get_tdomain();
unsigned long get_cdomain();
void temporal_set_userdata(void* userdata);
void temporal_set_userdata_tid(tid_t tid, void* userdata);
void* temporal_get_userdata();
void* temporal_get_userdata_tid(tid_t tid);
void temporal_report();

void temporal_set_pre_syscall_cb(int n);
void temporal_set_post_syscall_cb(int n);
void temporal_set_fd_cb(int n);

void temporal_set_pre_syscall_cb_tid(tid_t tid, int n);
void temporal_set_post_syscall_cb_tid(tid_t tid, int n);
void temporal_set_fd_cb_tid(tid_t tid, int n);

void temporal_set_cb_tid(tid_t tid, int pre, int post, int fd);

int temporal_return_nestedmemory(tid_t tid);
int temporal_fetch_nestedmemory(tid_t tid);

unsigned long _temporal_call(void* stub, unsigned long domain_id, int func, void* arg);
#define temporal_call(name, tid, func, arg0) \
({  \
    extern int CONCAT2(iv_domain_, name);   \
    extern void* CONCAT2(table_iv_func_, func); \
    extern void CONCAT2(_xcall_stub_, name)(); \
    _temporal_call( \
        (void*)CONCAT2(_xcall_stub_, name) + 64,   \
        (((unsigned long)tid) << 16) | (CONCAT2(iv_domain_, name) << 3),  \
        (int)CONCAT2(table_iv_func_, func), \
        (arg0) \
    );\
})

#define SYSFILTER __attribute__((section("sysfilter"))) 

#define _LEN(_0,_1,_2,_3,_4,_5,_6,P,...) P
#define GETLEN(...) _LEN(DUMMY,##__VA_ARGS__,6,5,4,3,2,1,0)
#define _CAT(x,y) x##y
#define CAT(x,y) _CAT(x,y)

typedef long(*iv_syscall_0)(long int sys_no);
typedef long(*iv_syscall_1)(long int sys_no, long);
typedef long(*iv_syscall_2)(long int sys_no, long,long);
typedef long(*iv_syscall_3)(long int sys_no, long,long,long);
typedef long(*iv_syscall_4)(long int sys_no, long,long,long,long);
typedef long(*iv_syscall_5)(long int sys_no, long,long,long,long,long);
typedef long(*iv_syscall_6)(long int sys_no, long,long,long,long,long,long);

#define temporal_syscall(req, name, args...) ((CAT(iv_syscall_, GETLEN(args)))((req)->syscall_table[GETLEN(args)]))(CAT(SYS_, name), args)

#endif
#endif