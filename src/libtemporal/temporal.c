#define ISONAME temporal
#define ISOSAFE 1
#define _GNU_SOURCE
#include <sys/mman.h>
#define _APP
#include <mt.h>
#include <temporal.h>
#include <small.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>

#define USE_MPORTECT
#ifdef USE_MPORTECT
#define PKEY_MP(a,b,c,d) pkey_mprotect(a, b, c, d)
#else
#define PKEY_MP(a,b,c,d) (0)
#endif
#define IV_TEMP 15

#define IV_TEMP 15

long iv_domain_temporal;
struct acl_s {
    acl_t* next;
    tid_t grant[16];
};

// pool memory increase from 4k to 2M

struct mempool {
    mempool_t* next;
    tid_t org_tid; // original context

    void* start, *tail;
    size_t size;
    int mapped; // is is memory mapped to spatial domain rather than IV_TEMP?
    // TODO: Having better access control and counter for 
    // mem access caps
    // Now, you cannot grant mem to another domain
    // All of them are hierarchy.
    // One corner case is *=0, in which case all mem
    // are accessible and you could imagine a mempool = All
    // but it's not really such a mempool, to prevent too much mprotect
    // acl_t* acl_list; // mem granted to
};

typedef struct ctx_pool ctx_pool_t;
struct ctx_pool {
    temporal_ctx_t ctxs[1023];
    ctx_pool_t* next;
};

#include <iso.h>
#include <iso_xcall.h>

int enter_called = 0;
int alloc_called = 0;

int ISO_DATA inited = 0;
ctx_pool_t ISO_DATA pool0;

void* current_thread = 0;
unsigned long current_enter_counter = 0;

temporal_ctx_t* ISO_CODE tid2ctx(tid_t tid) {
    int n = tid % 1023;
    int m = tid / 1023;
    ctx_pool_t *p = &pool0;
    while (p && m --> 0) p = p->next;
    if (!p) return NULL;
    if (!p->ctxs[n].used) 
        return NULL;
    return &(p->ctxs[n]);
}

temporal_ctx_t* ISO_CODE alloc_ctx() {
    alloc_called++;
    ctx_pool_t *p = &pool0;
    int t = 0;
    int o0 = 1;
    do {
        for (int o = o0; o < 1023; o++) {
            if (!p->ctxs[o].used) {
                p->ctxs[o].used = 1;
                p->ctxs[o].parent = 0;
                p->ctxs[o].memory_pool = 0;
                p->ctxs[o].tid = t * 1023 + o;
                p->ctxs[o].userdata = 0;
                p->ctxs[o].borrowed_ctx = 0;
                return &(p->ctxs[o]);
            }
        }
        if (!p->next) {
            p->next = (ctx_pool_t*)private_tcalloc(1);
        }
        p = p->next;
        t++;
        o0 = 0;
    } while (p);
}

int ISO_CODE valid_path(unsigned long domain_id) {
    return 1;
}

static int ISO_CODE has_control(temporal_ctx_t* cur, temporal_ctx_t* target) {
    if (cur == 0)
        return 1; // * has all
    while (target) {
        if (target->tid == cur->tid)
            return 1;
        target = tid2ctx(target->parent);
    }
    return 0;
}

static ISO_CODE temporal_ctx_t* fetch_ctx_safe(tid_t tid) {
    if (tid == 0)
        return NULL;
    temporal_ctx_t *target_ctx = tid2ctx(tid);
    if (!target_ctx)
        return NULL;
    unsigned long previous_domain = *(unsigned long*)(get_tls()->app_stack[0]);
    tid_t current_tid = previous_domain >> 16;
    int map_for_self = current_tid == tid;
    if (current_tid) {
        temporal_ctx_t *cur_ctx = tid2ctx(current_tid);
        //if (!has_control(cur_ctx, target_ctx)) {
        //    return NULL; // cannot map
        //}
    }
    return target_ctx;
}

#define IV_TEMP_ALLOW 13 // move mem to this domain so everyone can access
static void* ISO_CODE temporal_alloc_impl(tid_t tid, size_t sz) {
    temporal_ctx_t *target_ctx = fetch_ctx_safe(tid);
    if (!target_ctx)
        return NULL;
    unsigned long previous_domain = *(unsigned long*)(get_tls()->app_stack[0]);
    tid_t current_tid = previous_domain >> 16;
    
    int map_for_self = current_tid == tid;

    mempool_t *mp = (mempool_t*) private_tcalloc(0);
    if (!mp)
        return NULL;
    void * mem = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!mem) {
        private_tfree(0, mp);
        return NULL;
    }
    //printf("Allocated @ domain %lld for %d, addr=%p\n", current_tid, tid, mem);
    mp->start = mem;
    mp->org_tid = target_ctx->tid;
    mp->tail = mem + sz;
    mp->size = sz;
    int cur_code_domain = (previous_domain >> 3) & 0xf;
    #ifdef USE_MPORTECT
    if (current_tid != 0) {
        // this allows parent allocate memory for child and access it immediately.
        mp->mapped = IV_TEMP_ALLOW;
        pkey_mprotect(mem, sz, PROT_READ | PROT_WRITE, IV_TEMP_ALLOW);
    } else {
        // tid == *, we can map to IV_TEMP
        mp->mapped = 0;
        pkey_mprotect(mem, sz, PROT_READ | PROT_WRITE, IV_TEMP);
    }
    #else
        pkey_mprotect(mem, sz, PROT_READ | PROT_WRITE, IV_TEMP_ALLOW);
    #endif


    if (map_for_self) {
        // that's fine
    } else if (current_tid) {
        // put target domain on parent's borrow list
        // so we can unmap it after domain switch.
        if (target_ctx->borrowed_ctx == NULL) {
            // try borrwo it if not done before.
            temporal_ctx_t* ctx = tid2ctx(current_tid);        
            target_ctx->borrowed_ctx = ctx->borrowed_ctx;
            ctx->borrowed_ctx = target_ctx;
        }
    }
    // TODO: is there any need to make this thread-safe?
    mp->next = target_ctx->memory_pool;
    target_ctx->memory_pool = mp;
    return mem;
}

static int ISO_CODE temporal_free_impl(tid_t tid, void* mem) {
    temporal_ctx_t *target_ctx = fetch_ctx_safe(tid);
    if (!target_ctx)
        return -1; // cannot free
    // remove mem from linked list
    mempool_t *found = NULL;
    mempool_t** p = &(target_ctx->memory_pool);
    for (; *p; p = &((*p)->next)) {
        if ((*p)->start == mem) {
            found = *p;
            *p = (*p)->next;
            break;
        }
    }
    if (!found)
        return -2; // cannot free
    munmap(mem, found->size);
    private_tfree(0, found);
    return 0;
}

void* ISO_CODE temporal_alloc(tid_t tid, size_t sz) {
    return xcall(temporal, temporal_alloc_impl, tid, sz);
}

int ISO_CODE temporal_free(tid_t tid, void* mem) {
    return xcall(temporal, temporal_free_impl, tid, mem);
}

void ISO_CODE deactive_context(temporal_ctx_t* ctx) {
    for (mempool_t* m = ctx->memory_pool; m; m = m->next) {
        if (m->mapped) {
            // printf("UnMap, Move %p (size=%d) to pkey = %d", m->start, m->size, IV_TEMP);
            if (PKEY_MP(m->start, m->size, PROT_READ | PROT_WRITE, IV_TEMP) == 0) {
                //printf("succ\n");
                m->mapped = 0;
            }
        } else {
            //printf("not mapped\n");
        }
    }
}

void ISO_CODE activate_context(temporal_ctx_t* ctx) {
    for (mempool_t* m = ctx->memory_pool; m; m = m->next) {
        if (m->mapped == 0) {
            // printf("Move %p (size=%d) to pkey = %d\n", m->start, m->size, IV_TEMP_ALLOW);
            // if (pkey_mprotect(m->start, m->size, PROT_READ | PROT_WRITE, code_domain) == 0) {
            if (PKEY_MP(m->start, m->size, PROT_READ | PROT_WRITE, IV_TEMP_ALLOW) == 0) {
                //printf("succ\n");
                m->mapped = IV_TEMP_ALLOW;
            } //else printf("mp failed\n");
        } else {
           // printf("already mapped\n");
        }
    }
}

// no export
int ISO_CODE switch_tdomain(int code_domain, temporal_ctx_t *new_ctx, temporal_ctx_t *old_ctx) {
    // 1. move all old pages to IV_TEMP
    // 2. move all new pages to new domain
    //printf("MemSwitch from %d to %d\n", old_ctx? old_ctx->tid : 0, new_ctx?new_ctx->tid : 0);
    if (old_ctx) {
        deactive_context(old_ctx);
        for (temporal_ctx_t *next, *ctx = old_ctx->borrowed_ctx; ctx; ctx = next) {
            deactive_context(ctx);
            next = ctx->borrowed_ctx;
            ctx->borrowed_ctx = NULL;
        }
        old_ctx->borrowed_ctx = NULL;
        
        temporal_ctx_t *cur = old_ctx;
        while (cur) {
            if (cur->parent_memory) {
                if (cur->parent)
                    cur = tid2ctx(cur->parent);
                else break;
            } else break;
            deactive_context(cur);
        }
    }
    if (new_ctx) {
        temporal_ctx_t *cur = new_ctx;
        while (cur) {
            activate_context(cur);
            if (cur->parent_memory) {
                if (cur->parent)
                    cur = tid2ctx(cur->parent);
                else break;
            } else break;
        }
        
    }
    //printf("\n");
    return 0;
}

static int ISO_CODE temporal_destroy_impl(tid_t tid);

static int ISO_CODE enter_tdomain(unsigned long domain_id) {
    // TODO: maybe we want to acquire a global t domain lock for current thread?
    // as a security justification to prevent pass this function
    // from another thread accidentally
    // (intentionally by attacker I mean)
    enter_called++;
    if (current_thread == get_tls()->self) {
        current_enter_counter++;
    } else {
        unsigned long zero = 0;
        if (__atomic_compare_exchange_8(&current_thread, &zero, get_tls()->self, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            current_enter_counter = 1;
        } else {
            return -1; // failed, locked on another thread.
        }
    }
    tid_t tid = domain_id >> 16;
    temporal_ctx_t *new_ctx = tid2ctx(tid);
    if (!new_ctx) return -1; // failed
    new_ctx->called++;
    unsigned long previous_domain = *(unsigned long*)(get_tls()->app_stack[0]);
    tid_t old_tid = previous_domain >> 16;
    temporal_ctx_t *old_ctx = NULL;
    if (old_tid) {
        old_ctx = tid2ctx(old_tid);
        if (!old_ctx)
            return -2; // cannot get old ctx
    }
    // old_ctx might be NULL
    switch_tdomain((domain_id >> 3) & 0xf, new_ctx, old_ctx);
}

static int ISO_CODE exit_tdomain(unsigned long domain_id) {
    tid_t tid = domain_id >> 16;
    temporal_ctx_t *new_ctx = tid2ctx(tid);
    if (!new_ctx) return -1; // failed
    new_ctx->called--;
    if (new_ctx->freetag && new_ctx->called == 0) {
        temporal_destroy_impl(tid);
    }
    unsigned long previous_domain = *(unsigned long*)(get_tls()->app_stack[0]);
    tid_t old_tid = previous_domain >> 16;
    temporal_ctx_t *old_ctx = NULL;
    if (old_tid) {
        old_ctx = tid2ctx(old_tid);
        if (!old_ctx)
            return -2; // cannot get old ctx
    }
    if (current_thread == get_tls()->self) {
        current_enter_counter--;
        if (current_enter_counter == 0) {
            __atomic_store_8(&current_thread, 0, __ATOMIC_SEQ_CST);
        }
    }
    // new_ctx might be NULL
    switch_tdomain((previous_domain >> 3) & 0xf, old_ctx, new_ctx);
}

// we are on the caller's domain
unsigned long ISO_CODE _temporal_call(void* stub, unsigned long domain_id, int func, void* arg) {
    unsigned long ret;
    //printf(">> tcall %lld --> %lld\n", get_tls()->current_domain, ((domain_id)));
    int a = xcall(temporal, enter_tdomain, domain_id);
    // printf("_temporal_call a0 = %p\n", arg);
    if (a != 0)
        return -1;
    asm(
        "call *%3\n\t"
        :"=a"(ret)
        :"a"(((domain_id & ~(0xfffful))) | func), "D"(arg), "r"(stub)
        :"cc", "memory", "rcx", "rdx", "rsi", "r8", "r9",
        "r10", "r11"
    );
    a = xcall(temporal, exit_tdomain, domain_id);
    //printf(">> tret %lld\n", ((domain_id & ~(0xfffful))));
    return ret;
}

static tid_t ISO_CODE temporal_create_impl(tid_t parent, int parent_memory) {
    temporal_ctx_t *p_ctx = NULL;
    unsigned long previous_domain = *(unsigned long*)(get_tls()->app_stack[0]);
    tid_t old_tid = previous_domain >> 16;
    if (old_tid != parent)
        if (old_tid != 0)
            return 0;
    if (parent) {
        p_ctx = tid2ctx(parent);
        if (!p_ctx)
            return 0; // parent not exists
    }
    temporal_ctx_t *new_ctx = alloc_ctx();
    new_ctx->parent = parent;
    new_ctx->parent_memory = parent_memory;
    return new_ctx->tid;
}

tid_t ISO_CODE temporal_create(tid_t parent) {
    return xcall(temporal, temporal_create_impl, parent,0);
}

tid_t ISO_CODE temporal_create_ex(tid_t parent, int parent_memory) {
    return xcall(temporal, temporal_create_impl, parent,1);
}

// TODO: add check; prevernt destroy parent
// TODO: add mem counter to lazy free when some memory is borrowed by other
static int ISO_CODE temporal_destroy_impl(tid_t tid) {
    if (!tid)
        return 0;
    temporal_ctx_t* ctx = tid2ctx(tid);
    if (ctx) {
        if (ctx->called) {
            ctx->freetag = 1;
            return 0;
        }
        for (mempool_t*p = ctx->memory_pool, *n = NULL; p; p = n) {
            n = p->next;
            if (p->start) {
                munmap(p->start, p->size);
            }
            private_tfree(0, p);
        }
        ctx->used = 0;
        ctx->memory_pool = 0;
        ctx->parent = 0;
        ctx->called = 0;
        ctx->freetag = 0;
        return 0;
    }
    return -1;
}

static int ISO_CODE temporal_fetch_nestedmemory_impl(tid_t tid) {
    tid_t my_tid = get_tdomain();
    if (my_tid == 0 || my_tid == tid)
        return -1;
    temporal_ctx_t* my_ctx = tid2ctx(my_tid);
    temporal_ctx_t* ctx = fetch_ctx_safe(tid);
    if (!ctx)
        return -1;
    if (ctx->borrowed_ctx)
        return -1; // can't borrow twice
    
   // printf("borrowing %d: ", tid);
    activate_context(ctx);
    
    ctx->borrowed_ctx = my_ctx->borrowed_ctx;
    my_ctx->borrowed_ctx = ctx;
    
    return -1; // failed find memory
}

static int ISO_CODE temporal_return_nestedmemory_impl(tid_t tid) {
    // 1. find mem in current pool
    // 2. if found, remove it from current pool, and return it to org_tid
    //  this prevent you return "any memory" to other domain
    // 3. if not found, return -1
    tid_t my_tid = get_tdomain();
    if (my_tid == 0)
        return -1;
    temporal_ctx_t* my_ctx = tid2ctx(my_tid);
    if (!my_ctx)
        return -1;
    
    temporal_ctx_t** prev = &(my_ctx->borrowed_ctx);
    for (temporal_ctx_t* ctx = my_ctx->borrowed_ctx; ctx; ctx = ctx->borrowed_ctx) {
        //printf("ctx = %d, tid = %d\n", ctx->tid, tid);
        if (ctx->tid == tid) {
            *prev = ctx->borrowed_ctx;
            ctx->borrowed_ctx = NULL;
           // printf("return_nestedmemory %d: ", tid);
            deactive_context(ctx);
        }
        prev = &(ctx->borrowed_ctx);
    }
    return -1; // failed find memory
}

int ISO_CODE temporal_destroy(tid_t tid) {
    return xcall(temporal, temporal_destroy_impl, tid);
}

int ISO_CODE temporal_fetch_nestedmemory(tid_t tid) {
    return xcall(temporal, temporal_fetch_nestedmemory_impl, tid);
}

int ISO_CODE temporal_return_nestedmemory(tid_t tid) {
    return xcall(temporal, temporal_return_nestedmemory_impl, tid);
}

#define SYS_iv_set_tdomain_info 341
#define SYS_iv_set_tdomain_filter 342

static int ISO_CODE temporal_init_impl(int enable_syscall_filter, int *syscalls, void* func, void* st, void* ed) {
    if (inited) {
        return -1;
    }
    inited = 1;
    private_pool(0, sizeof(mempool_t), 4);
    private_pool(1, sizeof(ctx_pool_t), 72);
    // printf("temporal_init_impl, enable_syscall_filter = %d, pool0 = %p\n", enable_syscall_filter, &pool0);
    if (enable_syscall_filter) {
        syscall(SYS_iv_set_tdomain_info, &pool0, func,st,ed); // send pool0 to system
        for (int i = 0; i < enable_syscall_filter; i++) {
            //printf("syscall filter set: %d\n", syscalls[i]);
            syscall(SYS_iv_set_tdomain_filter, syscalls[i]);
        }
    }
}

#define PREPARE_CTX \
    temporal_ctx_t* ctx = NULL; \
    if (tid == 0) { \
        tid = get_tdomain(); \
        if (tid) \
            ctx = tid2ctx(tid); \
    } else { \
        ctx = fetch_ctx_safe(tid); \
    }

static void ISO_CODE temporal_set_userdata_impl(tid_t tid, void* userdata) {
    PREPARE_CTX
    // set once
    if (ctx) {
        if (!ctx->userdata)
            ctx->userdata = userdata;
    }
}

static void* ISO_CODE temporal_get_userdata_impl(tid_t tid) {
    PREPARE_CTX

    if (ctx)
        return ctx->userdata;
    else {
        printf("failed fetch ctx\n");
        return NULL;
    }
}

int ISO_CODE temporal_init() {
    return xcall(temporal, temporal_init_impl, 0, 0,0,0,0);
}

int ISO_CODE temporal_init_ex(int enable_syscall_filter, int *syscalls, syscall_cb_t* syscall_cbs, void* st, void* ed) {
    return xcall(temporal, temporal_init_impl, enable_syscall_filter, syscalls, syscall_cbs, st, ed);
}

void ISO_CODE temporal_set_userdata(void* userdata) {
    return xcall(temporal, temporal_set_userdata_impl, 0, userdata);
}

void ISO_CODE temporal_set_userdata_tid(tid_t tid, void* userdata) {
    return xcall(temporal, temporal_set_userdata_impl, tid, userdata);
}

void* ISO_CODE temporal_get_userdata() {
    return xcall(temporal, temporal_get_userdata_impl, 0);
}

void* ISO_CODE temporal_get_userdata_tid(tid_t tid) {
    return xcall(temporal, temporal_get_userdata_impl, tid);
}

void ISO_CODE temporal_set_cb_impl(tid_t tid, int pre, int post, int fd) {
    PREPARE_CTX
    if (ctx) {
        if (!ctx->fd_cb_n)
            ctx->fd_cb_n = fd;
        if (!ctx->pre_syscall_cb_n)
            ctx->pre_syscall_cb_n = pre;
        if (!ctx->post_syscall_cb_n)
            ctx->post_syscall_cb_n = post;
    }
}

void ISO_CODE temporal_set_pre_syscall_cb(int n) {
    xcall(temporal, temporal_set_cb_impl, 0, n, 0, 0);
}

void ISO_CODE temporal_set_post_syscall_cb(int n) {
    xcall(temporal, temporal_set_cb_impl, 0, 0, n, 0);
}

void ISO_CODE temporal_set_fd_cb(int n) {
    xcall(temporal, temporal_set_cb_impl, 0, 0, 0, n);
}


void ISO_CODE temporal_set_pre_syscall_cb_tid(tid_t tid, int n) {
    xcall(temporal, temporal_set_cb_impl, tid, n, 0, 0);
}

void ISO_CODE temporal_set_post_syscall_cb_tid(tid_t tid, int n) {
    xcall(temporal, temporal_set_cb_impl, tid, 0, n, 0);
}

void ISO_CODE temporal_set_fd_cb_tid(tid_t tid, int n) {
    xcall(temporal, temporal_set_cb_impl, tid, 0, 0, n);
}

void temporal_set_cb_tid(tid_t tid, int pre, int post, int fd) {
    xcall(temporal, temporal_set_cb_impl, tid, pre, post, fd);
}

void temporal_report(){
    printf("enter = %d\n", enter_called);
    printf("alloc = %d\n", alloc_called);
}

ISO_ENTRY(temporal_alloc_impl);
ISO_ENTRY(temporal_destroy_impl);
ISO_ENTRY(temporal_init_impl);
ISO_ENTRY(temporal_free_impl);
ISO_ENTRY(temporal_create_impl);
ISO_ENTRY(temporal_set_userdata_impl);
ISO_ENTRY(temporal_get_userdata_impl);
ISO_ENTRY(exit_tdomain);
ISO_ENTRY(enter_tdomain);
ISO_ENTRY(temporal_set_cb_impl);
ISO_ENTRY(temporal_fetch_nestedmemory_impl);
ISO_ENTRY(temporal_return_nestedmemory_impl);

unsigned long get_tdomain() {
    return get_tls()->current_domain >> 16;
}

unsigned long get_cdomain() {
    return get_tls()->current_domain & 0xffff;
}
#define ISO_SCALL_ID 338
#include <iso_init.h>
#include <iso_end.h>