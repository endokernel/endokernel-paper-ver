#include <pkru.h>
#include <erim/mmap/map.h>
#include <rawcall.h>
#include <shim_syscalls.h>
#include <asm-offsets.h>
#include <mt.h>
#include <app.h>
#include <cet.h>

extern int memlock;

#define MEMLOCK         iv_lock(&memlock)
#define MEMUNLOCK       iv_unlock(&memlock)

extern iv_stack_t shim_stack0;

int create_map(iv_encapslation_t *local, int domain_id) {
    map_addr_t addr0 = map_addr(local->code_begin, (char*)local->code_end - 1);
    if (!map_check_lock(addr0, READABLE | EXECUTABLE)) {
        map_unlock_read_all();
        MEMUNLOCK;
        printf("unexecutable code\n");
        return 0;
    }
    map_addr_t addr1 = map_addr(local->data_begin, (char*)local->data_end - 1);
    if (!map_check_lock(addr1, READABLE)) {
        map_unlock_read_all();
        MEMUNLOCK;
        printf("unreadable data\n");
        return 0;
    }
    map_addr_t addr2 = map_addr(local->stub_begin, (char*)local->stub_end - 1);
    if (!map_check_lock(addr2, READABLE)) {
        map_unlock_read_all();
        MEMUNLOCK;
        printf("unreadable stub\n");
        return 0;
    }
    map_addr_t addr3 = map_addr(local->iv_domain_mark, (char*)local->iv_domain_mark + 8 - 1);
    if (!map_check_lock(addr3, READABLE)) {
        map_unlock_read_all();
        MEMUNLOCK;
        printf("unreadable domain mark\n");
        return 0;
    }

    map_unlock_read_all();

    rawcall(mprotect_pkey, local->code_begin, (unsigned long)local->code_end - (unsigned long)local->code_begin, PROT_READ | PROT_EXEC, domain_id);
    map_set(addr0, map_norm(READABLE|EXECUTABLE, 0) | APP(domain_id));

    rawcall(mprotect_pkey, local->data_begin, (unsigned long)local->data_end - (unsigned long)local->data_begin, PROT_READ | PROT_WRITE, domain_id);
    map_set(addr1, map_norm(READABLE|WRITABLE, 0) | APP(domain_id));

    rawcall(mprotect_pkey, local->stub_begin, (unsigned long)local->stub_end - (unsigned long)local->stub_begin, PROT_READ | PROT_WRITE, IV_CONF);
    map_set(addr2, map_norm(READABLE|WRITABLE, 1));

    return 1;
}

int app_valid_v1(char* buf, iv_encapslation_t* local, int domain_id, box_t box_type) {
    MEMLOCK;
    iv_encapslation_v1_t *evt = (iv_encapslation_v1_t *) buf;
    printf("%p ~ %p\n", evt->code_begin, evt->code_end);
    printf("%p ~ %p\n", evt->data_begin, evt->data_end);
    printf("%p ~ %p\n", evt->func_begin, evt->func_end);
    printf("%p ~ %p | *%p = %d\n", evt->stub, evt->stub, evt->iv_domain_mark, *(unsigned int*)evt->iv_domain_mark);
    if (*(unsigned int*)evt->iv_domain_mark != 0) {
        box_type =*(unsigned int*)evt->iv_domain_mark;
        printf("override box type to %d\n", box_type);
    }
    int max_func = (evt->func_end - evt->func_begin) / 8;
    // page 0 = carry one gate
    // page 0.5 = normal gate
    int max_support_func = (((unsigned long)(0x8192)) - 4096) / 8;
    if (max_func > max_support_func || max_func > 0xffff) {
        MEMUNLOCK;
        printf("too many functions\n");
        return 0; // too many func
    }

    if (map_check_lock(map_addr(buf, buf + sizeof(iv_encapslation_v1_t) - 1), READABLE)) {
        local->box_type = box_type;
        
        local->code_begin = evt->code_begin;
        local->code_end = evt->code_end;
        if ((((unsigned long)local->code_begin) & 0xfff) != 0) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unaligned code\n");
            return 0;
        }
        if ((((unsigned long)local->code_end) & 0xfff) != 0) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unaligned code\n");
            return 0;
        }
        
        local->data_begin = evt->data_begin;
        local->data_end =( (unsigned long)evt->data_end) & ~0xfff;
        if ((((unsigned long)local->data_begin) & 0xfff) != 0) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unaligned data\n");
            return 0;
        }
        if ((((unsigned long)local->data_end) & 0xfff) != 0) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unaligned data\n");
            return 0;
        }
        
        local->func_begin = evt->func_begin;
        local->func_end = evt->func_end;
        if (!map_check_lock(map_addr(local->func_begin, (char*)local->func_end - 1), READABLE)) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unreadable func\n");
            return 0;
        }

        local->stub_begin = evt->stub;
        local->stub_end = evt->stub + 8192;
        if ((((unsigned long)local->stub_begin) & 0xfff) != 0) {
            map_unlock_read_all();
            MEMUNLOCK;
            printf("unaligned stub\n");
            return 0;
        }

        local->iv_domain_mark = evt->iv_domain_mark;
        
        int ret = create_map(local, domain_id);

        map_unlock_read_all();
        MEMUNLOCK;

        return ret;
    } 

    map_unlock_read_all();
    MEMUNLOCK;

    return 0;
}

#include <app_xcall.h>
typedef struct __attribute__((packed)) cmp {
    char cmp[1];
    unsigned int N;
} cmp_t;

static char * install_stub(char *_stub, unsigned int fcnt, unsigned long domain_id, unsigned int safe) {
    int fid = 0;
    unsigned long* stub = _stub;
    unsigned long* app_code = (unsigned long*)((safe?app_safe_xcall:app_sand_xcall)[domain_id]);
    unsigned long* end = (unsigned long*)((safe?app_safe_xcall_end:app_sand_xcall_end)[domain_id]);
    unsigned long* begin = app_code;
    for (unsigned long* _app = begin, *stub = _stub; _app < end; _app+=1, stub+=1) {
        *stub = *_app;
    }
    cmp_t* cmp_code = (cmp_t*) ((unsigned long)_stub + ((unsigned long)(safe?app_safe_xcall_cmp:app_sand_xcall_cmp)[domain_id] - (unsigned long)app_code));
    cmp_code->N = fcnt - 1;
    return _stub;
}

int outer_allowed[16];
int id_allocated[16] = {
    1,1,1,0,
    0,0,0,0,
    0,0,0,0,
    0,1,0,1
};

box_t id_box[16] = {
    RESERVED, RESERVED, UN      , RESERVED, 
    RESERVED, RESERVED, RESERVED, RESERVED,
    RESERVED, RESERVED, RESERVED, RESERVED,
    RESERVED, RESERVED, RESERVED, RESERVED,
};

unsigned int calc_pkru(unsigned int domain_id) {
    unsigned int base_pkru = get_tls()->app_pkrus[DOMAIN_DID(domain_id)];
    if (DOMAIN_TID(domain_id) == 0) {
        base_pkru &= ~notemp_pkru;
    }
    return base_pkru;
}


void app_update_tls(int domain_id, box_t boxtype) {
    if (boxtype == RESERVED)
        return ; // we don't need to update anything for
        // reserved box

    // for sandbox, pkru is always sandbox_pkru
    unsigned int new_pkru = sandbox_pkru(domain_id); 
    if (boxtype == SAFE || boxtype == FRIEND) {
        // app_pkrus allowed access to domain 15, and later removed by the xcall
        new_pkru = untrusted_pkru;
        for (int i = 0; i < 16; i++) {
            if (id_allocated[i] && id_box[i] != SAFE && id_box[i] != RESERVED) {
                // safebox access all boxes except other safeboxes
                // grant access
                // safebox can access FRIEND box
                new_pkru &= ~PKRU_NO_KEY(i);
            }
            
        }
    }
    printf("My (%d) box type is %d\n", domain_id, boxtype);
    if (boxtype == SAND || boxtype == FRIEND) {
        // for sandbox, grant access to other boxes.
        // friend box 
        for (int i = 0; i < 16; i++) {
            //printf("%d is sandbox, %d is %d, ")
            if (id_allocated[i] && id_box[i] != SAND) {
                // it's another friend box or unbox
                unsigned int old = shim_stack0.tls.app_pkrus[i];
                shim_stack0.tls.app_pkrus[i] &= ~ PKRU_NO_KEY(domain_id);
                printf("pkru[%d] = %u --> %u\n", i, old, shim_stack0.tls.app_pkrus[i]);
            }
        }
    }
    new_pkru &= ~PKRU_NO_KEY(domain_id);
    
    shim_stack0.tls.app_pkrus[domain_id] = new_pkru;
    printf("pkru[%d] = %u\n", domain_id, new_pkru);
    // sync
    for (int i = 0; i < 16; i++)
        get_tls()->app_pkrus[i] = shim_stack0.tls.app_pkrus[i];

    get_tls()->current_pkru = calc_pkru(get_tls()->current_domain);
    printf("Current PKRU for domain %lld updated to %u\n", get_tls()->current_domain, get_tls()->current_pkru);
    // TODO: all other cores must sync and reset PKRU

}

int install_app(char* buf, int domain_id, box_t boxtype) {
    if (id_allocated[domain_id] || domain_id < 0 || domain_id >= 16)
        return 0; // invalid

    id_box[domain_id] = boxtype;
    id_allocated[domain_id] = 1;

    iv_encapslation_t evt;
    if (!app_valid_v1(buf, &evt, domain_id, boxtype)) {
        return 0; // invalid
    }
    boxtype = evt.box_type;
    int max_func = (evt.func_end - evt.func_begin) / 8;
    
    char *xcall_stub = evt.stub_begin;
    // if boxtype != SAND, we install safebox stub
    // TODO: As we are now using dynamic app_pkru from TLS
    // We should merge the two trampolines
    
    xcall_stub = install_stub(xcall_stub, max_func, domain_id, evt.box_type != SAND);
    
    unsigned long* tf = (unsigned long*)(xcall_stub + 0x1000);
    for (int i = 0; i < max_func; i++) {
        tf[i] = ( (unsigned long* ) evt.func_begin)[i];
        ( (unsigned long* ) evt.func_begin)[i] = i;
    }
    // allow executaion
    MEMLOCK;
    map_addr_t addr2 = map_addr(evt.stub_begin, (char*)evt.stub_begin + 4096 - 1);
    rawcall(mprotect_pkey, evt.stub_begin, 0x1000, PROT_READ | PROT_EXEC, IV_CONF);
    map_set(addr2, map_norm(READABLE|EXECUTABLE, 1));

    map_addr_t addr3 = map_addr((char*)evt.stub_begin + 4096, (char*)evt.stub_end - 1);
    rawcall(mprotect_pkey, (char*)evt.stub_begin + 0x1000, (unsigned long)(evt.stub_end - evt.stub_begin - 4096), PROT_READ, IV_NORMAL);
    map_set(addr3, map_norm(READABLE, 1));
    MEMUNLOCK;

    if (boxtype == SAND) 
        sandbox_pkey(domain_id);

    int* mark = (int*) evt.iv_domain_mark;
    *mark = domain_id;
    outer_allowed[domain_id] = 1;

    // skip domian 14, it already set
    if (domain_id != 14)
        app_update_tls(domain_id, boxtype);

    printf("IV<%d> stub=%p %p\n", domain_id, xcall_stub, evt.stub_begin);
    return 0;
}

void app_alloc_stack(iv_tls_t* tls) {
    // MEMLOCK;
    const int stack_len = 8*4096;
    const int untrusted_len = 4096;
    const int total_size = stack_len * (16);
    char* stacks = rawcall(mmap, 0, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    for (int i = 0; i < 16; i++) {
        map_addr_t addr = map_addr(stacks, stacks + (stack_len - untrusted_len) - 1);
        map_mode_t mode = map_norm(PROT_READ | PROT_WRITE, 0) | (i << 16); // trusted mem for app i
        map_set(addr, mode);
        addr = map_addr(stacks + (stack_len - untrusted_len), stacks + stack_len - 1);
        mode = map_norm(PROT_READ | PROT_WRITE, 1); // cannot unmap
        map_set(addr, mode);
        // printf("Stack %d %p ~~ %p\n",i, stacks + (i)*stack_len, stacks + (i+1)*stack_len);
        rawcall(mprotect_pkey, stacks + (i)*stack_len, stack_len - untrusted_len, PROT_READ | PROT_WRITE, i);
        rawcall(mprotect_pkey, stacks + (i+1)*stack_len - untrusted_len, untrusted_len, PROT_READ | PROT_WRITE, IV_USER);
        tls->app_stack[i] = (unsigned long)(stacks + (i+1)*stack_len - untrusted_len);
        
        // prepare pkru values
        tls->app_pkrus[i] = shim_stack0.tls.app_pkrus[i];

        #ifdef CFICET
        if (i >= min_sandbox) {
            ssize_t user_stacklen = 0x1000 * 32;
            unsigned long addr = user_stacklen;
            int ret;
            if ((ret = rawcall(arch_prctl, 0x3004 /* alloc shstk */, &addr))) {
                printf("alloc stack failed. %d\n", ret);
                return 0;
            }
            rawcall(mprotect_pkey, addr, user_stacklen, PROT_READ | 0x10, i);
            map_set(map_addr(addr, ((char*)addr) + user_stacklen - 1), TRUSTED_MEM);
            addr = addr + user_stacklen;
            ss_put_restore(addr - 8, addr);
            tls->app_ssp[i] = addr;
        }
        #endif
    }
    // MEMUNLOCK;
}

int app_allow_outer_promote(int domain_id) {
    if (domain_id <= 1 || domain_id > 15)
        return 0;
    return outer_allowed[domain_id];
}