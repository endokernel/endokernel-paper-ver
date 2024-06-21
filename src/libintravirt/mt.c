
#include <asm/prctl.h>
#include <asm/unistd.h>

#include <mt.h>
#include <rawcall.h>
#include <shim_syscalls.h>
#include <asm-offsets.h>
#include <erim/mmap/map.h>
#include <shim_table.h>

#include <cet.h>

#include <shim_signal.h>

#include <pkru.h>

#include <app.h>

extern int memlock;

#define MEMLOCK         iv_lock(&memlock)
#define MEMUNLOCK       iv_unlock(&memlock)

#define align(begin, len) ((unsigned long)(begin)&(~0xffful)), ((unsigned long)(begin) - ((unsigned long)(begin)&(~0xffful))+(unsigned long)(len))
iv_stack_t* create_stack(char *stack) {
    MEMLOCK;
    if (!stack)
        stack = rawcall(mmap, 0, sizeof(iv_stack_t), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    iv_stack_t* iv_stack = (iv_stack_t*)stack;
    if (stack > 0) {
        map_addr_t addr = map_addr(stack, stack + sizeof(iv_stack_t) - 1);
        map_mode_t mode = map_norm(PROT_READ | PROT_WRITE, 1);
        map_set(addr, mode);
        rawcall(mprotect_pkey, align(iv_stack, sizeof(iv_stack_t)), PROT_READ | PROT_WRITE, IV_CONF);
        rawcall(mprotect_pkey, align(&iv_stack->tls, sizeof(iv_tls_t) - TP_OFFSET), PROT_READ | PROT_WRITE, IV_NORMAL);
        app_alloc_stack(&iv_stack->tls);
        void * addrof_unreach = (void*)passthrough_unreachable;
        for (int i = 0; i < SYSCALLNR; i++)
            iv_stack->tls.bypass[i] = shim_table[i] == addrof_unreach;
        #ifdef FILTERTP
        #ifndef RANDOM
        //printf("apply local trampoline %p + %d", iv_stack->local_trampoline, 4096);
        int res = rawcall(mprotect_pkey, iv_stack->local_trampoline, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, IV_CONF);
        //printf(" = %d\n", res);
        #endif
        #endif
    }else stack = 0;
    MEMUNLOCK;
    return stack;
}

void load_sigstack();

iv_tls_t* mt_create_thread(void* user_sp) {
    #ifdef QUEEN
    return 0;
    #else
    printf("user sp=%p\n", user_sp);
    iv_stack_t *stack = create_stack(0);
    if (stack) {
        struct shim_regs* user_regs = (struct shim_regs*) get_tls()->untrusted_stack;
        
        iv_tls_t* tls = &stack->tls;
        tls->self = tls;
        tls->trusted_stack = &stack->stack; 
        tls->base = stack;
        tls->top = stack->end;;
        tls->current_pkru = untrusted_pkru; // TODO: FIX: use calc_pkru
        tls->current_domain = DOMAIN_FIELD(2,0);
        tls->vfork = 0;
#ifdef FILTERTP
#ifdef RANDOM
        tls->trampoline = 0xcc;
#else
        tls->trampoline = stack->local_trampoline;
        *(unsigned int*)(tls->trampoline) = 0xccc3050f;
#endif
#endif
#ifdef CFICET
        ssize_t user_stacklen = 0x1000 * 32;
        unsigned long addr = user_stacklen;
        tls->trusted_ssp = 0;
        int ret;
        if ((ret = rawcall(arch_prctl, 0x3004 /* alloc shstk */, &addr))) {
            printf("alloc stack failed. %d\n", ret);
            return 0;
        }
        MEMLOCK;
        rawcall(mprotect_pkey, addr, user_stacklen, PROT_READ | 0x10, IV_USER);
        map_set(map_addr(addr, ((char*)addr) + user_stacklen - 1), TRUSTED_MEM); 
        MEMUNLOCK;
        addr = addr + user_stacklen;
        ss_put(addr - 8, user_regs->rip);
        ss_put_restore(addr - 16, addr - 8);
        tls->untrusted_ssp = addr - 8;
#endif
        // TODO: add return frame in user stack
        user_sp -= 0x80;
        user_sp -= sizeof(struct shim_regs);
        struct user_sp* new_user_regs = user_sp;
        memcpy(new_user_regs, user_regs, sizeof(struct shim_regs));
        tls->untrusted_stack = user_sp;
        return tls;
    } else {
        return 0;
    }
    #endif
}

int install_seccomp_filter(void* start, void* end);

void prepare_thread_stack(iv_tls_t* tls){
    //  dispatch if not CET
    // dispatch + nexpoline + tp
    // dispatch + cet + all code
    // seccomp + cet + all code
    #ifdef QUEEN
    return ;
    #else
    int ret = 0;
    {
        int sysno = 158;
        register unsigned long _a1 __asm__ ("rdi") = ARCH_SET_GS;
        register unsigned long _a2 __asm__ ("rsi") = tls;
        int res;
        __asm__ __volatile__ ("syscall\n\t"
                        : "=a" (res)
                        : "0" (sysno), "r"(_a1), "r"(_a2)
                        : "memory", "cc", "r11", "cx");

    }
    #ifdef FILTERTP
        // dispatch + nexpoline
        if((ret = install_seccomp_filter(tls->trampoline, tls->trampoline + 4096)) < 0) {
	        return ;
        }
    #else
    #ifdef DISPATCH
        // seccomp will not disable after clone, no need to install again
        extern char code_start;
        extern char code_end;
        if((ret = install_seccomp_filter(&code_start, &code_end)) < 0) {
	        return ;
        }
    #endif
    #endif


    #endif
    load_sigstack();
}
