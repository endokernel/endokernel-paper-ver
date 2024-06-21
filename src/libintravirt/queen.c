#include <sys/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>

#include <queen.h>
#include <shim_defs.h>
#include <shim_trampoline.h>
#include <shim_passthru.h>
#include <shim_syscalls.h>
#include <shim_types.h>

#include <asm-offsets.h>

#include "mmap/map.h"
#include <mt.h>

#include <pkru.h>

int q_flags = 0;
void *q_user_stack_addr = NULL;
int *q_parent_tidptr = NULL;
int *q_child_tidptr = NULL;
void *q_tls = NULL;
int q_ret = 0;
void *q_fs = NULL;
void *q_gs = NULL;
void *q_rip = NULL; 
void *q_rsp = NULL; 

extern int queenlock;
extern int qretlock;
#define QUEENLOCK   iv_lock(&queenlock)
#define QRETUNLOCK  iv_unlock(&qretlock)

static unsigned long *qstack;

int install_seccomp_filter(void* start, void* end);

void child_thread(void) {
    // Child thread jmp to here with "almost" empty stack

    // Get the stackptr and tls from the stack
    register void *rsp asm("rsp");
    unsigned long stackptr, tls, fs;
    stackptr = (unsigned long)*(unsigned long*)(rsp + 24);
    tls = (unsigned long)*(unsigned long*)(rsp + 32);
    fs = (unsigned long)*(unsigned long*)(rsp + 40);

    // Fill the syscall instruction for this thread (for a while)
    unsigned long* p_stackptr = (unsigned long*)stackptr;
    iv_tls_t* t_tls = p_stackptr;
    unsigned int *__trampoline = t_tls->trampoline;
    __trampoline[0] = 0xccc3050f;

    printf("child_thread: stackptr=%lx, tls=%lx, fs=%lx\n", stackptr, tls, fs);

    // Copy FS value npt to hit stack canary
    rawcall(arch_prctl, ARCH_SET_FS, fs);

    // Set GS value
    rawcall(arch_prctl, ARCH_SET_GS, stackptr);


    // Set the seccomp filter
    if(install_seccomp_filter((void *)t_tls->trampoline, (void *)(t_tls->trampoline + 3)) < 0) {
        printf("seccomp error\n");
        rawcall(exit_group, -1);
    }

    // Set TLS to RDI for the function parameter
    // switch to untrusted and return to thread_start
    // TODO: add check for setting PKRU
    __asm__ __volatile__ ("" : : "D" (tls):);
    __asm__("movq "STR(IV_TLS(trampoline))", %rcx\n\t"
            "movl $0xcccccccc, (%rcx)\n\t"
            "mov "STR(IV_TLS(untrusted_stack))", %rsp\n\t"
            "xor %ecx, %ecx\n"
            "xor %edx, %edx\n"
            "mov "STR(IV_TLS(current_pkru))", %eax\n"
            ".byte 0x0f, 0x01, 0xef\n"
            "retq");
}



void child_process(void) {
    printf("child_process\n");
    rawcall(arch_prctl, ARCH_SET_GS, q_gs);
    // Copy FS value npt to hit stack canary
    rawcall(arch_prctl, ARCH_SET_FS, q_fs);

    // Set the seccomp filter
    iv_tls_t *tls = q_gs;
    if(install_seccomp_filter((void *)tls->trampoline, (void *)(tls->trampoline + 3)) < 0) {
        printf("seccomp error\n");
        rawcall(exit_group, -1);
    }

}


void load_sigstack();

void child_untrusted_process(void) {
    printf("child_untrusted_process\n");
    rawcall(arch_prctl, ARCH_SET_GS, q_gs);
    // Copy FS value npt to hit stack canary
    rawcall(arch_prctl, ARCH_SET_FS, q_fs);

    load_sigstack();
    
    // Set the seccomp filter
    unsigned long *trampoline_addr = (unsigned long *)q_gs;
    if(install_seccomp_filter((void *)trampoline_addr[4], (void *)(trampoline_addr[4] + 3)) < 0) {
        printf("seccomp error\n");
        rawcall(exit_group, -1);
    }

    __asm__("mov "STR(IV_TLS(untrusted_stack))", %rsp\n"
            "xor %ecx, %ecx\n"
            "xor %edx, %edx\n"
            "mov "STR(IV_TLS(current_pkru))", %eax\n"
            ".byte 0x0f, 0x01, 0xef\n"
            "retq");
}


int nexpoline_flag[PAGESIZE];
unsigned long get_nexpoline(void) {
    unsigned long res = 0;
    for(int i = 2 ; i < PAGESIZE ; i++) {
        if (nexpoline_flag[i] == 0) {
            nexpoline_flag[i] = 1;
            res = (unsigned long)(&trampoline_start) + (i * 4);
            printf("trampoline: %lx\n", res);
            break;
        }
    }
    return res;
}



#define STACKPGSIZE 10
/**   Trusted stack data structure
 * +---------------------------------------------+  <- top addr
 * |                                             |
 * |                                             |
 * |                                             | <- trusted stack pointer (somewhere in here)
 * |      trusted stack (STACKPGSIZE pages)      |
 * |                                             |
 * |                                             |
 * +---------------------------------------------+
 * |          address of the nexpoline           |
 * +---------------------------------------------+
 * |        top addr of the trusted stack        |
 * +---------------------------------------------+
 * |       base addr of the trusted stack        |
 * +---------------------------------------------+
 * |      stack pointer for untrusted stack      |
 * +---------------------------------------------+
 * |       stack pointer for trusted stack       |
 * +---------------------------------------------+  <- base addr  (GS holds this address)
 */
void queen_loop(void) {
    //rawcall(arch_prctl, ARCH_SET_GS, qstack);

    // Get GS register to the temporary region in asm
    {
        iv_tls_t* tls = &((iv_stack_t*)qstack)->tls;
        unsigned long int sys_no = 158, resultvar;
        register long int _a2 __asm__ ("rsi") = tls;
        register long int _a1 __asm__ ("rdi") = ARCH_SET_GS;
        register long int _rbx __asm__ ("rbx") = tls->trampoline;

        __asm__ __volatile__ ("call *%%rbx\n\t"
                            : "=a" (resultvar)
                            : "0" (sys_no), "r"(_a1), "r"(_a2), "r"(_rbx)
                            : "memory", "cc", "r11", "cx");
    }
    while(1) {
        QUEENLOCK;

        // copy params
        int _flags = q_flags;
        void *_user_stack_addr = q_user_stack_addr;
        int *_parent_tidptr = q_parent_tidptr;
        int *_child_tidptr = q_child_tidptr;
        void *_tls = q_tls;
        void *_fs = q_fs;
        void *_gs = q_gs;
        void *_rip = q_rip; 
        void *_rsp = q_rsp; 

        printf("clone requested!: flags %x, stack %p, ptid %p, ctid %p, tls %p, fs %p\n", _flags, _user_stack_addr, _parent_tidptr, _child_tidptr, _tls, _fs);
        if(q_flags & CLONE_VM) {
            printf("new thread\n");
            iv_stack_t* ivs = create_stack(0);
            
            // Setup trusted stack of the child
            unsigned long *stackptr;
            stackptr = ivs->stack;
            stackptr--;
            *stackptr = (unsigned long)_fs;
            stackptr--;
            *stackptr = (unsigned long)_tls;
            stackptr--;
            *stackptr = (unsigned long)&ivs->tls;     // Use as function param
            stackptr--;
            *stackptr = (unsigned long)child_thread;    // Return address for the child thread

            printf("stackptr = %p\n", stackptr);

            // Store stack pointers
            iv_tls_t* tls = &ivs->tls;
            tls->base = ivs;
            tls->top = ivs->end;
            tls->untrusted_stack = _user_stack_addr;
            tls->self = tls;
            tls->trampoline = get_nexpoline();
            tls->trusted_stack =  ivs->stack;
            
            // TODO: what if someone forked from another domain?
            tls->current_pkru = untrusted_pkru; // TODO: FIX: use calc_pkru
            tls->current_domain = DOMAIN_FIELD(2,0);
            q_ret = rawcall(clone, _flags, stackptr, _parent_tidptr, _child_tidptr, _tls);
            printf("clone done: tid: %d\n", q_ret);
        } else {
            printf("new proc\n");
            // invoke queen thread in the 1st place
            q_ret = rawcall(clone, _flags, NULL, _parent_tidptr, _child_tidptr, _tls);
            
            if (q_ret == 0) {
                printf("child\n");
                unsigned long *stackptr;
                stackptr = _rsp;
                stackptr--;
                if(_user_stack_addr == NULL) {
                    // Simple fork()
                    *stackptr = (unsigned long)_rip;
                    stackptr--;
                    *stackptr = (unsigned long)child_process;    
                } else {
                    // New process with given stack pointer
                    *stackptr = (unsigned long) (*(unsigned long*)(_user_stack_addr));
                    stackptr--;
                    *stackptr = (unsigned long)child_untrusted_process;

                    unsigned long *ptr = _gs;
                    ptr++;
                    *ptr = (unsigned long)_user_stack_addr;
                }
                
                int child = rawcall(clone, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_SYSVSEM, 
                stackptr, &_parent_tidptr, &_child_tidptr, NULL);
            } else {
                printf("parent %d\n", q_ret);
            }
        }
        queenlock = 1;  // No one else sets this lock val
        QRETUNLOCK;
    }
}

int spawn_queen() {
    int child, ptid, ctid;
    unsigned long rsp;

    iv_stack_t* ivs = create_stack(0);
    qstack = ivs;
    rsp = ivs->stack;
    iv_tls_t *tls = &ivs->tls;
    tls->base = qstack;
    tls->top = ivs->end;
    tls->self = tls;
    tls->trusted_stack = 0;
    tls->untrusted_stack = 0;
    tls->trampoline = (unsigned long)(&trampoline_start) + 4;

    rsp &= ~0xff;
    unsigned long* stack_v = rsp;
    *--stack_v = queen_loop;

    child = rawcall(clone, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_SYSVSEM, 
                stack_v, &ptid, &ctid, NULL);
    if(child < 0) {
        printf("queen clone failed\n");
        rawcall(exit_group, -1);
    }

    return 0;
}


