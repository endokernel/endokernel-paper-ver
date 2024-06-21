#ifndef _SHIM_SIGNAL_H_
#define _SHIM_SIGNAL_H_

struct shim_regs {
    unsigned long r15,r14,r13,r12,r11,r10,r9,r8;
    unsigned long rcx, rdx,rsi,rdi,rbx,rbp;
    unsigned long rflags;
    unsigned long rip; // future: set return address to signal handler
};

void shim_sig_entry(int signum, siginfo_t *siginfo,void *uctx);
unsigned long shim_sighook_syscall();
void shim_sig_init();

// virts

struct __kernel_sigaction_1 {
    __sighandler_t k_sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer) (void);
    sigset_t sa_mask;
};

int virt_sigaction(int signum, const struct __kernel_sigaction_1 *act, struct __kernel_sigaction_1 *oldact);
int virt_sigaltstack(unsigned long sp, stack_t *_new, stack_t *old);
unsigned long virt_sigreturn(int simulated);
int virt_sigprocmask(int how, const unsigned long* set, unsigned long* oldset);

int virt_sigsuspend(unsigned long mask);
unsigned long virt_sigpending();

int virt_sigtimedwait(unsigned long set, siginfo_t *info, void* uts);
#endif