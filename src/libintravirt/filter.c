#include <api.h>
#include <bpf-helper.h>
#include <shim_passthru.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/prctl.h>

#include <shim_trampoline.h>
#include <rawcall.h>
#include <mt.h>

#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#ifndef SIGCHLD
# define SIGCHLD 17
#endif

#ifdef SECCOMP

void initial_syscall();
extern unsigned char trampoline_start, trampoline_end;

int install_seccomp_filter(void* start, void* end) {
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    printf("set up filter in %p-%p V2020528\n", start, end);

    struct sock_filter filter[] = {        
        LOAD_SYSCALL_NR,
        SYSCALL(__NR_exit_group,     ALLOW),
        SYSCALL(__NR_exit,     ALLOW),
        IP,
        JEQ(((unsigned long) &trampoline_start) + 2, ALLOW),
        JLT((unsigned long) start, TRAP),
        JGT((unsigned long) end,   TRAP),
        LOAD_SYSCALL_NR,
        ALLOW,
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    bpf_resolve_jumps(&labels, filter, prog.len);

    err = rawcall(prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (IS_ERR(err))
        return -ERRNO(err);
#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1UL << 2)
#endif
//    err = rawcall(prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    err = rawcall(seccomp, SECCOMP_SET_MODE_FILTER,  SECCOMP_FILTER_FLAG_SPEC_ALLOW, &prog);
    if (IS_ERR(err)) {
        return -ERRNO(err);
    }
    return 0;
}

#endif

#ifdef DISPATCH
# define PR_SET_SYSCALL_USER_DISPATCH	59
# define PR_SYS_DISPATCH_OFF	0
# define PR_SYS_DISPATCH_ON	1
int install_seccomp_filter(void* start, void* end) {
#ifndef CFICET
    rawcall(prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start, end, &(get_tls()->self->dispatch));
    get_tls()->dispatch = PR_SYS_DISPATCH_ON;
#else
    rawcall(prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start, end);
#endif
}

#endif
