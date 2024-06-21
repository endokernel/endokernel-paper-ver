#define ERIM_ISOLATE_UNTRUSTED
#define ERIM_SWAP_STACKS

#include <ucontext.h>
#include <signal.h>
#include <errno.h>

#include <erim.h>
#include <erim/mmap/map.h>
#include <api.h>

#include <rawcall.h>

#include <shim_signal.h>

#include <cet.h>

#include <asm-offsets.h>
#include <mt.h>
#include <pkru.h>

#include <iv_debug.h>

int printf (const char  *fmt, ...) __attribute__((format (printf, 1, 2)));
#include <stdarg.h>
int vprintf(const char * fmt, va_list ap) __attribute__((format (printf, 1, 0)));

typedef void (*shim_fp)(void);
typedef unsigned long (*shim_fp_6)(long,long,long,long,long,long);

extern shim_fp shim_table[];

#define SS_AUTODISARM	(1U << 31)
#define SA_RESTORER 0x04000000

#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

enum
{
  REG_R8 = 0,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
  REG_RDI,
  REG_RSI,
  REG_RBP,
  REG_RBX,
  REG_RDX,
  REG_RAX,
  REG_RCX,
  REG_RSP,
  REG_RIP,
  REG_EFL,
  REG_CSGSFS,		/* Actually short cs, gs, fs, __pad0.  */
  REG_ERR,
  REG_TRAPNO,
  REG_OLDMASK,
  REG_CR2
};


extern void sigtrampoline_for_trusted();
        
extern void monitor_ret();
extern void monitor_transaction_begin();
extern void monitor_cet_begin();
extern void monitor_transaction_end();

// instead, use PKRU value from uctx
char buf[256];
const char hex_table[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
void debug(unsigned long x) {
    int n = 254;
    buf[255] = 0;
    buf[n] = '0';
    int i = 0;
    if (x != 0) {
        while (x) {
            buf[n] = hex_table[x % 16];
            x /= 16;
            n--;
            i++;
        }
    } else i = 1;
    rawcall(write, 1, buf + n, i + 1);

}

/*
    signal virt related
*/

static struct __kernel_sigaction_1 sig_tables[65] = {0};
static stack_t sig_stack_current;
// static unsigned long get_tls()->sig_mask;

/*
    * get_tls()->sig_mask is the masking status of user
    * get_tls()->sig_mask | queued_sigs is mask we set for kernel
    * deliverable_sigs & queued_sigs & ~(get_tls()->sig_mask) is signal that we can deliver now
*/

static inline void reset_ss(){
    sig_stack_current.ss_sp = NULL;
    sig_stack_current.ss_flags = SS_DISABLE;
    sig_stack_current.ss_size = 0;
}

static inline int on_sig_stack(unsigned long sp) {
	if (sig_stack_current.ss_flags & SS_AUTODISARM)
		return 0;

	return sp > (unsigned long)sig_stack_current.ss_sp &&
		sp - (unsigned long)sig_stack_current.ss_sp <= sig_stack_current.ss_size;
}

static inline int ss_flags(unsigned long sp)
{
	if (!sig_stack_current.ss_size)
		return SS_DISABLE;

	return on_sig_stack(sp) ? SS_ONSTACK : 0;
}

/* mask for all SS_xxx flags */
#define SS_FLAG_BITS	SS_AUTODISARM
#define MINSIGSTKSZ	2048
int virt_sigaltstack(unsigned long sp, stack_t *_new, stack_t *old) {
    /////////////////////////
    /// TODO!!!
    ////////////////////////

    if (old) {
        memcpy(old, &sig_stack_current, sizeof(stack_t));
        old->ss_flags &= SS_FLAG_BITS;
        old->ss_flags |= ss_flags(sp);
    }

    if (_new) {
        void *new_sp = _new->ss_sp;
        size_t sz = _new->ss_size;
        if (on_sig_stack(sp)) 
            return -EPERM;
        int mode = _new->ss_flags & ~SS_FLAG_BITS;
        if (mode != SS_DISABLE && mode != SS_ONSTACK && mode) {
            return -EINVAL;
        }

        int new_mode = mode = _new->ss_flags & (~SS_ONSTACK); // we don't need SS_ONSTACK
        if (mode == SS_DISABLE) {
            new_sp = 0;
            sz = 0;
        } else {
            if (sz < MINSIGSTKSZ) {
                return -ENOMEM;
            }
        }

        sig_stack_current.ss_flags = new_mode;
        sig_stack_current.ss_size = sz;
        sig_stack_current.ss_sp = new_sp;
    }
    return 0;
}

static inline void __cpuid1(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile(
		"cpuid;"
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

#define XSTATE_PKRU_BIT	(9)
#define XSTATE_PKRU	0x200

#define XSTATE_CET_USER_BIT	(11)
#define XSTATE_CET_USER	0x900
static int _pkru_xstate_offset = 0;
static int _pkru_cet_user_offset = 0;

static inline int pkru_xstate_offset(void)
{
    if (_pkru_xstate_offset != 0)
        return _pkru_xstate_offset;

	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	int xstate_offset;
	int xstate_size;
	unsigned long XSTATE_CPUID = 0xd;
	int leaf;

	/* assume that XSTATE_PKRU is set in XCR0 */
	leaf = XSTATE_PKRU_BIT;
	{
		eax = XSTATE_CPUID;
		ecx = leaf;
		__cpuid1(&eax, &ebx, &ecx, &edx);

		if (leaf == XSTATE_PKRU_BIT) {
			xstate_offset = ebx;
			xstate_size = eax;
		}
	}

	if (xstate_size == 0) {
		//printf("could not find size/offset of PKRU in xsave state\n");
		return 0;
	}

	return _pkru_xstate_offset = xstate_offset;
}

static inline int cet_user_xstate_offset(void)
{
    if (_pkru_cet_user_offset != 0)
        return _pkru_cet_user_offset;

	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	int xstate_offset;
	int xstate_size;
	unsigned long XSTATE_CPUID = 0xd;
	int leaf;

	/* assume that XSTATE_PKRU is set in XCR0 */
	leaf = XSTATE_CET_USER_BIT;
	{
		eax = XSTATE_CPUID;
		ecx = leaf;
		__cpuid1(&eax, &ebx, &ecx, &edx);

		if (leaf == XSTATE_CET_USER_BIT) {
			xstate_offset = ebx;
			xstate_size = eax;
		}
	}

	if (xstate_size == 0) {
		//printf("could not find size/offset of PKRU in xsave state\n");
		return 0;
	}

	return _pkru_cet_user_offset = xstate_offset;
}

static unsigned long x_size = 0;
static inline unsigned long get_extended_size(){
    if (x_size)
        return x_size;
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    {
        unsigned long XSTATE_CPUID = 0xd;
        eax = XSTATE_CPUID;
        ecx = 0;
        __cpuid1(&eax, &ebx, &ecx, &edx);
    }

    x_size = ebx + FP_XSTATE_MAGIC2_SIZE;

    return x_size;
}

void _xsave(char *buf) {
    // with mask = -1
    asm volatile(
        "xor %%rax, %%rax\n\t"
        "not %%rax\n\t"
        "mov %%rax, %%rdx\n\t"
        "xsave %0"
        :"=m"(*buf) 
        ::"rax", "rdx");
}


void _xrstor(char *buf) {
    // with mask = -1
    //printf("_xrstor=%p\n", buf);
    asm volatile(
        "xor %%rax, %%rax\n\t"
        "not %%rax\n\t"
        "mov %%rax, %%rdx\n\t"
        "xrstor %0"
        :
        :"m"(*buf) 
        :"rax", "rdx");
}

struct xstate_region {
    /* 64-bit FXSAVE format.  */
    uint16_t		cwd;
    uint16_t		swd;
    uint16_t		ftw;
    uint16_t		fop;
    uint64_t		rip;
    uint64_t		rdp;
    uint32_t		mxcsr;
    uint32_t		mxcr_mask;
    struct _libc_fpxreg	_st[8];
    struct _libc_xmmreg	_xmm[16];

    uint32_t				reserved2[12];
    struct _fpx_sw_bytes reserved;

    //uint8_t extension[0];

    // FP_XSTATE_MAGIC2
};

struct sc_ext {
    unsigned long total_size;
    unsigned long ssp;
    unsigned long wait_endbr;
};

#define SSP_CLEARANCE (8*128)

/*
  We will utilize kernel's signal queue.
  i.e. for any signal, we only keep one slot for it to fall from kernel to signal virt

  before it's been deliver to user, we mask it
  and after we success deliver it, we unmask it
*/

struct sigqueue {
    int signum;
    siginfo_t siginfo;
    unsigned int cr2, trapno, csgsfs, err;
};

#define Q_SIZE 65
static struct sigqueue pending_sig[Q_SIZE]; // at most 64 pending signal
static unsigned long queued_sigs = 0;
static unsigned long deliverable_sigs = 0;


int virt_sigprocmask(int how, const unsigned long* set, unsigned long* oldset) {
    // Copy the old sigprocmask value to 'oldset'
    unsigned long _old = get_tls()->sig_mask;

    if (set) {
        // According on 'how', set the new sigprocmask value based on 'set'
        switch (how) {
            case SIG_BLOCK:
                get_tls()->sig_mask |= *set;
                break;

            case SIG_UNBLOCK:
                get_tls()->sig_mask &= ~*set;
                break;

            case SIG_SETMASK:
                get_tls()->sig_mask = *set;
                break;
        }
        unsigned long next_mask = get_tls()->sig_mask | queued_sigs;
        rawcall(rt_sigprocmask, SIG_SETMASK, &next_mask, NULL, sizeof(unsigned long));
    }

    if (oldset)
        *oldset = _old;
}

// assume someone already check args for me
int virt_sigaction(int signum, const struct __kernel_sigaction_1 *act, struct __kernel_sigaction_1 *oldact) {
    //if (signum == SIGSYS)
        //return 0;
    if (oldact) {
        memcpy(oldact, sig_tables + signum, sizeof(struct __kernel_sigaction_1));
    }
    
    if (act) {
        struct __kernel_sigaction_1 payload;
        memcpy(sig_tables + signum, act, sizeof(struct __kernel_sigaction_1));
        memcpy(&payload, act, sizeof(struct __kernel_sigaction_1));
        if (!(payload.k_sa_handler == SIG_IGN || payload.k_sa_handler == SIG_DFL || payload.k_sa_handler == SIG_ERR) ){
            deliverable_sigs |= (1ULL << (signum-1));
            get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));
            // remove SA_RESTART to make fanotify03 happy
            payload.sa_flags |= SA_ONSTACK | SA_SIGINFO | SA_RESTORER; //| SA_RESTART;
            payload.k_sa_handler = shim_sig_entry;
            payload.sa_flags &= ~SA_NODEFER; // we don't want to handle nested signal in our signal handler
            *((unsigned long*)&payload.sa_mask) = -1;
            payload.sa_restorer = sigtrampoline_for_trusted;
        } else {
            deliverable_sigs &= ~(1ULL<<(signum-1));
            get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));
        }
        printf("raw_signal = { signum=%d, handler=%p, flags=%x, mask=%x, restorer=%p }\n", signum, payload.k_sa_handler, payload.sa_flags, payload.sa_mask, payload.sa_restorer);
        return rawcall(rt_sigaction, signum, &payload, NULL, sizeof(unsigned long));
    }
    return 0;
}


#define reg(x) ((ucontext_t*)uctx)->uc_mcontext.gregs[REG_##x]
int push_signal(int signum, siginfo_t *siginfo, void *uctx) {
    if (!(queued_sigs & (1ULL << (signum -1)))) {
        queued_sigs |= (1ULL << (signum -1));
        pending_sig[signum].signum = signum;
        
        get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));
        //printf("get_tls()->pendsig = %d\n", get_tls()->pendsig);
        // print queued_sigs, deliverable_sigs, get_tls()->sig_mask in binary
        //printf("queued_sigs = %lx, deliverable_sigs = %lx, get_tls()->sig_mask = %lx\n", queued_sigs, deliverable_sigs, get_tls()->sig_mask);

        memcpy(&(pending_sig[signum].siginfo), siginfo, sizeof(siginfo_t));
        pending_sig[signum].cr2 = reg(CR2);
        pending_sig[signum].trapno = reg(TRAPNO);
        pending_sig[signum].csgsfs = reg(CSGSFS); // TODO: Should we allow user to modify CS/GS/SS???
        pending_sig[signum].err = reg(ERR);
        return 1;
    }
    return 0;
}

#define sig_stack_size  8192*8
//char buf_sig_stack[sig_stack_size];
char *buf_sig_stack;

void load_sigstack() {
    stack_t new_s, old_s;
    new_s.ss_sp = buf_sig_stack;
    new_s.ss_flags = 0;
    new_s.ss_size = sig_stack_size;
    printf("load signal stack @ %p\n", buf_sig_stack);
    rawcall(sigaltstack, &new_s, NULL);
}

void shim_sig_init(){
    buf_sig_stack = rawcall(mmap, NULL, sig_stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    rawcall(mprotect_pkey, buf_sig_stack, sig_stack_size, PROT_READ | PROT_WRITE, IV_CONF); // allow untrusted to write
    map_set(map_addr(buf_sig_stack, buf_sig_stack + sig_stack_size - 1), READABLE | WRITABLE | TRUSTED_MEM); 
    // anyway we don't want user to unmap this ...
    printf("shim_stack_addr=%p\n", buf_sig_stack);
    printf("shim_sig_entry=%p\n", shim_sig_entry);
    
    load_sigstack();

    memset(sig_tables, 0, sizeof(sig_tables));
    reset_ss();
    queued_sigs = 0;

    // sig SYS
    struct __kernel_sigaction_1 sa = {0};
    sa.k_sa_handler = shim_sig_entry;
    *((unsigned long*)&sa.sa_mask) = -1;
    sa.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_RESTORER | SA_RESTART;
    sa.sa_restorer = sigtrampoline_for_trusted;
    #ifdef USESIGTRAP
    rawcall(rt_sigaction, SIGSYS, &sa, NULL, sizeof(unsigned long));
    // register TRAP signal handler
    rawcall(rt_sigaction, SIGTRAP, &sa, NULL, sizeof(unsigned long));
    
    // register PKRU signal handler
    // rawcall(rt_sigaction, SIGSEGV, &sa, NULL, sizeof(unsigned long));
    #endif
}


struct ucontext_1 {
    unsigned long              uc_flags;
    struct ucontext_1*           uc_link;
    stack_t                    uc_stack;
    struct sigcontext          uc_mcontext;
    unsigned long                   uc_sigmask;
};

struct rt_sigframe {
	char *pretcode;
	struct ucontext_1 uc;
	siginfo_t info;
	/* fp state follows here */
};

struct rt_sigframe_without_ret {
	struct ucontext_1 uc;
	siginfo_t info;
	/* fp state follows here */
};

// TODO: should NOT use IP for checking security


#define from_trusted_stack(addr) ((void*)(addr) >= buf_sig_stack && (void*)(addr) < buf_sig_stack + sig_stack_size)
//#define from_trusted_stack(addr) (1)
unsigned long volatile __flag_from_kernel[65];
unsigned long shim_signal_touser(int signum, unsigned long onsigstack, unsigned long proposed_rsp, siginfo_t *siginfo, gregset_t *gregs, struct xstate_region* fpregs, unsigned long* ssp, unsigned long old_ssp);
extern unsigned char trampoline_start, trampoline_end;
/* RDI = sig
   RSI = info
   RDX = uc
*/
// detect if signal from kernel
// if signal from kernel
// we're in semi-trusted zone
// in which we can write to trusted memory
// but not in untrsuted
// so we be careful not to push&pop
// while checking the origin
//#define _SECURE_ENTRANCE 1
asm(
    "    nop\n\t"
    ".align 16\n\t"
    ".type shim_sig_entry,@function\n\t"
    "shim_sig_entry:\n\t"
#ifdef CFIECT
    "endbr64\n\t"
#endif
#ifdef _SECURE_ENTRANCE
    "movq $1, "STR(IV_TLS(flag_from_kernel))"\n\t"
#endif
    "mov %rdx, %r12\n\t"
    "xor %ecx, %ecx\n\t"
    "xor %edx, %edx\n\t"
    "mov $"STR(trusted_pkru)", %eax\n\t"
    ".byte 0x0f, 0x01, 0xef\n\t" // this is wrpkru
    "cmp $"STR(trusted_pkru)", %eax\n\t" 
    "jne __sigexit\n\t"
#ifdef _SECURE_ENTRANCE // this is to prevent attack, but now it'
    "cmpq $1, "STR(IV_TLS(flag_from_kernel))"\n\t"
    "jne __sigexit\n\t"
    "movq $0, "STR(IV_TLS(flag_from_kernel))"\n\t"
#endif
    "mov %r12, %rdx\n\t"
#ifdef FILTERTP
    "movq "STR(IV_TLS(trampoline))", %rax\n\t"
    "movl $0xccc3050f, (%rax)\n\t"
#endif
    "call _shim_sig_entry\n\t"
    "lea sigtrampoline_for_trusted(%rip), %r10\n\t"
    "mov %r10, (%rsp)\n\t"
    "retq\n\t"
    "__sigexit:\n\t" // exit syscall to terminate program
    "mov $0x1, %rsi\n\t"
    "mov $0xe7,%edi\n\t"
    "jmp _syscall1\n\t"
    "int3\n\t"
);

/* shadow stack */

#define ALIGN(x,a) _ALIGN(x, (typeof(x))(a) - 1)
#define _ALIGN(x,mask) (((x) + mask) & ~(mask))


/* end of shadow stack */

// shim user stack frame

int __syscall_from_trusted = 0;

#ifdef MEASUREMENT
extern unsigned long *entercount, *exitcount;
#endif

void _shim_sig_entry(int signum, siginfo_t *siginfo, void *uctx){
    // no read test should be performed here until we proof that previous state is untrested
    void** ra = (void**)__builtin_frame_address(0) + 1;
    //*ra = sigtrampoline_for_trusted;
    // TODO: might be a good idea to always rewrite RA
    stack_t t;
    if (!from_trusted_stack(ra)) {
        rawcall(write, 1, "invalid sp0\n", 12);
        //debug(ra);
        rawcall(exit_group, -1);

    }
    //*ra = (void*)sigtrampoline_for_trusted;
    
    if (!from_trusted_stack(siginfo) || !from_trusted_stack(siginfo + 1) || !from_trusted_stack(uctx)) {
        rawcall(write, 1, "invalid sp1\n", 12);
        rawcall(exit_group, -1);
    }

    ucontext_t * _uctx = (ucontext_t *)uctx;
    if (!from_trusted_stack(_uctx) || !from_trusted_stack(_uctx + 1)) {
        rawcall(write, 1, "invalid sp2\n", 13);
        rawcall(exit_group, -1);
    }
    
    void* x = (struct xstate_region*) _uctx->uc_mcontext.fpregs;
    struct xstate_region* y = (struct xstate_region*) _uctx->uc_mcontext.fpregs;
    if (!y) {
        rawcall(write, 1, "invalid fpp\n", 12);
        rawcall(exit_group, -1);
    }

    if (!from_trusted_stack(y) || !from_trusted_stack(y + 1)) {
        rawcall(write, 1, "invalid fpp\n", 12);
        rawcall(exit_group, -1);
    }

    if (y->reserved.magic1 != FP_XSTATE_MAGIC1) {
        rawcall(write, 1, "invalid mg\n", 11);
        rawcall(exit_group, -1);
    }

    if ((!from_trusted_stack( ((unsigned int*)(x + y->reserved.extended_size)) )) || y->reserved.extended_size < pkru_xstate_offset()) {
        rawcall(write, 1, "invalid mg\n", 11);
        rawcall(exit_group, -1);
    }
    IV_DBG("Signal %d captured! Current pkru=%p, pkru when signal happens: tls->pkru=%p", 
            siginfo->si_signo,
            (*((unsigned int*)(x + pkru_xstate_offset()))), get_tls()->current_pkru);
    // TODO: free GS, stacks, tls, and maybe Nexpoline
#ifdef MEASUREMENT
    printf("shim_sig_entry: entercount = %ld, exitcount = %ld\n", *entercount, *exitcount);
#endif
    int previous_trusted = (*((unsigned int*)(x + pkru_xstate_offset()))) == trusted_pkru;
    if (__syscall_from_trusted) {
        previous_trusted = 1;
    }

    int previous_apped = ((*((unsigned int*)(x + pkru_xstate_offset()))) != untrusted_pkru) && !previous_trusted;
    int previous_untrusted = ((*((unsigned int*)(x + pkru_xstate_offset()))) == untrusted_pkru);
    int in_fast_syscall = get_tls()->fast_syscall;

    struct sc_ext* ext = ALIGN((unsigned long)x + get_extended_size(), 8);

    /* 
     * Intercept mpk page fault. (SEGV_PKRUERR)
     * 1) Print a log
     * 2) give access to it 
     * 3) set TRAP FLAG.
     */
    /*
    if (siginfo->si_signo == SIGSEGV) {
        printf("rip = %p, gs=%p rax=%p\n", _uctx->uc_mcontext.gregs[REG_RIP], get_tls()->self, _uctx->uc_mcontext.gregs[REG_RAX]);
        printf("access %p for domain %d", siginfo->si_addr, PKEY(map_get(map_addr(siginfo->si_addr, siginfo->si_addr))));
        printf("rsp = %p\n", _uctx->uc_mcontext.gregs[REG_RSP]);
        printf("*rsp = %p\n", *(void**)_uctx->uc_mcontext.gregs[REG_RSP]);
        printf("pkru=%u\n", (*((unsigned int*)(x + pkru_xstate_offset()))));

        #ifdef APPPERF
            extern pid_t self;
            if (self == -1)
                self = rawcall(getpid);
            printf("======== APP Count report (PID=%d) ========\n", self);
            for (int i = 0; i < 16; i++)
                printf("APP %d: %d \n", i, get_tls()->app_count[i]);
            printf("======== ================ ========\n");
        #endif
        //rawcall(exit_group, 0);
    }
    */
    if (siginfo->si_signo == SIGSEGV && siginfo->si_code == SEGV_PKUERR) {
        //IV_DBG("SEGV-PKUERR: cross domain access violation from pkru %lx to domain %d on address %p at pc %p",
        //                    get_tls()->current_pkru, PKEY(map_get(map_addr(siginfo->si_addr, siginfo->si_addr))), siginfo->si_addr, reg(RIP));

        // set pkru to god mod
        (*((unsigned int*)(x + pkru_xstate_offset()))) = 0;
        // set trap bit
#define TRAP_BIT 0x100      //this is the TRAP bit in EFL register
        reg(EFL) |= TRAP_BIT;
        return;
    }
#ifdef USESIGTRAP
    if (siginfo->si_signo == SIGSEGV) {
        IV_DBG("SEGV-????: cross domain access from domain %lx to domain %d at address %p, at pc %p",
                            get_tls()->current_pkru, PKEY(map_get(map_addr(siginfo->si_addr, siginfo->si_addr))), siginfo->si_addr, reg(RIP));
        rawcall(exit_group, 1);
    }
#endif
    /* 
     * Intercept TRAP.
     * take back privelege from the domain
     * resume.
     */
    #ifdef USESIGTRAP
    if (siginfo->si_signo == SIGTRAP) {
       // IV_DBG("TRAP: retriving privilege from pkru %lx",
       //                     get_tls()->current_pkru);
        // clear trap bit
        reg(EFL) &= ~TRAP_BIT;
        // restore pkru
        (*((unsigned int*)(x + pkru_xstate_offset()))) = get_tls()->current_pkru;
        rawcall(exit_group, 1);
        return;
    }
    #endif
    
    #define SYS_SECCOMP 1
    if (siginfo->si_signo == SIGSYS && siginfo->si_code == SYS_SECCOMP) {
        rawcall(exit_group, 1); 
    }
    unsigned long rsp = reg(RSP);
#ifdef APPSIG
    if (previous_trusted || in_fast_syscall) {
#else   
    if ((!previous_untrusted) || in_fast_syscall) {
#endif
        // no need to do anyting, sigtrampoline_for_trusted
        // will bring us back to where we started
        // and restore all CPU states
        printf("Pending the signal\n");
        // MAYBE?: keep masking this signal in ucontext
        push_signal(signum, siginfo, uctx);
        
        unsigned long new_mask = get_tls()->sig_mask | queued_sigs;
        memcpy(&(_uctx->uc_sigmask), &new_mask, sizeof(new_mask));

        unsigned long rip = reg(RIP);

        // TODO: remove transaction???
        // we may not need this, since we're using previous_untrusted??
        // no time to think about this but.. let's see..
        if (rip >= &monitor_transaction_begin && rip < &monitor_transaction_end) {
            reg(RIP) = &monitor_transaction_begin; // restart monitor return
        }
        return ; // delay signal
    } else {
        // we can safely get memlock here because previous state is untrusted
        // !!!this code is not re-enterable for same signum!!!!
        // only unblock a signal @ ret path
        siginfo_t *send_signal = siginfo;
        int sending_num = signum;
        unsigned long pending_list = (queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask));

        if (signum >= 32) {
            // RT SIG IS QUEUED
            push_signal(signum, siginfo, uctx);
            pending_list |= 1<<(signum - 1);
            sending_num = __builtin_ctzl(pending_list) + 1;
            send_signal = &(pending_sig[sending_num].siginfo);
            reg(CR2) = pending_sig[sending_num].cr2;
            reg(TRAPNO) = pending_sig[sending_num].trapno;
            reg(CSGSFS) = pending_sig[sending_num].csgsfs;
            reg(ERR) = pending_sig[sending_num].err;
        }

        /*if (pending_list)*/
        {   // we can always send a signal for sure
            // send queued signal to user with state
            unsigned long frame_rsp = rsp - 0x80;
            unsigned long restore_ssp = ext->ssp;
            //printf("old ssp=%p\n", restore_ssp + 8);
            //printf("restore ssp=%p\n", (*(unsigned long*)restore_ssp)&~1ul);
            unsigned long new_ssp = restore_ssp - SSP_CLEARANCE;
            
            unsigned long was_wait_endbr = ext->wait_endbr;
            ext->wait_endbr = 0; // not waiting endbr for signal handler

            // TODO: chehck altstack
            unsigned long new_rsp = shim_signal_touser(sending_num,
                on_sig_stack(rsp), 
                frame_rsp,
                send_signal,
                &(_uctx->uc_mcontext.gregs), 
                _uctx->uc_mcontext.fpregs,
                &new_ssp,
                restore_ssp | 1 /* real ssp assert(*restore_ssp & ~1== restore_ssp + 8) */
            );

            struct rt_sigframe* frame = new_rsp;

            unsigned long erim_rsp = new_rsp - 0x80 - sizeof(struct shim_regs);
            struct shim_regs* ret_frame = (struct shim_regs*)erim_rsp;
            
            if (!map_check_lock(map_addr(erim_rsp, new_rsp), 2)) {
                // stackoverflow
                // don't care about lock
                rawcall(exit_group, SIGSEGV);
                __builtin_unreachable();
            }

            memset(ret_frame,0,sizeof(struct shim_regs));
            ret_frame->rip = sig_tables[sending_num].k_sa_handler;
            ret_frame->rdx = &(frame->uc); // arg3
            ret_frame->rsi = &(frame->info); // arg2
            ret_frame->rdi = sending_num; // arg1
    
            #ifdef CFICET
            new_ssp -= 8;
            ss_put(new_ssp, sig_tables[sending_num].k_sa_handler);
            ss_put_restore(new_ssp - 8, new_ssp); // will go to this _ssp;
            //printf("ext->ssp=%p\n", ext->ssp );
            ext->ssp = new_ssp - 8; // set to new restore token
            //get_tls()->untrusted_ssp = new_ssp;
            #endif
            // return will be done by kernel, invalid old ssp in ERIM
            //ss_push(sig_tables[sending_num].k_sa_handler);
            //ss_push_restore();  
            
            queued_sigs &= ~(1ULL << (sending_num-1));  // unqueue current signal
            get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));

            unsigned long new_mask = get_tls()->sig_mask | queued_sigs; // apply
            memcpy(&(_uctx->uc_sigmask), &new_mask, sizeof(new_mask));

            // make sure we return to trusted
            *((unsigned int*)(x + pkru_xstate_offset())) = trusted_pkru;
            // return to trusted domain after syscall ending
            reg(RIP) = &monitor_transaction_begin; // skip stack switching
            reg(RBP) = 0;
            reg(RSI) = 0; // 2
            reg(RDX) = 0; // 3
            reg(RDI) = 0; // 1 arg
            // rax after ret = r11
            reg(R11) = 0;
            reg(RSP) = erim_rsp; // do a monitor ret

            map_unlock_read_all();
        }
    }
}

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))

static unsigned long align_sigframe(unsigned long sp)
{
	sp = round_down(sp, 16) - 8;
	return sp;
}

unsigned long alloc_sigframe(unsigned long old_rsp, unsigned long extended_size, struct xstate_region **fpstate, struct sc_ext **cet) {
    if (extended_size == 0)
        extended_size = get_extended_size();
    old_rsp = old_rsp - sizeof(struct sc_ext) - 8;
    old_rsp = round_down(old_rsp - extended_size, 64);
    *fpstate = old_rsp;
    *cet = ALIGN(old_rsp + extended_size, 8); // align8 to higher address
    old_rsp = align_sigframe(old_rsp - sizeof(struct rt_sigframe)); // allocate rt_sigframe
    return old_rsp;
}

int volatile lock_que = 0;

// spin lock for queue

void lock_q() {
    while (__sync_lock_test_and_set(&lock_que, 1));
}

void unlock_q() {
    __sync_lock_release(&lock_que, 0);
}

unsigned long override_mask = 0;
int use_override = 0;
unsigned long shim_sighook_syscall() {
    // previous state
    // system call to sigreturn (from user)
    // create a ucontext in stack and jump to sigtrampoline_for_trusted
    unsigned long _rt_rax;
    asm volatile(
        "mov %%rax, %0;\n\t"
        :"=r"(_rt_rax)
        :
        :"memory"
    );
    
    unsigned long _user_rsp = (unsigned long) get_tls()->untrusted_stack;

    struct shim_regs *_user_regs = (struct shim_regs*) _user_rsp;

    _user_rsp += sizeof(struct shim_regs) + 0x80; // rollback rsp to where it should be after signal

    unsigned long _rt_freersp = _user_rsp - 0x80; // clearance for signalframe
    lock_q();
    unsigned long pending_list = 0;
    if (use_override) {
        pending_list = (queued_sigs) & deliverable_sigs & (~(override_mask));
        use_override = 0;
    } else {
        pending_list = (queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask));
    }
    if (pending_list) {
        // not empty
        // copy regs
        
        gregset_t gregs;
        gregs[REG_RSP] = _user_rsp; // set return rsp
        gregs[REG_RIP] = _user_regs->rip;
        gregs[REG_EFL] = _user_regs->rflags;
        gregs[REG_R8] = _user_regs->r8;
        gregs[REG_R9] = _user_regs->r9;
        gregs[REG_R10] = _user_regs->r10;
        gregs[REG_R11] = _user_regs->r11;
        gregs[REG_R12] = _user_regs->r12;
        gregs[REG_R13] = _user_regs->r13;
        gregs[REG_R14] = _user_regs->r14;
        gregs[REG_R15] = _user_regs->r15;
        gregs[REG_RBP] = _user_regs->rbp;
        gregs[REG_RBX] = _user_regs->rbx;
        gregs[REG_RCX] = _user_regs->rcx;
        gregs[REG_RDI] = _user_regs->rdi;
        gregs[REG_RDX] = _user_regs->rdx;
        gregs[REG_RSI] = _user_regs->rsi;
        gregs[REG_RAX] = _rt_rax;
        unsigned long sig = __builtin_ctzl(pending_list) + 1;
        //if (sig == 14) asm("int3");
        struct sigqueue* Q = pending_sig + sig;
        gregs[REG_TRAPNO] = Q->trapno;
        gregs[REG_CR2] = Q->cr2;
        gregs[REG_CSGSFS] = Q->csgsfs;
        gregs[REG_ERR] = Q->err;

#ifdef CFICET
        unsigned long old_ssp = get_tls()->untrusted_ssp;
        unsigned long new_ssp = old_ssp - SSP_CLEARANCE;
#else
        unsigned long old_ssp = 0;
        unsigned long new_ssp = 0;
#endif
        unsigned long new_sp = shim_signal_touser(sig, on_sig_stack(_user_rsp), _rt_freersp, &(Q->siginfo), gregs, NULL, &new_ssp, old_ssp); // push pending signal to user stack

        struct rt_sigframe* frame = new_sp;

        unsigned long shim_sp = new_sp - 0x80 - sizeof(struct shim_regs);

        // allocate space for return frame

        if (!map_check_lock(map_addr(shim_sp, new_sp), 2)) {
            rawcall(exit_group, SIGSEGV);
            __builtin_unreachable();
        }

        get_tls()->untrusted_stack = shim_sp;
        struct shim_regs * new_shim_frame = (struct shim_regs*)shim_sp;
        memset(new_shim_frame, 0, sizeof(struct shim_regs));

        //*ERIM_REGULAR_STACK_PTR = new_sp;
        new_shim_frame->rip = sig_tables[sig].k_sa_handler;
        new_shim_frame->rflags = 0;
        new_shim_frame->rbp = 0;
        new_shim_frame->rsi = &(frame->info); // 2 arg = sig info
        new_shim_frame->rdx = &(frame->uc); // 3 arg = uc
        new_shim_frame->rdi = sig; // 1 arg = sig number
        new_ssp -= 8;
        ss_put(new_ssp, sig_tables[sig].k_sa_handler); // use rop to jump to handler
        ss_put_restore(new_ssp - 8, new_ssp);
#ifdef CFICET
        get_tls()->untrusted_ssp = new_ssp;
#endif
        queued_sigs &= ~(1ULL << (sig - 1));
        get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));
        unsigned long new_s = queued_sigs | get_tls()->sig_mask;
        rawcall(rt_sigprocmask, SIG_SETMASK, &new_s, NULL, sizeof(unsigned long)); // this might cause a new signum to be queued
        unlock_q();
        map_unlock_read_all();
        return 0; // continue syscall_trap return process
    }
    unlock_q();
    // rax, rdx saved
    // get rsp of user stack
    return _rt_rax; // keep rax == rax
}



unsigned long virt_sigreturn(int simulated) {
    //unsigned long pending_list = (queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask));
    unsigned long _user_rsp = (unsigned long) get_tls()->untrusted_stack;
    unsigned long offset  = simulated ? 0 : sizeof(struct shim_regs);

    
    struct rt_sigframe_without_ret *frame = (struct rt_sigframe_without_ret *) (_user_rsp + offset + 0x80);
    map_addr_t addr = map_addr(frame, ((char*)frame) + sizeof(struct rt_sigframe_without_ret) - 1 );
    if (!map_check_lock(addr, 3)) {
        printf("invalid f0\n");
        rawcall(exit_group, -1);
        __builtin_unreachable();
    }

    if (frame->uc.uc_mcontext.fpstate == 0) {
        // this is fixable..
        // but I don't think it's necessary..
        printf("invalid f1\n");
        rawcall(exit_group, -1);
        __builtin_unreachable();
    }

    struct xstate_region *xstate = (struct xstate_region *)frame->uc.uc_mcontext.fpstate;
    struct sc_ext *ext = ALIGN((unsigned long)xstate + get_extended_size(), 8);;
    if (xstate) {
        map_addr_t addr2 = map_addr(xstate, (((void*)xstate) +  xstate->reserved.extended_size) - 1);
       
        if (!map_check_lock(addr2, 3)) {
            printf("invalid x0\n");
            rawcall(exit_group, -1);
            __builtin_unreachable();
            // illegal access to trusted mem
        }

        if (((unsigned long)xstate) & 63) {
            printf("xstate alignment\n");
            rawcall(exit_group, -1);
            __builtin_unreachable();
        }

        if (xstate->reserved.magic1 != FP_XSTATE_MAGIC1) {
            printf("invalid mg\n");
            rawcall(exit_group, -1);
            __builtin_unreachable();
        }
    }
    
    // finish input checking
    
    // restore fpu
    if (xstate) {
        *((unsigned int*)((void*)xstate + pkru_xstate_offset())) = trusted_pkru; // use trusted pku
        _xrstor(xstate);
    }

    // allocate erim frame in new stack pointer
    unsigned long prev_rsp = frame->uc.uc_mcontext.rsp;
    unsigned long new_rsp = prev_rsp - 0x80 - sizeof(struct shim_regs);
    struct sigcontext sigcxt_bkup;
    memcpy(&sigcxt_bkup, &(frame->uc.uc_mcontext), sizeof(struct sigcontext));

    struct shim_regs* _user_regs = (struct shim_regs*)new_rsp;
    map_addr_t addr3 = map_addr(_user_regs, _user_regs + sizeof(struct shim_regs) - 1);
    if (!map_check_lock(addr3, 3)) {
        printf("overflow\n");
        rawcall(exit_group, SIGSEGV);
        __builtin_unreachable();
    }

    // restore ssp
#ifdef CFICET
    if (ext) {
        if (ext->ssp & 1) {
            ext->ssp &= ~1ul;
            ss_put(ext->ssp, sigcxt_bkup.rip);
            ss_put_restore(ext->ssp - 8, ext->ssp);
        }
        get_tls()->untrusted_ssp = ext->ssp; //
    }
#endif
    // finish alloc

    #define cpreg(r) _user_regs->r = sigcxt_bkup.r;
    // rsp using 
    _user_regs->rflags = sigcxt_bkup.eflags;
    cpreg(rip);
    cpreg(r8);
    cpreg(r9);
    cpreg(r10);
    cpreg(r11);
    cpreg(r12);
    cpreg(r13);
    cpreg(r14);
    cpreg(r15);
    cpreg(rbp);
    cpreg(rbx);
    cpreg(rcx);
    cpreg(rdi);
    cpreg(rdx);
    cpreg(rsi);
    // rax = return
    unsigned long new_rax = sigcxt_bkup.rax;
    //memcpy(&sig_stack_current, &(frame->uc.uc_stack), sizeof(sig_stack_current));
    virt_sigaltstack(frame->uc.uc_mcontext.rsp, &(frame->uc.uc_stack), NULL); // check before switch

    get_tls()->untrusted_stack = new_rsp;

    get_tls()->sig_mask = frame->uc.uc_sigmask;
    
    //printf("set mask2=%lx\n", get_tls()->sig_mask);
    get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));
    map_unlock_read_all();

    unsigned long new_mask = frame->uc.uc_sigmask | queued_sigs;
    rawcall(rt_sigprocmask, SIG_SETMASK, &new_mask, NULL, sizeof(unsigned long));

    return new_rax;
}



int virt_sigsuspend(unsigned long mask){
    // No signal can be deliver to user from here
    unsigned long mask_all = -1LL;
    rawcall(rt_sigprocmask, SIG_SETMASK, &mask_all, NULL, sizeof(unsigned long));
    // Now we check if our target is pending?
    // this checking result is valid until we return
    // this is to ensure when we are calling real sigsuspend, the checking result is always valid
    override_mask = mask;
    use_override = 1;
    if (!((queued_sigs) & deliverable_sigs & (~(mask)))) {
       // no such signal, ask kernel for one
        rawcall(rt_sigsuspend, &mask, sizeof(mask));
    } else {
        // nothing to do, return and deliver that signal
    }
    // we have made decision, unroll sigmask
    unsigned long restore_mask = queued_sigs | get_tls()->sig_mask;
    rawcall(rt_sigprocmask, SIG_SETMASK, &restore_mask, NULL, sizeof(unsigned long));
    return -EINTR;
}

int virt_sigtimedwait(unsigned long set, siginfo_t *info, void* uts) {
    // Only mask interested signal
    // may cause race condition...
    // but control-flow should be fine (?)
    unsigned long mask_all = set;
    rawcall(rt_sigprocmask, SIG_SETMASK, &mask_all, NULL, sizeof(unsigned long));

    printf("sigtimedwait(%d, %p, %p)\n", set, info, uts);
    // Now we check if our target is pending?
    // this checking result is valid until we return
    // this is to ensure when we are calling real sigsuspend, the checking result is always valid
    unsigned long match = (queued_sigs & set);

    unsigned long has_pending = (queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)) & (~set);
    if (has_pending) {
        // sorry this call failed, pending signal will be deliver to user
        unsigned long restore_mask = queued_sigs | get_tls()->sig_mask;
        rawcall(rt_sigprocmask, SIG_SETMASK, &restore_mask, NULL, sizeof(unsigned long));
        return -EINTR;
    }
    // otherwise we can test our signals
    int sig = 0;
    if (!match) {
        // no such signal, ask kernel for one
        sig = rawcall(rt_sigtimedwait, &set, info, uts, sizeof(set));
    } else {
        // we have such signal, do it!
        sig = __builtin_ctzl(match) + 1;
        if (info) {
            printf("si_pid=%d\n", pending_sig[sig].siginfo.si_pid);
            printf("si_code=%d\n", pending_sig[sig].siginfo.si_code);
            printf("si_no=%d\n", pending_sig[sig].siginfo.si_signo);
            memcpy(info, &(pending_sig[sig].siginfo), sizeof(siginfo_t));
        }
        override_mask = -1ULL; // we will mask everything to ensure the signal being sent to user successfully.
        use_override = 1;
    }
    // we have made decision, unroll sigmask
    unsigned long restore_mask = queued_sigs | get_tls()->sig_mask;
    rawcall(rt_sigprocmask, SIG_SETMASK, &restore_mask, NULL, sizeof(unsigned long));
    return sig;
}

unsigned long virt_sigpending(){
    unsigned long ss;
    rawcall(rt_sigpending, &ss, sizeof(unsigned long));
    return (ss | queued_sigs); 
}

#define DEFINE_RESTORE_RT(syscall) DEFINE_RESTORE_RT2(syscall)

#define DEFINE_RESTORE_RT2(syscall)                 \
    __asm__ (                                       \
         "    nop\n"                                \
         ".align 16\n"                              \
         ".LSTART_restore_rt:\n"                    \
         "    .type __restore_rt,@function\n"       \
         "__restore_rt:\n"                          \
         "ENDBR64\n"                                \
         "mov $0xf, %eax\n"                         \
         "subq $128, %rsp\n"                       \
         "call syscall_trap\n");

DEFINE_RESTORE_RT(__NR_rt_sigreturn)

/* Workaround for an old GAS (2.27) bug that incorrectly
 * omits relocations when referencing this symbol */
__attribute__((visibility("hidden"))) void __restore_rt(void);


unsigned long shim_signal_touser(int signum, unsigned long onsigstack, unsigned long proposed_rsp, siginfo_t *siginfo, gregset_t *gregs, struct xstate_region* fpregs, unsigned long* ssp, unsigned long old_ssp){
    // create signal frame on user stack
    // if fpregs == NULL, create by xsave on user stack
    // if ON_STACK, use that stack instead of this
    unsigned long rsp = proposed_rsp;


    if (sig_tables[signum].sa_flags & SA_ONSTACK) {
        if (ss_flags(proposed_rsp) == 0) {
            // not currently on stack
            rsp = sig_stack_current.ss_sp + sig_stack_current.ss_size;
            // use signal stack
        }
    }

    size_t extended_size = 0;
    if (fpregs)
        extended_size = fpregs->reserved.extended_size;

    struct xstate_region* new_fpregs;
    struct sc_ext* ext;
    unsigned long new_rsp = alloc_sigframe(rsp, extended_size, &new_fpregs, &ext);
    struct rt_sigframe* new_sigframe = (struct rt_sigframe*) new_rsp;

    ext->total_size = sizeof(struct sc_ext);
    ext->wait_endbr = 0;
    ext->ssp = old_ssp;

    if (onsigstack && !(on_sig_stack(new_rsp))) {
        // unrecoverable error
        rawcall(exit_group, SIGSEGV);
    }

    if (((!map_check_lock(map_addr(new_rsp, rsp - 1),0))) || ((!map_check_lock(map_addr(new_rsp, rsp - 1), 2)))) {
        // signal stack spilled into trusted memory
        // signal stack spilled into non-writable
        rawcall(exit_group, SIGSEGV);
    }

    // copy data
    if (fpregs) {
        memcpy(new_fpregs, fpregs, extended_size);
        new_fpregs->reserved.magic1 = FP_XSTATE_MAGIC1;
    } else {
        memset(new_fpregs,0, get_extended_size());
        _xsave(new_fpregs);
        new_fpregs->reserved.magic1 = FP_XSTATE_MAGIC1;
        new_fpregs->reserved.extended_size = get_extended_size();
        new_fpregs->reserved.xstate_size = new_fpregs->reserved.extended_size - FP_XSTATE_MAGIC2_SIZE;
    }

    // modify MPK val in XSTATE
    int pkru_offset = pkru_xstate_offset();
    unsigned int *pkru_ptr = (unsigned int*) (((void*)new_fpregs) + pkru_offset);
	*pkru_ptr = untrusted_pkru; // reset PKRU 


    memcpy(&(new_sigframe->info), siginfo, sizeof(siginfo_t));
    memcpy(&(new_sigframe->uc.uc_mcontext), gregs, sizeof(gregset_t));
    new_sigframe->uc.uc_mcontext.fpstate = new_fpregs;
    new_sigframe->uc.uc_link = 0;
    #define UC_FP_XSTATE	0x1
    new_sigframe->uc.uc_flags = UC_FP_XSTATE;
    new_sigframe->uc.uc_sigmask = get_tls()->sig_mask;
    memcpy(&(new_sigframe->uc.uc_stack), &sig_stack_current, sizeof(stack_t));
    
    if (sig_stack_current.ss_flags & SS_AUTODISARM)
        reset_ss();

    if ((sig_tables[signum].sa_flags & SA_RESTORER) && sig_tables[signum].sa_restorer)
        new_sigframe->pretcode = (char*) sig_tables[signum].sa_restorer;
    else 
        new_sigframe->pretcode = (char*) __restore_rt;
    
    (*ssp) -= 8;
    ss_put(*ssp, new_sigframe->pretcode);
    // Am I setting it correctly??
    unsigned long new_masks = *((unsigned long*)&(sig_tables[signum].sa_mask));// | (~(1ULL << (signum-1)));

    if (!(sig_tables[signum].sa_flags & SA_NODEFER)) {
        new_masks |= ((1ULL << (signum-1)));
    }
    
    get_tls()->sig_mask = get_tls()->sig_mask | new_masks; // add into mask
    //printf("set mask3=%lx\n", get_tls()->sig_mask);
    get_tls()->pendsig = !!((queued_sigs) & deliverable_sigs & (~(get_tls()->sig_mask)));

    // signal deliver finished
    map_unlock_read_all();

    return new_rsp; // new rsp @ head of sigcontext
}

