#include <cet.h>
#ifdef CFICET
#include <shim_syscalls.h>
#include <rawcall.h>
void * ss_put(unsigned long long * ssp, void* ra) {
    unsigned long long payload[2];
    payload[0] = ssp;
    payload[1] = ra;
    int n = rawcall(arch_prctl, 0x3006 /* push */ , payload);
    return ssp;
}

#else
void * ss_put(unsigned long long * ssp, void* ra) { (void) ssp; (void) ra; }
#endif 

void ss_put_restore(unsigned long long * ssp, void* old_ssp) {
    ss_put(ssp, ((unsigned long long)old_ssp) | 1 /* restore token */);
}