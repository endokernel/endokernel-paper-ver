#include <sys/syscall.h>
#include <asm/unistd.h>

static __inline__ unsigned long long rdtsc(void){
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#define run(n, fmt) \
_Pragma("GCC ivdep") \
_Pragma("GCC unroll 2") \
for (unsigned long start = rdtsc(), end = 0; end == 0; end = printf(fmt, (double)(rdtsc() - start) / n)) \
_Pragma("GCC unroll 32") \
_Pragma("GCC ivdep") \
    for (unsigned long i = 0; i < n; i++) 

int empty_xcall(){
    return 0;
}

int baseline(){
    {
        run(10000000, "%f\n") {
            syscall(__NR_getppid);
        }
    }
    
}

int main(){
    baseline();
}