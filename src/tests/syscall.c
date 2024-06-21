#include <stdio.h>
#include <asm/unistd.h>

int main(int argc, char** argv) {
    unsigned long pid;
    __asm__ ("syscall\n\t"
             : "=a"(pid)
             : "i"(__NR_getppid));
    printf("getppid() = %ld\n", pid);
    return 0;
}
