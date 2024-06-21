#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

void handler(int sig, siginfo_t *info, void *ucontext){
    printf("sig!!!\n");
}
 
int main(){
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGUSR1, &sa, 0);
    for (int i = 0; i < 10; i++)
        kill(0, SIGUSR1);
    printf("finished!!\n");
}
