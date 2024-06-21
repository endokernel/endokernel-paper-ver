#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#define BUFSIZE 1024
void handler(int sig, siginfo_t *info, void *ucontext){
    printf("sig!!!\n");
}
 
int main(int argc, char *argv[]) {
	int myfd, mysize;
	char mybuf[BUFSIZE];
	int sysno;

	printf("Testing ditrect syscall instruction execution: read\n");

	// 1st syscall: open()
	myfd = open("/dev/urandom", O_RDONLY);
	if(myfd < 0) {
		fprintf(stderr, "oen error\n");
		exit(EXIT_FAILURE);
	}

	// 2nd syscall: read()
	// Let's just execute syscall instruction. This should be filtered out by seccomp
	sysno = 1;

	register long int _a3 __asm__ ("rdx") = (long int) BUFSIZE;
	register long int _a2 __asm__ ("rsi") = (long int) mybuf;
	register long int _a1 __asm__ ("rdi") = (long int) myfd;
	__asm__ __volatile__ ("syscall\n\t"
			: "=a" (mysize)
			: "0" (sysno), "r" (_a1), "r"(_a2), "r"(_a3)
			: "memory", "cc", "r11", "cx");

	fprintf(stderr, "You should not seee this. The program should crash\n");

	// 3rd syscall: close()
	close(myfd);

	printf("All syscall succeeded\n");
	return 0;
}
