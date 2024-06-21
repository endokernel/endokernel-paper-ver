#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUFSIZE 1024

void *gettrampoline(int *size) {
	FILE *mapfs = NULL;
	void *start, *end;
	int ptr, base, slen, i;
	char buf[BUFSIZE];
	char *path;

	mapfs = fopen("/proc/self/maps", "rb");
	if(mapfs == NULL) {
		fprintf(stderr, "fopen() error\n");
		exit(EXIT_FAILURE);
	}

	while(fgets(buf, BUFSIZE, mapfs) != NULL) {
		slen = strlen(buf) - 1;
		buf[slen] = 0;
		ptr = 0;
		base = 0;

		// Start address
		while(buf[ptr] != '-') {
			ptr++;
		}
		buf[ptr] = 0;
		start = (void*)strtol(buf, NULL, 16);
		ptr++;
		base = ptr;

		// End address
		while(buf[ptr] != ' ') {
			ptr++;
		}
		buf[ptr] = 0;
		end = (void*)strtol(buf+base, NULL, 16);
		buf[ptr++] = 0;
		base = ptr;

		// flag
		while(buf[ptr] != ' ') {
			ptr++;
		}
		buf[ptr] = 0;
		if(strcmp(buf+base, "rwxp") != 0) {
			continue;
		}
		ptr++;

		// pathname
		ptr = slen;
		while(buf[ptr] != '/') {
			ptr--;
		}
		path = buf + ptr;

		if(strcmp(path, "/libintravirt.so") == 0) {
			*size = end - start;
			fclose(mapfs);
			return start;
		}
	}
	fclose(mapfs);
	return NULL;
}



int main(int argc, char *argv[]) {
	int myfd, mysize;
	char mybuf[BUFSIZE * 10];
	int sysno;
	void *startptr, *hop;
	unsigned long myrandom;

	printf("Testing jmp to the trampoline address: testing read syscall\n");

	// 1st syscall: open()
	myfd = open("/proc/self/maps", O_RDONLY);
	if(myfd < 0) {
		fprintf(stderr, "oen error\n");
		exit(EXIT_FAILURE);
	}

	startptr = gettrampoline(&mysize);

	// get random number in bound of the trampoline.
	__asm__ __volatile__ ("rdrand %0\n\t" : "=a" (myrandom) : : );
	hop = (void *)(startptr + (myrandom % mysize));

	// 2nd syscall: read()
	// Let's jump random location somewhere in the trampoline.
	// This should end up with the trap.
	sysno = 1;

	register long int _a3 __asm__ ("rdx") = (long int) BUFSIZE;
	register long int _a2 __asm__ ("rsi") = (long int) mybuf;
	register long int _a1 __asm__ ("rdi") = (long int) myfd;
	register long int _rbx __asm__ ("rbx") = (long int) hop;
	__asm__ __volatile__ ("call *%%rbx\n\t"
			: "=a" (mysize)
			: "0" (sysno), "r" (_a1), "r"(_a2), "r"(_a3)
			: "memory", "cc", "r11", "cx");

	fprintf(stderr, "You should not seee this. The program should crash\n");

	// 3rd syscall: close()
	close(myfd);

	printf("All syscall succeeded\n");
	return 0;
}
