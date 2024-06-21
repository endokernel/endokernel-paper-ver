#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUFSIZE 1024

int main(int argc, char *argv[]) {
	int myfd, mysize;
	char mybuf[BUFSIZE];

	printf("Testing normal syscall routine: open, read, close\n");

	// 1st syscall: open()
	myfd = open("/dev/urandom", O_RDONLY);
	if(myfd < 0) {
		fprintf(stderr, "oen error\n");
		exit(EXIT_FAILURE);
	}

	// 2nd syscall: read()
	mysize = read(myfd, mybuf, BUFSIZE);
	if(mysize != BUFSIZE) {
		fprintf(stderr, "read error\n");
		exit(EXIT_FAILURE);
	}

	// 3rd syscall: close()
	close(myfd);

	printf("All syscall succeeded\n");
	return 0;
}
