#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	pid_t ppid, cpid;
	printf("Before fork\n");
	ppid = getpid();
	cpid = fork();
	if(cpid == 0) {
		cpid = getpid();
		printf("I am the child: %d\n", cpid);
	} else {
		printf("I am the parent: %d\n", ppid);
	}

	return 0;
}
