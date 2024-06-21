#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#define NUMTHREAD 50

void *tfunc(void *arg) {
	int *id = (int *)arg;
	for(int i = 0 ; i < 10000000 ; i++);
	printf("Thread[%d] is here\n", *id);
	return NULL;
}

int main(int argc, char* argv[]) {
	int res = 0;

	pthread_t tt[NUMTHREAD];
	int tid[NUMTHREAD];

	for(int i = 0 ; i < NUMTHREAD ; i++) {
		tid[i] = i;
		if(pthread_create(&tt[i], NULL, tfunc, &tid[i]) != 0) {
			fprintf(stderr, "pthread_create error: %d\n", tid[i]);
			exit(1);
		}
		printf("Thread[%d] cloned. tid=%d\n", i, tid[i]);
	}
	sleep(1);
	for(int i = 0 ; i < NUMTHREAD ; i++) {
		pthread_join(tt[i], NULL);
	}
	return 0;
}
