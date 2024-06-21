#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(){
    execlp("./hello", "hello", NULL);
    perror("Crap!. Execution failed: ");
}
