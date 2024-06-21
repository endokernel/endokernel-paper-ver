#include <stdio.h>
int
pkey_set (int key, unsigned int rights);
int main(){
    pkey_set(0, 0);
    printf("pkey_set\n");
}