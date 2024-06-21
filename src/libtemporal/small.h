#ifndef _SMALL_H_
#define _SMALL_H_
#include <stddef.h>
typedef struct tpool_s tpool_t;
tpool_t* private_pool(int n, size_t sz, size_t page);
void* private_talloc(int n);
void* private_tcalloc(int n);
void private_tfree(int n, void* ptr);
#endif