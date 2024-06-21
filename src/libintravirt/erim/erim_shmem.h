/*
 * erim_shmem.h
 */

#ifndef ERIM_SHMEM_H_
#define ERIM_SHMEM_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <asm/unistd.h>
#include <sys/mman.h>
#include "mmap/map.h"

#ifdef __x86_64__
  #include "sysdep-x86_64.h"
#endif

#include <erim_api_overlay.h>
  
#include <rawcall.h>

// mmap memory in secure region
#define erim_mmap_domain(addr, length, prot, flags, fd, offset, trustedDomain) \
  ( {									\
    void * __tmp = NULL;						\
    __tmp = ((__tmp = (void*) rawcall(mmap, addr, length, prot, flags, fd, offset)) == MAP_FAILED\
	     || rawcall(mprotect_pkey, __tmp, length, prot, trustedDomain) == -1) ? (void *) -1 : __tmp; \
    if (__tmp && __tmp != (void*)-1) \
      map_set(map_addr(__tmp, __tmp + length - 1), map_norm(prot, trustedDomain == 0)); \
      __tmp;								\
  } )
  
  // mmap memory in isolated region
#define erim_mmap_isolated(addr, length, prot, flags, fd, offset)	\
  ( {									\
    void *__tmp = erim_mmap_domain(addr, length, prot, flags, fd, offset, IV_USER); \
  } )

#define erim_mmap_trusted(addr, length, prot, flags, fd, offset) \
  ( { \
    void *__tmp = erim_mmap_domain(addr, length, prot, flags, fd, offset, IV_NORMAL); \
  })
  
#define erim_munmap(addr, length)                             \
  ( {                                                         \
    uintptr_t x = rawcall(munmap, addr, length);    \
    if (x)                                                    \
      map_clear(map_addr(addr, (addr + length - 1)));  \
    x;                                                        \
  } )

int erim_shmem_init(unsigned long long shmemSize, int trustedDomain);
int erim_shmem_fini(void);
  
void * erim_malloc(size_t size);
  
void * erim_zalloc(size_t size);
  
void * erim_realloc(void* ptr, size_t s);

void erim_free(void * ptr);
   
#ifdef __cplusplus
}
#endif

#endif /* ERIM_H_ */
