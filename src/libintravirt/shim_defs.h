#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#define SYSCALLNR  360
#define PAGESIZE   4096
#define PATHLEN    1024

#define __UNUSED(x) do { (void)(x); } while (0)
#define __attribute_always_inline __attribute__((always_inline))
#define __attribute_unused __attribute__((unused))
#define assert(x) do {} while (0)

#endif
