#ifndef _SHIM_INTERNAL_H_
#define _SHIM_INTERNAL_H_

#include <shim_defs.h>
#include <shim_types.h>

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

#include <asm/unistd.h>
#include <stdint.h>

#define ALIGNED(addr)   (!(((uintptr_t)(addr)) & ~(PAGESIZE - 1)))
#define ALIGN_UP(addr)      \
    ((__typeof__(addr)) ((((uintptr_t)(addr)) + PAGESIZE - 1) & ~(PAGESIZE - 1)))
#define ALIGN_DOWN(addr)    \
    ((__typeof__(addr)) (((uintptr_t)(addr)) & ~(PAGESIZE - 1)))

int printf (const char  *fmt, ...) __attribute__((format (printf, 1, 2)));
#include <stdarg.h>
int vprintf(const char * fmt, va_list ap) __attribute__((format (printf, 1, 0)));

#endif
