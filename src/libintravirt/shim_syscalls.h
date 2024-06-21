/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_syscalls.h
 */

#ifndef _SHIM_SYSCALLS_H_
#define _SHIM_SYSCALLS_H_

#include <api.h>
#include <shim_types.h>
#include <shim_defs.h>
#include <shim_passthru.h>
#include <shim_trampoline.h>

#define SHIM_ARG_TYPE long

extern unsigned long boom;
#define ENDBR(func) \
asm(  \
  "nop\n\t" \
  ".align 16\n\t" \
  ".global " #func "\n\t" \
  ".type "#func",@function\n\t" \
  #func":\n\t" \
  "endbr64\n\t" \
  "movl $1, boom(%rip)\n\t"\
  "call endbr_" #func "\n\t" \
  "retq\n\t" \
);

#define BEGIN_SHIM(name, args ...)                          \
    ENDBR(__shim_##name)                                             \
    SHIM_ARG_TYPE endbr___shim_##name(args) {                     \
        SHIM_ARG_TYPE ret = 0;

#define END_SHIM(name)                                      \
        return ret;                                         \
    }

#define SHIM_INT_NAME(name) shim_int_##name

#define SHIM_SYSCALL_INTFUNC(name, n, ret, args ...) ret name(PROTO_ARGS_##n(args))

#define SHIM_SYSCALL_EMULATED(name, n, ...)                                  \
    SHIM_SYSCALL_INTFUNC(SHIM_INT_NAME(name), n, __VA_ARGS__);               \
    SHIM_SYSCALL_##n (name, SHIM_INT_NAME(name), __VA_ARGS__)                \
    EXPORT_SHIM_SYSCALL (name, n, __VA_ARGS__);                              \
    SHIM_SYSCALL_INTFUNC(SHIM_INT_NAME(name), n, __VA_ARGS__)

#define PROTO_ARGS_0() void
#define PROTO_ARGS_1(t, a) t a
#define PROTO_ARGS_2(t, a, rest ...) t a, PROTO_ARGS_1(rest)
#define PROTO_ARGS_3(t, a, rest ...) t a, PROTO_ARGS_2(rest)
#define PROTO_ARGS_4(t, a, rest ...) t a, PROTO_ARGS_3(rest)
#define PROTO_ARGS_5(t, a, rest ...) t a, PROTO_ARGS_4(rest)
#define PROTO_ARGS_6(t, a, rest ...) t a, PROTO_ARGS_5(rest)

#define CAST_ARGS_0() 0
#define CAST_ARGS_1(t, a) (SHIM_ARG_TYPE) a
#define CAST_ARGS_2(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_1(rest)
#define CAST_ARGS_3(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_2(rest)
#define CAST_ARGS_4(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_3(rest)
#define CAST_ARGS_5(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_4(rest)
#define CAST_ARGS_6(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_5(rest)
#define CAST_ARGS(n, args ...) CAST_ARGS_##n(args)

#define DEFINE_SHIM_FUNC(func, n, r, args ...)             \
    r func (PROTO_ARGS_##n (args));

#define TYPE_HASH(t) ({ const char * _s = #t;              \
       ((uint16_t) _s[0] << 8) +  _s[1]; })

#define POINTER_TYPE(t) ({ int _h = TYPE_HASH(t);                   \
       _h == TYPE_HASH(void *) || _h == TYPE_HASH(char *) ||        \
       _h == TYPE_HASH(const); })

/*
#define EXPORT_SHIM_SYSCALL(name, n, r, args ...)                   \
    r _shim_##name (PROTO_ARGS_##n (args)) {                         \
        SHIM_ARG_TYPE ret =  __shim_##name (CAST_ARGS_##n (args));  \
        if (POINTER_TYPE(r)) {                                      \
            if ((uint64_t) ret >= (uint64_t) -4095L) return (r) 0;  \
        } else {                                                    \
            if ((int) ret < 0) return (r) -1;                       \
        }                                                           \
        return (r) ret;                                             \
    }
*/

extern int syscall_filter[SYSCALLNR];

int syscall_before (int sysno, int nr, SHIM_ARG_TYPE *ret,...);
long syscall_after (int sysno, int nr, SHIM_ARG_TYPE ret, ...);
#define EXPORT_SHIM_SYSCALL(name,n, r, args ...)  
#ifdef SYSCALLFILTER 
#define PARSE_SYSCALL1(name, n, ...)                                          \
    if (syscall_filter[__NR_##name])                                          \
        if (syscall_before (__NR_##name, n, &ret, CAST_ARGS(n, __VA_ARGS__))) \
            return ret;


#define PARSE_SYSCALL2(name,n, ret_type, ret,  ...)                     \
    if (syscall_filter[__NR_##name])                                    \
        ret = syscall_after (__NR_##name, n, ret, CAST_ARGS(n, __VA_ARGS__));
#else
#define PARSE_SYSCALL1(name, n, ...)                                          
#define PARSE_SYSCALL2(name,n, ret_type, ret,  ...) 
#endif


#define SHIM_SYSCALL_0(name, func, r)                           \
    BEGIN_SHIM(name, void)                                      \
        PARSE_SYSCALL1(name, 0);                                \
        r __ret = (func)();                                     \
        ret = (SHIM_ARG_TYPE) __ret;                            \
        PARSE_SYSCALL2(name, 0, #r, __ret);                     \
    END_SHIM(name)

#define SHIM_SYSCALL_1(name, func, r, t1, a1)                               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1)                                  \
        t1 a1 = (t1) __arg1;                                                \
        PARSE_SYSCALL1(name, 1, #t1, __arg1);                                   \
        r __ret = (func)(a1);                                               \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 1, #r, __ret, #t1, __arg1);                        \
    END_SHIM(name)

#define SHIM_SYSCALL_2(name, func, r, t1, a1, t2, a2)                       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        PARSE_SYSCALL1(name, 2, #t1, __arg1, #t2, __arg2);                          \
        r __ret = (func)(a1, a2);                                           \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 2, #r, __ret, #t1, __arg1, #t2, __arg2);               \
    END_SHIM(name)

#define SHIM_SYSCALL_3(name, func, r, t1, a1, t2, a2, t3, a3)               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        PARSE_SYSCALL1(name, 3, #t1, __arg1, #t2, __arg2, #t3, __arg3);                 \
        r __ret = (func)(a1, a2, a3);                                       \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 3, #r, __ret, #t1, __arg1, #t2, __arg2, #t3, __arg3);      \
    END_SHIM(name)

#define SHIM_SYSCALL_4(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4)       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        PARSE_SYSCALL1(name, 4, #t1, __arg1, #t2, __arg2, #t3, a3, #t4, __arg4);        \
        r __ret = (func)(a1, a2, a3, a4);                                   \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 4, #r, __ret, #t1, __arg1, #t2, __arg2, #t3, __arg3,       \
                       #t4, __arg4);                                            \
    END_SHIM(name)

#define SHIM_SYSCALL_5(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        PARSE_SYSCALL1(name, 5, #t1, __arg1, #t2, __arg2, #t3, __arg3, #t4, __arg4,         \
                       #t5, __arg5);                                            \
        r __ret = (func)(a1, a2, a3, a4, a5);                               \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 5, #r, __ret, #t1, __arg1, #t2, __arg2, #t3, __arg3,       \
                       #t4, __arg4, #t5, __arg5);                                   \
    END_SHIM(name)

#define SHIM_SYSCALL_6(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5, SHIM_ARG_TYPE __arg6)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        t6 a6 = (t6) __arg6;                                                \
        PARSE_SYSCALL1(name, 6, #t1, __arg1, #t2, __arg2, #t3, __arg3, #t4, __arg4,         \
                       #t5, __arg5, #t6, __arg6);                                   \
        r __ret = (func)(a1, a2, a3, a4, a5, a6);                           \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
        PARSE_SYSCALL2(name, 6, #r, __ret, #t1, __arg1, #t2, __arg2, #t3, __arg3,       \
                       #t4, __arg4, #t5, __arg5, #t6, __arg6);  \
    END_SHIM(name)

#define SHIM_PROTO_ARGS_0 void
#define SHIM_PROTO_ARGS_1 SHIM_ARG_TYPE __arg1
#define SHIM_PROTO_ARGS_2 SHIM_PROTO_ARGS_1, SHIM_ARG_TYPE __arg2
#define SHIM_PROTO_ARGS_3 SHIM_PROTO_ARGS_2, SHIM_ARG_TYPE __arg3
#define SHIM_PROTO_ARGS_4 SHIM_PROTO_ARGS_3, SHIM_ARG_TYPE __arg4
#define SHIM_PROTO_ARGS_5 SHIM_PROTO_ARGS_4, SHIM_ARG_TYPE __arg5
#define SHIM_PROTO_ARGS_6 SHIM_PROTO_ARGS_5, SHIM_ARG_TYPE __arg6

#define SHIM_PASS_ARGS_1 __arg1
#define SHIM_PASS_ARGS_2 SHIM_PASS_ARGS_1, __arg2
#define SHIM_PASS_ARGS_3 SHIM_PASS_ARGS_2, __arg3
#define SHIM_PASS_ARGS_4 SHIM_PASS_ARGS_3, __arg4
#define SHIM_PASS_ARGS_5 SHIM_PASS_ARGS_4, __arg5
#define SHIM_PASS_ARGS_6 SHIM_PASS_ARGS_5, __arg6

#define SHIM_UNUSED_ARGS_0()

#define SHIM_UNUSED_ARGS_1() do {               \
        __UNUSED(__arg1);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_2() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_3() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_4() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_5() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_6() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
        __UNUSED(__arg6);                       \
    } while (0)

#define SHIM_REGIZE_ARGS_0()

#define SHIM_REGIZE_ARGS_1() \
    register long int _a1 __asm__ ("rdi") = __arg1; 

#define SHIM_REGIZE_ARGS_2() \
    register long int _a1 __asm__ ("rdi") = __arg1;  \
    register long int _a2 __asm__ ("rsi") = __arg2;

#define SHIM_REGIZE_ARGS_3() \
    register long int _a1 __asm__ ("rdi") = __arg1;  \
    register long int _a2 __asm__ ("rsi") = __arg2;  \
    register long int _a3 __asm__ ("rdx") = __arg3;

#define SHIM_REGIZE_ARGS_4() \
    register long int _a1 __asm__ ("rdi") = __arg1;  \
    register long int _a2 __asm__ ("rsi") = __arg2;  \
    register long int _a3 __asm__ ("rdx") = __arg3;  \
    register long int _a4 __asm__ ("r10") = __arg4; 

#define SHIM_REGIZE_ARGS_5()  \
    register long int _a1 __asm__ ("rdi") = __arg1;  \
    register long int _a2 __asm__ ("rsi") = __arg2;  \
    register long int _a3 __asm__ ("rdx") = __arg3;  \
    register long int _a4 __asm__ ("r10") = __arg4;  \
    register long int _a5 __asm__ ("r8") = __arg5;  

#define SHIM_REGIZE_ARGS_6()  \
    register long int _a1 __asm__ ("rdi") = __arg1;  \
    register long int _a2 __asm__ ("rsi") = __arg2;  \
    register long int _a3 __asm__ ("rdx") = __arg3;  \
    register long int _a4 __asm__ ("r10") = __arg4;  \
    register long int _a5 __asm__ ("r8") = __arg5;  \
    register long int _a6 __asm__ ("r9") = __arg6;  

#define DO_SYSCALL_PASSTHRU(...) DO_SYSCALL_PASSTHRU2(__VA_ARGS__)
#define DO_SYSCALL_PASSTHRU2(n, ...) syscall##n(__VA_ARGS__)

#define DO_SYSCALL_PASSTHRU_0(sysno) syscall0(sysno)
#define DO_SYSCALL_PASSTHRU_1(sysno) DO_SYSCALL_PASSTHRU(1, sysno, SHIM_PASS_ARGS_1)
#define DO_SYSCALL_PASSTHRU_2(sysno) DO_SYSCALL_PASSTHRU(2, sysno, SHIM_PASS_ARGS_2)
#define DO_SYSCALL_PASSTHRU_3(sysno) DO_SYSCALL_PASSTHRU(3, sysno, SHIM_PASS_ARGS_3)
#define DO_SYSCALL_PASSTHRU_4(sysno) DO_SYSCALL_PASSTHRU(4, sysno, SHIM_PASS_ARGS_4)
#define DO_SYSCALL_PASSTHRU_5(sysno) DO_SYSCALL_PASSTHRU(5, sysno, SHIM_PASS_ARGS_5)
#define DO_SYSCALL_PASSTHRU_6(sysno) DO_SYSCALL_PASSTHRU(6, sysno, SHIM_PASS_ARGS_6)

#define ERIM_ISOLATE_UNTRUSTED
#define ERIM_SWAP_STACKS
#include <erim.h>

extern int __syscall_from_trusted;
extern unsigned char trampoline_start, trampoline_end;
#define SHIM_SYSCALL_ASM_ARG_0
#define SHIM_SYSCALL_ASM_ARG_1 ,"r"(_a1)
#define SHIM_SYSCALL_ASM_ARG_2 ,"r"(_a1), "r"(_a2)
#define SHIM_SYSCALL_ASM_ARG_3 ,"r"(_a1), "r"(_a2), "r"(_a3)
#define SHIM_SYSCALL_ASM_ARG_4 ,"r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)
#define SHIM_SYSCALL_ASM_ARG_5 ,"r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)
#define SHIM_SYSCALL_ASM_ARG_6 ,"r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6)

// TODO: fix passthru for EIV, but now we use old version for both

/*
#define SHIM_SYSCALL_PASSTHRU(name, n, ...)                         \
    BEGIN_SHIM(name, SHIM_PROTO_ARGS_##n)                           \
        SHIM_UNUSED_ARGS_##n();                                     \
        ret = DO_SYSCALL_PASSTHRU_##n(__NR_##name);                 \
    END_SHIM(name)                                                  \
    EXPORT_SHIM_SYSCALL(name, n, __VA_ARGS__)


#define SHIM_SYSCALL_PASSTHRUE(name, n, ...)                        \
    BEGIN_SHIM(name, SHIM_PROTO_ARGS_##n)                           \
        SHIM_UNUSED_ARGS_##n();                                     \
        ret = DO_SYSCALL_PASSTHRU_##n(__NR_##name);                 \
    END_SHIM(name)                                                  \
    EXPORT_SHIM_SYSCALL(name, n, __VA_ARGS__);                      \
    SHIM_SYSCALL_INTFUNC(SHIM_INT_NAME(name), n, __VA_ARGS__)
*/

#define SHIM_SYSCALL_PASSTHRU(name, n, ...)  \
long __shim_##name(SHIM_PROTO_ARGS_##n) __attribute__ ((weak, alias ("passthrough_unreachable")));

inline void iv_lock(int *key) {
    int res = 1;
    while(1) {
        if(__sync_bool_compare_and_swap(key, 0, 1))
            break;
        res = rawcall(futex, key, FUTEX_WAIT, 1, NULL, NULL, 0);
        if(res < 0) {
            if (res != -EAGAIN) {
                printf("iv_lock error: %d, %p\n", res, key);
                rawcall(exit_group, res);
            }
        }
    }
}



inline void iv_unlock(int *key) {
    int res;

    if(__sync_bool_compare_and_swap(key, 1, 0)) {
        res = rawcall(futex, key, FUTEX_WAKE, 0, NULL, NULL, 0);
        if(res < 0) {
            printf("iv_unlock error: %d, %p\n", res, key);
            rawcall(exit_group, res);
        }
    }
}

#endif /* _SHIM_SYSCALLS_H_ */
