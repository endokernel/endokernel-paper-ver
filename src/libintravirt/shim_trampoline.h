/* Copyright (C) 2020 Texas A&M University
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
 * shim_trampoline.h
 */

#ifndef _SHIM_TRAMPOLINE_H_
#define _SHIM_TRAMPOLINE_H_

#define SYSCALLNUM 512      // Size of flags
#define JMPINSTSIZE 6
//#define RANDFREQ 0
#define TRUSTED 1
#define UNTRUSTED 0
#define TRAMPOLINEPGSIZE 2  // 2 pages are enough unless we use randomized nexpoline
#define PGSIZE 4096


# ifdef __ASSEMBLER__

.extern syscalldb

# else

#  define syscall6(sysno, a1, a2, a3, a4, a5, a6)                    \
    _syscall6(sysno, (long int)a1, (long int)a2, (long int)a3,      \
              (long int)a4, (long int)a5, (long int)a6)
#  define syscall5(sysno, a1, a2, a3, a4, a5)                        \
    _syscall5(sysno, (long int)a1, (long int)a2, (long int)a3,      \
              (long int)a4, (long int)a5)
#  define syscall4(sysno, a1, a2, a3, a4)                            \
    _syscall4(sysno, (long int)a1, (long int)a2, (long int)a3, (long int)a4)
#  define syscall3(sysno, a1, a2, a3)                                \
    _syscall3(sysno, (long int)a1, (long int)a2, (long int)a3)
#  define syscall2(sysno, a1, a2)                                    \
    _syscall2(sysno, (long int)a1, (long int)a2)
#  define syscall1(sysno, a1) _syscall1(sysno, (long int)a1)
#  define syscall0(sysno) _syscall0(sysno)

long int _syscall6(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3, long int __arg4, long int __arg5,
                   long int __arg6);
long int _syscall5(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3, long int __arg4, long int __arg5);
long int _syscall4(long int sys_no, long int __arg1,long int __arg2,
                   long int __arg3 , long int __arg4 );
long int _syscall3(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3);
long int _syscall2(long int sys_no, long int __arg1, long int __arg2);
long int _syscall1(long int sys_no, long int __arg1);
long int _syscall0(long int sys_no);

# endif /* __ASSEMBLER__ */

int init_trampoline(unsigned char *trampoline_start);

#ifdef RANDOM
#define RTRAMPOLINE_PGSIZE 16 // Recommdn to use power of 2 for better performance
#define MAXTHREAD 2048
#define RTRAMPOLINE_START (1ull<<46)
#define RTRAMPOLINE_END  ((1ull<<46)+(PGSIZE*TRAMPOLINEPGSIZE*MAXTHREAD))


void start_randomize(void);
#endif

#endif /* _SHIM_TRAMPOLINE_H_ */
