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
 * syscall_trap.S
 *
 * This file contains the entry point of system call table in library OS.
 */

#include <shim_defs.h>
#include <asm-offsets.h>
#include <pkru.h>
#ifndef RFREQ
#define RFREQ 1024
#endif

// #define LOG_TRAP
#ifdef LOG_TRAP
        .extern trap_count
#define TRAP_COUNT addq $1, trap_count(%rip)
#else
#define TRAP_COUNT
#endif

        .global syscall_trap
        .global monitor_ret
        .global monitor_transaction_begin
        .global monitor_transaction_end
        .type syscall_trap, @function
        .extern shim_table
        .extern shim_sighook_sigreturn
        .extern trampoline_start
#ifdef RANDOM
        .extern is_initialized
#endif
syscall_fast:
        # clobbers: %rcx, %r11
        mov %rax, %r11
        push %rdx
        xor %ecx, %ecx
        xor %edx, %edx
        mov $trusted_pkru, %eax
        wrpkru
        cmp $trusted_pkru, %eax
        jne __exit
        # trusted
        TRAP_COUNT
        and $511, %r11
        cmpb $1, IV_TLS_DARY(bypass, %r11)
        je 1f
        mov $-1, %eax
        jmp fastover_nosp
1:
        mov IV_TLS(current_pkru), %ecx
        and $PKRU_NO_KEY(IV_USER), %ecx
        test %ecx, %ecx # do I need this??
        je 1f
        mov $-1, %eax
        jmp fastover_nosp
1:
        movq $1, IV_TLS(fast_syscall) # granted
        # prepare trampoline...
        pop %rdx
        mov %rdx, IV_TLS(previous_rdx)
        mov %r11, IV_TLS(previous_rax)
#ifdef FILTERTP
        mov %rsp, IV_TLS(previous_fastsp)
        mov IV_TLS_ARY(app_stack, 0), %rsp
        call 5f
5:
        cmp IV_TLS_ARY(app_stack, 0), %rsp
        je fastover # returned?
        # now rsp is trusted stack
#ifdef RANDOM
        cmpl $1, is_initialized(%rip)
        jne 3f
        mov IV_TLS(rand_freq), %rcx
        cmp $1, %rcx
        jbe 2f
        sub $0x1,%rcx
        mov %rcx, IV_TLS(rand_freq)
        mov IV_TLS(trampoline), %rax
        jmp 3f
2:
        movq $RFREQ, IV_TLS(rand_freq)              ## Randomization frequency setting
        mov IV_TLS(trampoline), %rcx
        movl $0xcccccccc, (%rcx)
1:
        rdrand %edx
        cmp $0xfffc, %dx
        ja 1b
        and $0xffff, %edx
        mov IV_TLS(trampoline), %rax
        and $~0xffff, %rax
        or %rdx, %rax
        movl $0xccc3050f, (%rax)
        mov %rax, IV_TLS(trampoline)
3:
#else
        movq IV_TLS(trampoline), %rax
        movl $0xccc3050f, (%rax)
#endif
#endif
        # do switch back to untrusted
#ifdef FILTERTP
        mov %rax, %r11
#endif
        xor %ecx, %ecx
        xor %edx, %edx
        mov IV_TLS(current_pkru), %eax
        wrpkru
        cmp IV_TLS(current_pkru), %eax
        jne __exit

        mov IV_TLS(previous_rax), %rax
        # do syscall
        # move rdx back
        mov IV_TLS(previous_rdx), %rdx
#ifdef FILTERTP
        # r11 contains address for syscall
        jmp *%r11
#else
        syscall
#endif
        # syscall finished, ret
fastover:
#ifdef FILTERTP
        mov IV_TLS(previous_fastsp), %rsp
#endif
fastover_nosp:
        mov %rax, %r11
        xor %ecx, %ecx
        xor %edx, %edx
        mov $trusted_pkru, %eax
        wrpkru
        cmp $trusted_pkru, %eax
        jne __exit

        movq $0, IV_TLS(fast_syscall)
#ifdef FILTERTP
#ifndef RANDOM
        mov IV_TLS(trampoline), %rcx
        movl $0xCCCCCCCC, (%rcx)
#endif
#endif
        xor %ecx, %ecx
        xor %edx, %edx
        mov IV_TLS(current_pkru), %eax
        wrpkru
        cmp IV_TLS(current_pkru), %eax
        jne __exit

        mov %r11, %rax
        mov IV_TLS(previous_rdx), %rdx
fastret:
        # check if any signal pending, do a restart signal system call
        cmpq $0, IV_TLS(pendsig)
        je 1f
        mov %rax, %r11
        mov $-1, %rax
        jmp empty_start
1:
        ret $128

.align 16
syscall_trap:
        .cfi_startproc
        endbr64
        cmpq $1, IV_TLS(pendsig)
        je 1f
        cmpb $1, IV_TLS_DARY(bypass, %eax)
        je syscall_fast

empty_start:
1:

        # Create shim_regs struct on the stack.
        pushfq

        # Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
        # thus TP=1 is stored on pushfq above. Upon consequent popfq,
        # TP is 1, resulting in spurious trap. Reset TP here.
        andq $~0x100, (%rsp)

        cld
        pushq %rbp
        pushq %rbx
        pushq %rdi
        pushq %rsi
        pushq %rdx
        pushq %rcx
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        #leaq SHIM_REGS_SIZE - SHIM_REGS_R15(%rsp), %rbx
        #pushq %rbx
        #pushq %rax
        # shim_regs struct ends here.

        # save rax, rdx (rcx not required, since not used)
        mov %rax, %r11
        mov %rdx, %r12

        # switch to trusted (ecx = edx = 0 && eax = TRUSTED PKRU)
        xor %ecx, %ecx
        xor %edx, %edx
        mov $trusted_pkru, %eax
        wrpkru
        cmp $trusted_pkru, %eax
        jne __exit
        TRAP_COUNT
        mov IV_TLS(current_pkru), %eax
        and $PKRU_NO_KEY(IV_USER), %eax
        test %eax, %eax
        jne __switch_back

        mov %rsp, IV_TLS(untrusted_stack)
        mov IV_TLS(trusted_stack), %rsp


        # TODO: FIXME: Use gs to locate ssp
#ifdef CFICET
        rdsspq %rax
        mov %rax, IV_TLS(untrusted_ssp)
        mov IV_TLS(trusted_ssp), %rax
        rstorssp -8(%rax)
        saveprevssp
#endif
        
        # SS Switch
        # setup trampoline
        # movl $0xccc3050f, %gs:(32)
        # movl $0xccc3050f, trampoline_start(%rip)

#ifdef FILTERTP
#ifdef RANDOM
        movq IV_TLS(trampoline), %rax
        cmpl $1, is_initialized(%rip)
        jne norand
        mov IV_TLS(rand_freq), %rdx
        cmp $1, %rdx
        jbe rerand
        sub $0x1,%rdx
        mov %rdx, IV_TLS(rand_freq)
        movq IV_TLS(trampoline), %rax
        jmp norand
rerand:
        movq $RFREQ, IV_TLS(rand_freq)              ## Randomization frequency setting
        mov IV_TLS(trampoline), %rax
        movl $0xcccccccc, (%rax)
rererand:
        rdrand %rax
        movzwl %ax, %edx
        cmp $0xfffc, %ax
        ja rererand
        mov IV_TLS(trampoline), %rax
        mov $0x0, %ax
        or %rdx, %rax
        movl $0xccc3050f, (%rax)
        mov %rax, IV_TLS(trampoline)
        # rax = trampoline
norand:
#else
        movq IV_TLS(trampoline), %rax
        movl $0xccc3050f, (%rax)
#endif
#endif
        #movq %rsp, %rbp
        #.cfi_def_cfa_offset SHIM_R EGS_SIZE
        #.cfi_offset %rbp, -3 * 8    # saved_rbp is at CFA-24 (saved_rflags + saved_rbp)
        #.cfi_def_cfa_register %rbp  # %rbp

        cmp $-1, %r11
        jne has_syscall
        # empty
        # restore return value
        mov IV_TLS(untrusted_stack), %r11
        mov 32(%r11), %rax
        jmp sighook
has_syscall:
        and $511, %r11
        cmpb $1, IV_TLS_DARY(bypass, %r11)
        je fastcall_inline

        # restore rax, rdx
        mov %r11, %rax
        mov %r12, %rdx

        cmp $SYSCALLNR, %rax
        jae isundef

        leaq shim_table(%rip), %rbx
        movq (%rbx,%rax,8), %rbx
        cmp $0, %rbx
        je isundef

        /* Translating x86_64 kernel calling convention to user-space
         * calling convention */
        movq %r10, %rcx
        andq $~0xF, %rsp  # Required by System V AMD64 ABI.
        call *%rbx
        jmp sighook
fastcall_inline:
        # rax = trampoline
        mov %r12, IV_TLS(previous_rdx) #rdx
        
#ifdef FILTERTP
        mov %rsp, IV_TLS(previous_fastsp)
        mov IV_TLS_ARY(app_stack, 0), %rsp
        call 4f
        4:
        cmp IV_TLS_ARY(app_stack, 0), %rsp
        je fastswitch_back # returned
#endif
        # switch to untrusted

        mov %rax, %r12
        mov %r11, %rax
        mov IV_TLS(previous_rdx), %rdx
        # do switch back to untrusted
        xor %ecx, %ecx
        xor %edx, %edx
        mov IV_TLS(current_pkru), %eax
        wrpkru
        cmp IV_TLS(current_pkru), %eax
        jne __exit

        mov %r11, %rax
        # do syscall
        # move rdx back
        mov IV_TLS(previous_rdx), %rdx
#ifdef FILTERTP
        # r11 contains address for syscall
        jmp *%r12
#else
        syscall
#endif
fastswitch_back:
#ifdef FILTERTP
        mov IV_TLS(previous_fastsp), %rsp
#endif
        mov %rax, %r11
        xor %ecx, %ecx
        xor %edx, %edx
        mov $trusted_pkru, %eax
        wrpkru
        cmp $trusted_pkru, %eax
        jne __exit

        movq $0, IV_TLS(fast_syscall)

        mov %r11, %rax
sighook:
        call shim_sighook_syscall # check if pending syscall
monitor_ret: # only point for ret to user
        # save rax, rdx (rcx not required, since not used)
        mov %rax, %r11
        #mov %rcx, %r12
        #mov %rdx, %r13

        # switch to untrusted stack
        # movabs $0x100000000014,%r14
        # mov    (%r14), %rsp
        mov %rsp, IV_TLS(trusted_stack)
        mov IV_TLS(untrusted_stack), %rsp

#ifdef CFICET
        # TODO: Fixme: Use GS to locate SSP
        rdsspq %rax
        mov %rax, IV_TLS(trusted_ssp)
        mov IV_TLS(untrusted_ssp), %rax
        rstorssp -8(%rax)
        saveprevssp
#endif

monitor_transaction_begin: # any int side transaction res

        # rollback trampoline
        # movl $0xcccccccc, trampoline_start(%rip)
#if FILTERTP
#ifndef RANDOM
        movq IV_TLS(trampoline), %rcx
        movl $0xcccccccc, (%rcx)
#endif
#endif
        # switch to untrusted PKRU
__switch_back:
        xor %ecx, %ecx
        xor %edx, %edx
        mov IV_TLS(current_pkru), %eax
        wrpkru
        cmp IV_TLS(current_pkru), %eax
        jne __exit
monitor_transaction_end:

.align 16

        # restore rax, rdx
        mov %r11, %rax
        #mov %r12, %rcx
        #mov %r13, %rdx

        #movq %rbp, %rsp
        #addq $2 * 8, %rsp   # skip orig_rax and rsp

        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi
        popq %rbx
        popq %rbp
        .cfi_def_cfa %rsp, 2 * 8 + 128  # +8 for ret_addr, +8 for saved_rflags
        popfq
        .cfi_def_cfa_offset 8 + 128    # +8 for ret_addr
        retq $128

isundef:
        movq $-38, %rax  # ENOSYS
        jmp monitor_ret

        .cfi_endproc
        .size syscall_trap, .-syscall_trap

__exit:
        mov $0x1, %rsi
        mov    $0xe7,%edi
        jmp _syscall1
