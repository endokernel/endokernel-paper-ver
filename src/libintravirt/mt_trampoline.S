#include <asm-offsets.h>

.type thread_start_asm, @function
.global thread_start_asm
thread_start_asm:
mov %rsp, %rdi
mov iv_tls_t_trusted_stack(%rsp), %rsp
call prepare_thread_stack
xor %rax, %rax # I'm child
jmp monitor_ret