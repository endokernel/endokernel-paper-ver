// return from signal
//sigtrampoline_for_untrusted:  # <- address for sigaction
//  call shim_sighook_sigreturn 
//sigtrampoline_for_trusted
//  load syscall trampoline address # trusted code modify retrun address by using __builtin_return_address to here
//  jmp

//.global sigtrampoline_for_untrusted
#include <asm-offsets.h>

//.extern shim_sighook_sigreturn
//sigtrampoline_for_untrusted:
//mov %rsp, %rdi
//call shim_sighook_sigreturn
.global sigtrampoline_for_trusted
sigtrampoline_for_trusted:
mov $0xf,%eax

#ifdef CFICET
syscall
retq
#else
jmp *IV_TLS(trampoline)
#endif

nop
.align 16
.global sigtrampoline_for_untrusted
.extern syscall_trap
sigtrampoline_for_untrusted:
mov $0xf, %eax
subq $128, %rsp

call syscall_trap
