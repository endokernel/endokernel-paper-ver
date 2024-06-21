.section .syscall_trampoline, "awx"
.global initial_syscall
initial_syscall: 
syscall
retq
int3
int3