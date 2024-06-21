.section .text 

// temps: rax r10 r11
// will use ecx = edx = 0
// rax = tempdomain [63:16] : func id [15:0]

# TODO: move to .app_template, ro

# TODO: Can I allocate a seperate domain for shadow stack?
# So that I don't have to switch stack for sandbox??

.balign 4096
.global domain_begin(domain_id)
.global domain_end(domain_id)
.global domain_cmp(domain_id)
domain_begin(domain_id):
# Now, xcall should allow
# 1. switch t domain without stack switch (exclude CET)
# 2. switch s domain with stack switch
# 3. switch t+s, swtich stack
#ifdef CFICET
endbr64
#endif
mov %ax, %r10w
mov IV_TLS(current_domain), %rax
mov %r10w, %ax
jmp 11f
.balign 64
#ifdef CFICET
endbr64
#endif
11:
push %rax
movzwl %ax, %r10d # remove temp domain id, r10 = func id
mov $domain_id * 8, %ax # rax = tempdomain [63:16] : new domain_id
cmp %rax, IV_TLS(current_domain) # compare if all domain equal
jne 0f
pop %rax
lea domain_table(domain_id)(%rip), %r11
mov (%r11, %r10, 8), %r10
jmp *%r10
ret
0:
push %rax # stack = [tid:fid, tid:sid]
#mov %r10w, %ax # restore function id

mov %rcx, %r11
mov %rdx, %r10

2:
mov $trusted_pkru, %eax
xor %ecx, %ecx
xor %edx, %edx
wrpkru
# now trusted
cmp $trusted_pkru, %eax
jne 2b
# cmpl $untrusted_pkru, IV_TLS(current_pkru)
# As we allowed nested xcall, we don't have to check current_pkru == untrusted
#je 4f
# neq
#5:
#mov IV_TLS(current_pkru), %eax
#xor %ecx, %ecx
#xor %edx, %edx
#wrpkru # back to current 
#cmp IV_TLS(current_pkru), %eax
#jne 5b
#pop %rax
#mov %r11, %rcx
#mov %r10, %rdx
#ret 
4:
#ifdef MEASUREMENT
addq $1, IV_TLS(entercount)
#endif

#ifdef APPPERF
addq $1, IV_TLS_ARY(app_count, domain_id)
#endif

# TODO: push stacks

# push current_domain

mov IV_TLS(current_domain), %rdx
mov IV_TLS_ARY(app_stack, 0), %rax
lea -8(%rax), %rax
mov %rax, IV_TLS_ARY(app_stack, 0) # app_stack -= 8
mov %rdx, (%rax) # save old current domain
pop %rax # tid, sid

pop %rcx
mov %cx, IV_TLS(previous_rax) # get rid of temp domain

# save %rsp for nested xcall
movzwl %dx, %edx # remove temp domain id
mov %rsp, IV_TLS_DARY(app_stack, %rdx)

# stack switch
#ifdef sandbox
#ifdef CFICET
#cmpw %ax, IV_TLS(current_domain) # ax(spatial domain) == current_domain[15:0]
#je 5f

rdsspq %rcx
#mov %rcx, IV_TLS(untrusted_ssp)
mov %rcx, IV_TLS_DARY(app_ssp, %rdx) # save restore point at app_ssp?
mov IV_TLS_ARY(app_ssp, domain_id), %rcx # save callee ssp
rstorssp -8(%rcx)
saveprevssp

#endif
#endif

#5:

mov %rax, IV_TLS(current_domain) # push new current_domain

# prepare new pkru
mov %rax, %rcx # rax = [tid:sid]
mov $notemp_pkru, %edx
shr $0x10, %rcx # rcx = rax >> 16
cmove %rcx, %rdx #rcx == 0, ZF=0, set edx = ecx = 0; otherwise edx = notemp_pkru
mov IV_TLS_ARY(app_pkrus, domain_id), %rax # get base pkru for called domain
# temp admin can always access
#if domain_id != 14
or %rdx, %rax # rax |= rdx to set IV_TEMP
#endif

6:
# switch to new pkru
movl %eax, IV_TLS(current_pkru)
# mov %rsp, IV_TLS(previous_sp)
7:
mov IV_TLS(current_pkru), %eax
xor %ecx, %ecx
xor %edx, %edx
wrpkru
cmp IV_TLS(current_pkru), %eax
jne 7b

# now in app domain, switch stack
xor %rax, %rax
mov IV_TLS(previous_rax), %ax # get function addr back

# restore old %rsp and set rsp
mov %r11, %rcx
mov %r10, %rdx
lea domain_table(domain_id)(%rip), %r11

domain_cmp(domain_id):
cmp $0xff, %eax
jg 3f
mov (%r11, %rax, 8), %rax
mov IV_TLS_ARY(app_stack, domain_id), %rsp # get app_stack[domain]

#lea (%r11), %rsp
#and $0xfffffffffffffff0, %rsp # align the stack before making the call
call *%rax # call
# keep return value in %rax %rdx
mov %rax, %r11
mov %rdx, %r10

# mov IV_TLS(previous_sp), %rsp # restore stack pointer
# we cannot restore here
# --now in untrusted stack-- It's still callee's stack
3:
mov $trusted_pkru, %eax
xor %ecx, %ecx
xor %edx, %edx
wrpkru
cmp $trusted_pkru, %eax
jne 3b

# now trusted

mov %rsp, IV_TLS_ARY(app_stack, domain_id) # giveup app_stack[domain]
# for some reason, rsp == caller rsp here


#ifdef MEASUREMENT
addq $1, IV_TLS(exitcount)
#endif

# pop stacks
# pop current_domain
mov IV_TLS(current_domain), %rax
mov %rax, IV_TLS(previous_rax)
mov IV_TLS_ARY(app_stack, 0), %rax
mov (%rax), %rdx # rdx = old domain
mov %rdx, IV_TLS(current_domain)
lea 8(%rax), %rax # rax += 8
mov %rax, IV_TLS_ARY(app_stack, 0) # save pointer

mov %rdx, %rax #
# now current_domain popped to %rax
# rax = [Temp] | [Domain]
# calc new pkru
mov %rax, %rcx
shr $0x10, %rcx # rcx = rax >> 16
mov $notemp_pkru, %edx
cmove %rcx, %rdx #rcx == 0, ZF=0, set edx = ecx = 0; otherwise edx = notemp_pkru
# rcx free
movzwl %ax, %ecx # remove temp domain id, ecx = domain id for caller
mov IV_TLS_DARY(app_pkrus, %rcx), %rax # rax = pkru; get base pkru for caller domain
or %rdx, %rax # rax |= rdx to set IV_TEMP
mov %eax, IV_TLS(current_pkru) # restore current_pkru
# rcx = domain_id

# restore %rsp for caller context
mov IV_TLS_DARY(app_stack, %rcx), %rsp


#ifdef sandbox
#ifdef CFICET
#cmp %cx, IV_TLS(previous_rax) # compare domain id
#je 5f # don't switch stack if equal

mov IV_TLS_DARY(app_ssp, %rcx), %rcx
rstorssp -8(%rcx)
saveprevssp

#5:
#endif
#endif
4:
mov IV_TLS(current_pkru), %eax
xor %ecx, %ecx
xor %edx, %edx
wrpkru
cmp IV_TLS(current_pkru), %eax
jne 4b
mov %r11, %rax
mov %r10, %rdx

ret
domain_end(domain_id):
.balign 4096
domain_table(domain_id):
.fill 4096,1,0xcc;