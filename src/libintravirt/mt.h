#ifndef _MT_H_
#ifndef GEN
#define _MT_H_
#endif
#ifndef DEFINE_STRUCT
#define DEFINE_STRUCT(name) typedef struct name {
#define DEFINE_FIELD(t, name) t name
#define DEFINE_ARY(t, name, len) t name[len]
#define END_STRUCT(name) } name##_t;
#endif

DEFINE_STRUCT(iv_tls)
    DEFINE_FIELD(struct iv_tls*, self);
    DEFINE_FIELD(void*, trusted_stack);
    DEFINE_FIELD(void*, untrusted_stack);
    DEFINE_FIELD(void*, base);
    DEFINE_FIELD(void*, top);
    DEFINE_FIELD(void*, flag_from_kernel);
    DEFINE_FIELD(unsigned long, current_pkru);
    DEFINE_FIELD(unsigned long, current_domain); // 63:16 temp domain; 15:0 code domain
    // domain_id  = real_domain_id * 8 to allow easier addressing
    DEFINE_ARY(unsigned long, app_stack, 16); // use app_stack[0] as domain_id stack
    // app_stack[0] is on IV_NORMAL which allows user to read and verify
    // domain switching relation
    DEFINE_ARY(unsigned long, app_pkrus, 16); // pkru values for app domain
    // stack must be saved during xcall
    // DEFINE_FIELD(unsigned long, previous_sp); use app_stack[X] as previous_sp
    DEFINE_FIELD(unsigned long, skipssp);
    DEFINE_FIELD(unsigned long, previous_rax);
    DEFINE_FIELD(unsigned long, previous_rdx);
    DEFINE_FIELD(unsigned long, pendsig);
    DEFINE_FIELD(unsigned long, sig_mask);
    DEFINE_FIELD(void*, signal_info);
    DEFINE_FIELD(unsigned long, fast_syscall);
    DEFINE_FIELD(unsigned long, previous_fastsp);

    DEFINE_ARY(void*, map_locked, 64);
    DEFINE_FIELD(unsigned long, locked_count);
#ifdef APPPERF
    DEFINE_ARY(unsigned long, app_count, 16);
#endif
#ifdef CFICET
    DEFINE_FIELD(void*, trusted_ssp);
    DEFINE_FIELD(void*, untrusted_ssp);
    DEFINE_ARY(unsigned long, app_ssp, 16);
    // nested call will break on CET
    // FIXME: verify the CET flags on the stack carefully
#endif
#ifdef DISPATCH
#ifndef CFICET
    DEFINE_FIELD(unsigned long, dispatch);
#endif
#endif
#ifdef RANDOM
    DEFINE_FIELD(unsigned long, rand_freq);
#endif
    DEFINE_ARY(char, bypass, 512);
    DEFINE_ARY(char, conf, 0);  
    // anything after here will be mapped into IV_CONF
#ifdef FILTERTP
    DEFINE_FIELD(void*, trampoline);
#endif

#ifdef MEASUREMENT
    DEFINE_FIELD(unsigned long, entercount);
    DEFINE_FIELD(unsigned long, exitcount);
#endif
// This might be useful for iterating all tls
// But not actually used now
    DEFINE_FIELD(unsigned long, vfork);
    DEFINE_FIELD(struct iv_tls*, next);
END_STRUCT(iv_tls)

#define TP_OFFSET (iv_tls_t_size - iv_tls_t_conf)
#define TP_OFFSET_DEF (sizeof(iv_tls_t) - __builtin_offsetof(iv_tls_t, conf))

DEFINE_STRUCT(iv_stack)
    DEFINE_ARY(char, stack0, 4096*2);
    DEFINE_ARY(char, stack, 0);
    DEFINE_ARY(char, padding0, 4096 - __builtin_offsetof(iv_tls_t, conf) % 4096);

    DEFINE_FIELD(iv_tls_t, tls);
    #ifdef FILTERTP
    DEFINE_ARY(char, padding1, 4096-(TP_OFFSET_DEF % 4096));
    
    #ifndef RANDOM
    DEFINE_ARY(char, local_trampoline, 4096);
    #endif
    #endif
    DEFINE_ARY(char, end, 0);
END_STRUCT(iv_stack)

#ifndef GEN
#define DOMAIN_DID(dm) (((dm) >> 3) & 0xf)
#define DOMAIN_TID(dm) (((dm) >> 16))
#define DOMAIN_FIELD(id, tid) (((id) << 3) | (tid << 16))
typedef __seg_gs iv_tls_t* tls_gs_t;
static tls_gs_t get_tls() {
    return (tls_gs_t) 0;
}

#ifndef _APP
#ifndef  __ASSEMBLY__
#ifndef QUEEN
void thread_start_asm(iv_tls_t* tls);
iv_tls_t* mt_create_thread(void* user_sp);
#endif
iv_stack_t* create_stack(char *stack);
#endif
#endif
#endif

#endif