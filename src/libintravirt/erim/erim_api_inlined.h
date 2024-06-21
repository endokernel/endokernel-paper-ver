/*
 * erim_api_inlined.h
 * 
 * Provides interface for switching and initlization of ERIM to be
 * used directly in functions.
 * 
 */
#ifndef ERIM_API_INLINED_H_
#define ERIM_API_INLINED_H_

#include <asm-offsets.h>
#include <pkru.h>
#include <iv_debug.h>
#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Debug prints
 */
#ifdef ERIM_DBG
  #define ERIM_DBM(...)				\
    do {					\
      printf(__VA_ARGS__);		\
      printf("\n");			\
    } while(0)
#else // disable debug
   #define ERIM_DBM(...)
#endif

/*
 * Error prints
 */
#ifdef ERIM_PRT_ERR
#define ERIM_ERR(...)				\
    do {					\
      printf(__VA_ARGS__);		\
      printf("\n");			\
    } while(0)
#else
  #define ERIM_ERR(...)
#endif
  
#include <stdint.h>
#include "pkeys.h"

#define ERIM_ISOLATED_DOMAIN 1

#define ERIM_STATIC_TRUSTED_STATE ((1ull<<44))
#define ERIM_TRUSTED_DOMAIN_IDENT_LOC ((void*)(ERIM_STATIC_TRUSTED_STATE))
#define ERIM_TRUSTED_DOMAIN_IDENT (*(int*)ERIM_TRUSTED_DOMAIN_IDENT_LOC)
#define ERIM_TRUSTED_FLAGS (*((int*)(ERIM_STATIC_TRUSTED_STATE+sizeof(int))))
#define ERIM_PKRU_VALUE_UNTRUSTED (*((int*)(ERIM_STATIC_TRUSTED_STATE+sizeof(int)*2)))
#define ERIM_REGULAR_STACK_PTR ((void**)(ERIM_STATIC_TRUSTED_STATE+sizeof(int)*3))
#define ERIM_ISOLATED_STACK_PTR ((void**)(ERIM_STATIC_TRUSTED_STATE+sizeof(int)*3+sizeof(void*)))
#define ERIM_REGULAR_SSTACK_PTR ((void**)(ERIM_STATIC_TRUSTED_STATE+sizeof(int)*3+2*sizeof(void*)))
#define ERIM_ISOLATED_SSTACK_PTR ((void**)(ERIM_STATIC_TRUSTED_STATE+sizeof(int)*3+3*sizeof(void*)))


// Get currently executing domain
//                                ISO Trusted (exec U)      ISO Untrusted (exec U)  ISO TRUSTED 
#define ERIM_EXEC_DOMAIN(pkru) ((0x0000000C & pkru) ? 0 : (0x00000003 & pkru) ? 1 : ERIM_TRUSTED_DOMAIN_IDENT )
  
#ifndef ERIM_ISOLATE_UNTRUSTED
  // trusted -> domain 1, untrusted -> domain 0
  #define ERIM_TRUSTED_DOMAIN 1
   #ifdef ERIM_INTEGRITY_ONLY
  // read(trusted = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_IO
   #else
      // read(trusted = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_CI
   #endif
#else
// trusted -> domain 0, untrusted -> domain 1
  #define ERIM_TRUSTED_DOMAIN 0
   #ifdef ERIM_INTEGRITY_ONLY
      // read(trusted = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_IO
   #else
      // read(trusted = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_CI
   #endif
#endif

// PKRU when running trusted (access to both domain 0 and 1)
#define ERIM_TRUSTED_PKRU (0x55555550)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_CI 0
#define ERIM_PKRU_ISOUTS_UNTRUSTED_IO 0
#define ERIM_PKRU_ISOTRS_UNTRUSTED_CI 0
#define ERIM_PKRU_ISOTRS_UNTRUSTED_IO 0
#ifdef ERIM_SWAP_STACKS
  // stack locations
#define ERIM_ISOLATED_STACK_START ((void*)(1ull<<43))
#define ERIM_ISOLATED_STACK_SIZE (40960 * 16)
#define ERIM_ISOLATED_STACK_ALLOC_SIZE (ERIM_ISOLATED_STACK_SIZE * 4)
#define ERIM_ISOLATED_STACK_LOC ((void*)((1ull<<43) + ERIM_ISOLATED_STACK_SIZE * 2))
#define ERIM_ISOLATED_STACK ((void *) ERIM_ISOLATED_STACK_LOC)

  // accessing stack values
#ifdef CFICET
#define ssp_switch(from, to) \
do { \
  asm volatile(           \
    "rdsspq %%rax\n\r"  \
    "mov %%rax, %"STR(IV_TLS(from##_ssp))"\n\r" \
    "mov %"STR(IV_TLS(to##_ssp))", %%rax\n\r" \
    "rstorssp -8(%%rax)\n\r"     \
    "saveprevssp\n\r"     \
    :::"rax", "memory" ); \
} while(0)
#else
#define ssp_switch(from, to) 
#endif

#define erim_save_stack(STACK)				\
  do {							\
    asm volatile("movq %%rsp, %0" : "+g" (*STACK));	\
  } while(0)

#define erim_set_stack(STACK) \
  do { \
    asm volatile("movq %0, %%rsp" : : "g" (*STACK)); \
  } while(0)

#if 0
#define ERIM_SWITCH_TO_ISOLATED_STACK					\
  do {									\
    erim_save_stack(ERIM_REGULAR_STACK_PTR); \
    erim_set_stack(ERIM_ISOLATED_STACK_PTR); \
    ssp_switch(ERIM_ISOLATED_SSTACK_PTR, ERIM_REGULAR_SSTACK_PTR); \
  } while(0)
#endif
#define ERIM_SWITCH_TO_ISOLATED_STACK	\
  do {									              \
    __asm__("mov %rsp, "STR(IV_TLS(trusted_stack))"\n"     \
          "mov "STR(IV_TLS(untrusted_stack))", %rsp");       \
    ssp_switch(trusted, untrusted); \
  } while(0)

  // TODO: CLEANUP!
  // erim_store_stackptr(ERIM_REGULAR_STACK_PTR);					
  //asm volatile("movq %0, %%rsp" : "m" (ERIM_ISOLATED_STACK));	
  // removed from script above     memcpy(ERIM_ISOLATED_STACK, ERIM_REGULAR_STACK, 128);		
  // TODO decide no what to do memcpy or not (depends on arguments of functions or not required)
  
#if 0
#define ERIM_SWITCH_TO_REGULAR_STACK					\
  do {									\
    erim_save_stack(ERIM_ISOLATED_STACK_PTR); \
    erim_set_stack(ERIM_REGULAR_STACK_PTR); \
    ssp_switch(ERIM_REGULAR_SSTACK_PTR, ERIM_ISOLATED_SSTACK_PTR); \
  } while(0)
  // asm volatile("movq %0, %%rsp\n" : "=m" (ERIM_REGULAR_STACK_PTR));	
#endif
#define ERIM_SWITCH_TO_REGULAR_STACK	\
  do {									              \
    __asm__("mov %rsp,"STR(IV_TLS(untrusted_stack))"\n"      \
            "mov "STR(IV_TLS(trusted_stack))", %rsp"   \
    );     \
    ssp_switch(untrusted, trusted); \
  } while(0)

#if ERIM_TRUSTED_DOMAIN == 1
  #define ERIM_SWITCH_TO_TRUSTED_STACK ERIM_SWITCH_TO_ISOLATED_STACK
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK ERIM_SWITCH_TO_REGULAR_STACK
  #define ERIM_TRUSTED_STACK_PTR ERIM_ISOLATED_STACK_PTR
  #define ERIM_UNTRUSTED_STACK_PTR ERIM_REGULAR_STACK_PTR
#else
  #define ERIM_SWITCH_TO_TRUSTED_STACK ERIM_SWITCH_TO_REGULAR_STACK
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK ERIM_SWITCH_TO_ISOLATED_STACK
  #define ERIM_TRUSTED_STACK_PTR ERIM_REGULAR_STACK_PTR
  #define ERIM_UNTRUSTED_STACK_PTR ERIM_ISOLATED_STACK_PTR
#endif
  
#else // ifdef ERIM_SWAP_STACKS
  #define ERIM_SWITCH_TO_TRUSTED_STACK 
  #define ERIM_SWITCH_TO_UNTRUSTED_STACK 
#endif
  
  #define __wrpkrucheck1(PKRU_ARG)						\
  do {									\
    __label__ erim_start;						\
  erim_start:								\
    asm goto ("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %"STR(PKRU_ARG)",%%eax\n\t.byte 0x0f,0x01,0xef\n\tcmp %"STR(PKRU_ARG)", %%eax\n\tjne %l0\n\t" \
	      : : 					\
	      :"eax", "ecx", "edx" : erim_start);			\
  } while (0)
// Switching between isolated and application
#define erim_switch_to_trusted						\
  do {                                                                  \
    __wrpkru(trusted_pkru);					\
    ERIM_SWITCH_TO_TRUSTED_STACK;					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
    IV_DBG("switching to trusted!");                \
  } while(0)
  
#define erim_switch_to_untrusted					\
  do {                                                                  \
    IV_DBG("switching to untrusted!");                \
    ERIM_SWITCH_TO_UNTRUSTED_STACK;					\
    __wrpkrucheck1(IV_TLS(current_pkru));					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
  } while(0)    
  
  // switch to untrustd based on trusted flags
#define erim_switch_to_untrusted_flags					\
  do {									\
    IV_DBG("switching to untrusted flags!");                \
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1){					\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    }									\
    __wrpkrumem(ERIM_PKRU_VALUE_UNTRUSTED);				\
    ERIM_DBM("pkru: %s", __rdpkru());					\
  } while(0)

  // switch to untrustd based on trusted flags
#define erim_switch_to_trusted_flags					\
  do {									\
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    if(ERIM_TRUSTED_DOMAIN_IDENT == 1) {				\
      ERIM_SWITCH_TO_ISOLATED_STACK;					\
    } else {								\
      ERIM_SWITCH_TO_REGULAR_STACK;					\
    }									\
    ERIM_DBM("pkru: %s", __rdpkru());					\
    IV_DBG("switching to trusted flags!");                \
  } while(0)
  
#define uint8ptr(ptr) ((uint8_t *)ptr)
  
#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)
  
#ifdef __cplusplus
}
#endif
 
#endif
