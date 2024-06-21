/* DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED. */
#ifndef _ASM_OFFSETS_H_
#define _ASM_OFFSETS_H_

#include <asm-generated.h>

#define IV_TLS(obj) %gs:(iv_tls_t_##obj)
#define IV_TLS_DARY(obj, idx) %gs:(iv_tls_t_##obj)(idx)
#define IV_TLS_ARY(obj, idx) %gs:(iv_tls_t_##obj + (idx) * 8)
#define STR2(x) # x
#define STR(x) STR2(x)
#endif
