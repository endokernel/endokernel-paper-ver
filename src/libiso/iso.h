#ifndef ISONAME
#error "Define ISO Name as your namespace"
#endif
#if __INCLUDE_LEVEL__ != 1
#error "#include <iso.h> directly in your c file"
#endif
#define _CONCAT2(x,y) x##y
#define CONCAT2(x,y) _CONCAT2(x,y)
#define _CONCAT3(x,y,z) x##y##z
#define CONCAT3(x,y,z) _CONCAT3(x,y,z)
#define _CONCAT4(x,y,z,q) x##y##z##q
#define CONCAT4(x,y,z,q) _CONCAT4(x,y,z,q)
#ifndef ISO_EXTERN
#define ISO_EXTERN(name) \
extern char CONCAT2(__start_iv_code_,name), CONCAT2(__stop_iv_code_,name); \
extern char CONCAT2(__start_iv_data_,name), CONCAT2(__stop_iv_data_,name); \
extern char CONCAT2(__start_iv_functable_,name), CONCAT2(__stop_iv_functable_,name);
ISO_EXTERN(ISONAME)

#define ISO_HIDDEN __attribute__ ((visibility ("hidden")))

#define STR2(x) #x
#define STR(x) STR2(x)
#define ISO_DATA __attribute__((section("iv_data_"STR(ISONAME))))
#define ISO_CODE __attribute__((section("iv_code_"STR(ISONAME))))
#define ISO_FTABLE __attribute__((section("iv_functable_"STR(ISONAME)))) ISO_HIDDEN
#define ISO_STUB(name) \
__attribute__((section("iv_stub_"STR(name)"_stub"))) __attribute__((aligned(4096))) void CONCAT2(_xcall_stub_, name)();
ISO_STUB(ISONAME)

// require GCC>=8
#define ISO_ENTRY(fname) void ISO_FTABLE * CONCAT2(table_iv_func_, fname) = &fname; \
void ISO_CODE __attribute__((naked)) CONCAT4(_xcall_stub_,ISONAME,_,fname)() {   \
    __asm__(    \
    "endbr64\n" \
    "mov table_iv_func_"STR(fname)"(%rip), %rax\n" \
    "jmp _xcall_stub_"STR(ISONAME)"\n" \
    );  \
}

#define ISO_DENTRY(fname) ISO_FTABLE void* CONCAT2(table_iv_func_, fname) = &fname;

#endif

