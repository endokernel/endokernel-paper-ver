#ifndef xcall
#ifndef CONCAT3

#define CONCAT2(x,y) x##y
#define CONCAT3(x,y,z) x##y##z
#define CONCAT4(x,y,z,q) x##y##z##q

#endif

#define xcall(iv_name, iv_func, ...) ({ void CONCAT4(_xcall_stub_,iv_name,_,iv_func)(); ((typeof(iv_func)*) CONCAT4(_xcall_stub_, iv_name, _, iv_func))(__VA_ARGS__); })
#define xcall_ptr(iv_name, iv_func) ({ void CONCAT4(_xcall_stub_,iv_name,_,iv_func)(); ((typeof(iv_func)*) CONCAT4(_xcall_stub_, iv_name, _, iv_func)); })
#endif