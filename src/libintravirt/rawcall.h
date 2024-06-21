#ifndef _RAWCALL_H_
#define _RAWCALL_H_
#define _LEN(_0,_1,_2,_3,_4,_5,_6,P,...) P
#define GETLEN(...) _LEN(DUMMY,##__VA_ARGS__,6,5,4,3,2,1,0)
#define EXPEND(...) __VA_ARGS__
#define EMPTY(...)
#define DEFER(...) __VA_ARGS__ EMPTY()
#define _CAT(x,y) x##y
#define CAT(x,y) _CAT(x,y)

#define _INC_0 1
#define _INC_1 2
#define _INC_2 3
#define _INC_3 4
#define _INC_4 5
#define _INC_5 6
#define _INC_6 7

#define INC(x) _INC_##x

#define _FOR_0(FUNC, n, X)
#define _FOR_1(FUNC, n, X) FUNC(n, X) 
#define _FOR_2(FUNC, n, X, ...) FUNC(n, X) _FOR_1(FUNC, INC(n), __VA_ARGS__)
#define _FOR_3(FUNC, n, X, ...) FUNC(n, X) _FOR_2(FUNC, INC(n), __VA_ARGS__)
#define _FOR_4(FUNC, n, X, ...) FUNC(n, X) _FOR_3(FUNC, INC(n), __VA_ARGS__)
#define _FOR_5(FUNC, n, X, ...) FUNC(n, X) _FOR_4(FUNC, INC(n), __VA_ARGS__)
#define _FOR_6(FUNC, n, X, ...) FUNC(n, X) _FOR_5(FUNC, INC(n), __VA_ARGS__)
#define APPLY(FUNC, ...) EXPEND(CAT(_FOR_,GETLEN(__VA_ARGS__))(FUNC, 1, __VA_ARGS__))

#define DEFARG(n, v) long _arg_##n = (long)v;

#define MAKE_ARG6(v) ,v
#define MAKE_ARG5(v) ,v
#define MAKE_ARG4(v) ,v
#define MAKE_ARG3(v) ,v
#define MAKE_ARG2(v) ,v
#define MAKE_ARG1(v) ,v
#define MAKE_ARG0() 

#define USEARG(n, v) EXPEND(MAKE_ARG##n)(_arg_##n)

#define rawcall(func, ...) ({             \
  APPLY(DEFARG,__VA_ARGS__)                 \
  CAT(_syscall,GETLEN(__VA_ARGS__))(__NR_##func APPLY(USEARG,__VA_ARGS__)); \
})
#endif