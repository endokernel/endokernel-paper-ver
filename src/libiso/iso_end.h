#ifndef ISONAME
#error "Define ISO Name as your namespace"
#endif
#if __INCLUDE_LEVEL__ != 1
#error "#include <iso.h> directly in your c file"
#endif

#undef ISONAME
#undef ISO_EXTERN