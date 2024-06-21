#define GEN
#include <stdio.h>
#include <stdlib.h>

#include "mt.h"

#undef DEFINE_STRUCT
#undef DEFINE_FIELD
#undef DEFINE_ARY
#undef END_STRUCT
#define DEFINE_STRUCT(name) { const char *current_struct = #name; typedef name##_t tcurrent;
#define END_STRUCT(name) fprintf(fout, "#define %s_t_size %d\n", current_struct, sizeof (tcurrent)); }
#define DEFINE_FIELD(t, name) fprintf(fout, "#define %s_t_"#name" %d\n", current_struct, __builtin_offsetof (tcurrent, name))
#define DEFINE_ARY(t, name, len) fprintf(fout, "#define %s_t_"#name" %d\n", current_struct, __builtin_offsetof (tcurrent, name))

int main(int argc, char*argv[]){
    if (argc == 1) {
        printf("Usage: %s fileOutput\n", argv[0]);
        exit(-1);
    }
    FILE *fout = fopen(argv[1], "w");
    #define STR2(x) #x
    #define STR(x) STR2(x)
    fprintf(fout, "// auto generated header with %s\n", STR(CMD));
    #include "mt.h"
    fclose(fout);

}