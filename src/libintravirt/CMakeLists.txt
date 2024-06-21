cmake_minimum_required(VERSION 2.8)

project(libintravirt C ASM)

set(OMIT_FRAME_POINTER ON CACHE BOOL "Omit frame pointer")

option(MT "Multithreading support" ON)

option(RANDOM "Randomized Nexpoline" OFF)

option(MEASUREMENT "Measurement option" OFF)

option(APPSIG "Allow signal inside app" ON)

option(APPPERF "App profile" OFF)

option(TOORHC "toorch feature" OFF)

option(SYSCALLFILTER "syscall filter" OFF)

option(VDSO "use VDSO" ON)

set(CFI "CFI" CACHE STRING "CET")
set_property(CACHE CFI PROPERTY STRINGS CET NEXPOLINE)

set(RSYSCALL "RSYSCALL" CACHE STRING "SECCOMP")
set_property(CACHE RSYSCALL PROPERTY STRINGS SECCOMP DISPATCH)

# MT+e"xpoline+Seccomp = Queen
# MT+Nexpoline+Seccomp+Random = Randomized Nexpoline, not queen

if (SYSCALLFILTER)
    add_definitions("-DSYSCALLFILTER")
endif()

if (VDSO)
    add_definitions("-DVDSO")
endif()

if (MT)
    add_definitions("-DMT")
    set(GEN_DEF ${GEN_DEF} "-DMT")
endif()

if (APPSIG)
    add_definitions("-DAPPSIG")
endif()

if (APPPERF)
    add_definitions("-DAPPPERF")
    set(GEN_DEF ${GEN_DEF} "-DAPPPERF")
endif()

if (TOORHC)
    add_definitions("-DTOORHC")
    set(GEN_DEF ${GEN_DEF} "-DTOORHC")
endif()

if (MT AND (CFI STREQUAL "NEXPOLINE") AND (RSYSCALL STREQUAL "SECCOMP"))
    if(RANDOM)
        set(QUEEN OFF)
        set(MT_LIB mt.c mt_trampoline.S)
        add_definitions("-DRANDOM")
        set(GEN_DEF ${GEN_DEF} "-DRANDOM")
    else()
        set(QUEEN ON)
        set(MT_LIB mt.c queen.c)
        add_definitions("-DQUEEN")
        set(GEN_DEF ${GEN_DEF} "-DQUEEN")
    endif()
else()
    if (MT)
        set(MT_LIB mt.c mt_trampoline.S)
    endif()
    set(QUEEN OFF)
endif()

if(MEASUREMENT)
    add_definitions("-DMEASUREMENT")
    set(GEN_DEF ${GEN_DEF} "-DMEASUREMENT")
endif()

include(../rules.cmake)

string(CONCAT CMAKE_C_FLAGS
    "-Wall -Wextra -O1 -fPIC -U_FORTIFY_SOURCE " #-std=c11 removed due to erim
    "-fno-stack-protector -Winline -Wwrite-strings "
    "-fmerge-all-constants -Wstrict-prototypes -Wtrampolines "
    "-Werror=implicit-function-declaration "
    "-fno-stack-protector -fno-builtin -Wno-inline -g ")
   # "-DERIM_DBG")

if(${OMIT_FRAME_POINTER})
    add_definitions("-DOMIT_FRAME_POINTER=1")
else()
    string(CONCAT CMAKE_C_FLAGS "-fno-omit-frame-point ")
    add_definitions("-DOMIT_FRAME_POINTER=0")
endif()

string(CONCAT CMAKE_C_FLAGS_DEBUG
    "-gdwarf-2 -g3 -DDEBUG ")
string(CONCAT CMAKE_ASM_FLAGS
    "-DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp ")


string(CONCAT CMAKE_SHARED_LINKER_FLAGS
        "-shared -nostdlib "
        "-Wl,-z,combreloc -Wl,-z,relro -Wl,-z,now -Wl,-z,defs "
        "-Wl,-T,${PROJECT_SOURCE_DIR}/shim.lds")

set(FILTER "TP")
if (CFI STREQUAL "CET")
    message("CET ON!")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-jump-tables")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,shstk -Wl,-z,ibt ")
    add_definitions("-DCFICET")
    set(GEN_DEF ${GEN_DEF} "-DCFICET")
    set(FILTER "ALL")
else()
    add_definitions("-DCFIMPK")
    set(GEN_DEF ${GEN_DEF} "-DCFIMPK")
endif()

if (RSYSCALL STREQUAL "SECCOMP")
    add_definitions("-DSECCOMP")
    set(GEN_DEF ${GEN_DEF} "-DSECCOMP")
endif()

if (RSYSCALL STREQUAL "DISPATCH")
    add_definitions("-DDISPATCH")
    set(GEN_DEF ${GEN_DEF} "-DDISPATCH")
endif()

if (FILTER STREQUAL "TP")
    add_definitions("-DFILTERTP")
    set(GEN_DEF ${GEN_DEF} "-DFILTERTP")
else()
    add_definitions("-DFILTERALL")
    set(GEN_DEF ${GEN_DEF} "-DFILTERALL")
endif()

include_directories(.)
include_directories(sysdeps/generic)
include_directories(erim)

if (SYSCALLFILTER)
    include_directories(../libtemporal)
endif()

set(QUEEN_SRC 
    queen.c)
    
set(LIBINTRAVIRT_SOURCE
    stdlib/printfmt.c
    string/atoi.c
    string/memcmp.c
    string/memcpy.c
    string/memset.c
    string/strchr.c
    string/strlen.c
    string/wordcopy.c
    erim/erim_shmem.c
    erim/shared_malloc.c
    erim/erim.c
    erim/mmap/map.c
    printf.c
    shim_trampoline.c
    filter.c
    bpf-helper.c
    shim_table.c
    shim_syscalls.c
    shim_syscalls_passthru.c
    shim_signal.c
    shim_signal_trampoline.S
    shim_trampoline.S
    shim_rtld.c
    shim_debug.c
    cet.c
    app.c
    app2.c
    app.S
    ${MT_LIB})

set(TRAP_SOURCE
    syscall_trap.S)
    
include_directories (${CMAKE_BINARY_DIR})
add_custom_command(
    OUTPUT asm-generated.h
    COMMAND gcc ${CMAKE_CURRENT_SOURCE_DIR}/gen_asm.c ${GEN_DEF} -DCMD="${GEN_DEF}" -o${CMAKE_BINARY_DIR}/gen_header && ${CMAKE_BINARY_DIR}/gen_header ${CMAKE_BINARY_DIR}/asm-generated.h
    DEPENDS gen_asm.c mt.h
    COMMENT "Generate asm-offsets"
)

add_library(intravirt SHARED
	${LIBINTRAVIRT_SOURCE}
    ${TRAP_SOURCE}
    ${PROJECT_SOURCE_DIR}/shim.map
    asm-generated.h)

set_property(TARGET intravirt APPEND_STRING PROPERTY LINK_FLAGS
    "-Wl,--version-script,${PROJECT_SOURCE_DIR}/shim.map")
