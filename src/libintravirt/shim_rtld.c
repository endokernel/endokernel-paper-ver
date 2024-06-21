/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/*
* shim_rtld.c
*
* This file contains codes for dynamic loading of ELF binaries in library OS.
* It's espeically used for loading interpreter (ld.so, in general) and
* optimization of execve.
* Most of the source codes are imported from GNU C library.
*/

//  TODO: make newly mapped memory RETIRED
// #define LOG_TRAP

#ifdef LOG_TRAP
void start_log_trap(const char* str);
#else
#define start_log_trap(x)
#endif

#include <api.h>
#include <shim_defs.h>
#include <shim_passthru.h>
#include <errno.h>
#include <elf.h>
#include <limits.h>
#include <asm/prctl.h>
#include <asm/mman.h>
#include <linux/fcntl.h>

#include "mmap/map.h"

#include <shim_trampoline.h>

#define ERIM_ISOLATE_UNTRUSTED
#define ERIM_SWAP_STACKS
#include <erim.h>

#include <shim_signal.h>
#include <queen.h>

#include <rawcall.h>

#include <mt.h>
#include <asm-offsets.h>

extern unsigned char trampoline_start, trampoline_end;
extern int fdsem[4096];

#ifdef MEASUREMENT
unsigned long *entercount, *exitcount;
#endif

/*
* This structure is similar to glibc's link_map, but only contains
* basic information needed for loading ELF binaries into memory
* without relocation.
*/
struct link_map {
    void*       base_addr;
    void*       map_start;
    void*       map_end;
    void*       entry;
    const char* interp_name;
    Elf64_Phdr* phdr_addr;
    size_t      phdr_num;
    Elf64_Dyn*  dyn_addr;
    size_t      dyn_num;
    Elf64_Sym*  symbol_table;
    const char* string_table;
    Elf64_Rela* rela_addr;
    size_t      rela_size;
    Elf64_Rela* jmprel_addr;
    size_t      jmprel_size;
    Elf64_Word* hash_buckets;
    Elf64_Word  nbuckets;
    Elf64_Word* hash_chain;
};

char interp_name[256];

static struct link_map exec_map, interp_map, shim_map;

#if __WORDSIZE == 32
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

static uint32_t sysv_hash(const char* str) {
    const unsigned char* s = (void*)str;
    uint_fast32_t h = 0;
    while (*s) {
        h = 16 * h + *s++;
        h ^= (h >> 24) & 0xf0;
    }
    return h & 0xfffffff;
}

static Elf64_Sym* find_symbol (struct link_map* map, const char* sym_name) {
    size_t   namelen = strlen(sym_name);
    uint32_t hash    = sysv_hash(sym_name);

    if (!map->hash_buckets)
        return NULL;

    Elf64_Word idx = map->hash_buckets[hash % map->nbuckets];

    for (; idx != STN_UNDEF ; idx = map->hash_chain[idx]) {
        Elf64_Sym* sym = &map->symbol_table[idx];
        if (!memcmp(map->string_table + sym->st_name, sym_name, namelen + 1))
            return sym;
    }

    return NULL;
}

extern void syscall_trap(void);
extern void gdb_trap(void);

static int load_link_map(struct link_map* map, int file, void* mapped, bool do_reloc) {
    int ret;

    char filebuf[FILEBUF_SIZE];
    const Elf64_Ehdr* ehdr;
    const Elf64_Phdr* phdr;

    if (mapped) {
        ehdr = (void*)mapped;
        phdr = (void*)mapped + ehdr->e_phoff;
    } else {
        ret = rawcall(pread64, file, filebuf, FILEBUF_SIZE, 0);
        if (IS_ERR(ret))
            return ERRNO(ret);

        ehdr = (void*)filebuf;
        phdr = (void*)filebuf + ehdr->e_phoff;
    }

    const Elf64_Phdr* ph;
    uintptr_t mapstart = (uintptr_t)-1;
    uintptr_t mapend   = (uintptr_t)0;

    memset(map, 0, sizeof(*map));

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                map->dyn_addr = (void*)ph->p_vaddr;
                map->dyn_num  = ph->p_memsz / sizeof(Elf64_Dyn);
                break;
            case PT_INTERP:
                map->interp_name = (const char*)ph->p_vaddr;
                break;
            case PT_LOAD: {
                uintptr_t start = ALIGN_DOWN(ph->p_vaddr);
                uintptr_t end   = ALIGN_UP(ph->p_vaddr + ph->p_memsz);
                if (start < mapstart)
                    mapstart = start;
                if (end > mapend)
                    mapend = end;
                break;
            }
        }

    if (mapstart >= mapend)
        return -EINVAL;

    uintptr_t mapoff = 0;

    if (mapped) {
        mapoff = (uintptr_t)mapped - mapstart;
    } else {
        if (ehdr->e_type == ET_DYN) {
            uintptr_t mapaddr = rawcall(mmap, NULL, mapend - mapstart,
                                               PROT_NONE, MAP_PRIVATE|MAP_FILE, file, 0);
            // TODO: how to map this?
            if (IS_ERR_P(mapaddr))
                return -ERRNO_P(mapaddr);

            mapoff = mapaddr - mapstart;
        } else {
            uintptr_t mapaddr = rawcall(mmap, mapstart, mapend - mapstart,
                                               PROT_NONE, MAP_FIXED|MAP_PRIVATE|MAP_FILE,
                                               file, 0);
            // TODO: how to map this?
            if (IS_ERR_P(mapaddr))
                return -ERRNO_P(mapaddr);
        }

        for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
            if (ph->p_type != PT_LOAD)
                continue;

            void* start = (void*)ALIGN_DOWN(ph->p_vaddr);
            void* end = (void*)ph->p_vaddr + ph->p_memsz;
            void* file_end = (void*)ph->p_vaddr + ph->p_filesz;
            void* file_end_aligned = (void*)ALIGN_UP(file_end);
            off_t file_off = ALIGN_DOWN(ph->p_offset);
            void* mapaddr = (void*)(mapoff + start);

            int prot = 0;
            if (ph->p_flags & PF_R)
                prot |= PROT_READ;
            if (ph->p_flags & PF_W)
                prot |= PROT_WRITE;
            if (ph->p_flags & PF_X) {
                prot |= PROT_EXEC;
                prot &= ~PROT_WRITE; // X^W
            }

            //printf("Map Region %p ~ %p\n", mapaddr, mapaddr + (file_end_aligned - start));
            //printf("SegInfo: vaddr %p, memsz %p, filesz %p, offset %p\n", ph->p_vaddr, ph->p_memsz, ph->p_filesz, ph->p_offset);
            if (file_end_aligned - start > 0) {
                mapaddr = (void*)rawcall(mmap, mapaddr,
                                            (unsigned long)(file_end_aligned - start), prot,
                                            MAP_PRIVATE|MAP_FILE|MAP_FIXED,
                                            file, file_off);
                if (IS_ERR_P(mapaddr))
                    return -ERRNO_P(mapaddr);
                map_set(map_addr(mapaddr, (void*)(mapaddr + (uintptr_t)file_end_aligned - start - 1)), map_norm(prot, 0));
                // ERIM protect memory to isolation domain
                rawcall(mprotect_pkey,  mapaddr, (unsigned long)(file_end_aligned - start), prot, IV_USER);
                //printf("pkey_mprotect: start=%p,\tend=%p,\tdomain=%d\n", mapaddr, mapaddr + (file_end_aligned - start), IV_USER);    
            }
            
            // ERIM perform memory scan
            erim_memScanRegion(untrusted_pkru, mapaddr, file_end_aligned - start, NULL, 0, NULL);

            if (end > file_end) {
                /*
                 * If there are remaining bytes at the last page, simply zero
                 * the bytes.
                 */
                if (file_end < file_end_aligned) {
                    memset((void*)(mapoff + file_end), 0, file_end_aligned - file_end);
                    file_end = file_end_aligned;
                }

                /* Allocate free pages for the rest of the section*/
                if (file_end < end) {
                    end = (void*)ALIGN_UP(end);
                    assert(ALIGNED(file_end));
                    mapaddr = (void*)(mapoff + file_end);
                    rawcall(mmap, mapaddr, (unsigned long)(end - file_end),
                                   prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
                    
                    // ERIM protect memory to isolation domain
                    rawcall(mprotect_pkey,  mapaddr,  (unsigned long)(end - file_end), prot, IV_USER);
                    //printf("pkey_mprotect: start=%p,\tend=%p,\tdomain=%d\n", mapaddr, mapaddr + (end - file_end), IV_USER);

                    map_set(map_addr(mapaddr, mapaddr + (end - file_end) - 1), map_norm(prot, 0));
                    
                    // ERIM perform memory scan
                    erim_memScanRegion(ERIM_UNTRUSTED_PKRU, mapaddr,  end - file_end, NULL, 0, NULL);
                }
            }
        }
    }

    map->base_addr = (void*)mapoff;
    map->dyn_addr  = (Elf64_Dyn*)(mapoff + (uintptr_t)map->dyn_addr);
    map->interp_name = map->interp_name ? (void*)(mapoff + (uintptr_t)map->interp_name): NULL;
    map->map_start = (void*)mapoff + mapstart;
    map->map_end   = (void*)mapoff + mapend;
    map->entry     = (void*)mapoff + (uintptr_t)ehdr->e_entry;
    map->phdr_addr = (Elf64_Phdr*)(map->map_start + ehdr->e_phoff);
    map->phdr_num  = ehdr->e_phnum;

    Elf64_Dyn* dyn = map->dyn_addr;
    for (; dyn < map->dyn_addr + map->dyn_num; ++dyn)
        switch(dyn->d_tag) {
            case DT_SYMTAB:
                map->symbol_table = (Elf64_Sym*) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                map->string_table = (const char *) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_HASH: {
                /*
                 * Structure of DT_HASH:
                 *  [      nbuckets      ]
                 *  [       nchain       ]
                 *  [     buckets[0]     ]
                 *  [        ...         ]
                 *  [ buckets[nbucket-1] ]
                 *  [      chain[0]      ]
                 *  [        ...         ]
                 *  [  chain[nchain-1]   ]
                 */
                Elf64_Word* hash = (Elf64_Word*) (map->base_addr + dyn->d_un.d_ptr);
                map->nbuckets = *hash++;
                hash++;
                map->hash_buckets = hash;
                hash += map->nbuckets;
                map->hash_chain = hash;
            }
            // fall through
            case DT_RELA:
                map->rela_addr = (Elf64_Rela*) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                map->rela_size = dyn->d_un.d_val;
                break;
            case DT_JMPREL:
                map->jmprel_addr = (Elf64_Rela*) (map->base_addr + dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                map->jmprel_size = dyn->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELCOUNT:
                printf("ERROR: PAL only supports RELA binaries");
                break;
        }

    struct {
        const char* name; void* addr; Elf64_Sym* sym;
    } trap_symbols[] = {
        { "syscall_trap",    &syscall_trap,        NULL },
        { "gdb_trap",        &gdb_trap,            NULL },
    };
    int ntraps = sizeof(trap_symbols) / sizeof(trap_symbols[0]);

    if (!do_reloc) {
        for (int i = 0; i < ntraps; i++)
            trap_symbols[i].sym = find_symbol(map, trap_symbols[i].name);
    }

    /* Making read-only mappings writable */
    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
        if (ph->p_type != PT_LOAD)
            continue;
        if (ph->p_flags & PF_W)
            continue;

        void* start = (void*)ALIGN_DOWN(mapoff + ph->p_vaddr);
        void* end   = (void*)ALIGN_UP(mapoff + ph->p_vaddr + ph->p_memsz);

        int prot = PROT_WRITE;
        if (ph->p_flags & PF_R)
            prot |= PROT_READ;
        if (ph->p_flags & PF_X) {
            prot |= PROT_EXEC;
        }

        rawcall(mprotect_pkey, start, (unsigned long)(end - start), prot, mapped ? IV_CONF : IV_USER);
        
        //printf("pkey_mprotect: start=%p,\tend=%p,\tdomain=%d\n", start, start + (end - start), mapped ? IV_CONF : IV_USER);

        // map_set(map_addr(start, end - 1), map_norm(prot, 0));
        // Reprotecting phase update mapping keys
    }

    Elf64_Rela* reloc_ranges[2][2] = {
        { map->rela_addr,   ((void*)map->rela_addr   + map->rela_size)   },
        { map->jmprel_addr, ((void*)map->jmprel_addr + map->jmprel_size) },
    };

    for (int i = 0 ; i < 2 ; i++) {
        Elf64_Rela* rel = reloc_ranges[i][0];
        if (!rel)
            continue;

        for (; rel < reloc_ranges[i][1] ; rel++) {
            unsigned long r_type = ELF64_R_TYPE(rel->r_info);
            void** reloc_addr = (void**)(mapoff + rel->r_offset);
            Elf64_Sym* sym = &map->symbol_table[ELF64_R_SYM(rel->r_info)];
            switch(r_type) {
                case R_X86_64_GLOB_DAT:
                case R_X86_64_JUMP_SLOT:
                    if (do_reloc) {
                        *reloc_addr = (void*)(mapoff + sym->st_value);
                    } else {
                        for (int i = 0; i < ntraps; i++)
                            if (sym && sym == trap_symbols[i].sym) {
                                sym->st_value = (Elf64_Addr)trap_symbols[i].addr - (Elf64_Addr)map->base_addr;
                                sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
                                *reloc_addr   = trap_symbols[i].addr;
                            }
                    }
                    break;
                case R_X86_64_64:
                case R_X86_64_32:
                    if (do_reloc)
                        *reloc_addr = (void*)(mapoff + sym->st_value + rel->r_addend);
                    break;
                case R_X86_64_RELATIVE:
                    if (do_reloc)
                        *reloc_addr = (void*)(mapoff + rel->r_addend);
                    break;
                default:
                    /* ignore other relocation type */
                    break;
            }
        }
    }

    /* Reprotecting read-only mappings */
    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
        if (ph->p_type != PT_LOAD)
            continue;
        if ((ph->p_flags & PF_W) && !mapped)
            continue;

        void* start = (void*)ALIGN_DOWN(mapoff + ph->p_vaddr);
        void* end   = (void*)ALIGN_UP(mapoff + ph->p_vaddr + ph->p_memsz);

        int prot = 0;
        if (ph->p_flags & PF_R)
            prot |= PROT_READ;
        if (ph->p_flags & PF_X)
            prot |= PROT_EXEC;
        if (ph->p_flags & PF_W)
            prot |= PROT_WRITE;
        

        rawcall(mprotect_pkey, start, (unsigned long)(end - start), prot, mapped ? IV_CONF : IV_USER);
        //printf("pkey_mprotect: start=%p,\tend=%p,\tdomain=%d\n", start, start + (end - start), mapped ? IV_CONF : IV_USER);

        map_set(map_addr(start, end - 1), map_norm(prot, 0));
    }

    return 0;
}

int shebang;
// this is incomplete, it has no support for chaining
int check_shebang(int fd) {
    // read the check if this file has a shebang, if so, open the interpreter instead of current file
    char buf[2];
    int ret = rawcall(read, fd, buf, 2);
    if (ret < 2)
        return fd;
    if (buf[0] != '#' || buf[1] != '!')
        return fd;
    char interp[256];
    int i = 0;
    while (1) {
        ret = rawcall(read, fd, buf ,1);
        if (ret < 1)
            return 0;
        if (buf[0] == ' ') continue;
        if (buf[0] == '\n')
            break;
        if (i >= sizeof(interp) - 1)
            return 0;
        interp[i++] = buf[0];
    }
    interp[i] = 0;
    shebang = 1;
    rawcall(close, fd);
    return rawcall(open, interp, O_RDONLY);
}

static int load_link_map_by_path(struct link_map* map, const char* dir_path,
                                 const char* path, int fd) {
    int dirfd = AT_FDCWD;

    if (fd == 0){
        if (dir_path) {
            dirfd = rawcall(open, dir_path, O_DIRECTORY, 0);
            if (IS_ERR(dirfd))
                return -ERRNO(dirfd);
        }

        fd = rawcall(openat, dirfd, path, O_RDONLY, 0);

        if (dirfd != AT_FDCWD)
            rawcall(close, dirfd);

        if (IS_ERR(fd))
            return -ERRNO(fd);
        fd = check_shebang(fd);
        if (fd == 0) {
            return -ENOENT;
        }
    }

    printf("Loading %s...\n", path);
    int ret = load_link_map(map, fd, NULL, false);
    rawcall(close, fd);
    return ret;
}

static bool usinginterp = false;

int load_executable(const char* exec_path, int exec_fd, const char* libc_location) {
    int ret = load_link_map_by_path(&exec_map, NULL, exec_path, exec_fd);
    usinginterp = false;
    if (ret < 0)
        return ret;
    if (exec_map.interp_name) {
        usinginterp = true;
        const char* filename = exec_map.interp_name + strlen(exec_map.interp_name) - 1;
        while (filename > exec_map.interp_name && *filename != '/')
            filename--;
        if (*filename == '/')
            filename++;

        /* Try loading the interpreter */
        ret = load_link_map_by_path(&interp_map, libc_location, filename, 0);
        if (ret < 0)
            return ret;

        int l1 = strlen(libc_location);
        int l2 = strlen(filename);
        assert(l1 + l2 + 1 < sizeof(interp_name));
        memcpy(interp_name, libc_location, l1);
        interp_name[l1] = '/';
        memcpy(interp_name + l1 + 1, filename, l2);
        interp_name[l1 + l2 + 1] = '\0';
    }

    return 0;
}

#define REQUIRED_ELF_AUXV           8
#define REQUIRED_ELF_AUXV_SPACE     16

void *saved_dl_random;
unsigned long sysinfo;

static int populate_user_stack (void * stack, size_t stack_size,
                                elf_auxv_t ** auxpp, int ** argcpp,
                                const char *** argvp, const char *** envpp)
{
    const int argc = **argcpp;
    const char ** argv = *argvp, ** envp = *envpp;
    const char ** new_argv = NULL, ** new_envp = NULL;
    elf_auxv_t *new_auxp = NULL;
    void * stack_bottom = stack;
    void * stack_top = stack + stack_size;
#define ALLOCATE_TOP(size)      \
    ({ if ((stack_top -= (size)) < stack_bottom) return -ENOMEM;    \
       stack_top; })
#define ALLOCATE_BOTTOM(size)   \
    ({ if ((stack_bottom += (size)) > stack_top) return -ENOMEM;    \
       stack_bottom - (size); })
    /* ld.so expects argc as long on stack, not int. */
    long * argcp = ALLOCATE_BOTTOM(sizeof(long));
    *argcp = **argcpp;
    if (!argv) {
        *(const char **) ALLOCATE_BOTTOM(sizeof(const char *)) = NULL;
        goto copy_envp;
    }
    new_argv = stack_bottom;
    while (argv) {
        /* Even though the SysV ABI does not specify the order of argv strings,
           some applications (notably Node.js's libuv) assume the compact
           encoding of argv where (1) all strings are located adjacently and
           (2) in increasing order. */
        int argv_size = 0;
        for (const char ** a = argv ; *a ; a++)
            argv_size += strlen(*a) + 1;
        char * argv_bottom = ALLOCATE_TOP(argv_size);
        for (const char ** a = argv ; *a ; a++) {
            const char ** t = ALLOCATE_BOTTOM(sizeof(const char *));
            int len = strlen(*a) + 1;
            char * abuf = argv_bottom;
            argv_bottom += len;
            memcpy(abuf, *a, len);
            *t = abuf;
        }
        *((const char **) ALLOCATE_BOTTOM(sizeof(const char *))) = NULL;
copy_envp:
        if (!envp)
            break;
        new_envp = stack_bottom;
        argv = envp;
        envp = NULL;
    }
    if (!new_envp) {
        *(const char **) ALLOCATE_BOTTOM(sizeof(const char *)) = NULL;
    }

    /* reserve space for ELF aux vectors, populated later by LibOS */
    new_auxp = ALLOCATE_BOTTOM(REQUIRED_ELF_AUXV * sizeof(elf_auxv_t) +
                               REQUIRED_ELF_AUXV_SPACE);

    /* deliver randomness for loader */
    void *isolated_random = ALLOCATE_BOTTOM(sizeof(uintptr_t));
    memcpy (isolated_random, saved_dl_random, sizeof (uintptr_t));
    
    // TODO: Should I put isolated_random on the stack?
    // Or, since it's the cookie for stack, I should put it somewhere more secure??
    
    new_auxp[0].a_type     = AT_PHDR;
    new_auxp[0].a_un.a_val = (__typeof(new_auxp[0].a_un.a_val))exec_map.phdr_addr;
    new_auxp[1].a_type     = AT_PHNUM;
    new_auxp[1].a_un.a_val = exec_map.phdr_num;
    new_auxp[2].a_type     = AT_PAGESZ;
    new_auxp[2].a_un.a_val = PAGE_SIZE;
    new_auxp[3].a_type     = AT_ENTRY;
    new_auxp[3].a_un.a_val = (uintptr_t)exec_map.entry;
    new_auxp[4].a_type     = AT_BASE;
    new_auxp[4].a_un.a_val = (uintptr_t)interp_map.base_addr;
    new_auxp[5].a_type     = AT_RANDOM;
    new_auxp[5].a_un.a_val = (uintptr_t)isolated_random;

#ifdef VDSO
    new_auxp[6].a_type     = AT_SYSINFO_EHDR;
    new_auxp[6].a_un.a_val = (uintptr_t)sysinfo;
#else
    new_auxp[6].a_type     = AT_NULL;
    new_auxp[6].a_un.a_val = 0;
#endif
    new_auxp[7].a_type     = AT_NULL;
    new_auxp[7].a_un.a_val = 0;


    /* x86_64 ABI requires 16 bytes alignment on stack on every function
       call. */
    size_t move_size = stack_bottom - stack;
    *argcpp = stack_top - move_size;
    *argcpp = ALIGN_DOWN_PTR(*argcpp, 16UL);
    **argcpp = argc;
    size_t shift = (void*)(*argcpp) - stack;
    memmove(*argcpp, stack, move_size);
    *argvp = new_argv ? (void *) new_argv + shift : NULL;
    *envpp = new_envp ? (void *) new_envp + shift : NULL;
    *auxpp = new_auxp ? (void *) new_auxp + shift : NULL;
    /* clear working area at the bottom */
    memset(stack, 0, shift);
    return 0;
}

/*
 * Copy arguments (argv, envp, auxp) to the program as expected by libc
 * This requires to allocate isolated memory to store the values of the 
 * argument pointer arrays (argv, envp, auxp).
 * 
 * Each of these arrays is copied via cpy_stack_ptr_array, which copies
 * an array of char * pointers to the new stack location and deep copies
 * the contents of each char * to a memory space.
 */

extern int gs_ready;

iv_stack_t __attribute__((align(4096))) shim_stack0;

void initial_syscall();

int prepare_isolated_stack(const char ** argv, const char ** envp, elf_auxv_t * auxp, int _new_argc) {
    // copy and prepare stack

    int new_argc = _new_argc, ret = 0;
    int* new_argcp = &new_argc;
    const char** new_argp = argv;
    const char ** new_envp = envp;
    elf_auxv_t* new_auxp = auxp;
    map_set(map_addr(ERIM_ISOLATED_STACK_START, ERIM_ISOLATED_STACK_START + ERIM_ISOLATED_STACK_ALLOC_SIZE - 1), READABLE | WRITABLE);
    printf("set %p ~ %p as stack\n", ERIM_ISOLATED_STACK_START, ERIM_ISOLATED_STACK_START + ERIM_ISOLATED_STACK_ALLOC_SIZE - 1);
    if((ret = populate_user_stack(ERIM_ISOLATED_STACK, ERIM_ISOLATED_STACK_SIZE, 
        &new_auxp, &new_argcp, &new_argp, &new_envp)) != 0) {
        return ret;
    }
    #ifdef CFICET
    ssize_t user_stacklen = 0x1000 * 32;
    void *addr = user_stacklen;
    if ((ret = rawcall(arch_prctl, 0x3004 /* alloc shstk */, &addr))) {
        printf("alloc stack failed. %d\n", ret);
        return ret;
    }
    void *base = ((char*)addr);
    addr = user_stacklen + ((char*)addr);
    rawcall(mprotect_pkey, base, user_stacklen, PROT_READ | 0x10, IV_USER);
    map_set(map_addr(base, ((char*)addr) - 1), TRUSTED_MEM); 
    #endif
    printf("%p\n", new_auxp);
    elf_auxv_t* av;
    for (av = new_auxp; av->a_type != AT_NULL; av++) {
        printf("%ld\n", av->a_type);
    }

    printf("start %p end %p argcp %p\n", ERIM_ISOLATED_STACK, 
        ((char*)ERIM_ISOLATED_STACK)  +ERIM_ISOLATED_STACK_SIZE,
        new_argcp);
    printf("argc %d\n", *new_argcp);
    printf("argv %p %s\n", new_argp, new_argp[0]);
    printf("envp %p %s\n", new_envp, new_envp[0]);
    printf("ERIM_REGULAR_STACK_PTR=%p\n", ERIM_REGULAR_STACK_PTR);
    printf("ERIM_ISOLATED_STACK_PTR=%p\n", ERIM_ISOLATED_STACK_PTR);
    
    iv_tls_t *tls_obj = (iv_tls_t*) &shim_stack0.tls;
    tls_obj->self = tls_obj;
    tls_obj->trusted_stack = &shim_stack0.stack;
    tls_obj->untrusted_stack = new_argcp;
    tls_obj->current_pkru = untrusted_pkru;
    tls_obj->current_domain = DOMAIN_FIELD(2,0);
    for (int i = 0; i < 16; i++)
        tls_obj->app_pkrus[i] = unsafe_pkru; // no priv by default
    tls_obj->app_pkrus[2] = untrusted_pkru;
    tls_obj->app_pkrus[14] = temp_pkru; // 14 is the manager
    tls_obj->app_pkrus[0] = 0xffffffff; 
    tls_obj->app_pkrus[1] = 0xffffffff; 
    tls_obj->app_pkrus[15] = 0xffffffff; // cannot use 15;
    // domain 15 reserved for temp manage

#ifdef MEASUREMENT
    tls_obj->entercount = 0;
    tls_obj->exitcount = 0;

    entercount = &(tls_obj->entercount);
    exitcount = &(tls_obj->exitcount);
#endif

#ifdef RANDOM
    // Duplicated code from shim_trampoline.c: get_random_trampoline() due to the lack of GS register here.
    unsigned long myrandom;
    unsigned int *gadget;
    unsigned long *trampoline = RTRAMPOLINE_START;
    rawcall(mprotect_pkey, RTRAMPOLINE_START, PGSIZE * RTRAMPOLINE_PGSIZE, PROT_EXEC | PROT_READ | PROT_WRITE, IV_CONF);
    map_set(map_addr((void*)RTRAMPOLINE_START, (void*)(RTRAMPOLINE_END-1)), TRUSTED_MEM);
    for(int i = 0 ; i < PGSIZE * RTRAMPOLINE_PGSIZE / 8 ; i++)
        trampoline[i] = 0xcccccccccccccccc;

    do {
        __asm__ __volatile__ ("rdrand %0\n\t" : "=a" (myrandom) : : );
        myrandom = myrandom & 0xffff;
    } while ((myrandom > 0xfffc) || myrandom <= 4);
    gadget = (unsigned int*)((unsigned long)RTRAMPOLINE_START + myrandom);
    trampoline[0] = gadget[0] = 0xccc3050f;
    tls_obj->trampoline = (void *)gadget;
    
#else
#ifdef FILTERTP
    tls_obj->trampoline = (unsigned long)(&trampoline_start);
#endif
#endif

#ifdef CFICET
    tls_obj->untrusted_ssp = addr;
#endif 
    // Setup GS register for the initial stack value
    rawcall(arch_prctl, ARCH_SET_GS, tls_obj);
    gs_ready = 1;

#ifdef RANDOM
    unsigned int *early_syscall_code = (unsigned int *)&initial_syscall;
    early_syscall_code[0] = 0xcccccccc;
    trampoline[0] = 0xcccccccc;
    start_randomize();
#endif

    return 0;
}

// TODO: use return path to jump to executable
int start_execute(void) {

    void * entry = 0;
    if (usinginterp) 
        entry = (interp_map.entry);
    else 
        entry = (exec_map.entry);

    *((unsigned int*)&trampoline_start) = 0;
    /*
    __asm__(
        "movabs $0x100000009ff8,%r13\n" // 10 pages for trusted stack
        "mov    %r13,%rsp"
    );
    */
    erim_switch_to_untrusted;

#if defined(__x86_64__)
    __asm__ __volatile__ ("jmp *%%rax\r\n"
                          :
                          : "a" (entry)
                          : "memory");
#else
# error "architecture not supported"
#endif

    /* Should not reach here */
    rawcall(exit, -1);
    return 0;
}

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */

__asm__ (
    ".global shim_start \n"
    "  .type shim_start,@function \n"

    "shim_start: \n"
    "  movq %rsp, %rdi \n"
    "  lea "STR(iv_stack_t_stack)"+shim_stack0(%rip), %rsp\n"
    "  call shim_main \n"
);

void shim_start(void);
int install_seccomp_filter(void* start, void* end);

void init_debugger(Elf64_Addr loader_base, const char* loader_name, Elf64_Dyn* loader_dyn,
                   Elf64_Addr exec_base, const char* exec_name, Elf64_Dyn* exec_dyn,
                   Elf64_Addr interp_base, const char* interp_name, Elf64_Dyn* interp_dyn);

bool intravirt_initialized = false;
char resolved_libc_location[8192];
char *abs_libc_location;

#ifdef CFIMPK
#ifndef RANDOM
#define EARLY_SYSCALL "syscall\n\t"
#else
#define EARLY_SYSCALL "call initial_syscall\n\t"
#endif

void *prepare_temp_trampoline(void) {
    unsigned long int resultvar, res;
    unsigned long int sysno = 9;
    // Prepare 1 page for temporary syscall region. This should be all asm
    register long int _a6 __asm__ ("r9")  = 0;
    register long int _a5 __asm__ ("r8")  = -1;
    register long int _a4 __asm__ ("r10") = MAP_PRIVATE | MAP_ANONYMOUS;
    register long int _a3 __asm__ ("rdx") = PROT_READ | PROT_WRITE | PROT_EXEC;
    register long int _a2 __asm__ ("rsi") = PAGESIZE;
    register long int _a1 __asm__ ("rdi") = (long int)NULL;
    __asm__ __volatile__ (EARLY_SYSCALL
                        : "=a" (resultvar)
                        : "0" (sysno), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6)
                        : "memory", "cc", "r11", "cx");

    // Get GS register to the temporary region in asm
    sysno = 158;
    _a2 = resultvar;
    _a1 = ARCH_SET_GS;
    __asm__ __volatile__ (EARLY_SYSCALL
                        : "=a" (res)
                        : "0" (sysno), "r"(_a1), "r"(_a2)
                        : "memory", "cc", "r11", "cx");


    // Fill trusted stack data structure
    iv_tls_t *mygs = (unsigned long*)(resultvar);
    mygs->self = mygs;

    #ifdef FILTERTP
    mygs->trampoline = resultvar + 1000;
    #endif
    
    #ifdef RANDOM
    
    // rawcall(mmap, RTRAMPOLINE_START, PGSIZE * RTRAMPOLINE_PGSIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0); use the early syscall

    _a1 = (long int)RTRAMPOLINE_START;
    _a2 = PGSIZE * RTRAMPOLINE_PGSIZE;
    _a3 = PROT_EXEC | PROT_READ | PROT_WRITE;
    _a4 = MAP_ANONYMOUS | MAP_PRIVATE;
    _a5 = -1;
    _a6 = 0;
    sysno = 9;
    __asm__ __volatile__ (EARLY_SYSCALL
                        : "=a" (resultvar)
                        : "0" (sysno), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6)
                        : "memory", "cc", "r11", "cx");
    mygs->trampoline = resultvar;
    
    #endif

    // Fill 0x0f05c3
    unsigned char *opcodes = (unsigned char*)(mygs->trampoline);
    opcodes[0] = 0x0f;
    opcodes[1] = 0x05;
    opcodes[2] = 0xc3;

    // We need to remove this region after Tursted stack is ready.
    return (void *)mygs;
}
#endif

void shim_main(void* args) {
    /*
     * fetch arguments and environment variables, the previous stack
     * pointer is in rdi (arg). The stack structure starting at rdi
     * will look like:
     *            auxv[m - 1] = AT_NULL
     *            ...
     *            auxv[0]
     *            envp[n - 1] = NULL
     *            ...
     *            envp[0]
     *            argv[argc] = NULL
     *            argv[argc - 1]
     *            ...
     *            argv[0]
     *            argc
     *       ---------------------------------------
     *            user stack
     */
    const char ** all_args = (const char **) args;
    int argc = (uintptr_t) all_args[0];
    int _new_argc = argc - 2;
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;
    void* entry_addr = NULL;
    int ret;

    // We have to prepare nexpoline before the 1st syscall
    #ifdef MT
    #ifndef CFICET
    void *tmptrampolone = prepare_temp_trampoline();
    #endif
    #endif

    printf("Trampoline region: %p ~ %p\n", &trampoline_start, &trampoline_end);
    printf("Pid=%ld\n", rawcall(getpid));

    /* fetch environment information from aux vectors */
    const char ** e = envp;
    for (; *e ; e++)
        ;

    elf_auxv_t* auxp = (elf_auxv_t *)(e + 1);
    elf_auxv_t* av;
    for (av = auxp; av->a_type != AT_NULL; av++) {
        switch (av->a_type) {
            case AT_ENTRY:
                entry_addr = (void*)av->a_un.a_val;
                break;
            case AT_RANDOM:
                saved_dl_random = (void *) av->a_un.a_val;
                break;
            case AT_SYSINFO_EHDR:
                sysinfo = av->a_un.a_val;
        }
    }

    void* base_addr = (void*)((uintptr_t)entry_addr - (uintptr_t)&shim_start);
    const char* loader_name   = (argv++)[0];
    const char* libc_location = (argv++)[0];

    const char* errstring = NULL;

    
    if (!loader_name) {
        errstring = "Something wrong with the command-line?";
        goto init_fail;
    }

    if (!libc_location) {
        errstring = "Need to specify the system library C location";
        goto init_fail;
    }
    
    if (argc < 3) {
        rawcall(exit_group, 0);
    }

    if (libc_location[0] != '/') {
        if (rawcall(getcwd, resolved_libc_location, 8190)) {
            // abs = cwd + libc_location
            int n_libc = strlen(libc_location);
            int n_abs = strlen(resolved_libc_location);
            resolved_libc_location[n_abs++] = '/';
            resolved_libc_location[n_abs] = 0;
            for (int i = 0, pi = 0; i <= n_libc; i++) {
                if (libc_location[i] == '/' || libc_location[i] == 0) {
                    // pi..i-1
                    if (pi != i) {
                        int n_sub = i - pi;
                        if (!(n_sub == 1 && libc_location[pi] == '.')) {
                            if (n_sub == 2 && libc_location[pi] == '.' && libc_location[pi + 1] == '.') {
                                // roll
                                if (n_abs > 1) {
                                    n_abs--;
                                    while (n_abs > 1 && resolved_libc_location[n_abs - 1] != '/') n_abs--;
                                    resolved_libc_location[n_abs] = 0;
                                }
                            } else {
                                // push
                                for (int j = pi; j < i && n_abs < 8192; j++){
                                    resolved_libc_location[n_abs++] = libc_location[j];
                                }
                                if (n_abs >= 8192)
                                    break;
                                if (libc_location[i] != 0)
                                    resolved_libc_location[n_abs++] = '/';
                                if (n_abs >= 8192)
                                    break;
                            }
                        }
                    }
                    pi = i + 1;
                }
            }
            if (n_abs >= 8192) {
                goto init_fail;
                errstring = "lib location too long";
            }
            resolved_libc_location[n_abs] = 0;
            abs_libc_location = resolved_libc_location;
            printf("real_libc = %s\n", resolved_libc_location);
        }
    } else {
        int n_libc = strlen(libc_location);
        memcpy(resolved_libc_location, libc_location, n_libc);
        resolved_libc_location[n_libc] = 0;
        abs_libc_location = resolved_libc_location;
    }

    int noseccomp = 0;
    char *buf_s, *buf_c;
    void sys_loadexecbuff(char*, char*);
    if (memcmp(argv[0], "-exec", 5) == 0) {
        noseccomp = 1;
        argv++;
        buf_s = (char *)*argv++;
        buf_c = (char *)*argv++;
        _new_argc -= 3;
        sys_loadexecbuff(buf_s, buf_c);
    }
    if (memcmp(argv[0], "-noseccomp", 10) == 0) {
        _new_argc -= 1;
        noseccomp = 1;
        argv++;
    }
    int exec_fd = 0;
    if (memcmp(argv[0], "-fd", 3) == 0) {
        argv++;
        printf("fd= %s\n", *argv);
        exec_fd = strtol(*argv++, NULL, 16);
        _new_argc -= 2;
    }

    pkey_alloc(0, 0); // 1
    pkey_alloc(0, 0); // 2

    for (int i = 3; i < 16; i++)
        pkey_alloc(0, 0); // 3...15

    ret = load_link_map(&shim_map, -1, base_addr, true);
    if (ret < 0) {
        errstring = "Failed to recognize the binary of the library OS";
        goto init_fail;
    }

    create_stack(&shim_stack0);
    
    if((ret = init_trampoline(&trampoline_start)) < 0) {
        errstring = "Failed to initiate the trampoline";
	    goto init_fail;
    }
    start_log_trap(argv[0]);
    ret = load_executable(argv[0], exec_fd, libc_location);
    if (ret < 0) {
        errstring = "Unable to load the executable or the interpreter";
        goto init_fail;
    }

    init_debugger((Elf64_Addr)base_addr, loader_name, shim_map.dyn_addr,
                  (Elf64_Addr)exec_map.base_addr, argv[0], exec_map.dyn_addr,
                  (Elf64_Addr)interp_map.base_addr, interp_name, interp_map.dyn_addr);

    if (shebang) {
        if (exec_fd) {
            printf("shebang + fd is not possible\n");
            return -3;
        }
        // prepand the real exec to shebang args
        argv --;
        _new_argc++;
    }

    if((ret = prepare_isolated_stack(argv, envp, auxp, _new_argc)) < 0) {
        errstring = "Failed to copy argv, envp, auxp to isolated stack";
        goto init_fail;
    }
    
#ifdef QUEEN
    spawn_queen();
#endif
#ifdef MT

    #ifndef CFICET
    rawcall(munmap, tmptrampolone, PAGESIZE);
    #endif

    for (int i = 3 ; i < 4096 ; i++) {
        fdsem[i] = INT_MIN;
    }
#endif
    intravirt_initialized = true;
    shim_sig_init();


    // map a test page that a test case try to access this page.
    char* mem = (char*)rawcall(mmap, 0x7FABADBD0000LL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (mem != (char*)0x7FABADBD0000LL) {
        errstring = "create flag failed!\n";
        goto init_fail;
    }
    rawcall(mprotect_pkey, 4, mem, 4096, PROT_READ | PROT_WRITE, IV_NORMAL);
    memcpy(mem, "This is my secret!\n", 19);
    mem[19] = 0;
    map_set(map_addr(mem, mem+4095), TRUSTED_MEM);

    /* Initiate the seccomp filter */
    if (!noseccomp) {
#ifdef RANDOM
    if((ret = install_seccomp_filter((void*)RTRAMPOLINE_START, (void*)RTRAMPOLINE_END)) < 0) {
#else
#ifdef FILTERTP
        if((ret = install_seccomp_filter(get_tls()->trampoline, get_tls()->trampoline + 4096)) < 0) {
#else
        extern char code_start;
        extern char code_end;
        if((ret = install_seccomp_filter(&code_start, &code_end)) < 0) {
#endif
#endif
	        errstring = "Seccomp installation failed";
	        goto init_fail;
        }
    }

    start_execute();

    /* Should never reach here */
    return;

init_fail:
    printf("%s\n", errstring);
    printf("USAGE: %s libc_location executable args ...\n", loader_name);
    rawcall(exit_group, -1);
}
