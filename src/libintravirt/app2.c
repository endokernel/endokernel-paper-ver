#include <pkru.h>
#include <erim/mmap/map.h>
#include <shim_trampoline.h>
#include <rawcall.h>
#include <asm-offsets.h>
#include <app2_xcall.h>
#include <link.h>
#include <elf.h>
#include <app.h>

#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <iv_debug.h>

#ifndef __NR_mprotect_pkey
#define __NR_mprotect_pkey 329
#endif

int memcmp(const void* s1, const void* s2, size_t len) ;
int printf (const char  *fmt, ...) __attribute__((format (printf, 1, 2)));
size_t strlen (const char *str);

int startsWith(const char *pre, const char *str) {
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? 0 : memcmp(pre, str, lenpre) == 0;
}

typedef long int Lmid_t;

struct link_map1 {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld; 
    struct link_map1 *l_next, *l_prev;
    struct link_map1 *l_real;
    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[DT_NUM + 0 + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
};

typedef struct __attribute__((packed)) cmp {
    char cmp[1];
    unsigned int N;
} cmp_t;


static char * install_stub(char *_stub, unsigned int fcnt, unsigned long domain_id) {
    int fid = 0;
    unsigned long* stub = _stub;
    unsigned long* app_code = (unsigned long*)((app2_safe_xcall)[domain_id]);
    unsigned long* end = (unsigned long*)((app2_safe_xcall_end)[domain_id]);
    unsigned long* begin = app_code;
    for (unsigned long* _app = begin, *stub = _stub; _app < end; _app+=1, stub+=1) {
        *stub = *_app;
    }
    cmp_t* cmp_code = (cmp_t*) ((unsigned long)_stub + ((unsigned long)(app2_safe_xcall_cmp)[domain_id] - (unsigned long)app_code));
    cmp_code->N = fcnt - 1;
    return _stub;
}

#ifndef PAGESIZE
#define PAGESIZE 4096
#define ALIGNED(addr)   (!(((uintptr_t)(addr)) & ~(PAGESIZE - 1)))
#define ALIGN_UP(addr)      \
    ((__typeof__(addr)) ((((uintptr_t)(addr)) + PAGESIZE - 1) & ~(PAGESIZE - 1)))
#define ALIGN_DOWN(addr)    \
    ((__typeof__(addr)) (((uintptr_t)(addr)) & ~(PAGESIZE - 1)))
#endif

typedef struct __attribute__((packed)) {
    char endbr64[4];
    struct __attribute__((packed)) {
        char b8;
        unsigned int id;
    } mov_id_eax;
    struct __attribute__((packed)) {
        char e9;
        unsigned int offset;
    }   jmp;
} xcall_stub_t;

const xcall_stub_t default_stub = {
    .endbr64 = {0xf3, 0x0f, 0x1e, 0xfa},
    .mov_id_eax = {0xb8, 0},
    .jmp = {0xe9, 0},
};

#define D_PTR(map, i) ((map)->i->d_un.d_ptr)

void* oldpage = 0;
void final_page(){
    if (oldpage) {
        rawcall(mprotect, oldpage, 4096, PROT_READ);
        oldpage = 0;
    }
}
void final_page_e(){
    if (oldpage) {
        rawcall(mprotect, oldpage, 4096, PROT_READ | PROT_EXEC);
        oldpage = 0;
    }
}
void prepare_page(void* addr) {
    void* newpage = (ALIGN_DOWN(addr));
    if (newpage == oldpage)
        return;
    final_page();
    rawcall(mprotect, newpage, 4096, PROT_READ | PROT_WRITE);
    oldpage = newpage;
}
void prepare_page_e(void* addr) {
    void* newpage = (ALIGN_DOWN(addr));
    if (newpage == oldpage)
        return;
    final_page_e();
    rawcall(mprotect, newpage, 4096, PROT_READ | PROT_WRITE);
    oldpage = newpage;
}

int contains(char* link, char*all[]) {
    for (int i = 0; all[i] != NULL; i++) {
        if (link == all[i])
            return 1;
    }
    return 0;
}

typedef struct noinstall {
    void *start, *end;
} noinstall_t;

int findnoinstall(struct link_map1* link,  noinstall_t* result) {
    char* elf = link->l_addr;
    char* strtab = D_PTR(link, l_info[DT_STRTAB]);
    Elf64_Sym* symtab = D_PTR(link, l_info[DT_SYMTAB]);
    const ElfW(Sym) *symtabend;
    
    if (link->l_info[DT_HASH] != NULL)
	    symtabend = (symtab
		     + ((Elf_Symndx *) D_PTR (link, l_info[DT_HASH]))[1]);
    else
        symtabend = (const ElfW(Sym) *) strtab;
    if (!symtab)
        return 0;
    int found = 0;
    Elf64_Sym* s = symtab;
    for (int i = 0; s != symtabend && (found != 2); i++, s++){
        unsigned char info = (s->st_info);
        int bind = ELF64_ST_BIND(info);
        int type = ELF64_ST_TYPE(info);
        if (s->st_value && bind == STB_GLOBAL && type == STT_NOTYPE) {
            char *name = strtab + s->st_name;
            int nanme = strlen(name);
            
            if (nanme == 19) {
                if (memcmp(name, "__stop_iv_noinstall", 19) == 0) {
                    result->end = elf + s->st_value;
                    found++;
                }
            }
            if (nanme == 20) {
                if (memcmp(name, "__start_iv_noinstall", 20) == 0) {
                    result->start = elf + s->st_value;
                    found++;
                }
            }
        }
    }
    if (found == 2)
        return 1;
    return 0;

}

int strequ(char*a, char*b) {
    int na = strlen(a);
    int nb = strlen(b);
    if (na != nb)
        return 0;
    return memcmp(a,b,na) == 0;
}
/*
const char* blacklist[] = {
    "SSL_CTX_set_alpn_select_cb",
    "SSL_CTX_callback_ctrl", 
    "SSL_CTX_set_next_protos_advertised_cb",
    "SSL_CTX_set_cert_cb",
};

int cannotskip(char* na) {
    for (int i = 0; i < sizeof(blacklist) / sizeof(char*); i++) {
        if (strequ(na, blacklist[i]))
            return 1;
    }
    return 0;
}
*/
int install_app2_single(int domain_id, char* _link, char* all[], int* domain_id_addr) {
    struct link_map1* link = _link;
    char* elf = link->l_addr;
    const Elf64_Ehdr* ehdr = elf;
    const Elf64_Phdr* phdr = elf + ehdr->e_phoff;
    char* vend = 0;
    char* vstart = -1UL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        char* end = ALIGN_UP(phdr[i].p_vaddr + phdr[i].p_memsz);
        char st = ALIGN_DOWN(phdr[i].p_vaddr);
        if (end > vend)
            vend = end;
        if (st < vstart)
            vstart = st;
    }

    unsigned long maplen = vend - vstart;
    char* mapend = elf + maplen;

    rawcall(mprotect_pkey, elf, maplen, PROT_READ | PROT_WRITE |PROT_EXEC, IV_CONF);

    char* strtab = D_PTR(link, l_info[DT_STRTAB]);

    Elf64_Sym* symtab = D_PTR(link, l_info[DT_SYMTAB]);

    printf("Install App for %s, symtab: %p ~ %p ~ %p\n", link->l_name, elf, symtab, mapend);

    const ElfW(Sym) *symtabend;
    
    if (link->l_info[DT_HASH] != NULL)
	    symtabend = (symtab
		     + ((Elf_Symndx *) D_PTR (link, l_info[DT_HASH]))[1]);
    else
        symtabend = (const ElfW(Sym) *) strtab;

    if (!symtab)
        return 0;
    
    int nFunc = 0;

    Elf64_Sym* s = symtab;
    
    for (int i = 0; s != symtabend; i++, s++){
        unsigned char info = (s->st_info);
        int bind = ELF64_ST_BIND(info);
        int type = ELF64_ST_TYPE(info);
        if (s->st_value && bind == STB_GLOBAL && type == STT_FUNC) {
            // function
            //printf("Func %s, Addr: %p\n", strtab + s->st_name, s->st_value);
            nFunc ++;
        }
    }

    if (nFunc > 0xFFFF) {
        return 0; // too many functions
    }

    unsigned long sz_stub = sizeof(xcall_stub_t) * nFunc;
    unsigned long sz_stub_align = ALIGN_UP(sz_stub);
    unsigned long sz_gate = 4096;
    unsigned long sz_gate_data = ALIGN_UP(nFunc * 8);
    unsigned long sz_gate_align = (sz_gate) + sz_gate_data;
    unsigned long sz_new_page = sz_stub_align + sz_gate_align;
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS        0x20
#endif
    char* sys = rawcall(mmap, ALIGN_UP(mapend), sz_new_page, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    char* xgate_copy = sys + sz_stub_align;
    //char* xgate_nocopy = sys + sz_stub_align + 2048;
    xcall_stub_t *stub0 = sys;
    xcall_stub_t *stub = stub0;
    for (int i = 0; i < nFunc; i++) {
        void* memcpy(void* dstpp, const void* srcpp, size_t len);
        memcpy(stub, &default_stub, sizeof(xcall_stub_t));
        stub->jmp.offset = (unsigned long)xgate_copy - (unsigned long)(stub + 1);
        stub->mov_id_eax.id = i;
        //printf("%p\n", stub);
        stub++;
    }
    
    install_stub(xgate_copy, nFunc, domain_id);
    unsigned long* func_addr = xgate_copy + 4096;
    int tt = 0;
    s = symtab;
    int nSyms = 0;
    int nSkips = 0;
    for (int i = 0; s != symtabend; s++){
        unsigned char info = (s->st_info);
        int bind = ELF64_ST_BIND(info);
        int type = ELF64_ST_TYPE(info);

        struct link_map1* head = link;
        while (head->l_prev) head = head->l_prev;
        if (s->st_value && bind == STB_GLOBAL && type == STT_FUNC) {
            // function
            /*
            if (!cannotskip(strtab + s->st_name))
                continue;
            */
            unsigned long oldaddr = s->st_value + (unsigned long)elf;
            unsigned long newaddr = ((unsigned long)(stub0 + i));
            func_addr[i] = oldaddr;
            s->st_value = newaddr - (unsigned long)elf; // hook function
            int is_target = 0;
            //if (i == 95)
            //    printf("HookFunc %s, Addr: %p --> %p|%p\n", strtab + s->st_name, s->st_value, func_addr[i], s);
            // relocate
            struct link_map1* cur = head;
            struct {
                Elf64_Rela * rela;
                ssize_t relasz;
            } relas[2];
            int nRelas = 0;
            
            if (cur->l_info[DT_JMPREL]) {
                relas[nRelas].rela = D_PTR(cur, l_info[DT_JMPREL]);
                relas[nRelas++].relasz = D_PTR(cur, l_info[DT_PLTRELSZ]);
            }
            
            if (cur->l_info[DT_RELA]) {
                relas[nRelas].rela = D_PTR(cur, l_info[DT_RELA]);
                relas[nRelas++].relasz = D_PTR(cur, l_info[DT_RELASZ]);
            }
            
            for (;cur != NULL; cur = cur->l_next) {
                if (contains(cur, all))
                    continue;
                noinstall_t nos;
                int hasNoinstall = findnoinstall(cur, &nos);
                if (hasNoinstall) {
                    //printf("No install range %p ~ %p\n", nos.start, nos.end);
                }
                for (int rr = 0; rr < nRelas; rr++) {
                    Elf64_Rela * rela = relas[rr].rela;
                    ssize_t relasz = relas[rr].relasz;
                    if (rela) {
                        int n = relasz / sizeof(Elf64_Rela);
                        for (int j = 0; j < n; j++) {
                            if (ELF64_R_TYPE(rela[j].r_info) == R_X86_64_JUMP_SLOT || ELF64_R_TYPE(rela[j].r_info) == R_X86_64_GLOB_DAT) {
                                unsigned long* addr = rela[j].r_offset + cur->l_addr;
                                nSyms+=(*addr == oldaddr);
                                if (hasNoinstall && (addr >= nos.start) && (addr < nos.end)) {
                                    nSkips ++;
                                    continue;
                                }
                                if (*addr == oldaddr) {
                                    //if (is_target) {
                                        Elf64_Sym* sym = D_PTR(cur, l_info[DT_SYMTAB]);
                                        char* str = sym[ELF64_R_SYM(rela[j].r_info)].st_name + D_PTR(cur, l_info[DT_STRTAB]);
                                        // printf("Lib[%s].%s(%p) -> %p\n", cur->l_name, str, oldaddr, newaddr); 
                                    //}
                                    prepare_page(addr);
                                    *addr = newaddr;
                                }
                            } //else if (is_target && (rela == 0x7ffff7baaa98ul)) printf("%d\n", ELF64_R_TYPE(rela[j].r_info));
                        }
                    }
                }
            }
            i++;
        }
    }
    final_page();
    printf("%d symbols found, %d skipped, %d replaced\n", nSyms, nSkips, nSyms - nSkips);
    
    // TODO: mapping...
    if (domain_id_addr)
        *domain_id_addr = domain_id;
    IV_DBG("domain_id %d", domain_id);

    // TODO: update mmap
    rawcall(mprotect_pkey, sys, sz_stub_align + 0x1000, PROT_READ | PROT_EXEC, IV_CONF);
    rawcall(mprotect_pkey, sys + sz_stub_align + 0x1000, (unsigned long)(sz_gate_data), PROT_READ, IV_NORMAL);
    rawcall(mprotect_pkey, elf, maplen, PROT_READ | PROT_WRITE |PROT_EXEC, IV_USER);

    /* Currently, full protection is not supported, because
     * 1) Glibc has to read & write the library memory for dynamic symbol lookup.
     * 2) Glibc exists in untrusted domain, which does not has privilege to the
     * safebox library domain
     * Therefore, symbol lookup leads to crash on execution.
     * TODO: FIXME
     */
//#define PROTECT_DOMAIN
#ifdef PROTECT_DOAMIN
    for (int i = 0; i < ehdr->e_phnum; i++) { 
        char* end = ALIGN_UP(phdr[i].p_vaddr + phdr[i].p_memsz) - (unsigned long)vstart + elf;
        char* st = ALIGN_DOWN(phdr[i].p_vaddr) - (unsigned long)vstart + elf;
        Elf64_Phdr* ph = &phdr[i];
        if (ph->p_type == PT_LOAD) {
            int prot = 0;
            if (ph->p_flags & PF_R)
                prot |= PROT_READ;
            if (ph->p_flags & PF_W)
                prot |= PROT_WRITE;
            if (ph->p_flags & PF_X) {
                prot |= PROT_EXEC;
                prot &= ~PROT_WRITE; // X^W
            }
            rawcall(mprotect_pkey, st, (unsigned long)end - (unsigned long)st, prot|PROT_READ, domain_id);
            map_set(map_addr(st, end - 1), map_norm(prot|PROT_READ, 0)|APP(domain_id));
            IV_DBG("added %p to %p to domain %d", st, end, domain_id);
        }
    }
#endif


    return 1;
}

typedef struct friend_hook {
    struct link_map1* libaddr;
    char* prefix;
    char* libname;
    char* stubname;
} friend_hook_t;

struct func_pair {
    int addend;
    void* trampoline;
    void* real;
    char* name;
} func_temp[256];

int install_app2_friend(int domain_id, friend_hook_t *friend) {
    struct link_map1* link = friend->libaddr;

    char* elf = link->l_addr;
    const Elf64_Ehdr* ehdr = elf;
    const Elf64_Phdr* phdr = elf + ehdr->e_phoff;

    char* strtab = D_PTR(link, l_info[DT_STRTAB]);

    Elf64_Sym* symtab = D_PTR(link, l_info[DT_SYMTAB]);

    printf("Install Friend for %s, symtab: %p ~ %p\n", link->l_name, elf, symtab);

    const ElfW(Sym) *symtabend;
    
    if (link->l_info[DT_HASH] != NULL)
	    symtabend = (symtab
		     + ((Elf_Symndx *) D_PTR (link, l_info[DT_HASH]))[1]);
    else
        symtabend = (const ElfW(Sym) *) strtab;

    if (!symtab)
        return 0;
    
    int nFunc = 0;

    Elf64_Sym* s = symtab;
    void* static_stub;
    int stubname_len = strlen(friend->stubname);
    
    for (int i = 0; s != symtabend; i++, s++) {
        unsigned char info = (s->st_info);
        int bind = ELF64_ST_BIND(info);
        int type = ELF64_ST_TYPE(info);
        if (s->st_value && bind == STB_WEAK && type == STT_FUNC) {
            if (startsWith(friend->prefix, strtab + s->st_name)) {
                func_temp[nFunc].trampoline = s->st_value + (unsigned long)elf;
                func_temp[nFunc].addend = s->st_value;
                func_temp[nFunc].name = strtab + s->st_name;
                nFunc ++;
            }
        } else {
            if (type == STT_FUNC) {
                if (strlen(strtab + s->st_name) == stubname_len) {
                    if (memcmp(strtab + s->st_name, friend->stubname, stubname_len) == 0) {
                        static_stub = s->st_value + (unsigned long)elf;
                        // printf("Found friend stub %s @ %p\n", strtab + s->st_name, static_stub);
                    }
                }
            }
        }
    }

    if (static_stub == 0)
        return 0;    

    if (nFunc > 0xFF) {
        printf("too many funcs\n");
        return 0; // too many functions
    }
    s = symtab;
    int nFound = 0;
    for (int i = 0; s != symtabend; i++, s++) {
        unsigned char info = (s->st_info);
        int bind = ELF64_ST_BIND(info);
        int type = ELF64_ST_TYPE(info);
        if (s->st_value && bind == STB_WEAK && type == STT_FUNC) {
            // find real functions
            char* name0 = strtab + s->st_name;
            int ls = strlen(name0);
            if (ls > 2) {
                if (name0[0] == '_' && name0[1] == '_') {
                    for (int j = 0; j < nFunc; j++) {
                        if (strlen(func_temp[j].name) == ls - 2) {
                            if (memcmp(func_temp[j].name, name0 + 2, ls - 2) == 0) {
                                printf("Found %s matches %s for func id %d\n", name0, func_temp[j].name, j);
                                func_temp[j].real = s->st_value + (unsigned long)elf;
                                nFound++;
                            }
                        }
                    }
                }
            }
        }
    }
    printf("%d/%d Found.\n", nFound, nFunc);
    unsigned long sz_stub = 0;
    unsigned long sz_stub_align = ALIGN_UP(sz_stub);
    unsigned long sz_gate = 4096;
    unsigned long sz_gate_data = ALIGN_UP(nFunc * 8);
    unsigned long sz_gate_align = (sz_gate) + sz_gate_data;
    unsigned long sz_new_page = sz_stub_align + sz_gate_align;
    if (sz_new_page > 8192)
        return 0;
    char* sys = static_stub;
    
    rawcall(mprotect_pkey, sys, 8192, PROT_READ | PROT_WRITE | PROT_EXEC, IV_CONF);

    char* xgate_copy = sys + sz_stub_align;
    //char* xgate_nocopy = sys + sz_stub_align + 2048;
    for (int i = 0; i < nFunc; i++) {
        xcall_stub_t *stub = func_temp[i].trampoline;
        // printf("prepare page @ %p\n", func_temp[i].trampoline);
        prepare_page_e(func_temp[i].trampoline);
        void* memcpy(void* dstpp, const void* srcpp, size_t len);
        memcpy(stub, &default_stub, sizeof(xcall_stub_t));
        stub->jmp.offset = (unsigned long)xgate_copy - (unsigned long)(stub + 1);
        stub->mov_id_eax.id = i;
        //printf("%p\n", stub);
    }
    final_page_e();
    
    install_stub(xgate_copy, nFunc, domain_id);
    unsigned long* func_addr = xgate_copy + 4096;
    for (int i = 0; i < nFunc; i++) {
        func_addr[i] = func_temp[i].real;
    }
    
    IV_DBG("domain_id %d", domain_id);

    // TODO: update mmap
    rawcall(mprotect_pkey, sys, sz_stub_align + 0x1000, PROT_READ | PROT_EXEC, IV_CONF);
    rawcall(mprotect_pkey, sys + sz_stub_align + 0x1000, (unsigned long)(sz_gate_data), PROT_READ, IV_NORMAL);
    //rawcall(mprotect_pkey, elf, maplen, PROT_READ | PROT_WRITE |PROT_EXEC, IV_USER);
}

int install_app2(int domain_id, char* _link[], int* domain_id_addr[]) {
    if (id_allocated[domain_id] || domain_id < 0 || domain_id >= 16)
        return 0; // invalid
    id_box[domain_id] = SAFE;
    id_allocated[domain_id] = 1;
    int i = 0;
    for (i = 0; _link[i]; i++) {
        printf("domain id=%p\n", domain_id_addr[i]);
        install_app2_single(domain_id, _link[i], _link, domain_id_addr[i]);
    }
    /*)
    i++;
    printf("Link[%d] = %p\n", i, (void*)_link[i]);
    for (; _link[i]; i++) {
        //install_app2_friend(domain_id, (friend_hook_t*)_link[i]);
    }
    */
    app_update_tls(domain_id, SAFE);
}
