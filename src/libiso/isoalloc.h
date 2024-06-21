#ifndef ISONAME
#error "Define ISO Name as your namespace"
#endif
#if __INCLUDE_LEVEL__ != 1
#error "#include <iso.h> directly in your c file"
#endif

#ifndef CONCAT3
#define _CONCAT2(x,y) x##y
#define CONCAT2(x,y) _CONCAT2(x,y)
#define _CONCAT3(x,y,z) x##y##z
#define CONCAT3(x,y,z) _CONCAT3(x,y,z)
#define _CONCAT4(x,y,z,q) x##y##z##q
#define CONCAT4(x,y,z,q) _CONCAT4(x,y,z,q)
#endif

#define _GNU_SOURCE
#include <sys/mman.h>
#include <linux/mman.h>

typedef enum {
    SZ_16, SZ_32, SZ_128, SZ_256, SZ_512, SZ_1024, SZ_2048, SZ_4096, SZ_END
} pool_size_t;

static ISO_DATA size_t pool_to_size[] = {16,32,128,256,512,1024,2048,4096};

typedef struct mm_block {
    struct mm_block *next;
} mm_block_t;

typedef struct mm_pool {
    mm_block_t* pools[SZ_END];
    int _locks[SZ_END];
} mm_pool_t;

typedef struct mm_block_link {
    mm_block_t *begin, *end;
} mm_block_link_t;

typedef struct mm_map_info {
    pool_size_t sz;
} mm_map_info_t;

static mm_pool_t ISO_DATA iso_pool = {.pools={0}, ._locks={0}};
extern int CONCAT2(iv_domain_, ISONAME);

static mm_block_link_t ISO_CODE build_link(char* mem, pool_size_t sz) {
    const int len = 1024 * 1024; // get at most 1 mb
    const size_t unit = pool_to_size[sz];
    mm_block_link_t lnk;
    mm_map_info_t* map = mem;
    map->sz = sz;

    lnk.begin = mem + unit;
    lnk.end = mem + len - unit;
    for (char* m = lnk.begin; m < lnk.end; m += unit) {
        mm_block_t *blk = m;
        blk->next = (mm_block_t *)(m + unit);
    }
    lnk.end->next = 0;
    return lnk;
}

static mm_block_link_t ISO_CODE iso_mmap(pool_size_t sz) {
    mm_block_link_t null = {0,0};
    const int len = 1024 * 1024 * 2; // map 2mb to get 1 mb aligned memory
    char* addr = mmap(0, len, PROT_READ | PROT_WRITE, MAP_HUGE_2MB | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    /* printf("addr = %p ~ %p, aligned = %p ~ %p\n", 
        addr, addr + len, 
        ((unsigned long)addr + 0xFFFFF) & ~0xFFFFF,
        len / 2 + ((unsigned long)addr + 0xFFFFF) & ~0xFFFFF
    ); */
    // TODO: free unused pages
    
    if (addr) {
        if (pkey_mprotect(addr, len, PROT_READ | PROT_WRITE, CONCAT2(iv_domain_, ISONAME)) == 0) {
            addr = (char*)(((unsigned long)addr + 0xFFFFF) & ~0xFFFFF);
            return build_link(addr, sz);
        } else {
            munmap(addr, len);
            return null; // priv
        }
    } else {
        return null; // OOM
    }
}

static pool_size_t ISO_CODE get_sz(size_t sz) {
    if (sz <= 16)
        return SZ_16;
    if (sz <= 32)
        return SZ_32;
    if (sz <= 128)
        return SZ_128;
    if (sz <= 256)
        return SZ_256;
    if (sz <= 512)
        return SZ_512;
    if (sz <= 1024)
        return SZ_1024;
    if (sz <= 2048)
        return SZ_2048;
    if (sz <= 4096)
        return SZ_4096;
}

static inline void ISO_CODE iv_lock(int* spinlock) {
    int cmp = 0;
    while (!__atomic_compare_exchange_n(spinlock, &cmp, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { cmp = 0; }
}

static inline void ISO_CODE iv_unlock(int* spinlock) {
    __atomic_store_n(spinlock, 0, __ATOMIC_SEQ_CST);
}

static mm_block_t* ISO_CODE iso_get(pool_size_t sz){
    iv_lock(&iso_pool._locks[sz]);
    while (1) {
        if (iso_pool.pools[sz]) {
            mm_block_t *blk = iso_pool.pools[sz];
            // printf("iso_get(%d) = %p, next = %p\n", sz, blk, blk->next);
            iso_pool.pools[sz] = iso_pool.pools[sz]->next;
            iv_unlock(&iso_pool._locks[sz]);
            return blk;
        } else {
            mm_block_link_t lnk = iso_mmap(sz);
            iso_pool.pools[sz] = lnk.begin;
        }
    }
    iv_unlock(&iso_pool._locks[sz]);
    return 0;
}

static void* ISO_CODE iso_mem(size_t sz) {
    if (sz > 4096)
        return 0;
    mm_block_t* blk = iso_get(get_sz(sz));
    for (int i = 0; i < sz; i++)
        ((char*)blk)[i] = 0;
    return blk;
}

static int ISO_CODE iso_free(void* ptr) {
    // printf("iso_free = %p\n", ptr);
    mm_map_info_t *info = (mm_map_info_t *)((unsigned long)ptr & ~0xFFFFF);
    mm_block_t *blk = ptr;
    pool_size_t sz = info->sz;
    if (sz >= SZ_END || sz < 0)
        return 0;
    int len = pool_to_size[sz];
    for (int i = 0; i < len; i++)
        ((char*)ptr)[i] = 0;
    iv_lock(&iso_pool._locks[sz]);
    blk->next = iso_pool.pools[sz];
    iso_pool.pools[sz] = blk;
    iv_unlock(&iso_pool._locks[sz]);
    return 1;
}