#include "map.h"
#include <erim.h>
#include <erim_shmem.h>
#include <rawcall.h>
#include <mt.h>

// TODO: We can upgrade to interval tree for better performance 
#define MAXLOCK 64
typedef struct {
    map_block_t *b;
    uintptr_t idx;
} map_slot_t;

static map_block_t start_block_pool[8];
static int n_start_blocks = 0;

static map_block_t *gTail = 0;

int isSand[16];
void sandbox_pkey(int key) {
    isSand[key] = 1;
}

static map_block_t *alloc_block(void){
    void *mem = 0;
    if (n_start_blocks < 8) {
        mem = (void*) (start_block_pool + n_start_blocks++);
    } else {
        mem = (void*)rawcall(mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        rawcall(mprotect_pkey, 4, mem, 4096, PROT_READ | PROT_WRITE, IV_NORMAL);
    }
    map_block_t *b = (map_block_t*)mem;
    b->entries[0].addr.low = (uintptr_t)mem;
    b->entries[0].addr.high = (uintptr_t)mem + 4096 - 1;
    b->prev = gTail;
    gTail = b;
    return b;
}

map_slot_t alloc_slot(void) {
    map_slot_t slot = {0};
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            if (tail->entries[idx].mode == NONE) {
                slot.b = tail; 
                slot.idx = idx;
                return slot;
            }
        }
    }
    // no empty slot;
    map_block_t *new_b = alloc_block();
    slot.b = new_b;
    slot.idx = 1; // 0 this the block itself
    return slot;
}

#define min(a,b) (((a) > (b)) ? (b) : (a))
#define max(a,b) (((a) > (b)) ? (a) : (b))

map_addr_t intersection(map_addr_t a, map_addr_t b) {
    map_addr_t t = {0,0};
    if (b.low > a.high || a.low > b.high) return t;
    t.low = max(a.low, b.low);
    t.high = min(a.high, b.high);
    return t;
}
int printf (const char  *fmt, ...) __attribute__((format (printf, 1, 2)));

void map_clear_unlocked(map_addr_t addr) {
    //printf("map_clean %p ~ %p\n", addr.low, addr.high);
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t e = tail->entries[idx];
            if (e.mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    int hasLeft = overlap.low != e.addr.low;
                    int hasRight = overlap.high != e.addr.high;
                    //printf("clean %p ~ %p from %p ~ %p (%d%d)\n", overlap.low, overlap.high, e.addr.low, e.addr.high, hasLeft, hasRight);
                    tail->entries[idx].mode = NONE;
                    tail->entries[idx].addr.low = 0;
                    tail->entries[idx].addr.high = 0;
                    tail->entries[idx].lock_obj.lock = 0;

                    
                    map_slot_t slot = {0};
                    slot.b = tail;
                    slot.idx = idx; 
                    if (hasLeft) {
                        //printf("add %p ~ %p\n", e.addr.low, overlap.low - 1);
                        slot.b->entries[slot.idx].lock_obj.lock_mode = 2;
                        asm volatile("" ::: "memory");
                        slot.b->entries[slot.idx].addr.low = e.addr.low;
                        slot.b->entries[slot.idx].addr.high = overlap.low - 1;
                        slot.b->entries[slot.idx].mode = e.mode;
                        asm volatile("" ::: "memory");
                        slot.b->entries[slot.idx].lock_obj.lock_mode = 0; // data ready
                        slot.b = 0;
                    }
                    if (hasRight) {
                        if (!slot.b) {
                            slot = alloc_slot();
                        }
                        //printf("add %p ~ %p\n", overlap.high + 1, e.addr.high);
                        slot.b->entries[slot.idx].lock_obj.lock_mode = 2;
                        asm volatile("" ::: "memory");
                        slot.b->entries[slot.idx].addr.low =overlap.high + 1;
                        slot.b->entries[slot.idx].addr.high = e.addr.high;
                        slot.b->entries[slot.idx].mode = e.mode;
                        asm volatile("" ::: "memory");
                        slot.b->entries[slot.idx].lock_obj.lock_mode = 0; // data ready
                        slot.b = 0;
                    }
                }
            }
        }
    }
}

map_mode_t map_get(map_addr_t addr) {
    map_mode_t mode = 0;
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t e = tail->entries[idx];
            if (e.mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    mode |= e.mode;
                    // printf("get %p ~ %p from %p ~ %p (%d)\n", overlap.low, overlap.high, e.addr.low, e.addr.high, e.mode);
                }
            }
        }
    }
    return mode;
}

map_addr_t map_addr(void* a, void* b) {
    map_addr_t t;
    t.low = (uintptr_t)a;
    t.high = (uintptr_t)b;
    return t;
}

map_mode_t map_norm(int prot, int trusted) {
    if (trusted) 
        return TRUSTED_MEM;
    if ((!!(prot & PROT_EXEC)) && (!!(prot & PROT_WRITE))) {
        // TODO: error!
    }
    map_mode_t m = NONE;
    if (prot & PROT_READ) {
        m |= READABLE;
    }
    if (prot & PROT_WRITE) {
        m |= WRITABLE;
    }
    if (prot & PROT_EXEC) {
        m |= EXECUTABLE;
    }
    return m;
}

int map_prot(map_mode_t mode) {
    int prot = 0;
    if (mode & READABLE)
        prot |= PROT_READ;
    if (mode & WRITABLE)
        prot |= PROT_WRITE;
    if (mode & EXECUTABLE)
        prot |= PROT_EXEC;
    return prot;
}

int read_lock_entry(volatile map_entry_t* e, int n) {
    // atomic operation
    while (1) {
        map_lock_t old = e->lock_obj;
        if (old.lock_mode == 0) {
            map_lock_t new = old;
            if (new.lock_count == 0x7fffffff) {
                return -1;
            }
            new.lock_count ++;
            if (__sync_bool_compare_and_swap(&e->lock_obj.lock, old.lock, new.lock)) {
                get_tls()->self->map_locked[n] = e;
                return 1;
            }
        } else {
            return -1;
        }
    }
    return -1;
}

int read_lock_unlock(map_entry_t* e) {
    // atomic operation
    while (1) {
        map_lock_t old = e->lock_obj;
        if (old.lock_mode != 0 || old.lock_count <= 0) {
            return -2;
        }
        map_lock_t new = old;
        new.lock_count --;
        if (__sync_bool_compare_and_swap(&e->lock_obj.lock, old.lock, new.lock)) {
            return 1;
        }
    }
    return -1;
}

int map_lock_read(map_addr_t addr) {
    int n = get_tls()->self->locked_count;
    int old_n = n;
    void* locked_obj = &(get_tls()->self->map_locked);

    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t e = tail->entries[idx];
            if (e.mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    // try lock the address
                    if (n >= MAXLOCK) {
                        goto failed;
                    }
                    if (read_lock_entry(&e, n) != 1) {
                        goto failed;
                    } else {
                        n++;
                    }
                }
            }
        }
    }
    get_tls()->self->locked_count = n;
    return 1;
failed:
    for (int i = old_n; i < n; i++) {
        map_entry_t* e = get_tls()->self->map_locked[i];
        read_lock_unlock(e);
    }
    return 0;
}

int map_unlock_read_all() {
    int n = get_tls()->self->locked_count;
    for (int i = 0; i < n; i++) {
        map_entry_t* e = get_tls()->self->map_locked[i];
        if (read_lock_unlock(e) != 0) {
            return -1;
        }
        get_tls()->self->map_locked[i] = 0;
    }
    get_tls()->self->locked_count = 0;
    return 0;
}

int write_lock_entry(volatile map_entry_t* e) {
    // atomic operation
    while (1) {
        map_lock_t old = e->lock_obj;
        if (old.lock_mode == 0 && old.lock_count == 0) {
            map_lock_t new = old;
            new.lock_mode = 2;
            if (__sync_bool_compare_and_swap(&e->lock_obj.lock, old.lock, new.lock)) {
                return 1;
            }
        } else {
            return -1;
        }
    }
    return -1;
}

int map_lock_write(map_addr_t addr) {
    map_entry_t* locked[MAXLOCK];
    int n = 0;
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t e = tail->entries[idx];
            if (e.mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    if (n >= MAXLOCK) {
                        goto failed;
                    }
                    if (write_lock_entry(&e) != 1) {
                        goto failed;
                    } else {
                        locked[n++] = &e;
                    }
                }
            }
        }
    }
    return 1;
failed:
    for (int i = 0; i < n; i++) {
        map_entry_t* e = locked[i];
        e->lock_obj.lock = 0;
    }
    return 0;
}

void map_clear(map_addr_t addr) {
    map_lock_write(addr);
    map_clear_unlocked(addr);
    // no need for unlock
}

void map_set(map_addr_t addr, map_mode_t mode) {
    map_clear(addr); // remove this address (if exists)
    map_slot_t slot = alloc_slot(); 
    //printf("map_set %p ~ %p, %d\n", addr.low, addr.high, mode);
    map_block_t* block = slot.b;
    uintptr_t idx = slot.idx;
    block->entries[idx].lock_obj.lock = 0;
    block->entries[idx].addr = addr;
    block->entries[idx].mode = mode;
}

#ifdef STRICT
int map_check(map_addr_t addr, map_mode_t rwe) {
    unsigned int current_pkru = get_tls()->current_pkru;
    size_t hit = 0;
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t e = tail->entries[idx];
            if (e.mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    if ((e.mode & TRUSTED_MEM) || (e.mode == NONE))
                        return 0; // cannot do trusted mem
                    unsigned int acc = 7;
                    int pk = PKEY(e.mode);
                    if (pk && !isSand[pk]) {
                        int key = 3 & PKEY_KEY(current_pkru, pk);
                        if (key == 0)
                            return 0;
                        acc = (key) | 4;
                    }
                    int _rwe = e.mode & acc; // rw
                    if ((_rwe & rwe) != rwe) 
                        return 0;
                    hit += overlap.high - overlap.low + 1;
                }
            }
        }
    }
    if (rwe == 0)
        return 1;
    if (hit != (addr.high - addr.low + 1)) {
        return 0;
        //asm("int3");
    }
    return 1; //hit == (addr.high - addr.low + 1); //1; // succ
}
#else
int map_check_lock(map_addr_t addr, map_mode_t rwe) {
    int n = get_tls()->self->locked_count;
    int old_n = n;
    unsigned int current_pkru = get_tls()->current_pkru;
    for (map_block_t* tail = gTail; tail; tail = tail->prev) {
        for (uintptr_t idx = 0; idx < max_entry; idx++) {
            map_entry_t *e = tail->entries + idx;
            if (e->mode != NONE) {
                map_addr_t overlap = intersection(addr, tail->entries[idx].addr);
                if (overlap.high != 0 && overlap.low != 0) {
                    if ((e->mode & TRUSTED_MEM) || (e->mode == NONE)) {
                        goto failed;
                    }
                    if (n == MAXLOCK)
                        goto failed;
                    if (read_lock_entry(e, n) == 1) {
                        n++;
                    } else {
                        printf("lock failed\n");
                        goto failed;
                    }
                    if ((e->mode & TRUSTED_MEM) || (e->mode == NONE)) {
                        goto failed;
                    }
                    unsigned int acc = 7;
                    int pk = PKEY(e->mode);
                    if (pk && !isSand[pk]) {
                        int key = 3 & PKEY_KEY(current_pkru, pk);
                        if (key == 0)
                            goto failed;
                            //return 0;
                        acc = (key) | 4;
                    }
                    int _rwe = e->mode & acc; // rw
                    if ((_rwe & rwe) != rwe)  {
                        goto failed;
                    }
                }
            }
        }
    }
    get_tls()->self->locked_count = n;
    if (rwe == 0)
        return 1;
    return 1; // succ
failed:
    for (int i = old_n; i < n; i++) {
        map_entry_t* e = get_tls()->self->map_locked[i];
        read_lock_unlock(e);
        get_tls()->self->map_locked[i] = 0;
    }
    return 0;
}

#endif