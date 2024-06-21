#ifndef _MAP_H_
#define _MAP_H_

#include <stdint.h>

typedef enum {
    NONE = 0, // invalid
    READABLE = 1,
    WRITABLE = 2, EXECUTABLE = 4, RETIRED = 8, // ISOLATED
    TRUSTED_MEM = 16, // CANNOT MAP
} map_mode_t;

#define MODE(x) (x & 0x1F)
#define PKEY(x) ((x >> 16) & 0xF)
#define APP(x) (((x) & 0xf) << 16)
// [low, high]
typedef struct {
    void* low, *high;
} map_addr_t;
typedef union {
        struct {
            int lock_mode; // 0: none,  2: write using
            int lock_count; // counts for read lock
        };
        uint64_t lock;
} map_lock_t;
typedef struct {
    map_addr_t addr;
    // -- rw lock -- //
    map_lock_t lock_obj;
    map_mode_t mode;
} map_entry_t;


#define max_entry ((4096 - sizeof(void*)) / sizeof(map_entry_t))
typedef struct mnode {
    map_entry_t entries[max_entry];
    struct mnode* prev;
} map_block_t;

// NEED global MEMLOCK
void map_set(map_addr_t addr, map_mode_t mode);
// NEED global MEMLOCK
void map_clear(map_addr_t addr); 
// can be safely used if global MEMLCOCK is held or read lock is held
map_mode_t map_get(map_addr_t addr); // check the map type of addr

map_addr_t map_addr(void* a, void* b);
map_mode_t map_norm(int prot, int trusted);
int map_prot(map_mode_t mode);

// used internally when map_check
int map_lock_read(map_addr_t addr); // 0 success, -1 fail
// unlock read all lock in current thread
int map_unlock_read_all();

int map_check_lock(map_addr_t addr, map_mode_t rw);
void sandbox_pkey(int key);

#endif 