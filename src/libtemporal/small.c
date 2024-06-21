#include <small.h>

#define _GNU_SOURCE
#include <sys/mman.h>

#define ISO_DATA __attribute__((section("iv_data_temporal")))
#define ISO_CODE __attribute__((section("iv_code_temporal")))

struct tblock {
    struct tblock* next;
};

struct tpool_s {
    size_t sz;
    size_t page;
    struct tblock* ptr;
};

static tpool_t ISO_DATA small_pools[2];
static int npool = 0;

tpool_t* ISO_CODE private_pool(int n, size_t sz, size_t page) {
    tpool_t* p = small_pools + n;
    p->sz = sz;
    p->ptr = 0;
    p->page = page;
}

#define PKEY_TEMPMAN 14
// pkey14 = temp manage data

static struct tblock * ISO_CODE private_map(size_t sz, size_t page) {
    struct tblock *m = (struct tblock *)mmap(0, page * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    int ret = pkey_mprotect(m, page * 4096, PROT_READ | PROT_WRITE, PKEY_TEMPMAN); 
    if (ret != 0)
    printf("pkey_mprotect ret: %d\n", ret);
    struct tblock *head = m;
    int nObj = (page * 4096) / sz;
    for (int i = 0; i < nObj; i++) {
        if (i + 1 == nObj) {
            m->next = 0;
        } else {
            m->next = m ++;
        }
    }
    return head;
}

void* private_talloc(int n) {
    tpool_t* p = small_pools + n;
    if (!p->ptr) {
        p->ptr = private_map(p->sz, p->page);
    }

    void *m = p->ptr;
    p->ptr = p->ptr->next;
    return m;
}

void* private_tcalloc(int n) {
    tpool_t* p = small_pools + n;
    char *m = private_talloc(n);
    for (int i = 0; i < p->sz; i++)
        m[i] = 0;
    return m;
}

void private_tfree(int n, void* ptr) {
    tpool_t* p = small_pools + n;
    struct tblock *d = (struct tblock *)ptr;
    d->next = p->ptr;
    p->ptr = d;
}
