/*
temporal_call cost vs. # mem allocated (0~31)
------------
vs xcall vs normal call vs getppid() system call vs system call in temporal with policy installed (no policy)
------------
read, write with and without system call policy vs. no temporal at all
------------
mmap, gettimeofday, getppid, lstat with and without policy installed vs no temporal at att
------------
temporal_create, temporal_alloc, temporal_free, temporal_destroy temporalfetch* cost
*/

// temporal_call cost vs. # mem allocated (0~31)
#include "benchmark.h"

#ifdef HAS_TEMPORAL
#include <temporal.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syscall.h>

#define N 100000ULL

void *mems[N];

#ifdef HAS_TEMPORAL
int temporal_call_cost_vs_alloc_init(task_t* t){
    int n = t->n_cur;
    for (int i = 0; i < n; i++) {
        mems[i] = temporal_alloc(t->tid, 4096 * 16);
    }
}

int temporal_call_cost_vs_alloc_done(task_t* t) {
    int n = t->n_cur;
    for (int i = 0; i < n; i++) {
        temporal_free(t->tid, mems[i]);
    }
}

REG_TASK_CALL(temporal_call_cost_vs_alloc, 17, 10000, temporal_call_cost_vs_alloc_init, temporal_call_cost_vs_alloc_done);

// xcall v. normal call v. empty system call v. systemcall in temporal with policy

int xcallcost(task_t* t){
    run(N, "xcallcost: %f\n") {
        xcall(test, empty_xcall);
    };
}

REG_TASK_GLOBAL(xcallcost);
#endif

#pragma GCC push_options
#pragma GCC optimize ("O0")
int normalcall(task_t* t){
    run(100000000ULL, "normalcall: %f\n") {
        empty_xcall();
    }
}
#pragma GCC pop_options

REG_TASK_GLOBAL(normalcall);

// read, write, open with and without system call policy vs. no temporal at all
#ifdef HAS_TEMPORAL
extern int open_test;
#endif
int fd_init(task_t* t){
    #ifdef HAS_TEMPORAL
    open_test = 1;
    #endif
    syscall_init(t);
}

int readcost(task_t* t){
    int fd = syscall(SYS_open, "/dev/null", O_RDWR); 
    char buf[4096];
    run(N, "readcost: %f\n") {
        syscall(SYS_read, fd, buf, 4096);
        //read(fd, buf, 4096);
    }
    close(fd);
}

int fd_done(task_t* t){
}

REG_TASK_INSIDEN(readcost, 2, fd_init, fd_done);

int writecost(task_t* t){
    int fd = syscall(SYS_open, "/dev/null", O_RDWR); // open("/dev/null", O_RDONLY);
    printf("fd = %d\n", fd);
    char buf[4096];
    run(N, "writecost: %f\n") {
        syscall(SYS_write, fd, buf, 4096);
        //write(fd, buf, 4096);
    }
    close(fd);
}

REG_TASK_INSIDEN(writecost, 2, fd_init, fd_done);

// mmap, gettimeofday with and without policy installed vs no temporal at att

int syscall_init(task_t* t){
    
    //printf("Subtask tid: %d\n", t->tid);
}

int mmapcost(task_t* t){
    run(N, "mmapcost: %f\n") {
        mems[i] = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE, 0, 0);
    }
    // unmap
    run(N, "munmapcost: %f\n") {
        munmap(mems[i], 4096);
    }
}

REG_TASK_INSIDEN(mmapcost, 2, syscall_init, 0);

int gettimeofdaycost(task_t* t){
    struct timeval tv;
    run(N, "gettimeofdaycost: %f\n") {
        gettimeofday(&tv, NULL);
    }
}

REG_TASK_INSIDEN(gettimeofdaycost, 2, syscall_init, 0);

int getppid(task_t* t){
    run(N, "getppidcost: %f\n") {
        syscall(SYS_getppid);
    }
}

REG_TASK_INSIDEN(getppid, 2, syscall_init, 0);

int lstatcost(task_t* t){
    struct stat st;
    run(N, "lstatcost: %f\n") {
        lstat("/dev/null", &st);
    }
}

REG_TASK_INSIDEN(lstatcost, 2, syscall_init, 0);

// new syscalls

// network: socket, connect
// sendfile

int fds_close[N];

int socketcost(task_t* t){
    //int fd = socket(AF_INET, SOCK_STREAM, 0);
    run(3000, "socketcost: %f\n") {
        fds_close[i] = socket(AF_INET, SOCK_STREAM, 0);
    }
    for (int i = 0; i < 3000; i++) {
        close(fds_close[i]);
    }
}

REG_TASK_INSIDEN(socketcost, 2, syscall_init, 0);

// listen
int listen_bind_cost(task_t* t){
    for (int i = 0; i < 3000; i++) {
        fds_close[i] = socket(AF_INET, SOCK_STREAM, 0);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    run(3000, "bind_cost: %f\n") {
        addr.sin_port = htons(9000 + i);
        bind(fds_close[i], (struct sockaddr*)&addr, sizeof(addr));
    }
    run(3000, "listen_cost: %f\n") {
        listen(fds_close[i], 10);
    }
    for (int i = 0; i < 3000; i++) {
        close(fds_close[i]);
    }
}

REG_TASK_INSIDEN(listen_bind_cost, 2, syscall_init, 0);

// sendfile to empty pipe
int sendfilecost(task_t* t){
    int fd = open("/dev/null", O_RDONLY);
    int pipefd[2];
    pipe(pipefd);
    run(N, "sendfilecost: %f\n") {
        sendfile(pipefd[1], fd, NULL, 4096);
    }
    close(fd);
    close(pipefd[0]);
    close(pipefd[1]);
}

REG_TASK_INSIDEN(sendfilecost, 2, syscall_init, 0);

// syscalls global

int mmapcost_global(task_t* t){
    run(N, "mmapcost_global: %f\n") {
        mems[i] = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE, 0, 0);
    }
    // unmap
    run(N, "munmapcost_global: %f\n") {
        munmap(mems[i], 4096);
    }
}

REG_TASK_GLOBAL(mmapcost_global);

int gettimeofdaycost_global(task_t* t){
    struct timeval tv;
    run(N, "gettimeofdaycost_global: %f\n") {
        gettimeofday(&tv, NULL);
    }
}

REG_TASK_GLOBAL(gettimeofdaycost_global);

int getppid_global(task_t* t){
    run(N, "getppidcost_global: %f\n") {
        syscall(SYS_getppid);
    }
}

REG_TASK_GLOBAL(getppid_global);

int lstatcost_global(task_t* t){
    struct stat st;
    run(N, "lstatcost_global: %f\n") {
        lstat("/dev/null", &st);
    }
}

REG_TASK_GLOBAL(lstatcost_global);

// temporal_create, temporal_alloc, temporal_free, temporal_destroy temporalfetch* cost

#ifdef HAS_TEMPORAL
int temporal_create_cost(task_t* t){
    //int tid = temporal_create();
    run(4096, "temporal_create_cost: %f\n") {
        mems[i] = temporal_create(0);
    }
    run(4096, "temporal_destroy_cost: %f\n") {
        temporal_destroy(mems[i]);
    }
}

REG_TASK_GLOBAL(temporal_create_cost);

int temporal_alloc_cost(task_t* t){
    tid_t tid = t->tid;
    temporal_alloc(tid, 4096);
    run(16, "temporal_alloc_cost: %f\n") {
        mems[i] = temporal_alloc(tid, 4096);
    }
    run(16, "temporal_free_cost: %f\n") {
        temporal_free(tid, mems[i]);
    }
}

REG_TASK_INSIDE(temporal_alloc_cost, 0, 0);

tid_t chs[N];

int temporal_fetch_init(task_t* t){
    tid_t tid = t->tid;
    for (int i = 0; i < 10000; i++) {
        tid_t child = chs[i] = temporal_create(tid);
        mems[i] = temporal_alloc(child, 4096);
    }
}

int temporal_fetch_cost(task_t* t){
    tid_t tid = t->tid;
    run(10000, "temporal_fetch_nestedmemory_cost: %f\n") {
        temporal_fetch_nestedmemory(chs[i]);
    }
    run(10000, "temporal_return_nestedmemory_cost: %f\n") {
        temporal_return_nestedmemory(chs[i]);
    }
}

int temporal_fetch_done(task_t* t){
    tid_t tid = t->tid;
    for (int i = 0; i < 10000; i++) {
        temporal_free(chs[i], mems[i]);
        temporal_destroy(chs[i]);
    }
}

REG_TASK_INSIDE(temporal_fetch_cost, temporal_fetch_init, temporal_fetch_done);

#endif