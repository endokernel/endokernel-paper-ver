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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_syscalls.c
 *
 * This file contains macros to redirect all system calls to the system call
 * table in library OS.
 */

#include <asm/prctl.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>
#include <linux/fcntl.h>

#include <errno.h>
#include <limits.h>

#include <shim_defs.h>
#include <shim_table.h>
#include <shim_syscalls.h>
#include <shim_trampoline.h>
#include <shim_signal.h>
#include <shim_types.h>
#define ERIM_SWAP_STACKS
#include <erim/erim_api_inlined.h>
#include <iv_debug.h>
#include <mt.h>

#include <stdarg.h>

// #define LOG_TRAP

#ifdef LOG_TRAP

long trap_count = 0;
struct timespec time_start;

static void writen(int fn, long n) {
    if (n == 0) {
        rawcall(write, fn, "0", 1);
        return;
    }

    char buf[32];
    int i = 32;
    while (n > 0) {
        buf[--i] = '0' + (n % 10);
        n /= 10;
    }
    rawcall(write, fn, buf + i, 32 - i);
}

void log_trap(const char* str) {
    int mypid = rawcall(getpid);
    // open("/tmp/trap.log", O_CREAT | O_WRONLY, 0666);
    int fd = rawcall(open, "/tmp/trap.log", O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (fd < 0) {
        return;
    }
    // [pid, trap_count = trap_count] %s
    rawcall(write, fd, "[", 1);
    writen(fd, mypid);
    rawcall(write, fd, ", trap_count = ", 14);
    writen(fd, trap_count);
    rawcall(write, fd, "] ", 2);
    // time = %d
    struct timespec time_now;
    rawcall(clock_gettime, CLOCK_MONOTONIC, &time_now);
    long time_diff = (time_now.tv_sec - time_start.tv_sec) * 1000000000 + time_now.tv_nsec - time_start.tv_nsec;
    rawcall(write, fd, "time = ", 7);
    writen(fd, time_diff);
    rawcall(write, fd, " ns, ", 5);

    rawcall(write, fd, str, strlen(str));
    rawcall(write, fd, "\n", 1);
    // flush
    rawcall(fsync, fd);
    rawcall(close, fd);
}

void start_log_trap(const char* str) {
    // [pid] start %s
    int mypid = rawcall(getpid);
    // clock_gettime(CLOCK_MONOTONIC, &time_start);
    rawcall(clock_gettime, 1, (long) &time_start);
    int fd = rawcall(open, "/tmp/trap.log", O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (fd < 0) {
        return;
    }
    rawcall(write, fd, "[", 1);
    writen(fd, mypid);
    rawcall(write, fd, "] start ", 8);
    rawcall(write, fd, str, strlen(str));
    rawcall(write, fd, "\n", 1);
    rawcall(fsync, fd);
    rawcall(close, fd);
}

#else
#define log_trap(str)
#endif

# define F_DUPFD_CLOEXEC 1030
#define UNUSED(x) (void)(x) // Just to remove warning msg

#ifdef SYSCALLFILTER
#include <temporal.h>
static syscall_cb_t syscall_cbs[128];
typedef struct ctx_pool ctx_pool_t;
struct ctx_pool {
    temporal_ctx_t ctxs[1023];
    ctx_pool_t* next;
};
static ctx_pool_t *pool0;


static temporal_ctx_t* tid2ctx(tid_t tid) {
    int n = tid % 1023;
    int m = tid / 1023;
    ctx_pool_t *p = pool0;
    while (p && m --> 0) p = p->next;
    if (!p) return NULL;
    if (!p->ctxs[n].used) 
        return NULL;
    return &(p->ctxs[n]);
}
#endif

int syscall_filter[SYSCALLNR];


unsigned long get_tdomain() {
    return get_tls()->current_domain >> 16;
}

unsigned long get_cdomain() {
    return get_tls()->current_domain & 0xffff;
}

/*
* TODOs:
    exec
    somehow arg filter for all syscalls
*/

//////////////////////////////////////////////////
//  Mappings from system calls to shim calls
///////////////////////////////////////////////////

/*
  Missing, but need to be added:
  * clone
  * semctl

  from 'man unimplemented':
  NOT IMPLEMENTED in kernel (always return -ENOSYS)

  NAME
  afs_syscall,  break,  ftime,  getpmsg, gtty, lock, madvise1, mpx, prof,
  profil, putpmsg, security, stty, tuxcall, ulimit,  vserver  -
  unimplemented system calls

  SYNOPSIS
  Unimplemented system calls.

  DESCRIPTION
  These system calls are not implemented in the Linux 2.6.22 kernel.

  RETURN VALUE
  These system calls always return -1 and set errno to ENOSYS.

  NOTES
  Note  that ftime(3), profil(3) and ulimit(3) are implemented as library
  functions.

  Some system calls,  like  alloc_hugepages(2),  free_hugepages(2),  ioperm(2),
  iopl(2), and vm86(2) only exist on certain architectures.

  Some  system  calls, like ipc(2), create_module(2), init_module(2), and
  delete_module(2) only exist when the Linux kernel was built  with  support
  for them.

  SEE ALSO
  syscalls(2)

  COLOPHON
  This  page  is  part of release 3.24 of the Linux man-pages project.  A
  description of the project, and information about reporting  bugs,  can
  be found at http://www.kernel.org/doc/man-pages/.

  Linux                            2007-07-05                  UNIMPLEMENTED(2)



  Also missing from shim:
  * epoll_ctl_old
  * epoll_wait_old


  According to kernel man pages, glibc does not provide wrappers for
  every system call (append to this list as you come accross more):
  * io_setup
  * ioprio_get
  * ioprio_set
  * sysctl
  * getdents
  * tkill
  * tgkill


  Also not in libc (append to this list as you come accross more):

  * add_key: (removed in Changelog.17)
  * request_key: (removed in Changelog.17)
  * keyctl: (removed in Changelog.17)
  Although these are Linux system calls, they are not present in
  libc but can be found rather in libkeyutils. When linking,
  -lkeyutils should be specified to the linker.x

  There are probably other things of note, so put them here as you
  come across them.

*/

/* Please move implemented system call to sys/ directory and name them as the
 * most important system call */

//#include <fcntl.h>

#include <erim.h>
#include <erim/mmap/map.h>

#include <rawcall.h>
#include <app.h>

void print_console(const char* str, int size) {
    rawcall(write, 1, str, size);
}

//#define	PROT_READ	0x04	/* pages can be read */
//#define	PROT_WRITE	0x02	/* pages can be written */
//#define	PROT_EXEC	0x01	/* pages can be executed */

#define future_protect(mem, len)
#define future_unprotect(mem, len, prot) rawcall(pkey_mprotect, mem, len, prot, IV_USER)
//#define read_test(mem, len) (!(map_get(map_addr(mem, mem+len-1)) & TRUSTED_MEM))

#define IOV_MAX 1024

unsigned long boom;

struct iovec buf_iov[16][IOV_MAX];
int volatile iov_used[16];

void release_iov(int id){
    iov_used[id] = 0;
}

void* copy_iov(void *iovec, int cnt, int* id) {
    int i;
    for (i = 0; i < 16; i++) {
        // compare and swap iov_used
        if (__sync_bool_compare_and_swap(&iov_used[i], 0, 1)) {
            *id = i;
            break;
        }
    }
    if (i == 16)
        return NULL;
    // check address okay
    memcpy(buf_iov[*id], iovec, cnt*sizeof(struct iovec));
    return buf_iov[*id];
}

typedef struct {
    void * iov_base;    /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
} iovec_t;

#define iov_check(v, cnt) \
    if ((int) (cnt) < 0 || (int) (cnt) >= IOV_MAX) return -EINVAL; \
    { \
        map_mode_t m = map_get(map_addr((void*)v, ((void*)v) + sizeof(iovec_t) * cnt - 1));  \
        if ((m & TRUSTED_MEM) || ((!(m & READABLE))) && (m != 0)) { return -EFAULT; } \
    } while (0);

bool read_test(void *a, int count) {
    if (count == 0) {
        return true;
    }
    return map_check_lock(map_addr(a, a+count-1), 1);
}

int write_test(void *a, size_t count){
    if(count == 0) {
        return true;
    }
    return map_check_lock(map_addr(a, a+count-1), 2);
}

ssize_t readv_test(const struct iovec* vec, unsigned long vlen) {
    ssize_t ret = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        if (vec[i].iov_len == 0)
            continue;
        ret += vec[i].iov_len;
        if (ret < 0)
            return -EINVAL;
        if (!read_test(vec[i].iov_base, vec[i].iov_len)) {
            return -EFAULT;
        }
    }
    return ret;
}

ssize_t writev_test(const struct iovec* vec, unsigned long vlen) {
    ssize_t ret = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        if (vec[i].iov_len == 0)
            continue;
        ret += vec[i].iov_len;
        if (ret < 0)
            return -EINVAL;
        if (!write_test(vec[i].iov_base, vec[i].iov_len)) {
            return -EFAULT;
        }
    }
    return ret;
}

#define MAX_CNT 4096

#define exam_type do {                          \
    ssize_t cnt = 0;                            \
    if (!read_test(ary, sizeof(*ary)))          \
        return -EFAULT;                         \
    unsigned long tested = ((unsigned long)ary) >> 12;          \
    while (cnt < MAX_CNT) {                     \
        if ((((unsigned long)ary >> 12) != tested) ||   \
((((unsigned long)ary + sizeof(*ary) - 1) >> 12) != tested)   \
        ) {                                     \
            if (!read_test(ary, sizeof(*ary)))  \
                return -EFAULT;                 \
            tested = ((unsigned long)ary + sizeof(*ary) - 1) >> 12;        \
        }                                       \
        *cpy++ = *ary;                          \
        if (*ary == 0)                          \
            return cnt;                         \
        cnt++;                                  \
        if (cnt > MAX_CNT)                      \
            return -E2BIG;                      \
        ary++;                                  \
    }                                           \
    return cnt;                                 \
} while (0);

ssize_t exam_ary(void **ary, void** cpy) {
    exam_type;
}

ssize_t exam_str(char *ary, char* cpy){
    exam_type;
}

#define MAXFD 4096

static struct stat stat_mem;
static int stat_mem_init = 0;
static struct stat stat_buf;

#define NO_FILE     0       // Not opened fd
#ifdef TOORHC
#define UNBOX_FILE  2      // File that accessible from unbox and safebox
                            // 3 - 15 are the files for each domain
#define SAND_FILE   16      // Normal files, sockets, pipes, and polls that everyone could access
#define SAFE_FILE   17      // File that accessible from safebox only
#define MEM_FILE    18      // /proc/self/mem

#else

#define UNBOX_FILE  1      // File that accessible from unbox and safebox
                            // 3 - 15 are the files for each domain
#define SAND_FILE   1      // Normal files, sockets, pipes, and polls that everyone could access
#define SAFE_FILE   2      // File that accessible from safebox only
#define MEM_FILE    3      // /proc/self/mem

#endif

#define FILE_LABEL_NAME "security.iv"

static int subscribed[MAXFD] = {SAND_FILE, SAND_FILE, SAND_FILE};   // 0: Invalid fd, 1: normal fd, 2: /proc/self/mem. We need invalid status to prevent any possible race condition
                                            // stdin, stdout, stderr should exist from the beginning by default. We don't know how we could deal with redirected those fds.
static bool closeatexec[MAXFD];

#ifdef SYSCALLFILTER
static int fd_check_temporal_s(int sysno, int fd);
#define fd_check_temporal(sysno, fd) fd_check_temporal_s(sysno, fd)
#else
#define fd_check_temporal(sysno, fd) (1)
#endif

// Base64 implementation copied from the Internet. I don't not know the license.
// https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

int base64_encode(const unsigned char *data, size_t input_length, char *output) {

    int res = 4 * ((input_length + 2) / 3);

    for (unsigned int i = 0, j = 0; i < input_length;) {

        unsigned int octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        unsigned int octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        unsigned int octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        output[res - 1 - i] = '=';

    return res;
}

int base64_decode(const char *data, size_t input_length, unsigned char* output) {
    char decoding_table[256];
    int res;

    for(int i = 0 ; i < 64 ; i++) {
	    decoding_table[(unsigned char) encoding_table[i]] = i;
    }

    if (input_length % 4 != 0) return -1;

    res = input_length / 4 * 3;
    if (data[input_length - 1] == '=') res--;
    if (data[input_length - 2] == '=') res--;

    for (unsigned int i = 0, j = 0; i < input_length;) {

        unsigned int sextet_a = data[i] == '=' ? 0 & i++ : (unsigned int)decoding_table[(int)data[i++]];
        unsigned int sextet_b = data[i] == '=' ? 0 & i++ : (unsigned int)decoding_table[(int)data[i++]];
        unsigned int sextet_c = data[i] == '=' ? 0 & i++ : (unsigned int)decoding_table[(int)data[i++]];
        unsigned int sextet_d = data[i] == '=' ? 0 & i++ : (unsigned int)decoding_table[(int)data[i++]];

        unsigned int triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if ((int)j < res) output[j++] = (triple >> 2 * 8) & 0xFF;
        if ((int)j < res) output[j++] = (triple >> 1 * 8) & 0xFF;
        if ((int)j < res) output[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return res;
}

// Compress and base64 encode for the fd flags to pass them to the executed process by argv
// bitsize is 1 to 6. Any bigger than 6 does not work.
void encode(int *input, char *output, int bitsize) {
	unsigned char buf[(int)(bitsize*MAXFD/8) + 1];
	int i = 0, j = 0, k = 0;
	for(i = 0 ; i <= (bitsize*MAXFD/8) ; i++)
		buf[i] = 0;

	for(int i = 0 ; i < MAXFD ; i++) {
		buf[j] = buf[j] | input[i] << k;
		k += bitsize;
		if(k >= 8) {
			j++;
			k %= 8;
			buf[j] = input[i] >> (bitsize - k);
		}
	}
	base64_encode(buf, j, output);
	printf("%s\n", output);
}

void decode(char *input, int inputsize, int *output, int bitsize) {
	unsigned char buf[(int)(bitsize*MAXFD/8) + 1];
	int i = 0, j = 0, k = 0;
	unsigned char mask = (0xff >> bitsize << bitsize) ^ 0xff;
	unsigned char rmask;
	
	base64_decode(input, inputsize, buf);
	
	for(i = 0 ; i < MAXFD ; i++) {
		output[i] = (buf[j] >> k) & mask;
		k += bitsize;
		if(k >= 8) {
			j++;
			k %= 8;
			rmask = (0xff >> (k) << (k)) ^ 0xff;
			output[i] |= (buf[j] & rmask) << (bitsize - k);
		}
	}
}

char buf_s[MAXFD];
char buf_c[MAXFD];

int fdsem[4096] = {0, 0, 0};
int fd_sub_lock[4096] = {1, 1, 1};
int openlock = 0;
int memlock = 0;
int siglock = 0;
int clonelock = 0;
int queenlock = 1;
int qretlock = 1;
int linklock = 0;

#define LOCKFD(fd)      if ((int)fd >= 0) iv_lock(&fd_sub_lock[fd])
#define UNLOCKFD(fd)    if ((int)fd >= 0) iv_unlock(&fd_sub_lock[fd])
#define MEMLOCK         iv_lock(&memlock)
#define MEMUNLOCK       iv_unlock(&memlock)
#define SIGLOCK         iv_lock(&siglock)
#define SIGUNLOCK       iv_unlock(&siglock)
#define QUEENUNLOCK     iv_unlock(&queenlock)
#define QRETLOCK        iv_lock(&qretlock)
#define CLONELOCK       iv_lock(&clonelock);
#define CLONEUNLOCK     iv_unlock(&clonelock);
#define LINKLOCK        iv_lock(&linklock);
#define LINKUNLOCK      iv_unlock(&linklock);

#ifdef TOORHC
#define EXITFD(key)     __sync_sub_and_fetch(&fdsem[key], 1)
#define ENTERFD(key)                                                    \
                        do {                                            \
                        if(__sync_add_and_fetch(&fdsem[key], 1) <= 0) { \
                            EXITFD(key);                                 \
                            return -EBADF;                              \
                        } } while(0)
#else
#define EXITFD(key) 
#define ENTERFD(key)
#endif

int usingAppV2 = 0;


#ifdef TOORHC
inline void iv_closefd(int key) {
    while(1) {
        // Goto to minimum value and the attacker need to increment until 0 if the attacker wants to perform some file I/O on this fd
        if(__sync_bool_compare_and_swap(&fdsem[key], 0, INT_MIN)) {
            break;
        }
        // Not ready to close. Let's wait
        rawcall(sched_yield);
    }
}
#else
#define iv_closefd(key)
#endif


// Get current domain based on the pkru value and the current policy.
int get_domain(unsigned int pkru) {
    int ret;
    for(ret = 0 ; ret < 16 ; ret++) {
        if((pkru & 0x3) == 0) {
            return ret;
        }
        pkru = pkru >> 2;
    }
    return ret;
}


#ifdef TOORHC
struct toorhc {
    char *path;
    int pathsize;
    int domainid;
};
struct toorhc *iv_toorhc = NULL;
char *top = NULL;
int toorhcsize = 0;

int check_protected_directory(fd) {
    int ret = 0;
    
    // Get the actual path by reading /proc/self/fd/[FD]
    char fdpath[20], abspath[1025];
    memcpy(fdpath, "/proc/self/fd/", 14);
    
    // Local crappy itoa
    int ptr;    
    if(fd < 10) {
        ptr = 15;
    } else if(fd < 100) {
        ptr = 16;
    } else if(fd < 1000) {
        ptr = 17;
    } else if(fd < 4096) {
        ptr = 18;
    } else {
        return -EFAULT;
    }
    int tmpfd = fd;
    fdpath[ptr--] = 0;
    while(tmpfd > 0) {
        fdpath[ptr--] = (tmpfd % 10) + '0';
        tmpfd /= 10;
    }

    ret = rawcall(readlink, fdpath, abspath, 1024); // TODO: Could have buffer overflow
    if(ret < 0) {
        return ret;
    }
    ret = 0;
    
    // Add '/' if the abspath is a directory
    struct stat stat_buf;
    rawcall(fstat, fd, &stat_buf);
    if((stat_buf.st_mode & S_IFMT) == S_IFDIR) {
        ptr = 0;
        while(abspath[ptr] != 0) {
            ptr++;
        }
        abspath[ptr] = '/';
        abspath[ptr+1] = 0;
    }

    // Compare the protected directories and the current one
    for(int i = 0 ; i < toorhcsize ; i++) {
        if(memcmp(iv_toorhc[i].path, abspath, iv_toorhc[i].pathsize) == 0)  {
            ret = iv_toorhc[i].domainid;
            break;
        }
    }
    return ret;
}



int label_conflict(int xattrlabel, int dirlabel) {
    int ret = xattrlabel;
    // File label is one of the safebox
    if(xattrlabel >= min_safebox && xattrlabel <= max_safebox) {
        if(dirlabel >= min_safebox && dirlabel <= max_safebox) {
            if(xattrlabel != dirlabel) {
                return -EPERM;
            }
        }
    } else if(xattrlabel == SAFE_FILE) {     // File label is general safebox
        if(dirlabel >= min_safebox && dirlabel <= max_safebox) {
            ret = dirlabel;
        }
    } else if(xattrlabel < min_safebox) {    // File label is unbox
        if(dirlabel <= max_safebox && dirlabel > 0) {
            ret = dirlabel;
        }
    } else if(xattrlabel >= min_sandbox) {   // File label is one of the sandbox
        if(dirlabel <=max_safebox && dirlabel > 0) {
            ret = dirlabel;
        } else if(dirlabel > max_safebox) {
            if(xattrlabel != dirlabel) {
                return -EPERM;
            }
        }
    } else if(xattrlabel == SAND_FILE) {     // File label is general sandbox
        if(dirlabel <= max_safebox && dirlabel > 0) {
            ret = dirlabel;
        }
        if(dirlabel > max_safebox) {
            ret = dirlabel;
        }
    }
    return ret;
}



int check_fd_perm(int fd) {
    int label = subscribed[fd];
    if(fd < 0)
        return fd;
    //if(fd == 0)
    //    return -EFAULT;

    // Get the caller domain
    int dom = get_domain(get_tls()->current_pkru);

    // The fd is not opened by the app. IV opened it.
    if(label == NO_FILE) {
        char charlabel[2];
        int ret = rawcall(fgetxattr, fd, FILE_LABEL_NAME, charlabel, 2);
        if(ret < 0) {
            if(ret == -ENODATA) {
                charlabel[0] = SAND_FILE + '0';
            } else {
                return ret;
            }
        }
        label = (int)charlabel[0] - '0';

        // Check whether the fd is in the proected directory.
        int dirlabel = check_protected_directory(fd);
        if(dirlabel < 0) {
            return dirlabel;
        }
        // Compete the security label of the file bewteen xattr and the protected directory
        // More secure label wins
        label = label_conflict(label, dirlabel);
    }

    // The file could be protected for a specific domain
    if(label < 16) {
        if (dom == label) {
            return 0;
        } else {
        return -EPERM;
        }
    }

    // Unbox domain
    if(dom < min_safebox) {
        // Unbox cannot access safebox file
        if(label == SAFE_FILE) {
            return -EPERM;
        }
    } else if(dom >= min_sandbox) {
        if(label != SAND_FILE) {
            return -EPERM;
        }
    }
    // Safebox is allowed to everything
    return 0;
}



int check_link_perm(const char *path) {
    int ret;
    
    int dom = get_domain(get_tls()->current_pkru);
    
    // Get label of the path
    char label[2];
    ret = rawcall(lgetxattr, path, FILE_LABEL_NAME, label, 2);
    if(ret < 0) {
        if(ret == -ENODATA) {
            label[0] = SAND_FILE + '0';
        } else {
            return ret;
        }
    }
    label[0] -= '0';

    // Unbox domain
    if(dom < min_safebox) {
        if((int)label[0] > UNBOX_FILE) {
            return -EPERM;
        }
    } else if(dom >= min_sandbox) { // Sandbox domain
        if((int)label[0] != SAND_FILE) {
            return -EPERM;
        }
    }
    // Safebox is allowed to everything
    return 0;
}
#endif


void sys_loadexecbuff(char* _buf_s, char* _buf_c){
    decode(_buf_s, strlen(_buf_s), subscribed, 2);
    decode(_buf_c, strlen(_buf_c), (int*)closeatexec, 2);
    int close_cnt = 0, sub_cnt = 0;
    //printf("Sub=%s\n", _buf_s);
    //printf("Close=%s\n", _buf_c);

    for (int i = 3; i < 4096; i++) {
        if (closeatexec[i]) {
            subscribed[i] = NO_FILE;
            closeatexec[i] = 0;
            close_cnt = close_cnt + 1;
        }
        if (subscribed[i] == MEM_FILE)
            sub_cnt++;
    }
    printf("FDExec Close=%d, Sub=%d\n", close_cnt, sub_cnt);
}

SHIM_SYSCALL_EMULATED(mmap, 6, void*, void*, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset) {
    void *mem;
    MEMLOCK;
    map_addr_t dest = map_addr(addr, (void*)(addr + length - 1));

    if ((!!(prot & PROT_EXEC)) && (!!(prot & PROT_WRITE))) {
        prot &= ~PROT_WRITE; // remove write priv
    }

#ifdef TOORHC
    // Check permission
    if(fd >= 0 && check_fd_perm(fd) < 0) {
        return (void*)-EPERM;
    }
#endif

#ifdef RANDOM
    // Nexpoline pool is reserved, noone can mmap it
    if((unsigned long)addr >= RTRAMPOLINE_START && (unsigned long)addr <= RTRAMPOLINE_END) {
        mem = (void *)-1;
        goto end;
    }
    if(((unsigned long)addr + length) >= RTRAMPOLINE_START && ((unsigned long)addr + length) <= RTRAMPOLINE_END) {
        mem = (void *)-1;
        goto end;
    }
#endif

    map_mode_t mode = map_norm(prot, 0);

    // MAP_FIXED
    if (flags & (0x10)){
        if (!map_check_lock(dest, 0)) { // never overleap protected region
            mem = (void*)-1;
            goto end;
        }
    }
    // MAP_ANONYMOUS	0x20
    if (flags & (0x20)) {
        if (fd != -1)
            fd = -1;
            //return -1;
        mem = (void*)rawcall(mmap, addr, length, prot, flags, fd, offset);
        dest = map_addr(mem, (void*)(mem + length - 1));
        if (flags & MAP_PRIVATE)
            mode |= RETIRED; // make it retired
        map_unlock_read_all();
        map_set(dest, mode); // new memory always retired
        //if (addr >= 0x7ffff8000000 && addr <= 0x800037c00000) goto end;
        future_unprotect(mem, length, prot);
        goto end;
    } else {
        int kill = 0;
        int need_scan = 0;

        if (mode & EXECUTABLE)
            need_scan = 1;
        if (! kill) {
            mem = 0; // real memory
            if (need_scan) {
                //mem = (void*)rawcall(mmap, addr, length, prot, flags, fd, offset);
                
                // You need to round up the legnth to page size. mmap will map the file with the page size anyway.
                length = (length + 0xfff ) & (~0xfff);
                mem = (void*)rawcall(mmap, addr, length, (prot | PROT_WRITE) & (~PROT_EXEC), (flags & (~MAP_SHARED) & (~MAP_FILE)) | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                size_t cur = rawcall(lseek, fd, 0, SEEK_CUR);
                rawcall(lseek, fd, offset, SEEK_SET);

                // Reading the file should be careful. You may need to read the file multiple times
                unsigned int readlen = 0, curlen = 0;
                while(readlen < length) {
                    curlen = rawcall(read, fd, mem, length);
                    if(curlen == 0)
                        break;
                    readlen += curlen;
                }
                rawcall(lseek, fd, cur, SEEK_SET);
                //mem1 = (void*)rawcall(mmap, addr, length, prot | PROT_READ, flags, fd, offset);
                // TODO: what if mem1 is not readable??
            } else {
                mem = (void*)rawcall(mmap, addr, length, prot, flags, fd, offset);
            }
            if ((unsigned long)mem > 0) {
                if (need_scan) {
                    // region boundary check
                    char *scanBegin = mem;
                    unsigned long long scanLen = length;
                    
                    if (map_get(map_addr(mem - 8, mem - 1)) & EXECUTABLE) {
                        scanBegin -= 8;
                    }

                    if (map_get(map_addr(mem + length, mem + length + 8)) & EXECUTABLE) {
                        scanLen += 8;
                    }
                    printf("erim scan %p %p\n", scanBegin, scanBegin + scanLen);
                    if (erim_memScanRegion(ERIM_PKRU_VALUE_UNTRUSTED, scanBegin, scanLen, NULL, 0, NULL)) {
                        rawcall(munmap, mem, length);
                        printf("failed\n");
                        mem = (void*)-1;
                        goto end;
                    }
                }
                map_unlock_read_all();
                rawcall(mprotect, mem, length, prot);
                map_set(map_addr(mem, mem + length - 1), mode); // protect
                future_unprotect(mem, length, prot);
                goto end;
            }
        }
    }
end:
    map_unlock_read_all();
    MEMUNLOCK;
    return (void*) mem;
}

int do_mprotect(void *addr, size_t len, int prot, int pkey) {
    if (pkey <= 1 || pkey > 15)
        return -ENOSYS;
    unsigned int current_pkru = get_tls()->current_pkru;
    if (unlikely(!app_allow_outer_promote(pkey) && (PKEY_KEY(current_pkru, pkey) == 0)))
        return -1; // no priv
    map_addr_t adr = map_addr(addr, addr + len - 1);
    map_mode_t mode = map_get(adr);
    int e = 0;
    MEMLOCK;
    if (!map_check_lock(adr, 0)) {
        e = -1;
        goto end;
    }
    map_unlock_read_all();
#ifdef RANDOM
    // Nexpoline pool is reserved, noone can mmap it
    if((unsigned long)addr >= RTRAMPOLINE_START && (unsigned long)addr <= RTRAMPOLINE_END) {
        e = -1;
        goto end;
    }
    if(((unsigned long)addr + len) >= RTRAMPOLINE_START && ((unsigned long)addr + len) <= RTRAMPOLINE_END) {
        e = -1;
        goto end;
    }
#endif

    map_mode_t new_mode = map_norm(prot, 0);
    if ((mode & RETIRED) && !(new_mode & EXECUTABLE))
        new_mode |= RETIRED;

    if (mode & EXECUTABLE) {
        if (usingAppV2) {
            e = -1;
            goto end;
        }
        if (!(new_mode & EXECUTABLE))
            new_mode |= RETIRED; // EX deprivlege
        if (new_mode & WRITABLE) {
            if (new_mode & EXECUTABLE) {
                e = -1;     // TODO: error for violate W^X
                goto end;
            }
        }
    } else {
        if (new_mode & EXECUTABLE) {
            if (mode & RETIRED) {
                char *scanBegin = addr;
                unsigned long long scanLen = len;

                if (map_get(map_addr(addr - 8, addr - 1)) & EXECUTABLE) {
                    scanBegin -= 8;
                }

                if (map_get(map_addr(addr + len, addr + len + 8)) & EXECUTABLE) {
                    scanLen += 8;
                }
                printf("erim scan %p %p\n", scanBegin, scanBegin + scanLen);
                
                // Rounding up the len to fit with the page size
                len = (len + 0xfff ) & (~0xfff);
                
                // Prevent writing/executing from other untrusted threads
                rawcall(pkey_mprotect, addr, len, PROT_READ | PROT_WRITE, IV_NORMAL);
                if (erim_memScanRegion(ERIM_PKRU_VALUE_UNTRUSTED, scanBegin, scanLen, NULL, 0, NULL)) {
                    printf("failed\n");
                    e = -1;     // TODO: error for scan failed
                    rawcall(pkey_mprotect, addr, len, map_prot(mode), IV_USER);
                    goto end;
                }
                if (new_mode & WRITABLE) {
                    rawcall(pkey_mprotect, addr, len, map_prot(mode), IV_USER);
                    e = -1; // TODO: error for violate W^X
                    goto end;
                }
            }
        }
    }
    //e = rawcall(mprotect, addr, len, prot);       // You don't need this if you call pkey_mprotect() after this.
    e = rawcall(pkey_mprotect, addr, len, prot, pkey);
    if (pkey != IV_USER)
        map_set(adr, new_mode | APP(pkey));
    else
        map_set(adr, new_mode);

end:
    map_unlock_read_all();
    MEMUNLOCK;
    return e;
}

SHIM_SYSCALL_EMULATED(mprotect, 3, int, void*, addr, size_t, len, int, prot) {
    return do_mprotect(addr, len, prot, IV_USER);
}



SHIM_SYSCALL_EMULATED(munmap, 2, int, void*, addr, size_t, len) {
    int e;
    MEMLOCK;
    map_addr_t adr = map_addr(addr, addr + len - 1);
    if (!map_check_lock(adr, 0)) {
        e = -1;
        printf("unmap trusted error = %p, len=%ld, e=%d\n", addr, len, e);
        goto end;
    }
    if (usingAppV2) {
        if (map_get(adr) & EXECUTABLE) {
            e = -1;
            printf("unmap executable = %p, len=%ld, e=%d\n", addr, len, e);
            goto end;
        }
    }
    e = rawcall(munmap, addr, len);
    if (e) {
        printf("unmap error = %p, len=%ld, e=%d\n", addr, len, e);
    }
    map_clear(adr);
end:
    map_unlock_read_all();
    MEMUNLOCK;
    return e;
}



SHIM_SYSCALL_EMULATED(brk, 1, void*, void*, brk) {
    MEMLOCK;
    // TODO: unaligned brk
    void * oldbrk = (void*)rawcall(brk, 0);
    void * newbrk = (void*)rawcall(brk, brk);
    //printf("brk(%p)=%p (from %p)\n", brk, newbrk, oldbrk);
    if (oldbrk == newbrk) {
        goto end;
    }
    if (oldbrk < newbrk) {
        map_addr_t adr = map_addr(oldbrk, newbrk - 1);
        if (future_unprotect(oldbrk, (size_t)newbrk - (size_t)oldbrk, PROT_READ | PROT_WRITE) < 0){
            rawcall(write, STDERR_FILENO, "fail\n", 5);
        }
        map_set(adr, map_norm(PROT_READ | PROT_WRITE, 0));
        goto end;
    } else {
        map_addr_t adr = map_addr(newbrk, oldbrk - 1);
        map_clear(adr);
        goto end;
    }
end:
    MEMUNLOCK;
    return newbrk;
}



//#define _PASSALL
#ifdef _PASSALL
#undef SHIM_SYSCALL_EMULATED
#define SHIM_SYSCALL_EMULATED SHIM_SYSCALL_PASSTHRUE
#endif
SHIM_SYSCALL_EMULATED(read, 3, size_t, int, fd, void*, buf, size_t, count) {
    size_t res;
    if (fd >= 4096 || fd < 0) {
        res = -EBADF;
        return res;
    }

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

#ifdef TOORHC
    // Check file perm
    ENTERFD(fd);
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        EXITFD(fd);
        goto end;
    }
#endif

    if(!write_test(buf, count)) {
        res = -EFAULT;
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        LOCKFD(fd);
        size_t position = rawcall(lseek, fd, 0, SEEK_CUR);
        if (read_test((void*)position, count)) {
            res = rawcall(read, fd, buf, count);
        } else {
            res = -EFAULT;
        }
        UNLOCKFD(fd);
    } else {
        res = rawcall(read, fd, buf, count);
    }
end:
#ifdef TOORHC
EXITFD(fd);
#endif
    map_unlock_read_all();
    return res;
}



SHIM_SYSCALL_EMULATED(write, 3, size_t, int, fd, const void*, buf, size_t, count) {
    //IV_DBG("write(%d)", fd);
    
    size_t res;
    if (fd >= 4096 || fd < 0) {
        res = -EBADF;
#ifdef TOORHC
    } else if(check_fd_perm(fd) < 0) {
        res = -EPERM;
#endif
    } else if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
    } else if(!read_test((void*)buf, count)) {
        res = -EFAULT;
    } else if (subscribed[fd] == MEM_FILE) {
        ENTERFD(fd);
        LOCKFD(fd);
        size_t position = rawcall(lseek, fd, 0, SEEK_CUR);
        if (write_test((void*)position, count)) {
            res = rawcall(write, fd, buf, count);
        } else {
            res = -EFAULT;
        }
        UNLOCKFD(fd);
    } else {
        ENTERFD(fd);
        res = rawcall(write, fd, buf, count);
    }
    EXITFD(fd);
    map_unlock_read_all();
    return res;
}

SHIM_SYSCALL_EMULATED(bpf, 3, int, int, cmd, union bpf_attr*, attr, unsigned int, size) {
    int fd = rawcall(bpf, cmd, attr, size);
    if (fd < 0) {
        return fd;
    }
    
    if (fd >= 4096) {
        rawcall(close, fd);
        return -EMFILE;
    }

    subscribed[fd] = 1;
    fdsem[fd] = 0;

    return fd;
}

SHIM_SYSCALL_EMULATED(open, 3, int, const char*, file, int, flags, mode_t, mode) {
    if (!stat_mem_init) {
        long fdx = rawcall(open, "/proc/self/mem", 0, 0600);
        rawcall(fstat, fdx, &stat_mem);
        stat_mem_init = 1;
        rawcall(close, fdx);
    }

    long fd = rawcall(open, file, flags, mode);
    if(fd < 0) {
        return fd;
    }
    rawcall(fstat, fd, &stat_buf);
    if (fd >= 4096) {
        rawcall(close, fd);
        return -EMFILE;
    }
    if (stat_buf.st_dev == stat_mem.st_dev && stat_buf.st_ino == stat_mem.st_ino) {
        subscribed[fd] = MEM_FILE;
        if (flags & FD_CLOEXEC)
            closeatexec[fd] = 1;
    } else {
#ifdef TOORHC
        // Get the file label
        // Current policy: 
        //      SAND_FILE: Normal file, no need to protect, 
        //      UNBOX_FILE: Unbox and safebox could access, 
        //      SAFE_FILE: Only safebox could access
        //      No label is same as SAND_FILE
        char label[2];
        int ret = check_fd_perm(fd);
        if(ret < 0) {
            rawcall(close, fd);
            return -EPERM;
        }
        ret = rawcall(fgetxattr, fd, FILE_LABEL_NAME, label, 2);
        if(ret < 0){
            if(ret == -ENODATA) {
                label[0] = SAND_FILE + '0';
            } else {
                rawcall(close, fd);
                return -EMFILE;
            }
        }
        label[0] -= '0';
        if(label[0] < SAND_FILE || label[1] > SAFE_FILE) {
            rawcall(close, fd);
            printf("IV file permission error\n");
            return -EMFILE;
        }

        // Get the directory label if it's protected
        int dirlabel = check_protected_directory(fd);

        // Get the domain
        int dom = get_domain(get_tls()->current_pkru);
        // Set the label
        label[0] = (char)label_conflict((int)label[0], dirlabel);
        subscribed[fd] = (int)label[0];
#else
        subscribed[fd] = SAND_FILE;
#endif
    }
    fdsem[fd] = 0;
    return fd;
}



SHIM_SYSCALL_EMULATED(close, 1, int, int, fd) {
    int res;
    // leave empty file check to kernel
    if (fd < 0 || fd >= 4096/* || subscribed[fd] == NO_FILE*/) {
        res = -EBADF;
#ifdef TOORHC
    } else if(check_fd_perm(fd) < 0) {
        res = -EPERM;
#endif
    } else if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
    } else {
        iv_closefd(fd);
        subscribed[fd] = NO_FILE;
        closeatexec[fd] = false;
        res = rawcall(close, fd);
    }
    return res;
}



SHIM_SYSCALL_EMULATED(lseek, 3, off_t, int, fd, off_t, offset, int, origin) {
    ENTERFD(fd);
    off_t res;
    // origin is SEEK_SET then lock
#ifdef TOORHC
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
    } else if(check_fd_perm(fd) < 0) {
        res = -EPERM;
    } else if(origin & SEEK_SET && subscribed[fd] == MEM_FILE) {
#else
    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
    } else if(origin & SEEK_SET && subscribed[fd] == MEM_FILE) {
#endif
        LOCKFD(fd);     // No need to lock open because it just could change offset of a fd.
        res = rawcall(lseek, fd, offset, origin);
        UNLOCKFD(fd);
    } else {
        res = rawcall(lseek, fd, offset, origin);
    }
    EXITFD(fd);
    return res;
}


/*
Policy:
    mapping (source) -> (dest)
    if dest.protected -> kill (cannnot map to protected address)
    if src.executable -> kill (cannot map executable address to any other address)
    if src.retired -> src.remove(retire) remap of a retired address deprivledge it
    if dest.executable -> memopy & erimScan & remove writable (modifying src won't change dest)
*/



SHIM_SYSCALL_EMULATED(pread64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos) {
    size_t res;
    ENTERFD(fd);

    if (fd >= 4096 || fd < 0 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
        return res;
    }

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if(!write_test(buf, count)) {
        res = -EFAULT;
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        // We don't need file lock because we already have the offset
        size_t position = pos;
        if (read_test((void*)position, count)) {
            res = rawcall(pread64, fd, buf, count);
        } else {
            res = -EFAULT;
        }
    } else {
        res = rawcall(pread64, fd, buf, count);
    }
end:
    map_unlock_read_all();
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(pwrite64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos) {
    size_t res;
    ENTERFD(fd);

    if (fd >= 4096 || fd < 0 || subscribed[fd] == NO_FILE) {
        res =-EBADF;
#ifdef TOORHC
    } else if(check_fd_perm(fd) < 0) {
        res = -EPERM;
#endif
    } else if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
    } else if(!read_test(buf, count)) {
        res = -EFAULT;
    } else if (subscribed[fd] == MEM_FILE) {
        size_t position = pos;
        if (write_test((void*)position, count)) {
            res = rawcall(pwrite64, fd, buf, count);
        } else {
            res = -EFAULT;
        }
    } else {
        res = rawcall(pwrite64, fd, buf, count);
    }
    map_unlock_read_all();
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(readv, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen) {
    // Copying is required to make pointer secure in the multi threaded environment
    iov_check(vec, vlen);
    int id;
    vec = copy_iov((void*)vec, vlen, &id);
    
    ssize_t write_cnt = writev_test(vec, vlen);

    if (write_cnt < 0) {
        map_unlock_read_all();
        release_iov(id);
        return write_cnt;
    }
    int res = 0;
    ENTERFD(fd);

    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
#ifdef TOORHC
    } else if(check_fd_perm(fd) < 0) {
        res = -EPERM;
#endif
    } else if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
    } else if (subscribed[fd] == MEM_FILE) {
        LOCKFD(fd);
        size_t position = rawcall(lseek, fd, 0, SEEK_CUR);
        if (!write_test((void*)position, write_cnt)) {
            res = -EFAULT;
        }
        res = rawcall(readv, fd, vec, vlen);
        UNLOCKFD(fd);
    } else {
        res = rawcall(readv, fd, vec, vlen);
    }
    release_iov(id);
    map_unlock_read_all();
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(writev, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen) {
    // Copying is required to make pointer secure in the multi threaded environment
    // printf("checkpoint1\n");
    iov_check(vec, vlen);
    // printf("checkpoint2\n");
    int id;
    vec = copy_iov((void*)vec, vlen, &id);
    ssize_t len_sum = 0, res;
    
    len_sum = readv_test(vec, vlen);

    if (len_sum < 0) {
        release_iov(id);
        map_unlock_read_all();
        //printf("F1\n");
        return len_sum;
    }

    ENTERFD(fd);

    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
        //printf("F2\n");
        goto end;
    }

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        //printf("F3\n");
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        LOCKFD(fd);
        size_t position = rawcall(lseek, fd, 0, SEEK_CUR);
        if (!write_test((void*)position, len_sum)) {
            res = -EFAULT;
            goto end;
        }
        res = rawcall(writev, fd, vec, vlen);
        UNLOCKFD(fd);
    } else {
        //printf("F4\n");
        res = rawcall(writev, fd, vec, vlen);
    }
end:
    release_iov(id);
    map_unlock_read_all();
    EXITFD(fd);
    return res;
}



// WARN: A new flag MREMAP_DONTUNMAP has been added to kernel
// EX pages is private, so cannot remap it by old_size = 0
SHIM_SYSCALL_EMULATED(mremap, 5, void*, void*, addr, size_t, old_len, size_t, new_len, int, flags, void*, new_addr) {
    void* new_addr_f;
    MEMLOCK;
    size_t xold_len = (old_len == 0) ? (4096) : old_len;
    map_addr_t old_addr = map_addr(addr, addr+xold_len - 1);
    map_mode_t mode = map_get(old_addr);

#ifdef RANDOM
    // Nexpoline pool is reserved, noone can mmap it
    if((unsigned long)addr >= RTRAMPOLINE_START && (unsigned long)addr <= RTRAMPOLINE_END) {
        new_addr_f = (void *)-1;
        goto end;
    }
    if(((unsigned long)addr + new_len) >= RTRAMPOLINE_START && ((unsigned long)addr + new_len) <= RTRAMPOLINE_END) {
        new_addr_f = (void *)-1;
        goto end;
    }
#endif
    if ((mode & EXECUTABLE) || !map_check_lock(old_addr, 0)) {
        new_addr_f = (void*)-EFAULT;
        goto end;
    }
    /*if (!read_test(addr, xold_len))
        return (void*) -1;
    */
    if (flags & 2) { // MREMAP_FIXED
        if (!map_check_lock(map_addr(new_addr, new_addr + new_len - 1),0)) {
            new_addr_f = (void*)-EFAULT;
            map_unlock_read_all();
            goto end;
        }
    }
    map_unlock_read_all();
    // make sure nobody can read the new address
    new_addr_f = (void*)rawcall(mremap, addr, old_len, new_len, flags, new_addr);
    if (new_addr_f != MAP_FAILED) {
        //if (flags & 1) { // MREMAP_MAYMOVE
        map_clear(old_addr);
        map_addr_t new_addr_m = map_addr(new_addr_f, new_addr_f + new_len - 1);
        map_set(new_addr_m, mode);
        future_unprotect(new_addr_f, new_len, map_prot(mode));
        //}
    }
end:
    map_unlock_read_all();
    MEMUNLOCK;
    return (void*) new_addr_f;
}

/*
int dup_debug = -1;

void dup_write(int fd, const char* str) {
    if (dup_debug == -1) {
        dup_debug = rawcall(open, "/tmp/dup_debug", O_CREAT | O_WRONLY, 0666);
    }
    // write [fd] str to dup_debug
    rawcall(write, dup_debug, "[", 1);
    char buf[10];
    int n = fd, i = 10;
    while (n > 0) {
        buf[--i] = n % 10 + '0';
        n /= 10;
    }
    rawcall(write, dup_debug, buf + i, 10 - i);
    rawcall(write, dup_debug, "] ", 2);
    rawcall(write, dup_debug, str, strlen(str));
    // flush
    rawcall(fsync, dup_debug);
}
*/

SHIM_SYSCALL_EMULATED(dup, 1, int, int, fd) {
    int res;
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        if (subscribed[fd] == NO_FILE) {
            // puts "NO_FILE" to stderr using rawcall
            //dup_write(fd, "NO_FILE\n");
        } else {
            // puts "OOF FD" to stderr using rawcall
            //dup_write(fd, "OOF FD\n");
        }
        res = -EBADF;
        return res;
    }

    ENTERFD(fd);
    
#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif
    
    if (fd_check_temporal(__NR_dup, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    int _d = rawcall(dup, fd);
    if (_d != -1) {
        if (_d < 4096) {
            subscribed[_d] = subscribed[fd];
            closeatexec[_d] = closeatexec[fd];
            fdsem[_d] = 0;
        } else {
            rawcall(close, _d);
            res = -EMFILE;
            goto end;
        }
        res = _d;
        goto end;
    }
    res = -1;
end:
    EXITFD(fd);
    return res;
}


SHIM_SYSCALL_EMULATED(dup2, 2, int, int, oldfd, int, newfd) {
    int res;
    ENTERFD(oldfd);
    
    if (newfd < 0 || newfd >= 4096) {
        // puts "OOF FD" to stderr using rawcall
        res = -EBADF;
        goto end;
    }
#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(oldfd) < 0 || check_fd_perm(newfd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif
    
    if (fd_check_temporal(__NR_dup2, oldfd) == 0) {
        res = -EPERM;
        goto end;
    }
    
    if (fd_check_temporal(__NR_dup2, newfd) == 0) {
        res = -EPERM;
        goto end;
    }

    // If newfd is occupied, the kernel will silently close it. So, we need to do it before kernel does it
    if(subscribed[newfd] > NO_FILE) {
        rawcall(close, newfd);
    }

    int _d = rawcall(dup2, oldfd, newfd);
    if (_d >= 0) {
        if (_d < 4096) {
            subscribed[_d] = subscribed[oldfd];
            closeatexec[_d] = closeatexec[oldfd];
            fdsem[_d] = 0;
        } else {
            rawcall(close, _d);
            res = -EMFILE;
            goto end;
        }
        res = _d;
        goto end;
    }
    res = _d;
end:
    EXITFD(oldfd);
    return res;
}

// avoid zero copy by not allowing to set SO_ZEROCOPY
SHIM_SYSCALL_EMULATED(setsockopt, 5, int, int, fd, int, level, int, optname, char*, optval, int, optlen) {
    int res;
    if (fd < 0 || fd >= 4096) {
        res = -EBADF;
        return res;
    }

    if (subscribed[fd] == NO_FILE) {
        res = -EBADF;
        return res;
    }

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (optname == 60) {
        // SO_ZEROCOPY?
        res = -EINVAL;
        goto end;
    }
    if (optlen > 1024) {
        res = -EINVAL;
        goto end;
    }
    
    if (read_test(optval, optlen)) {
        res = rawcall(setsockopt, fd, level, optname, optval, optlen);
    } else {
        res = -EFAULT;
    }

end:
    map_unlock_read_all();
    return res;
}


SHIM_SYSCALL_EMULATED(sendfile, 4, ssize_t, int, out_fd, int, in_fd, off_t*, offset, size_t, count) {
    ssize_t res;

    ENTERFD(in_fd);
    ENTERFD(out_fd);

    if(subscribed[in_fd] == NO_FILE || subscribed[out_fd] == NO_FILE) {
        res = -EBADF;
        goto end;
    }
    

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(in_fd) < 0 || check_fd_perm(out_fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, in_fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (fd_check_temporal(0, out_fd) == 0) {
        res = -EPERM;
        goto end;
    }

    // for multiple threads version, we should copy offset
    if (offset && !write_test(offset, sizeof(off_t*))) {
        printf("failed 1\n");
        res = -EFAULT; // cannot write to trusted *offset
        goto end;
    }
    
    if (subscribed[in_fd] == MEM_FILE) {
        LOCKFD(in_fd);
        // check read range
        size_t position = offset ? (*offset) : (rawcall(lseek, in_fd, 0, SEEK_CUR));
        if (!read_test((void*)position, count)) {
            res = -EFAULT;
            goto end;
        }
    }

    if (subscribed[out_fd] == MEM_FILE) {
        LOCKFD(out_fd);
        // check write range
        size_t position = rawcall(lseek, out_fd, 0, SEEK_CUR);
        if (!write_test((void*)position, count)) {
            res = -EFAULT;
            goto end;
        }
    }

    res = rawcall(sendfile, out_fd, in_fd, offset, count);
end:
    if(subscribed[in_fd] == MEM_FILE)
        UNLOCKFD(in_fd);
    if(subscribed[out_fd] == MEM_FILE)
        UNLOCKFD(out_fd);
    EXITFD(out_fd);
    EXITFD(in_fd);
    map_unlock_read_all();
    return res;
}

SHIM_SYSCALL_EMULATED(fanotify_init, 2, int, int, flags, int, event_f_flags) {
    int fd = rawcall(fanotify_init, flags, event_f_flags);
    if (fd < 0) {
        return fd;
    }
    if (fd < 4096) {
        subscribed[fd] = 1;
        closeatexec[fd] = 0;
        fdsem[fd] = 0;
        return fd;
    } else {
        rawcall(close, fd);
        return -EMFILE;
    }
}

SHIM_SYSCALL_EMULATED(fanotify_mark, 5, int, int, fanotify_fd, int, flags, unsigned long, mask, int, fd, const char*, pathname) {
    #define FAN_MARK_ADD 0x00000001
    #define FAN_OPEN_EXEC 0x00001000
    #define FAN_OPEN_EXEC_PERM 0x00040000
    printf("fanotify_mark: %d %d %d %d %s\n", fanotify_fd, flags, mask, fd, pathname);
    if (mask & (FAN_OPEN_EXEC | FAN_OPEN_EXEC_PERM)) {
        printf("fanotify_mark: FAN_OPEN_EXEC\n");
        return -EINVAL;
    }
    return rawcall(fanotify_mark, fanotify_fd, flags, mask, fd, pathname);
}

SHIM_SYSCALL_EMULATED(fcntl, 3, int, int, fd, int, cmd, unsigned long, arg) {
    int res;
    
    if (fd < 0 || fd >= 4096) {
        // make dup6 happy
        res = (int)-EBADF;
        return res;
    }

    /*if (subscribed[fd] == NO_FILE){
        res = (int)-EBADF;
        return res;
    }*/

#ifdef TOORHC
    // Check file perm
    ENTERFD(fd);
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        EXITFD(fd);
        goto end;
    }
#endif
    
    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    res = rawcall(fcntl, fd, cmd, arg);
    printf("fcntl(%d, %d, %lu) = %d)", fd, cmd, arg, res);
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        if (res < 0)
            goto end;
        if (res >= 4096) {
            rawcall(close, res);
            res = (int)-EMFILE;
            goto end;
        }
        subscribed[res] = subscribed[fd];
        fdsem[res] = 0;
        if (cmd == F_DUPFD_CLOEXEC) {
            closeatexec[res] = 1;
        }
    }
    if(cmd == F_SETFD && (arg & FD_CLOEXEC)) {
        printf("set close at exec for fd %d\n", fd);
        closeatexec[fd] = 1;
    }
end:
#ifdef TOORHC
        EXITFD(fd);
#endif
    return res;
}



SHIM_SYSCALL_EMULATED(creat, 2, int, const char*, path, mode_t, mode) {
    if (!stat_mem_init) {
        long fdx = rawcall(open, "/proc/self/mem", 0, 0600);
        rawcall(fstat, fdx, &stat_mem);
        stat_mem_init = 1;
        rawcall(close, fdx);
    }

    long fd = rawcall(creat, path, mode);
    if(fd < 0) {
        return fd;
    }
#ifdef TOORHC
    rawcall(fstat, fd, &stat_buf);
    if (fd >= 4096) {
        rawcall(close, fd);
        return -EMFILE;
    }
    if (stat_buf.st_dev == stat_mem.st_dev && stat_buf.st_ino == stat_mem.st_ino) {
        subscribed[fd] = MEM_FILE;
    } else {
        // Get the file label
        // Current policy: 
        //      SAND_FILE: Normal file, no need to protect, 
        //      UNBOX_FILE: Unbox and safebox could access, 
        //      SAFE_FILE: Only safebox could access
        //      No label is same as SAND_FILE
        char label[2];
        int ret = check_fd_perm(fd);
        if(ret < 0) {
            rawcall(close, fd);
            return -EPERM;
        }
        ret = rawcall(fgetxattr, fd, FILE_LABEL_NAME, label, 2);
        if(ret < 0){
            if(ret == -ENODATA) {
                label[0] = SAND_FILE + '0';
            } else {
                rawcall(close, fd);
                return -EMFILE;
            }
        }
        label[0] -= '0';
        if(label[0] < SAND_FILE || label[1] > SAFE_FILE) {
            rawcall(close, fd);
            printf("IV file permission error\n");
            return -EMFILE;
        }

        // Get the directory label if it's protected
        int dirlabel = check_protected_directory(fd);

        // Get the domain
        int dom = get_domain(get_tls()->current_pkru);
        // Set the label
        label[0] = (char)label_conflict((int)label[0], dirlabel);
        subscribed[fd] = (int)label[0];
    }
    fdsem[fd] = 0;
#else
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
#endif
    return fd;
}



#ifdef TOORHC
SHIM_SYSCALL_EMULATED(openat, 4, int, int, dfd, const char*, filename, int, flags, int, mode) {
    IV_DBG("openat %s", filename);
    if (!stat_mem_init) {
        long fdx = rawcall(open, "/proc/self/mem", 0, 0600);
        rawcall(fstat, fdx, &stat_mem);
        stat_mem_init = 1;
        rawcall(close, fdx);
    }

    long fd;
    if(dfd != AT_FDCWD) {
        ENTERFD(dfd);
        if(check_fd_perm(dfd) < 0){
            fd = -EPERM;
            goto end;
        }
    }

    fd = rawcall(openat, dfd, filename, flags, mode);
    if(fd < 0) {
        goto end;
    }
    rawcall(fstat, fd, &stat_buf);
    if (fd >= 4096) {
        rawcall(close, fd);
        fd = -EMFILE;
        goto end;
    }
    if (stat_buf.st_dev == stat_mem.st_dev && stat_buf.st_ino == stat_mem.st_ino) {
        subscribed[fd] = MEM_FILE;
        if (flags & FD_CLOEXEC)
            closeatexec[fd] = 1;
    } else {
        // Get the file label
        // Current policy: 
        //      SAND_FILE: Normal file, no need to protect, 
        //      UNBOX_FILE: Unbox and safebox could access, 
        //      SAFE_FILE: Only safebox could access
        //      No label is same as SAND_FILE
        char label[2];
        int ret = check_fd_perm(fd);
        if(ret < 0) {
            rawcall(close, fd);
            fd = -EPERM;
            goto end;
        }
        ret = rawcall(fgetxattr, fd, FILE_LABEL_NAME, label, 2);
        if(ret < 0){
            if(ret == -ENODATA) {
                label[0] = SAND_FILE + '0';
            } else {
                rawcall(close, fd);
                fd = -EMFILE;
                goto end;
            }
        }
        label[0] -= '0';
        if(label[0] < SAND_FILE || label[1] > SAFE_FILE) {
            rawcall(close, fd);
            printf("IV file permission error\n");
            fd = -EMFILE;
            goto end;
        }

        // Get the directory label if it's protected
        int dirlabel = check_protected_directory(fd);

        // Get the domain
        int dom = get_domain(get_tls()->current_pkru);
        // Set the label
        label[0] = (char)label_conflict((int)label[0], dirlabel);
        subscribed[fd] = (int)label[0];
    }
    fdsem[fd] = 0;
end:
    if(dfd != AT_FDCWD) {
        EXITFD(dfd);
    }
    return fd;
}
#else
SHIM_SYSCALL_EMULATED(openat, 4, int, int, dfd, const char*, filename, int, flags, int, mode) {
    if (!stat_mem_init) {
        long fdx = rawcall(open, "/proc/self/mem", 0, 0600);
        rawcall(fstat, fdx, &stat_mem);
        stat_mem_init = 1;
        rawcall(close, fdx);
    }

    long fd = rawcall(openat, dfd, filename, flags, mode);
    if (fd < 0) {
        printf("open failed %s\n", filename);
        return fd;
    }
    rawcall(fstat, fd, &stat_buf);
    if (fd >= 4096) {
        rawcall(close, fd);
        fd = -EMFILE;
    } else if (stat_buf.st_dev == stat_mem.st_dev && stat_buf.st_ino == stat_mem.st_ino) {
        subscribed[fd] = MEM_FILE;
        if (flags & FD_CLOEXEC)
            closeatexec[fd] = 1;
    } else {
        subscribed[fd] = SAND_FILE;
    }
    fdsem[fd] = 0;
    return fd;
}
#endif



SHIM_SYSCALL_EMULATED(dup3, 3, int, int, oldfd, int, newfd, int, flags) {
    if (oldfd == newfd)
        return -EINVAL;
    if (flags & ~(O_CLOEXEC|O_NONBLOCK))
        return -EINVAL;
    
    int res;
    ENTERFD(oldfd);
    
    if (oldfd < 0 || oldfd >= 4096 || subscribed[oldfd] == NO_FILE) {
        res = -EBADF;
        goto end;
    }
    
    if (newfd < 0 || newfd >= 4096) {
        res = -EBADF;
        goto end;
    }

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(oldfd) < 0 || check_fd_perm(newfd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(__NR_dup3, oldfd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (fd_check_temporal(__NR_dup3, newfd) == 0) {
        res = -EPERM;
        goto end;
    }

    // If newfd is occupied, the kernel will silently close it. So, we need to do it before kernel does it
    if(subscribed[newfd] > NO_FILE) {
        rawcall(close, newfd);
    }

    int _d = rawcall(dup3, oldfd, newfd, flags);
    if (_d >= 0) {
        if (_d < 4096) {
            subscribed[_d] = subscribed[oldfd];
            closeatexec[_d] = closeatexec[oldfd];
            fdsem[_d] = 0;
        } else {
            rawcall(close, _d);
            res = -EMFILE;
            goto end;
        }
        res = _d;
        goto end;
    }
    res = _d;
end:
    EXITFD(oldfd);
    return res;
}



SHIM_SYSCALL_EMULATED(preadv, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h) {
    unsigned long long pos = pos_l | (pos_h << 32);
    // Copying is required to make pointer secure in the multi threaded environment
    iov_check(vec, vlen);
    int id;
    vec = copy_iov((void*)vec, vlen, &id);

    ssize_t vec_len = writev_test(vec, vlen);
    if (vec_len < 0) {
	map_unlock_read_all();
        return vec_len;
    }
        
    int res;
    if (fd >= 4096 || subscribed[fd] == NO_FILE) {
	map_unlock_read_all();
        res = -EBADF;
        return res;
    }
    ENTERFD(fd);

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        size_t position = pos;
        if (!read_test((void*)position, vec_len)) {
            res = -EFAULT;
            goto end;
        }
    }
    res = rawcall(preadv, fd, vec, vlen, pos_l, pos_h);
end:
    release_iov(id);
    map_unlock_read_all();
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(pwritev, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h) {
    unsigned long long pos = pos_l | (pos_h << 32);
    // Copying is required to make pointer secure in the multi threaded environment
    iov_check(vec, vlen);
    int id;
    vec = copy_iov((void*)vec, vlen, &id);
    
    ssize_t len_sum = readv_test(vec, vlen);
    if (len_sum < 0) {
	
        map_unlock_read_all();
        return len_sum;
    }
    int res;
    if (fd >= 4096 || subscribed[fd] == NO_FILE) {
	map_unlock_read_all();
        res = -EBADF;
        return res;
    }
    ENTERFD(fd);

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        size_t position = pos;
        if (!write_test((void*)position, len_sum)) {
            res = -EFAULT;
            goto end;
        }
    }
    res = rawcall(pwritev, fd, vec, vlen, pos_l, pos_h);
end:
    map_unlock_read_all();
    release_iov(id);
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(open_by_handle_at, 3, int, int, mountdirfd, struct linux_file_handle*, handle, int, flags){
    if (!stat_mem_init) {
        long fdx = rawcall(open, "/proc/self/mem", 0, 0600);
        rawcall(fstat, fdx, &stat_mem);
        stat_mem_init = 1;
        rawcall(close, fdx);
    }
    long fd;
#ifdef TOORHC
    if(mountdirfd != AT_FDCWD) {
        ENTERFD(mountdirfd);
        if(check_fd_perm(mountdirfd) < 0){
            fd = -EPERM;
            goto end;
        }
    }
#endif

    fd = rawcall(open_by_handle_at, mountdirfd, handle, flags);
    if(fd < 0) {
        goto end;
    }
    rawcall(fstat, fd, &stat_buf);
    if (fd >= 4096) {
        rawcall(close, fd);
        fd = -EMFILE;
        goto end;
    }
    if (stat_buf.st_dev == stat_mem.st_dev && stat_buf.st_ino == stat_mem.st_ino) {
        subscribed[fd] = MEM_FILE;
        if (flags & FD_CLOEXEC) {
            closeatexec[fd] = 1;
        }
    } else {
#ifdef TOORHC
        // Get the file label
        // Current policy: 
        //      SAND_FILE: Normal file, no need to protect, 
        //      UNBOX_FILE: Unbox and safebox could access, 
        //      SAFE_FILE: Only safebox could access
        //      No label is same as SAND_FILE
        char label[2];
        int ret = check_fd_perm(fd);
        if(ret < 0) {
            rawcall(close, fd);
            fd = -EPERM;
            goto end;
        }
        ret = rawcall(fgetxattr, fd, FILE_LABEL_NAME, label, 2);
        if(ret < 0){
            if(ret == -ENODATA) {
                label[0] = SAND_FILE + '0';
            } else {
                rawcall(close, fd);
                fd = -EMFILE;
                goto end;
            }
        }
        label[0] -= '0';
        if(label[0] < SAND_FILE || label[1] > SAFE_FILE) {
            rawcall(close, fd);
            printf("IV file permission error\n");
            fd = -EMFILE;
            goto end;
        }

        // Get the directory label if it's protected
        int dirlabel = check_protected_directory(fd);

        // Get the domain
        int dom = get_domain(get_tls()->current_pkru);
        // Set the label
        label[0] = (char)label_conflict((int)label[0], dirlabel);
        subscribed[fd] = (int)label[0];
#else
        subscribed[fd] = SAND_FILE;
#endif
    }
    fdsem[fd] = 0;
end:
    if(mountdirfd != AT_FDCWD) {
        EXITFD(mountdirfd);
    }
    return fd;
}



pid_t self = -1;
// TOOD
SHIM_SYSCALL_EMULATED(process_vm_readv, 6, ssize_t, pid_t, pid, const struct iovec*, local_iov, unsigned long, liovcnt, const struct iovec*, remote_iov, unsigned long, riovcnt, unsigned long, flags) {
    if (self == -1){
        self = rawcall(getpid);
    }
    iov_check(local_iov, liovcnt);
    iov_check(remote_iov, riovcnt);
    int id1, id2;
    // Copying is required to make pointer secure in the multi threaded environment
    remote_iov = copy_iov((void*)remote_iov, riovcnt, &id1);
    // Copying is required to make pointer secure in the multi threaded environment
    local_iov = copy_iov((void*)local_iov, liovcnt, &id2);

    ssize_t size1 = 0, size2 = 0;

    for (unsigned long i = 0; i < liovcnt; i++) {
        if (local_iov[i].iov_len == 0)
            continue;
        size1 += local_iov[i].iov_len;
        if (size1 < 0) {
            release_iov(id1);
            release_iov(id2);
            return -EINVAL;
        }
        if (!write_test(local_iov[i].iov_base, local_iov[i].iov_len)) {
            release_iov(id1);
            release_iov(id2);
            return -EFAULT;
        }
    }
    if (pid == self) {
        for (unsigned long i = 0; i < riovcnt; i++) {
            if (remote_iov[i].iov_len == 0)
                continue;
            size2 += remote_iov[i].iov_len;
            if (size2 < 0) {
                release_iov(id1);
                release_iov(id2);
                return -EINVAL;
            }
            if (!read_test(remote_iov[i].iov_base, remote_iov[i].iov_len)) {
                release_iov(id1);
                release_iov(id2);
                return -EFAULT;
            }
        }
    }
    ssize_t res = rawcall(process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt,  flags);
    release_iov(id1);
    release_iov(id2);
    map_unlock_read_all();
    return res;
}


// TOOD
SHIM_SYSCALL_EMULATED(process_vm_writev, 6, ssize_t, pid_t, pid, const struct iovec*, local_iov, unsigned long, liovcnt, const struct iovec*, remote_iov, unsigned long, riovcnt, unsigned long, flag) {
    if (self == -1){
        self = rawcall(getpid);
    }
    iov_check(local_iov, liovcnt);
    iov_check(remote_iov, riovcnt);
    //local_iov = copy_iov(local_iov, liovcnt, 0);
    //remote_iov = copy_iov(remote_iov, riovcnt, 1);
    if (!read_test((void*)local_iov, liovcnt * sizeof(struct iovec))) {
        map_unlock_read_all();
        return -EFAULT;
    }
    int id1, id2;
    local_iov = copy_iov((void*)local_iov, liovcnt, &id1);
    if (!read_test((void*)remote_iov, riovcnt * sizeof(struct iovec))) {
        release_iov(id1);
        map_unlock_read_all();
        return -EFAULT;
    }
    remote_iov = copy_iov((void*)remote_iov, riovcnt, &id2);

    ssize_t size1 = 0, size2 = 0;
    for (unsigned long i = 0; i < liovcnt; i++) {
        if (local_iov[i].iov_len == 0)
            continue;
        size1 += local_iov[i].iov_len;
        if (size1 < 0) {
            release_iov(id1);
            release_iov(id2);
            map_unlock_read_all();
            return -EINVAL;
        }
        if (!read_test(local_iov[i].iov_base, local_iov[i].iov_len)) {
            release_iov(id1);
            release_iov(id2);
            map_unlock_read_all();
            return -EFAULT;
        }
    }
    if (pid == self) {
        for (unsigned long i = 0; i < riovcnt; i++) {
            if (remote_iov[i].iov_len == 0)
                continue;
            size2 += remote_iov[i].iov_len;
            if (size2 < 0) {
                release_iov(id1);
                release_iov(id2);
                map_unlock_read_all();
                return -EINVAL;
            }
            if (!write_test(remote_iov[i].iov_base, remote_iov[i].iov_len)) {
                release_iov(id1);
                release_iov(id2);
                map_unlock_read_all();
                return -EFAULT;
            }
        }
    }
    ssize_t res = rawcall(process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flag);
    release_iov(id1);
    release_iov(id2);
    map_unlock_read_all();
    return res;
}


// TOOD
SHIM_SYSCALL_EMULATED(copy_file_range, 6, ssize_t, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out, size_t, len, unsigned int, flags) {
    ssize_t res = 0;
    ENTERFD(fd_in);
    ENTERFD(fd_out);

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd_in) < 0 || check_fd_perm(fd_out) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd_in) == 0) {
        res = -EPERM;
        goto end;
    }
    
    if (fd_check_temporal(0, fd_out) == 0) {
        res = -EPERM;
        goto end;
    }

    if (subscribed[fd_in] == MEM_FILE) {
        if (!read_test((void*)off_in, len)) {
            res = (ssize_t) -EFAULT;
            goto end;
        }
    }
    if (subscribed[fd_out] == MEM_FILE) {
        if (!write_test(off_out, len)) {
            res = (ssize_t) -EFAULT;
            goto end;
        }
    }
    res = rawcall(copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
end:
    EXITFD(fd_out);
    EXITFD(fd_in);
    map_unlock_read_all();
    return res;
}


// splice

SHIM_SYSCALL_EMULATED(splice, 6, int, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out, size_t, len, int, flags) {
    // avoid SPLICE_F_GIFT in flags
    if (flags & 8)
        return -EINVAL;
    // check fd
    if (fd_in < 0 || fd_in >= 4096 || fd_out < 0 || fd_out >= 4096 || subscribed[fd_in] == NO_FILE || subscribed[fd_out] == NO_FILE)
        return -EBADF;
    ENTERFD(fd_in);
    ENTERFD(fd_out);
    if (subscribed[fd_in] == MEM_FILE) {
        if (!read_test((void*)off_in, len)){
            map_unlock_read_all();
            return -EFAULT;
        }
    }
    if (subscribed[fd_out] == MEM_FILE) {
        if (!write_test(off_out, len)) {   
            map_unlock_read_all();
            return -EFAULT;
        }
    }
    int res = rawcall(splice, fd_in, off_in, fd_out, off_out, len, flags);
    EXITFD(fd_out);
    EXITFD(fd_in);
    map_unlock_read_all();
    return res;
}


SHIM_SYSCALL_EMULATED(preadv2, 6, ssize_t, int, fd, const struct iovec*, iov, int, iovcnt, unsigned long, pos_l, unsigned long, pos_h, int, flags) {
    off_t offset = pos_l | (pos_h << 32);

    iov_check(iov, iovcnt);
    // Copying is required to make pointer secure in the multi threaded environment
    int id;
    iov = copy_iov((void*)iov, iovcnt, &id);
    
    if (flags & ~(RWF_DSYNC | RWF_HIPRI | RWF_SYNC | RWF_NOWAIT |0x00000010)) {
	map_unlock_read_all();
        release_iov(id);
        return -EOPNOTSUPP;
    }

    ssize_t len_sum = writev_test(iov, iovcnt);
    if (len_sum < 0) {
	map_unlock_read_all();
        release_iov(id);
        return len_sum;
    }

    ssize_t res;
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
	map_unlock_read_all();
        release_iov(id);
        res = -EBADF;
        return res;
    }

    ENTERFD(fd);
    
#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (subscribed[fd] == MEM_FILE) {
        size_t position = offset == (-1) ? (rawcall(lseek, fd, 0, SEEK_CUR)) : offset;
        if (!read_test((void*)position, len_sum)) {
            res = -EFAULT;
            goto end;
        }
    }
    res = rawcall(preadv2, fd, iov, iovcnt, offset, flags);
end:
    map_unlock_read_all();
    release_iov(id);
    EXITFD(fd);
    return res;
}


// TOOD
SHIM_SYSCALL_EMULATED(pwritev2, 6, ssize_t, int, fd, const struct iovec*, iov, int, iovcnt, unsigned long, pos_l, unsigned long, pos_h, int, flags) {
    off_t offset = pos_l | (pos_h << 32);
    ssize_t len_sum = 0;

    iov_check(iov, iovcnt);
    // Copying is required to make pointer secure in the multi threaded environment
    int id;
    iov = copy_iov((void*)iov, iovcnt, &id);

    if (flags & ~(RWF_DSYNC | RWF_HIPRI | RWF_SYNC | RWF_NOWAIT |0x00000010)) {
        release_iov(id);
        return -EOPNOTSUPP;
    }
    
    len_sum = readv_test(iov, iovcnt);
    if (len_sum < 0) {
        release_iov(id);
        return len_sum;
    }

    ssize_t res;
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
        release_iov(id);
        return res;
    }

    ENTERFD(fd);
    
#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        size_t position = offset == (-1) ? (rawcall(lseek, fd, 0, SEEK_CUR)) : offset;
        if (!write_test((void*)position, len_sum)) {
            res = -EFAULT;
            goto end;
        } 
    }
    res = rawcall(pwritev2, fd, iov, iovcnt, offset, flags);
end:
    map_unlock_read_all();
    release_iov(id);
    EXITFD(fd);
    return res;
}



SHIM_SYSCALL_EMULATED(rt_sigaction, 4, int, int, signum, const struct __kernel_sigaction*, act, struct __kernel_sigaction*, oldact, size_t, sigsetsize) {
    // SIGKILL and SIGSTOP cannot be caught or ignored
    if (signum == SIGKILL || signum == SIGSTOP || signum <= 0 || signum > NUM_SIGS || sigsetsize != sizeof(__sigset_t))
        return -EINVAL;
    // If 'act' is given, it must point to readable memory
    if (act && !read_test((void*)act, sizeof(struct __kernel_sigaction))) {
        map_unlock_read_all();
        return -EFAULT;
    }

    // If 'oldact' is given, it must point to writable memory
    if (oldact && !write_test((void*)oldact, sizeof(struct __kernel_sigaction))) {
        map_unlock_read_all();
        return -EFAULT;
    }

    SIGLOCK;
    virt_sigaction(signum, (struct __kernel_sigaction_1*)act, (struct __kernel_sigaction_1*)oldact);
    SIGUNLOCK;

    map_unlock_read_all();
    return 0;
}



SHIM_SYSCALL_EMULATED(rt_sigprocmask, 4, int, int, how, const __sigset_t*, set, __sigset_t*, oldset, size_t, sigsetsize) {
    if ((how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) || (sigsetsize != sizeof(__sigset_t)))
        return -EINVAL;

    // If 'set' is given, it must point to readable memory
    if (set && !read_test((void*)set, sizeof(__sigset_t))) {
        map_unlock_read_all();
        return -EFAULT;
    }

    // If 'oldset' is given, it must point to writable memory
    if (oldset && !write_test((void*)oldset, sizeof(__sigset_t))) {
        map_unlock_read_all();
        return -EFAULT;
    }

    SIGLOCK;
    virt_sigprocmask(how, (const unsigned long*)set, (unsigned long*)oldset);
    SIGUNLOCK;
    
    map_unlock_read_all();
    return 0;
}

SHIM_SYSCALL_EMULATED(rt_sigreturn, 1, unsigned long, int, __unused) {
    UNUSED(__unused);
    return virt_sigreturn(0);
}

stack_t stk;
SHIM_SYSCALL_EMULATED(sigaltstack, 2, int, const stack_t*, ss, stack_t*, oss) {
    if (ss && !read_test((void*)ss, sizeof(stack_t))) {   
        map_unlock_read_all();
        return -EFAULT;
    }

    int res;
    
    SIGLOCK;
    if (ss) {
        memcpy(&stk, ss, sizeof(stack_t));
        ss = &stk;
    }
    if (ss && ss->ss_sp && !write_test(ss->ss_sp, ss->ss_size)) {
        res = -EFAULT;
        goto end;
    }

    if (oss && !write_test((void*)oss, sizeof(stack_t))) {
        res =  -EFAULT;
        goto end;
    }

    res = virt_sigaltstack((unsigned long) *ERIM_UNTRUSTED_STACK_PTR, (stack_t*)ss, oss);
end:
    SIGUNLOCK;
    map_unlock_read_all();
    return res;
}



// TODO
SHIM_SYSCALL_EMULATED(rt_sigqueueinfo, 3, int, int, pid, int, sig, siginfo_t*, uinfo) {
    // For now, I'm going to pass-through it
    if (uinfo && !read_test(uinfo, sizeof(siginfo_t))) {
        return -EFAULT;
    }
    int res;
    SIGLOCK;
    res = rawcall(rt_sigqueueinfo, pid, sig, uinfo);
    SIGUNLOCK;
    return res;
}



SHIM_SYSCALL_EMULATED(rt_sigsuspend, 2, int, const __sigset_t*, mask, size_t, sigsetsize) {
    // For now, I'm going to pass-through it
    if (mask && !read_test((void*)mask, sizeof(sigset_t))) {
        map_unlock_read_all();
        return -EFAULT;
    }
    if (sigsetsize != sizeof(unsigned long)) {
        map_unlock_read_all();
        return -EINVAL;
    }
    int res;
    SIGLOCK;
    res = virt_sigsuspend(*(unsigned long*)(mask)); //rawcall(rt_sigsuspend, mask, sigsetsize);
    SIGUNLOCK;
    map_unlock_read_all();
    return res;
}



SHIM_SYSCALL_EMULATED(rt_sigpending, 2, int, __sigset_t*, set, size_t, sigsetsize) {
    // For now, I'm going to pass-through it
    if (set && !write_test(set, sizeof(sigset_t))) {
        map_unlock_read_all();
        return -EFAULT;
    }
    if (sigsetsize != sizeof(unsigned long)) {
        map_unlock_read_all();
        return -EINVAL;
    }
    SIGLOCK;
    *((unsigned long*)(set)) = virt_sigpending();
    SIGUNLOCK;
    
    map_unlock_read_all();
    return 0;
}



// TODO
SHIM_SYSCALL_EMULATED(rt_sigtimedwait, 4, int, const __sigset_t*, uthese, siginfo_t*, uinfo, const struct timespec*, uts, size_t, sigsetsize) {
    // Ideally, we do not have to emulate sigtimedwait, because sigtimedwait
    // does not change the control flow.
    
    if (uts &&!read_test((void*)uts, sizeof(struct timespec))) {
        map_unlock_read_all();
        return -EFAULT;
    }
    if (uinfo && !write_test(uinfo, sizeof(siginfo_t))) {
        map_unlock_read_all();
        return -EFAULT;
    }
    if (sigsetsize != sizeof(unsigned long)) {
        map_unlock_read_all();
        return -EINVAL;
    }
    int res;
    SIGLOCK;
    res = virt_sigtimedwait(*(unsigned long*)(uthese), uinfo, (void*)uts);
    SIGUNLOCK;
    map_unlock_read_all();
    return res;
}

SHIM_SYSCALL_EMULATED(alarm, 1, int, unsigned int, seconds) {
    // printf("alarm(%d)\n", seconds);
    return rawcall(alarm, seconds);
}

SHIM_SYSCALL_EMULATED(restart_syscall, 0, int) {
    // We can't emulate this right now, and neither can we let it pass through
    return -ENOSYS;
}



// TODO
SHIM_SYSCALL_EMULATED(timer_create, 3, int, clockid_t, which_clock, struct sigevent*, timer_event_spec, timer_t*, created_timer_id) {
    return rawcall(timer_create, which_clock, timer_event_spec, created_timer_id);
}



// TODO
SHIM_SYSCALL_EMULATED(kill, 2, int, pid_t, pid, int, sig) {
    return rawcall(kill, pid, sig);
}



// Signal, fd, doesn't seem to leak info? should be fine to just passthrough?
// TODO
SHIM_SYSCALL_EMULATED(signalfd, 3, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask) {
    int res;
    res = rawcall(signalfd, ufd, user_mask, sizemask);
    // TODO: check udf
    if (res < 0)
        return res;
    if (res > 4096){
        rawcall(close, res);
        return -EMFILE;
    }
    subscribed[res] = 1;
    fdsem[res] = 0;
    return res;
}



// TODO
SHIM_SYSCALL_EMULATED(signalfd4, 4, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask, int, flags) {
    int res;
    res = rawcall(signalfd4, ufd, user_mask, sizemask, flags);
    if (res < 0)
        return res;
    if (res > 4096){
        rawcall(close, res);
        return -EMFILE;
    }
    subscribed[res] = 1;
    fdsem[res] = 0;
    return res;
}


// ioctl
/*
SHIM_SYSCALL_EMULATED(ioctl, 3, int, int, fd, unsigned long, request, unsigned long, arg) {
    UNUSED(request);
    UNUSED(arg);
    UNUSED(fd);
    return -1;
}
*/

// vmsplice

SHIM_SYSCALL_EMULATED(vmsplice, 4, int, int, fd, const struct iovec*, iov, unsigned long, nr_segs, int, flags) {
    if (flags & 8) {
        // SPLICE_F_GIFT
        return -EINVAL;
    }
    iov_check(iov, nr_segs);
    // printf("checkpoint2\n");
    int id;
    iov = copy_iov((void*)iov, nr_segs, &id);
    ssize_t len_sum = 0, res;
    
    len_sum = readv_test(iov, nr_segs);

    if (len_sum < 0) {
        release_iov(id);
        //printf("F1\n");
        return len_sum;
    }

    ENTERFD(fd);

    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        res = -EBADF;
        //printf("F2\n");
        goto end;
    }

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        res = -EPERM;
        goto end;
    }
#endif

    if (fd_check_temporal(0, fd) == 0) {
        res = -EPERM;
        //printf("F3\n");
        goto end;
    }

    if (subscribed[fd] == MEM_FILE) {
        size_t position = rawcall(lseek, fd, 0, SEEK_CUR);
        if (!write_test((void*)position, len_sum)) {
            res = -EFAULT;
            goto end;
        }
    }
    res = rawcall(vmsplice, fd, iov, nr_segs, flags);
end:
    map_unlock_read_all();
    release_iov(id);
    EXITFD(fd);
    return res;
}

// userfaultfd

SHIM_SYSCALL_EMULATED(userfaultfd, 1, int, int, flags) {
    UNUSED(flags);
    return -1;
}

// io uring
SHIM_SYSCALL_EMULATED(io_setup, 2, int, unsigned, nr_reqs, aio_context_t*, ctx) {
    return -1;
}

SHIM_SYSCALL_EMULATED(io_destroy, 1, int, aio_context_t, ctx) {
    return -1;
}

SHIM_SYSCALL_EMULATED(io_getevents, 5, int, aio_context_t, ctx_id, long, min_nr, long, nr, struct io_event*, events, struct timespec*, timeout) {
    return -1;
}

SHIM_SYSCALL_EMULATED(io_submit, 3, int, aio_context_t, ctx_id, long, nr, struct iocb**, iocbpp) {
    return -1;
}

SHIM_SYSCALL_EMULATED(io_cancel, 3, int, aio_context_t, ctx_id, struct iocb*, iocb, struct io_event*, result) {
    return -1;
}

// MPK


// block
SHIM_SYSCALL_EMULATED(pkey_alloc, 2, int, unsigned long, flags, unsigned long, access_rights) {
    UNUSED(flags);
    UNUSED(access_rights);
    return -1;
    //return rawcall(pkey_alloc, flags, access_rights);
}



// block
SHIM_SYSCALL_EMULATED(pkey_free, 1, int, int, pkey) {
    UNUSED(pkey);
    return -1;
    //return rawcall(pkey_free, pkey);
}



// block
SHIM_SYSCALL_EMULATED(pkey_mprotect, 4, int, void*, addr, size_t, len, int, prot, int, pkey) {
    return do_mprotect(addr, len, prot, pkey);
}


// LDT
SHIM_SYSCALL_EMULATED(modify_ldt, 3, int, int, func, void*, ptr, unsigned long, bytecount) {
    UNUSED(func);
    UNUSED(ptr);
    UNUSED(bytecount);
    return -1;
}



// I don't understand
/*
SHIM_SYSCALL_EMULATED(rt_tgsigqueueinfo, 4, int, pid_t, tgid, pid_t, pid, int, sig, siginfo_t*, uinfo) {
    UNUSED(tgid);
    UNUSED(pid);
    UNUSED(sig);
    UNUSED(uinfo);
    return -1;
}
*/


SHIM_SYSCALL_EMULATED(seccomp, 3, int, int, operation, unsigned int, flags, void*, args) {
    UNUSED(operation);
    UNUSED(flags);
    UNUSED(args);
    return -1;
}



#ifndef PR_SET_SECCOMP
# define PR_GET_SECCOMP  21
# define PR_SET_SECCOMP  22
#endif
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
# define PR_GET_NO_NEW_PRIVS 39
#endif

SHIM_SYSCALL_EMULATED(prctl, 5, int, int, option, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5) {
    if (option == PR_SET_SECCOMP || option == PR_GET_SECCOMP)
        return -1;
    return rawcall(prctl, option, arg2, arg3, arg4, arg5);
}



// TODO
SHIM_SYSCALL_EMULATED(msgctl, 3, int, int, msqid, int, cmd, struct msqid_ds*, buf) {
    return rawcall(msgctl, msqid, cmd, buf);
}



extern char* abs_libc_location; // libc location
char *_argv[256 + 3 + 2 + 2 + 1 + 1];
char buf_fd[32];
static const char hex_table[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
static char* stoh(unsigned int i) {
    int n = 9;
    buf_fd[n] = 0;
    do {
        buf_fd[--n] = hex_table[i & 0xf];
        i >>= 4;
    } while (i);
    return buf_fd + n;
}



#define AT_EMPTY_PATH		    0x1000
#define AT_SYMLINK_NOFOLLOW     0x100
#define max_arg 100000

// TODO: error when argv too large
char buf_inthead[1024];
char **new_argv[4096];
char **new_envp[4096];
char buf_arg[max_arg + 4096];
static int do_execve(int fd, const char ** argv, const char ** envp, const char*pathname) {
    int opt = 0;
    int n_read = rawcall(read, fd, buf_inthead, 1024);
    if (n_read  < 3) {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        return -ENOEXEC;
    }
    //printf("buf[0.1] = %c%c\n", buf_inthead[0], buf_inthead[1]);
    if (buf_inthead[0] == '#' && buf_inthead[1] == '!') {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        char *s = buf_inthead + 2;
        int x_i = 2;
        while (*s != '\n' && x_i < 1024) {
            for (; *s == ' ' && x_i < 1024; ) *s++ = '\0', x_i++;
            if (*s != '\n')
                _argv[7 + opt++] = s;
            while (*s != ' ' && *s != '\n' && x_i < 1024) s++, x_i++;
        }
        _argv[7 + opt++] = (char*)pathname; // interpreter [optional-arg] pathname arg
        if (x_i == 1024) {
            return -E2BIG;
        }
        *s = 0;
        if (opt == 0)
            return -ENOEXEC;
        int acc = rawcall(access, _argv[7], R_OK | X_OK);
            if (acc != 0) {
            return acc;
        }
        printf("exec: %s\n", _argv[7]);
        fd = rawcall(open, _argv[7], O_RDONLY);
        if (fd < 0)
            return fd;
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    } else rawcall(lseek, fd, 0, SEEK_SET);

    encode(subscribed, buf_s, 2);
    encode((int*)closeatexec, buf_c, 1);

    _argv[0] = (char*)"/proc/self/exe";
    _argv[1] = abs_libc_location;
    _argv[2] = (char *)"-exec";
    _argv[3] = buf_s;
    _argv[4] = buf_c;
    _argv[5] = (char *)"-fd";
    _argv[6] = stoh(fd);
    ssize_t argc = exam_ary((void**)argv, (void**)new_argv);
    argv = (const char**)new_argv;
    if (argc < 0) {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        return argc;
    }
    if (argc >= 256) {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        return -E2BIG;
    }
    size_t s_size = 0;
    int i = 7 + opt;
    if (opt)
        argv++; // skip arg[0]
    char *_buf_arg = buf_arg;
    for (i = 7 + opt; *argv && i < 256 + 2 + 3 + 2; i++, argv++) {
        ssize_t n_arg = exam_str((char *)(*argv), _buf_arg);
        if (n_arg < 0) {
            rawcall(close, fd);
            subscribed[fd] = NO_FILE;
            fdsem[fd] = INT_MIN;
            return n_arg;
        } else 
            s_size += n_arg + 1;
        if (s_size > max_arg)
            break;
        _argv[i] = _buf_arg;
        _buf_arg += n_arg + 1;
    }
    if (s_size > max_arg) {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        return -E2BIG;
    }

    _argv[i] = 0;
    printf("envp = %p\n", envp);
    if (envp) {
        ssize_t envc = exam_ary((void**)envp, (void**)new_envp);
        envp = (const char**)new_envp;
        if (envc < 0) {
            rawcall(close, fd);
            subscribed[fd] = NO_FILE;
            fdsem[fd] = INT_MIN;
            return envc;
        }
        for (int i = 0; i < envc; i++) {
            ssize_t n_env = exam_str((char *)envp[i], _buf_arg);
            if (n_env < 0) {
                rawcall(close, fd);
                subscribed[fd] = NO_FILE;
                fdsem[fd] = INT_MIN;
                printf("failed env\n\n");
                return n_env;
            } else
                s_size += n_env + 1;
            if (s_size > max_arg)
                break;
            envp[i] = _buf_arg;
            _buf_arg += n_env + 1;
        }
    }
    if (s_size > max_arg) {
        rawcall(close, fd);
        subscribed[fd] = NO_FILE;
        fdsem[fd] = INT_MIN;
        return -E2BIG;
    }
    
    if (get_tls()->self->vfork != 0) {
        iv_unlock(&get_tls()->self->vfork);
    }
    int xret = rawcall(execve, "/proc/self/exe", _argv, envp);
    // unlikely
    rawcall(close, fd);
    subscribed[fd] = NO_FILE;
    fdsem[fd] = INT_MIN;
    return xret;
}



char _pathname[4096];
SHIM_SYSCALL_EMULATED(execve, 3, int, const char*, file, const char**, argv, const char**, envp) {
    // self = /proc/self/exe
    // TODO: Use FD version
    log_trap("execve");
    log_trap(file);
    printf("execve: %s\n", file);
    if (!read_test(argv, 8)){
        printf("fail read test %s\n", file);
        map_unlock_read_all();
        return -EFAULT;
    }
    ssize_t n_file = exam_str((char *)file, _pathname);
    file = _pathname;
    if (n_file < 0) {
        map_unlock_read_all();
        return n_file;
    }
    if (n_file > 128) {
        map_unlock_read_all();
        return -ENAMETOOLONG;
    }
    int acc = rawcall(access, file, R_OK | X_OK);
    if (acc != 0) {
        printf("can't access %s\n", file);
        map_unlock_read_all();
        return acc;
    }

    int fd = 0;
    fd = rawcall(open, file, O_RDONLY);
    if (fd < 0) {
        map_unlock_read_all();
        return fd;
    }

#ifdef TOORHC
    // Check file perm
    if(check_fd_perm(fd) < 0) {
        rawcall(close, fd);
        map_unlock_read_all();
        return -EPERM;
    }
#endif
    subscribed[fd] = SAND_FILE;
    fdsem[fd] = 0;

    int r_exec = do_execve(fd, argv, envp, file);
    subscribed[fd] = NO_FILE;
    fdsem[fd] = INT_MIN;
    map_unlock_read_all();
    return r_exec;
}



char buf_reopen[48];
SHIM_SYSCALL_EMULATED(execveat, 5, int, int, dirfd, const char*, pathname, const char**, argv, const char**, envp, int, flags) {
    int fd = 0;
    int open_flag = O_RDONLY;
    log_trap("execveat");
    log_trap(pathname);
    if (flags & ~(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH)) {
        map_unlock_read_all();
        return -EINVAL;
    }
    if (flags & AT_SYMLINK_NOFOLLOW) {
        open_flag |= O_NOFOLLOW;
    }
    int n_path = exam_str((char *)pathname, _pathname);
    pathname = _pathname;
    if (n_path < 0) {
        map_unlock_read_all();
        return n_path;
    }
    if (-100 == dirfd) {
        if (flags & AT_EMPTY_PATH) {
            map_unlock_read_all();
            return -EBADF;
        }
    } else 
        if (dirfd < 0) {
            if (pathname[0] != '/') {
                map_unlock_read_all();
                return -EBADF;
            }
        }
    // TODO: Input value sanitization. You should copy argv and envp and perform exec for input value sanitization.

    if (flags & AT_EMPTY_PATH) {
        int x = rawcall(fcntl, dirfd, F_GETFD);
        if (x < 0) {
            map_unlock_read_all();
            return x;
        }
        snprintf(buf_reopen, 48, "/proc/self/fd/%d", dirfd);
        fd = rawcall(open, buf_reopen, O_RDONLY); //rawcall(openat, dirfd, pathname, O_RDONLY);
#ifdef TOORHC
        // TODO: Check executable?
        if (IS_ERR(fd)) {
            return fd;
        }
        // Check file perm
        if(check_fd_perm(fd) < 0) {
            rawcall(close, fd);
            map_unlock_read_all();
            return -EPERM;
        }
#endif
        fdsem[fd] = 0;
        subscribed[fd] = SAND_FILE;
        snprintf(buf_reopen, 1024, "/dev/fd/%d", fd);
    } else {    
        fd = rawcall(openat, dirfd, pathname, open_flag);
#ifdef TOORHC
        // TODO: Check executable?
        if (IS_ERR(fd)) {
            map_unlock_read_all();
            return fd;
        }
        // Check file perm
        if(check_fd_perm(fd) < 0) {
            rawcall(close, fd);
            map_unlock_read_all();
            return -EPERM;
        }
#endif
        fdsem[fd] = 0;
        subscribed[fd] = SAND_FILE;
        //snprintf(buf_reopen, 1024, "/dev/fd/%d", dirfd, pathname);
        snprintf(buf_reopen, 1024, "/dev/fd/%d", dirfd);
    }
#ifndef TOORHC
    // TODO: Check executable?
    if (IS_ERR(fd)) {
        map_unlock_read_all();
        return fd;
    }
#endif
    int r_exec = do_execve(fd, argv, envp, buf_reopen);
    map_unlock_read_all();
    return r_exec;
}

/*
struct {
    void* addr;
    int size;
    int used;
} shm_buf[32];

SHIM_SYSCALL_EMULATED(shmget, 3, int, key_t, key, size_t, size, int, shmflg) {
    return -ENOSYS;
}

SHIM_SYSCALL_EMULATED(shmctl, 3, int, int, shmid, int, cmd, struct shmid_ds*, buf) {
    return -ENOSYS;
}

SHIM_SYSCALL_EMULATED(shmdt, 1, int, const void*, shmaddr) {
    return -ENOSYS;
    for (int i = 0; i < 32; i++) {
        if (shm_buf[i].addr == shmaddr) {
            if (shm_buf[i].used == 0) {
                return -EINVAL;
            }
            shm_buf[i].used = 0;
            return rawcall(shmdt, shmaddr);
        }
    }
    return -EINVAL;
}

SHIM_SYSCALL_EMULATED(shmat, 3, void*, int, shmid, const void*, shmaddr, int, shmflg) {
    return -ENOSYS;
    map_mode_t m;
    if (shmflg & SHM_RDONLY)
        m = READABLE;
    else
        m = READABLE | WRITABLE;
    
    // get sizeof segment 
    struct shmid_ds buf;
    int ret = rawcall(shmctl, shmid, IPC_STAT, &buf);
    if (ret < 0)
        return ret;
    // IDK, how to get the real size??
    size_t size = 0xf0000; // buf.shm_segsz;
    void* res = 0;
    MEMLOCK;
    if (shmaddr != 0 & !ALIGNED(shmaddr)) {
        if (SHM_RND & shmflg) {
            shmaddr = (void*)ALIGN_DOWN(shmaddr);
        } else {
            MEMUNLOCK;
            return -EINVAL;
        }
    }
    if (shmaddr != 0 && (!map_check_lock(map_addr(shmaddr, shmaddr + size - 1), 0))) {
        res = -EINVAL;
        goto out;
    }
    void* addr = rawcall(shmat, shmid, shmaddr, shmflg);
    if (addr < 0) {
        map_unlock_read_all();
        return addr;
    }
    map_set(map_addr(addr, addr + size - 1), m);
    res = -ENOMEM;
    for (int i = 0; i < 32; i++) {
        // compare and swap atomic
        if (__sync_bool_compare_and_swap(&shm_buf[i].used, 0, 1)) {
            shm_buf[i].size = size;
            shm_buf[i].addr = addr;
            res = addr;
            int mp = rawcall(pkey_mprotect, addr, size, map_prot(m), IV_USER);
            printf("pkey_mprotect(%p, %d, %d, %d) = %d\n", addr, size, map_prot(m), IV_USER, mp);
            goto out;
        }
    }
    rawcall(shmdt, addr);    
out:
    
    map_unlock_read_all();
    MEMUNLOCK;
    return res;
}
*/

int install_seccomp_filter(void* start, void* end);
#ifdef QUEEN
SHIM_SYSCALL_EMULATED(fork, 0, int){
    int f = rawcall(fork);
    if (f == 0) {
        // I'm child
        self = rawcall(getpid);
    }
    return f;
}

#else
SHIM_SYSCALL_EMULATED(fork, 0, int){
    int f = rawcall(fork);
    if (f == 0) {
        // I'm child
        self = rawcall(getpid);

#ifdef DISPATCH
        int ret = 0;
#ifdef FILTERTP
        if((ret = install_seccomp_filter(get_tls()->trampoline, get_tls()->trampoline + 4096)) < 0) {
#else
        extern char code_start;
        extern char code_end;
        if((ret = install_seccomp_filter(&code_start, &code_end)) < 0) {
#endif
        }
#endif
    }
    return f;
}
#endif


#ifdef QUEEN

extern int q_flags;
extern void *q_user_stack_addr;
extern int *q_parent_tidptr;
extern int *q_child_tidptr;
extern void *q_tls;
extern int q_ret;
extern void *q_fs;
extern void *q_gs;
extern void *q_rip;
extern void *q_rsp;

SHIM_SYSCALL_EMULATED(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls) {
    int f;
    if (self < 1)
        self = rawcall(getpid);
    int isvfork = flags & CLONE_VFORK;
    if (isvfork) {
        flags &= ~CLONE_VFORK;
        flags &= ~CLONE_VM;
    }
    // TODO: fix queen thread for vfork
    CLONELOCK;
    q_flags = flags;
    q_user_stack_addr = user_stack_addr;
    q_parent_tidptr = parent_tidptr;
    q_child_tidptr = child_tidptr;
    q_tls = tls;
    if (flags & CLONE_SETTLS)
        q_fs = q_tls;
    else
        rawcall(arch_prctl, ARCH_GET_FS, &q_fs);
    rawcall(arch_prctl, ARCH_GET_GS, &q_gs);
    __asm__ __volatile__("movq %%rsp, %0\n\t" : "=m"(q_rsp) : : );
    __asm__ __volatile__("1: lea 1b(%%rip), %0;": "=a"(q_rip) : :);

    q_rip = &&child_ret_point;      // Ugly hack for the child thread jump to this function, after QRETLOCK, a few lines below
    QUEENUNLOCK;
    QRETLOCK;
    
    f = q_ret;
    CLONEUNLOCK;

    if(f == 0) {
        child_ret_point:
        CLONEUNLOCK;
        self = rawcall(getpid);
        printf("shim_child\n");
    } else {
        printf("shim_parent. %d\n", f);
    }
    return f;
}

#else
#ifdef RANDOM
#define STACKPGSIZE 2
int nexpoline_flag[MAXTHREAD];
int get_nexpoline(void) {
    for(int i = 1 ; i < MAXTHREAD ; i++) {
        if (nexpoline_flag[i] == 0) {
            nexpoline_flag[i] = 1;
            return i;
        }
    }
    return -1;
}

/****************************************************************
 * Randomized Nexpoline structure
 * RTRAMPOLINE_START (1ull<<46) ----- RTRAMPOLINE_END  ((1ull<<46)+(PGSIZE*TRAMPOLINEPGSIZE*MAXTHREAD)
 * We have one seccomp filter that only allows the syscall between RTRAMPOLINE_START and RTRAMPOLINE_END
 * We do not allow user to mmap these region for other use.
 * Each thread is assigned PGSIZE*TRAMPOLINEPGSIZE bytes of the Nexpoline region on thread create
 * The region is free on exit()
 * The radomized trampoline coud jump somewhere inside the region
 *********************************************************************/
void *create_random_nexpoline(int index, iv_tls_t *tls) {
    unsigned long myrandom;
    unsigned int *gadget;
    void *baseaddr;

    baseaddr = (void*)(RTRAMPOLINE_START + (RTRAMPOLINE_PGSIZE * PGSIZE * index));
    unsigned long *trampoline = rawcall(mmap, baseaddr, PGSIZE * RTRAMPOLINE_PGSIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
    for(int i = 0 ; i < PGSIZE * RTRAMPOLINE_PGSIZE / 8 ; i++)
        trampoline[i] = 0xcccccccccccccccc;

    do {
        __asm__ __volatile__ ("rdrand %0\n\t" : "=a" (myrandom) : : );
        myrandom = myrandom & 0xffff;
    } while (myrandom > 0xfffd);

    gadget = (unsigned int*)((unsigned long)baseaddr + myrandom);
    gadget[0] = 0xccc3050f;
    tls->trampoline = (void *)gadget;
    return 0;
}

void load_sigstack();

void child_thread(void) {
    // Child thread jmp to here with "almost" empty stack

    // Get the stackptr and tls from the stack
    register void *rsp asm("rsp");
    unsigned long tls; 
    iv_stack_t *ivs = (iv_stack_t*)*(unsigned long*)(rsp+32);
    iv_tls_t* _tls = &ivs->tls;
    tls = (unsigned long)*(unsigned long*)(rsp + 24);

    // Fill the syscall instruction for this thread (for a while)

    // Set GS value We need to use asm because Nexpoline for the parent could be already removed
    // rawcall(arch_prctl, ARCH_SET_GS, stackptr);
    unsigned long int resultvar;
    register long int _a2 __asm__ ("rsi") = (long  int)(_tls->self);
    register long int _a1 __asm__ ("rdi") = ARCH_SET_GS;
    register long int _a0 __asm__ ("rbx") = (long int)_tls->trampoline;
    __asm__ __volatile__ ("call *%%rbx\n\t"
                        : "=a" (resultvar)
                        : "0" (__NR_arch_prctl), "r"(_a0), "r"(_a1), "r"(_a2), "r"(_a0)
                        : "memory", "cc", "r11", "cx");

    printf("child thread: trampioline=%p\n", _tls->trampoline);
    
    load_sigstack();
    // Set TLS to RDI for the function parameter
    // switch to untrusted and return to thread_start
    // TODO: add check for setting PKRU
    __asm__ __volatile__ ("" : : "D" (tls):);
    __asm__("mov "STR(IV_TLS(untrusted_stack))", %rsp\n\t"
            "xor %ecx, %ecx\n"
            "xor %edx, %edx\n"
            "mov "STR(IV_TLS(current_pkru))", %eax\n"
            ".byte 0x0f, 0x01, 0xef\n"  
            "retq");
    __builtin_unreachable();
}

SHIM_SYSCALL_EMULATED(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls) {
    // Simply copy of Queen's code, not running in Queen
    int f;
    int isvfork = flags & CLONE_VFORK;
    if (isvfork) {
        flags &= ~CLONE_VFORK;
        flags &= ~CLONE_VM;
    }
    if((flags & (CLONE_THREAD | CLONE_VM)) || (isvfork)) {
        iv_stack_t* ivs = create_stack(0);

        // Setup trusted stack of the child
        unsigned long *stackptr;
        stackptr = (unsigned long*)ivs->stack;
        stackptr--;
        *stackptr = (unsigned long)ivs;
        stackptr--;
        *stackptr = (unsigned long)tls;
        stackptr--;
        *stackptr = (unsigned long)child_thread;    // Return address for the child thread

        // Store stack pointer
        iv_tls_t* __tls = (iv_tls_t*)&ivs->tls;
        __tls->base = ivs;
        __tls->top = ivs->end;
        __tls->untrusted_stack = user_stack_addr;
        __tls->self = __tls;
        create_random_nexpoline(get_nexpoline(), __tls);
        __tls->trusted_stack = (void*)ivs->stack;
        __tls->current_pkru = untrusted_pkru;
        __tls->current_domain = DOMAIN_FIELD(2,0);
        //f = rawcall(clone, flags, stackptr, parent_tidptr, child_tidptr, tls);
        // Borrow child's Nexpoline gadget because parent one could be rerandomized before child is created which make child cannot return.
        // So, we jmp to the new child's Nexpoline in asm
        register long int _a5 __asm__ ("r8")  = (long int)tls;
        register long int _a4 __asm__ ("r10") = (long int)child_tidptr;
        register long int _a3 __asm__ ("rdx") = (long int)parent_tidptr;
        register long int _a2 __asm__ ("rsi") = (long int)stackptr;
        register long int _a1 __asm__ ("rdi") = flags;
        register long int _a0 __asm__ ("rbx") = (long int)__tls->trampoline;
        __asm__ __volatile__ ("call *%%rbx\n\t"
                            : "=a" (f)
                            : "0" (__NR_clone), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a0)
                            : "memory", "cc", "r11", "cx");

        printf("parent: %d\n", f);

    } else {
        // fork
        f = rawcall(clone, flags, user_stack_addr, parent_tidptr, child_tidptr, tls);
        if (f == 0) {
            self = rawcall(getpid);
        }
    }
    return f;
}
#else
#ifdef MT
SHIM_SYSCALL_EMULATED(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls) {
    int isvfork = flags & CLONE_VFORK;
    if (isvfork) {
        flags &= ~CLONE_VFORK;
        // flags &= ~CLONE_VM;
    }
    if ((flags & (CLONE_THREAD | CLONE_VM)) || (isvfork) || (user_stack_addr != NULL)) {
        // thread
        iv_tls_t* thread = mt_create_thread(user_stack_addr);
        if (isvfork) {
            iv_lock(&thread->vfork);
        }
        // new rsp will be the pointer to gs
        #ifdef DISPATCH
        #ifndef CFICET
        get_tls()->dispatch = 0;
        #endif
        #endif
        int f = 0;
        {
            unsigned long int resultvar;
            register long int _a5 __asm__ ("r8")  = tls;
            register long int _a4 __asm__ ("r10") = child_tidptr;
            register long int _a3 __asm__ ("rdx") = parent_tidptr;
            register long int _a2 __asm__ ("rsi") = thread->self;
            register long int _a1 __asm__ ("rdi") = flags;
            __asm__ __volatile__ ("syscall"
                                : "=a" (resultvar)
                                : "0" (__NR_clone), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)
                                : "memory", "cc", "r11", "cx", "rbx");
            f = resultvar;
        }
        if (f == 0){
            // I'm child
            asm ("jmp thread_start_asm\n\t");
            __builtin_unreachable();
        } else {
            iv_lock(&thread->vfork);
            iv_unlock(&thread->vfork);
            #ifdef DISPATCH
            #ifndef CFICET
            get_tls()->dispatch = 1;
            #endif
            #endif
        }
        return f;
    } else {
        // fork
        #ifdef DISPATCH
        #ifndef CFICET
        get_tls()->dispatch = 0;
        #endif
        #endif
        int f = rawcall(clone, flags, user_stack_addr, parent_tidptr, child_tidptr, tls);
        if (f == 0) {
            self = rawcall(getpid);
            printf("Cloned %d\n", self);
            int ret = 0;
    
#ifdef DISPATCH
    #ifdef FILTERTP
            if((ret = install_seccomp_filter(get_tls()->trampoline, get_tls()->trampoline + 4096)) < 0) {
    #else
            extern char code_start;
            extern char code_end;
            if((ret = install_seccomp_filter(&code_start, &code_end)) < 0) {
    #endif
            }
#endif
        }
        return f;
    }
}
#else
// if we did nothing for multithread, for test only
SHIM_SYSCALL_PASSTHRU(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls);
#endif
#endif
#endif

#ifdef MEASUREMENT
extern unsigned long *entercount, *exitcount;
#endif

SHIM_SYSCALL_EMULATED(exit, 1, int, int, error_code) {
    // We need to munmap trusted stack which is allocated in clone()
    // But, without stack, you cannot exit, so, we switch to untrusted stack
    // Untrusted stack will be munmap()ed by the parent in pthread_join()
    if (get_tls()->self->vfork != 0) {
        iv_unlock(&get_tls()->self->vfork);
    }
        
    // TODO: free GS, stacks, tls, and maybe Nexpoline
#ifdef MEASUREMENT
    printf("exit: entercount = %ld, exitcount = %ld\n", *entercount, *exitcount);
#endif
    return rawcall(exit, error_code);
}

SHIM_SYSCALL_EMULATED(exit_group, 1, int, int, error_code) {
#ifdef MEASUREMENT
    printf("exit_group: entercount = %ld, exitcount = %ld\n", *entercount, *exitcount);
#endif
    if (get_tls()->self->vfork != 0) {
        iv_unlock(&get_tls()->self->vfork);
    }
    log_trap("exit_group");
    return rawcall(exit_group, error_code);
}


SHIM_SYSCALL_EMULATED(vfork, 0, int){
    int f = rawcall(fork);
    if (f == 0) {
        // I'm child
        self = rawcall(getpid);

#ifdef DISPATCH
        int ret = 0;
#ifdef FILTERTP
        if((ret = install_seccomp_filter(get_tls()->trampoline, get_tls()->trampoline + 4096)) < 0) {
#else
        extern char code_start;
        extern char code_end;
        if((ret = install_seccomp_filter(&code_start, &code_end)) < 0) {
#endif
        }
#endif
    }
    return f;
}



SHIM_SYSCALL_EMULATED(ptrace, 4, int, long, request, pid_t, pid, void*, addr, void*, data) {
    UNUSED(request);
    UNUSED(pid);
    UNUSED(addr);
    UNUSED(data);
    return -1;
}



SHIM_SYSCALL_EMULATED(arch_prctl, 2, void*, int, code, void*, addr) {
    // We do not allow modification of GS register because we are using it
    if (code == ARCH_SET_GS ) {
        return (void*)-EPERM;
    }
    return (void*)rawcall(arch_prctl, code, addr);
}



SHIM_SYSCALL_EMULATED(truncate, 2, int, const char*, path, loff_t, length) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, path, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    if(ret == 0) {
        ret = rawcall(ftruncate, fd, length);
    }
    rawcall(close, fd);
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(truncate, path, length);
#endif
}



SHIM_SYSCALL_EMULATED(ftruncate, 2, int, int, fd, loff_t, length) {
#ifdef TOORHC
    int ret;
    
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ENTERFD(fd);
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(ftruncate, fd, length);
        }
    }
    EXITFD(fd);
    return ret;
#else

    if (fd_check_temporal(0, fd) == 0) {
        return -EPERM;
    }

    return rawcall(ftruncate, fd, length);
#endif
}



SHIM_SYSCALL_EMULATED(flock, 2, int, int, fd, int, cmd) {
#ifdef TOORHC
    int ret;
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ENTERFD(fd);
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(flock, fd, cmd);
        }
    }
    EXITFD(fd);
    return ret;
#else

    if (fd_check_temporal(0, fd) == 0) {
        return -EPERM;
    }

    return rawcall(flock, fd, cmd);
#endif
}



SHIM_SYSCALL_EMULATED(rename, 2, int, const char*, oldname, const char*, newname) {
#ifdef TOORHC
    int ret;
    int fd;
    LINKLOCK;
    fd = rawcall(open, oldname, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret < 0) {
        goto end;
    }

    // Kernel will replace newname, so newname should be accessible too.
    fd = rawcall(open, newname, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret == 0 || ret == -ENOENT) {
        ret = rawcall(rename, oldname, newname);
    }
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(rename, oldname, newname);
#endif
}



SHIM_SYSCALL_EMULATED(unlink, 1, int, const char*, file) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd;
    fd = rawcall(open, file, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret == 0) {
        ret = rawcall(unlink, file);
    }
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(unlink, file);
#endif
}



SHIM_SYSCALL_EMULATED(unlinkat, 3, int, int, dfd, const char*, pathname, int, flag) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, pathname, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(unlinkat, dfd, pathname, flag);
    }
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(unlinkat, dfd, pathname, flag);
#endif
}



// TODO: New name check!!!
SHIM_SYSCALL_EMULATED(renameat, 4, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(olddfd != AT_FDCWD)
        ENTERFD(olddfd);
    if(newdfd != AT_FDCWD)
        ENTERFD(newdfd);
    
    // Check the permission of oldname
    int myfd = rawcall(openat, olddfd, oldname, O_RDONLY);
    // Error on open.
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret != 0) {
        goto end;
    }

    // Check the permission of newname
    
    myfd = rawcall(openat, newdfd, newname, O_RDONLY);
    // Error on open.
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(renameat, olddfd, oldname, newdfd, newname);
    }

end:
    if(newdfd != AT_FDCWD)
        EXITFD(newdfd);
    if(olddfd != AT_FDCWD)
        EXITFD(olddfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(renameat, olddfd, oldname, newdfd, newname);
#endif
}



SHIM_SYSCALL_EMULATED(renameat2, 5, int, int, olddirfd, const char*, oldpath, int, newdirfd, const char*, newpath, unsigned int, flags) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(olddirfd != AT_FDCWD)
        ENTERFD(olddirfd);
    if(newdirfd != AT_FDCWD)
        ENTERFD(newdirfd);

    // Check the permission of oldname
    int myfd = rawcall(openat, olddirfd, oldpath, O_RDONLY);
    // Error on open.
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret != 0) {
        goto end;
    }

    // Check the permission of newname
    myfd = rawcall(openat, newdirfd, newpath, O_RDONLY);
    // Error on open.
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);

    if(ret == 0) {
        ret = rawcall(renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
    }

end:
    if(newdirfd != AT_FDCWD)
        EXITFD(newdirfd);
    if(olddirfd != AT_FDCWD)
        EXITFD(olddirfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
#endif
}



SHIM_SYSCALL_EMULATED(chmod, 2, int, const char*, filename, mode_t, mode) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, filename, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    if(ret == 0) {
        ret = rawcall(fchmod, fd, mode);
    }
    rawcall(close, fd);
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(chmod, filename, mode);
#endif
}



SHIM_SYSCALL_EMULATED(fchmod, 2, int, int, fd, mode_t, mode) {
#ifdef TOORHC
    int ret;
    ENTERFD(fd);
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(fchmod, fd, mode);
        }
    }
    EXITFD(fd);
    return ret;
#else

    if (fd_check_temporal(0, fd) == 0) {
        return -EPERM;
    }

    return rawcall(fchmod, fd, mode);
#endif
}



SHIM_SYSCALL_EMULATED(fchmodat, 3, int, int, dfd, const char*, filename, mode_t, mode) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, filename, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    if(ret == 0) {
        ret = rawcall(fchmod, myfd, mode);
    }
    rawcall(close, myfd);
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(fchmodat, dfd, filename, mode);
#endif
}



SHIM_SYSCALL_EMULATED(chown, 3, int, const char*, filename, uid_t, user, gid_t, group) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, filename, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    if(ret == 0) {
        ret = rawcall(fchown, fd, user, group);
    }
    rawcall(close, fd);
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(chown, filename, user, group);
#endif
}



SHIM_SYSCALL_EMULATED(fchown, 3, int, int, fd, uid_t, user, gid_t, group) {
#ifdef TOORHC
    int ret;
    ENTERFD(fd);
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(fchown, fd, user, group);
        }
    }
    EXITFD(fd);
    return ret;
#else
    return rawcall(fchown, fd, user, group);
#endif
}



SHIM_SYSCALL_EMULATED(fchownat, 5, int, int, dfd, const char*, filename, uid_t, user, gid_t, group, int, flag) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, filename, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(fchownat, dfd, filename, user, group, flag);
    }
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(fchownat, dfd, filename, user, group, flag);
#endif
}



SHIM_SYSCALL_EMULATED(lchown, 3, int, const char*, filename, uid_t, user, gid_t, group) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = check_link_perm(filename);
    if(ret == 0) {
        ret = rawcall(lchown, filename, user, group);
    }
    LINKUNLOCK;
    return ret;
#else
    return rawcall(lchown, filename, user, group);
#endif
}



SHIM_SYSCALL_EMULATED(setxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags) {
#ifdef TOORHC
    int ret;

    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    LINKLOCK;
    int fd;
    fd = rawcall(open, path, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    if(ret == 0) {
        ret = rawcall(fsetxattr, fd, name, value, size, flags);
    }
    rawcall(close, fd);
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(setxattr, path, name, value, size, flags);
#endif
}



SHIM_SYSCALL_EMULATED(lsetxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags) {
#ifdef TOORHC
    int ret;
    
    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    LINKLOCK;
    ret = check_link_perm(path);
    if(ret == 0) {
        ret = rawcall(lsetxattr, path, name, value, size, flags);
    }
    LINKUNLOCK;
    return ret;
#else
    return rawcall(lsetxattr, path, name, value, size, flags);
#endif
}



SHIM_SYSCALL_EMULATED(fsetxattr, 5, int, int, fd, const char*, name, const void*, value, size_t, size, int, flags) {
#ifdef TOORHC
    int ret;
    
    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    ENTERFD(fd);
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(fsetxattr, fd, name, value, size, flags);
        }
    }
    EXITFD(fd);
    return ret;
#else
    return rawcall(fsetxattr, fd, name, value, size, flags);
#endif
}



SHIM_SYSCALL_EMULATED(removexattr, 2, int, const char*, path, const char*, name) {
#ifdef TOORHC
    int ret;
    
    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    LINKLOCK;
    int fd = rawcall(open, path, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    if(ret == 0) {
        ret = rawcall(fremovexattr, fd, name);
    }
    rawcall(close, fd);
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(removexattr, path, name);
#endif
}



SHIM_SYSCALL_EMULATED(lremovexattr, 2, int, const char*, path, const char*, name) {
#ifdef TOORHC
    int ret;
    
    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    LINKLOCK;
    ret = check_link_perm(path);
    if(ret == 0) {
        ret = rawcall(lremovexattr, path, name);
    }
    LINKUNLOCK;
    return ret;
#else
    return rawcall(lremovexattr, path, name);
#endif
}



SHIM_SYSCALL_EMULATED(fremovexattr, 2, int, int, fd, const char*, name) {
#ifdef TOORHC
    int ret;
    
    // Sandbox domain channot set extended attribute
    int dom = get_domain(get_tls()->current_pkru);
    if(dom >= min_sandbox) {
        return -EPERM;
    }
    ENTERFD(fd);
    if (fd < 0 || fd >= 4096 || subscribed[fd] == NO_FILE) {
        ret = -EBADF;
    } else {
        ret = check_fd_perm(fd);
        if(ret == 0) {
            ret = rawcall(fremovexattr, fd, name);
        }
    }
    EXITFD(fd);
    return ret;
#else
    return rawcall(fremovexattr, fd, name);
#endif
}



SHIM_SYSCALL_EMULATED(utime, 2, int, char*, filename, struct utimbuf*, times) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, filename, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret == 0) {
        ret = rawcall(utime, filename, times);
    }
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(utime, filename, times);
#endif
}



SHIM_SYSCALL_EMULATED(utimes, 2, int, char*, filename, struct timeval*, utimes) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, filename, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret == 0) {
        ret = rawcall(utimes, filename, utimes);
    }
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(utimes, filename, utimes);
#endif
}



SHIM_SYSCALL_EMULATED(futimesat, 3, int, int, dfd, const char*, filename, struct timeval*, utimes) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, filename, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(futimesat, dfd, filename, utimes);
    }
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(futimesat, dfd, filename, utimes);
#endif
}



SHIM_SYSCALL_EMULATED(utimensat, 4, int, int, dfd, const char*, filename, struct timespec*, utimes, int, flags) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, filename, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(utimensat, dfd, filename, utimes, flags);
    }
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(utimensat, dfd, filename, utimes, flags);
#endif
}



SHIM_SYSCALL_EMULATED(chdir, 1, int, const char*, filename) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = rawcall(chdir, filename);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(chdir, filename);
#endif
}



SHIM_SYSCALL_EMULATED(fchdir, 1, int, int, fd) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = rawcall(fchdir, fd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(fchdir, fd);
#endif
}



SHIM_SYSCALL_EMULATED(link, 2, int, const char*, oldname, const char*, newname){
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = rawcall(link, oldname, newname);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(link, oldname, newname);
#endif
}



SHIM_SYSCALL_EMULATED(linkat, 5, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname, int, flags){
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(olddfd != AT_FDCWD)
        ENTERFD(olddfd);
    int myfd = rawcall(openat, olddfd, oldname, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    // Thank god, linkat does not overwrite newname, so we do not need to check perm.
    if(ret == 0) {
        ret = rawcall(linkat, olddfd, oldname, newdfd, newname, flags);
    }
end:
    if(olddfd != AT_FDCWD)
        EXITFD(olddfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(linkat, olddfd, oldname, newdfd, newname, flags);
#endif
}



SHIM_SYSCALL_EMULATED(symlink, 2, int, const char*, old, const char*, new){
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = rawcall(symlink, old, new);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(symlink, old, new);
#endif
}



SHIM_SYSCALL_EMULATED(symlinkat, 3, int, const char*, oldname, int, newdfd, const char*, newname) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    ret = rawcall(symlinkat, oldname, newdfd, newname);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(symlinkat, oldname, newdfd, newname);
#endif
}



SHIM_SYSCALL_EMULATED(access, 2, int, const char*, file, mode_t, mode) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    int fd = rawcall(open, file, O_RDONLY);
    if(fd < 0) {
        ret = fd;
        goto end;
    }
    ret = check_fd_perm(fd);
    rawcall(close, fd);
    if(ret == 0) {
        ret = rawcall(access, file, mode);
    }
end:
    LINKUNLOCK;
    return ret;
#else
    return rawcall(access, file, mode);
#endif
}



SHIM_SYSCALL_EMULATED(faccessat, 3, int, int, dfd, const char*, filename, int, mode) {
#ifdef TOORHC
    int ret;
    LINKLOCK;
    if(dfd != AT_FDCWD)
        ENTERFD(dfd);
    int myfd = rawcall(openat, dfd, filename, O_RDONLY);
    if(myfd < 0) {
        ret = myfd;
        goto end;
    }
    ret = check_fd_perm(myfd);
    rawcall(close, myfd);
    if(ret == 0) {
        ret = rawcall(faccessat, dfd, filename, mode);
    }
end:
    if(dfd != AT_FDCWD)
        EXITFD(dfd);
    LINKUNLOCK;
    return ret;
#else
    return rawcall(faccessat, dfd, filename, mode);
#endif
}



// We need to emulate all syscalls which open a new file descripter even though we are not interested in the syscalls themselves.
// If not, read and write will not work properly for those file descriptors which are opened by those syscalls.
SHIM_SYSCALL_EMULATED(accept, 3, int, int, fd, struct sockaddr*, addr, socklen_t*, addrlen) {
    long res;
    
    if (fd_check_temporal(0, fd) == 0) {
        return -EPERM;
    }

    res = rawcall(accept, fd, addr, addrlen);
    if(res >= 0) {
        subscribed[res] = SAND_FILE;
        fdsem[res] = 0;
    }
    return res;
}

SHIM_SYSCALL_EMULATED(accept4, 4, int, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen, int, flags)
{
    long res;
    
    if (fd_check_temporal(0, sockfd) == 0) {
        return -EPERM;
    }

    res = rawcall(accept4, sockfd, addr, addrlen, flags);
    if(res >= 0) {
        subscribed[res] = SAND_FILE;
        fdsem[res] = 0;
    }
    return res;
}

SHIM_SYSCALL_EMULATED(socket, 3, int, int, family, int, type, int, protocol) {
    int res;
    res = rawcall(socket, family, type, protocol);
    if(res >= 0) {
        subscribed[res] = SAND_FILE;
        fdsem[res] = 0;
    }
    return res;
}

SHIM_SYSCALL_EMULATED(memfd_create, 2, int, const char*, name, unsigned int, flags) {
    int fd = rawcall(memfd_create, name, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;

}

SHIM_SYSCALL_EMULATED(pipe, 1, int, int*, fildes) {
    int res;
    res = rawcall(pipe, fildes);
    if(res == 0) {
        subscribed[fildes[0]] = SAND_FILE;
        subscribed[fildes[1]] = SAND_FILE;
        fdsem[fildes[0]] = 0;
        fdsem[fildes[1]] = 0;
    }
    return res;
}

SHIM_SYSCALL_EMULATED(pipe2, 2, int, int*, fildes, int, flags) {
    int res;
    res = rawcall(pipe2, fildes, flags);
    if(res == 0) {
        subscribed[fildes[0]] = SAND_FILE;
        subscribed[fildes[1]] = SAND_FILE;
        fdsem[fildes[0]] = 0;
        fdsem[fildes[1]] = 0;
    }
    return res;
}


SHIM_SYSCALL_EMULATED(perf_event_open, 5, int, struct perf_event_attr*, attr_uptr, pid_t, pid, int, cpu, int, group_fd, int, flags) {
    int fd = rawcall(perf_event_open, attr_uptr, pid, cpu, group_fd, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(select, 5, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, struct __kernel_timeval*, timeout) {
    int fd = rawcall(select, nfds, readfds, writefds, errorfds, timeout);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(pselect6, 6, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, const struct __kernel_timespec*, tsp, const __sigset_t*, sigmask) {
    int fd = rawcall(pselect6, nfds, readfds, writefds, errorfds, tsp, sigmask);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(inotify_init, 0, int) {
    int fd = rawcall(inotify_init);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(inotify_init1, 1, int, int, flags) {
    int fd = rawcall(inotify_init1, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(eventfd, 1, int, int, count) {
    int fd = rawcall(eventfd, count);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(eventfd2, 2, int, int, count, int, flags) {
    int fd = rawcall(eventfd2, count, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(epoll_create, 1, int, int, size) {
    int fd = rawcall(epoll_create, size);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(epoll_create1, 1, int, int, flags) {
    int fd = rawcall(epoll_create1, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(timerfd_create, 2, int, int, clockid, int, flags) {
    int fd = rawcall(timerfd_create, clockid, flags);
    if(fd >= 0) {
        subscribed[fd] = SAND_FILE;
        fdsem[fd] = 0;
    }
    return fd;
}

SHIM_SYSCALL_EMULATED(socketpair, 4, int, int, domain, int, type, int, protocol, int*, sv) {
    int res;
    res = rawcall(socketpair, domain, type, protocol, sv);
    if(res == 0) {
        subscribed[sv[0]] = SAND_FILE;
        subscribed[sv[1]] = SAND_FILE;
        fdsem[sv[0]] = 0;
        fdsem[sv[1]] = 0;
    }
    return res;
}

int domain_id_safebox = min_safebox;
int domain_id_sandbox = min_sandbox;

#define __NR_iv_domain_safe 333
SHIM_SYSCALL_EMULATED(iv_domain_safe, 1, int, const char*, buf) {
    IV_DBG();
    if (!buf) {
        // prevent further loading
        domain_id_safebox = 16;
        domain_id_sandbox = 16;
        return -1;
    }
    int cur_id = __atomic_fetch_add(&domain_id_safebox, 1, __ATOMIC_SEQ_CST);
    if (cur_id > max_safebox) {
        domain_id_safebox = 16;
        return -1;
    }
    install_app(buf,cur_id, 1);
    return cur_id;
}

#define __NR_iv_domain_sand 334
SHIM_SYSCALL_EMULATED(iv_domain_sand, 1, int, const char*, buf) {
    IV_DBG();
    int cur_id = __atomic_fetch_add(&domain_id_sandbox, 1, __ATOMIC_SEQ_CST);
    if (cur_id > max_sandbox) {
        domain_id_sandbox = 16;
        return -1;
    }
    install_app(buf,cur_id, 0);
    return cur_id;
}

#define __NR_iv_domain_lib 335
SHIM_SYSCALL_EMULATED(iv_domain_lib, 2, int, const char*, elf, int*, addr) {
    IV_DBG();
    int cur_id = __atomic_fetch_add(&domain_id_safebox, 1, __ATOMIC_SEQ_CST);
    if (cur_id > max_sandbox) {
        domain_id_safebox = 16;
        return -1;
    }
    usingAppV2 = 1;
    install_app2(cur_id, elf, addr);
    return cur_id;
}



// Baseline policy for memory domain change
// 1. Sandbox domain is not allowed
// 2. All other domains can change as long as the target memory is accessible and the target domain is mappable.
#define __NR_iv_change_mem_domain 336
SHIM_SYSCALL_EMULATED(iv_change_mem_domain, 3, int, void*, addr, size_t, size, int, target_domain) {
printf("Memory domain change requested: %p, %ld\n", addr, size);
    // Verify input
    if ((unsigned long)addr & 0xfff || size & 0xfff) {
        return -1;
    }
    if(target_domain > 15 || target_domain < 0) {
        return -1;
    }
    
    // Get the caller domain and disallow if it's from sandbox
    unsigned int current_pkru = get_tls()->current_pkru;
    unsigned int current_sdomain = DOMAIN_DID(get_tls()->current_domain); //get_domain(current_pkru);
    
    // Get the domain of the current pkru
    if (id_box[current_sdomain] == SAND) {   // It's sandbox domain
        return -EACCES;
    }
    
    MEMLOCK;
    // Check the mem page's current domain
    map_addr_t adr = map_addr(addr, addr + size - 1);
    map_mode_t mode = map_get(adr);
    if (mode == 0) {    // Invalid mem
        return -EINVAL;
    }

    // If the memory is not accessible
    if(!map_check_lock(adr, 0)) {
        return -EACCES;
    }

    // If the caller domain cannot map a page into the target domain
    if(unlikely(!app_allow_outer_promote(target_domain) && (PKEY_KEY(current_pkru, target_domain) == 0))) {
        return -EACCES;
    }

    // Get the prot
    int prot = 0;
    if (mode & EXECUTABLE)
        prot = PROT_EXEC;
    if (mode & READABLE)
        prot = prot | PROT_READ;
    if (mode & WRITABLE)
        prot = prot | PROT_WRITE;
    
    rawcall(pkey_mprotect, addr, size, prot, target_domain);
    if (target_domain != IV_USER)
        map_set(adr, mode | APP(target_domain));
    else
        map_set(adr, mode);

    MEMUNLOCK;
    return 0;
}

SHIM_SYSCALL_EMULATED(connect, 3, int, int, sockfd, struct sockaddr*, addr, int, addrlen) {
    return rawcall(connect, sockfd, addr, addrlen);
}


#ifdef TOORHC
#define __NR_endo_toorhc 337
int toorhclock = 0;
SHIM_SYSCALL_EMULATED(endo_toorhc, 2, int, int, domain_id, char*, path) {
    int ret;

   
    // Only safebox domain can call this
    int dom = get_domain(get_tls()->current_pkru);

    IV_DBG("endo_toorhc(%d, %s) from domain %d", domain_id, path, dom);

//   if(dom > max_safebox || dom < min_safebox) {
//        return -EPERM;
//    }
    if(domain_id == 0) {
        domain_id = dom;
    }

    
    // Let's open it
    struct stat stat_dir;
    int fd = rawcall(open, path, O_RDONLY);
    if(fd < 0) {
        return fd;
    }
    subscribed[fd] = SAND_FILE;

    // Check whether the path is a directory.
    rawcall(fstat, fd, &stat_dir);
    if((stat_dir.st_mode & S_IFMT) != S_IFDIR) {
        printf("Only Directory could be protected!\n");
        ret = -EINVAL;
        goto end;
    }

    // Get the actual path by reading /proc/self/fd/[FD]
    char fdpath[20];
    memcpy(fdpath, "/proc/self/fd/", 14);
    
    // Local crappy itoa
    int ptr;    
    if(fd < 10) {
        ptr = 15;
    } else if(fd < 100) {
        ptr = 16;
    } else if(fd < 1000) {
        ptr = 17;
    } else if(fd < 4096) {
        ptr = 18;
    } else {
        ret = -EFAULT;
        goto end;
    }
    int tmpfd = fd;
    fdpath[ptr--] = 0;
    while(tmpfd > 0) {
        fdpath[ptr--] = (tmpfd % 10) + '0';
        tmpfd /= 10;
    }
    iv_lock(&toorhclock);
    if(iv_toorhc == NULL) {
        iv_toorhc = (struct toorhc*)rawcall(mmap, NULL, PGSIZE * 8, 
                        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
        top = (void*)((unsigned long)iv_toorhc + PGSIZE);
    }
    ret = rawcall(readlink, fdpath, top, 1024); // TODO: Could be buffer overflow
    if(ret < 0) {
        goto end;
    }
    iv_toorhc[toorhcsize].domainid = domain_id;
    iv_toorhc[toorhcsize].path = top;
    iv_toorhc[toorhcsize].path[ret] = '/';
    iv_toorhc[toorhcsize].pathsize = ret + 1;
    top += iv_toorhc[toorhcsize].pathsize + 2;
    toorhcsize++;
    iv_unlock(&toorhclock);

end:
    rawcall(close, fd);
    subscribed[fd] = NO_FILE;
    return ret;
}
#endif


#define __NR_iv_domain_temp 338
int temp_once = 0;
SHIM_SYSCALL_EMULATED(iv_domain_temp, 1, int, const char*, buf) {
    IV_DBG();
    int cur_id = 14; // install it on temp domain
    if (temp_once) return -1;
    temp_once = 1;
    install_app(buf, cur_id, 1);
    return cur_id;
}

#define __NR_iv_empty 339
SHIM_SYSCALL_EMULATED(iv_empty, 0, int) {
    return 0;
}
#define __NR_iv_force_getppid 340
SHIM_SYSCALL_EMULATED(iv_force_getppid, 0, int) {
    return rawcall(getppid);
}

#define __NR_iv_set_tdomain_info 341
SHIM_SYSCALL_EMULATED(iv_set_tdomain_info, 4, int, void*, newpool, void**, funclist, void*, start, void*, end) {
#ifdef SYSCALLFILTER
    if (pool0)
        return -1; // already set
    pool0 = newpool;
    for (int i = 0; ; i++) {
        if (funclist[i] == NULL)
            break;
        syscall_cbs[i] = funclist[i];
    }
    if (start) {
        map_set(map_addr(start, end - 1), TRUSTED_MEM);
        rawcall(pkey_mprotect, start, (long)end - (long)start, PROT_EXEC | PROT_READ, IV_CONF);
    }
    return 0;
#endif
    return -1;
}

#define __NR_iv_set_tdomain_filter 342
SHIM_SYSCALL_EMULATED(iv_set_tdomain_filter, 1, int, int, id) {
#ifdef SYSCALLFILTER
    if (id >= 0 && id < SYSCALLNR)
        syscall_filter[id] = 1;
    return 0;
#endif
    return -1;
}

#ifdef SYSCALLFILTER

iv_syscall_t rawcalls[] = {
    (iv_syscall_t)_syscall0,
    (iv_syscall_t)_syscall1,
    (iv_syscall_t)_syscall2,
    (iv_syscall_t)_syscall3,
    (iv_syscall_t)_syscall4,
    (iv_syscall_t)_syscall5,
    (iv_syscall_t)_syscall6,
};

static int fd_check_temporal_s(int sysno, int fd) {
    if (!pool0) return 1;
    int tid = get_tdomain();
    if (tid == 0) return 1;
    while (tid) {
        temporal_ctx_t* ctx = tid2ctx(tid);
        if (ctx->fd_cb_n > 0 && ctx->fd_cb_n <= 128 && syscall_cbs[ctx->fd_cb_n - 1]) {
            if (((fd_cb_t)syscall_cbs[ctx->fd_cb_n - 1])(ctx, sysno, fd, (iv_syscall_t*) rawcalls) == 0) {
                printf("fd check %d failed for tid = %d\n", fd, tid);
                return 0;
            }
        }
        tid = ctx->parent;
    }
    return 1;
}

int syscall_before (int sysno, int nr, SHIM_ARG_TYPE *ret,...) {
    if (!pool0) return 0;
    int tid = get_tdomain();
    if (tid == 0) return 0;
    va_list args;
    syscall_req_t req;
    // printf("syscall_before %d tid = %d\n", sysno, tid);
    if (nr > 0 && nr <= 6) {
        va_start(args, ret);
        for (int i = 0; i < nr; i++) 
            req.args[i] = va_arg(args, long);
        va_end(args);
        req.ret = 0;
    }
    req.syscall_table = (iv_syscall_t*) rawcalls;
    while (tid) {
        temporal_ctx_t* ctx = tid2ctx(tid);
        if (ctx->pre_syscall_cb_n > 0 && ctx->pre_syscall_cb_n <= 128 && syscall_cbs[ctx->pre_syscall_cb_n - 1]) {
            if (syscall_cbs[ctx->pre_syscall_cb_n - 1](ctx, sysno, &req)) {
                *ret = req.ret;
                return 1;
            }
        }
        tid = ctx->parent;
    }
    return 0;
}

long syscall_after (int sysno, int nr, SHIM_ARG_TYPE ret, ...) {
    if (!pool0) return 0;
    int tid = get_tdomain();
    if (tid == 0) return ret;
    va_list args;
    syscall_req_t req;
    
    if (nr > 0 && nr <= 6) {
        va_start(args, ret);
        for (int i = 0; i < nr; i++)
            req.args[i] = va_arg(args, long);
        va_end(args);
    }

    req.ret = ret;
    req.syscall_table = (iv_syscall_t*) rawcalls;
    while (tid) {
        temporal_ctx_t* ctx = tid2ctx(tid);
        //printf("syscall_after: ctx = %p\n", ctx);
        //printf("post_syscall_cb_n: cb_n = %p\n", ctx->post_syscall_cb_n);
        //printf("post_syscall_cb_n: syscall_cbs[ctx->post_syscall_cb_n - 1] = %p\n", syscall_cbs[ctx->post_syscall_cb_n - 1]);
       // asm("int3");
        if (ctx->post_syscall_cb_n > 0 && ctx->post_syscall_cb_n <= 128 && syscall_cbs[ctx->post_syscall_cb_n - 1]) {
            if (syscall_cbs[ctx->post_syscall_cb_n - 1](ctx, sysno, &req)) {
                return req.ret;
            }
        }
        tid = ctx->parent;
    }
    return req.ret;
}

#endif
