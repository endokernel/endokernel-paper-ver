#include <shim_syscalls.h>

long passthrough_unreachable() {
    rawcall(exit, 0);
}

//SHIM_SYSCALL_PASSTHRU(read, 3, size_t, int, fd, void*, buf, size_t, count)

//SHIM_SYSCALL_PASSTHRU(write, 3, size_t, int, fd, const void*, buf, size_t, count)

//SHIM_SYSCALL_PASSTHRU(open, 3, int, const char*, file, int, flags, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(close, 1, int, int, fd)

SHIM_SYSCALL_PASSTHRU(stat, 2, int, const char*, file, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHRU(fstat, 2, int, int, fd, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHRU(lstat, 2, int, const char*, file, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHRU(poll, 3, int, struct pollfd*, fds, nfds_t, nfds, int, timeout)

//SHIM_SYSCALL_PASSTHRU(lseek, 3, off_t, int, fd, off_t, offset, int, origin)

//SHIM_SYSCALL_PASSTHRU(mmap, 6, void*, void*, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)

//SHIM_SYSCALL_PASSTHRU(mprotect, 3, int, void*, addr, size_t, len, int, prot)

//SHIM_SYSCALL_PASSTHRU(munmap, 2, int, void*, addr, size_t, len)

//SHIM_SYSCALL_PASSTHRU(brk, 1, void*, void*, brk)

//SHIM_SYSCALL_PASSTHRU(rt_sigaction, 4, int, int, signum, const struct __kernel_sigaction*, act, struct __kernel_sigaction*, oldact, size_t, sigsetsize)

//SHIM_SYSCALL_PASSTHRU(rt_sigprocmask, 3, int, int, how, const __sigset_t*, set, __sigset_t*, oldset)

//SHIM_SYSCALL_PASSTHRU(rt_sigreturn, 1, int, int, __unused)

//SHIM_SYSCALL_PASSTHRU(ioctl, 3, int, int, fd, int, cmd, unsigned long, arg)

//SHIM_SYSCALL_PASSTHRU(pread64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos)

//SHIM_SYSCALL_PASSTHRU(pwrite64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos)

//SHIM_SYSCALL_PASSTHRU(readv, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen)

//SHIM_SYSCALL_PASSTHRU(writev, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen)

//SHIM_SYSCALL_PASSTHRU(access, 2, int, const char*, file, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(pipe, 1, int, int*, fildes)

//SHIM_SYSCALL_PASSTHRU(select, 5, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, struct __kernel_timeval*, timeout)

SHIM_SYSCALL_PASSTHRU(sched_yield, 0, int)

//SHIM_SYSCALL_PASSTHRU(mremap, 5, void*, void*, addr, size_t, old_len, size_t, new_len, int, flags, void*, new_addr)

SHIM_SYSCALL_PASSTHRU(msync, 3, int, void*, start, size_t, len, int, flags)

SHIM_SYSCALL_PASSTHRU(mincore, 3, int, void*, start, size_t, len, unsigned char*, vec)

SHIM_SYSCALL_PASSTHRU(madvise, 3, int, void*, start, size_t, len, int, behavior)

SHIM_SYSCALL_PASSTHRU(shmget, 3, int, key_t, key, size_t, size, int, shmflg)

SHIM_SYSCALL_PASSTHRU(shmat, 3, void*, int, shmid, const void*, shmaddr, int, shmflg)

SHIM_SYSCALL_PASSTHRU(shmctl, 3, int, int, shmid, int, cmd, struct shmid_ds*, buf) // TODO:should we also consdier this call?

//SHIM_SYSCALL_PASSTHRU(dup, 1, int, int, fd)

//SHIM_SYSCALL_PASSTHRU(dup2, 2, int, int, oldfd, int, newfd)

SHIM_SYSCALL_PASSTHRU(pause, 0, int)

SHIM_SYSCALL_PASSTHRU(nanosleep, 2, int, const struct __kernel_timespec*, rqtp, struct __kernel_timespec*, rmtp)

SHIM_SYSCALL_PASSTHRU(getitimer, 2, int, int, which, struct __kernel_itimerval*, value)

// SHIM_SYSCALL_PASSTHRU(alarm, 1, int, unsigned int, seconds)

SHIM_SYSCALL_PASSTHRU(setitimer, 3, int, int, which, struct __kernel_itimerval*, value, struct __kernel_itimerval*, ovalue)

SHIM_SYSCALL_PASSTHRU(getpid, 0, pid_t)

//SHIM_SYSCALL_PASSTHRU(sendfile, 4, ssize_t, int, out_fd, int, in_fd, off_t*, offset, size_t, count)

//SHIM_SYSCALL_PASSTHRU(socket, 3, int, int, family, int, type, int, protocol)

//SHIM_SYSCALL_PASSTHRU(connect, 3, int, int, sockfd, struct sockaddr*, addr, int, addrlen)

//SHIM_SYSCALL_PASSTHRU(accept, 3, int, int, fd, struct sockaddr*, addr, socklen_t*, addrlen)

SHIM_SYSCALL_PASSTHRU(sendto, 6, ssize_t, int, fd, const void*, buf, size_t, len, int, flags, const struct sockaddr*, dest_addr, socklen_t, addrlen)

SHIM_SYSCALL_PASSTHRU(recvfrom, 6, ssize_t, int, fd, void*, buf, size_t, len, int, flags, struct sockaddr*, addr, socklen_t*, addrlen)

SHIM_SYSCALL_PASSTHRU(bind, 3, int, int, sockfd, struct sockaddr*, addr, socklen_t, addrlen)

SHIM_SYSCALL_PASSTHRU(listen, 2, int, int, sockfd, int, backlog)

SHIM_SYSCALL_PASSTHRU(sendmsg, 3, ssize_t, int, fd, struct msghdr*, msg, int, flags)

SHIM_SYSCALL_PASSTHRU(recvmsg, 3, ssize_t, int, fd, struct msghdr*, msg, int, flags)

SHIM_SYSCALL_PASSTHRU(shutdown, 2, int, int, sockfd, int, how)

SHIM_SYSCALL_PASSTHRU(getsockname, 3, int, int, sockfd, struct sockaddr*, addr, int*, addrlen)

SHIM_SYSCALL_PASSTHRU(getpeername, 3, int, int, sockfd, struct sockaddr*, addr, int*, addrlen)

//SHIM_SYSCALL_PASSTHRU(socketpair, 4, int, int, domain, int, type, int, protocol, int*, sv)

//SHIM_SYSCALL_PASSTHRU(setsockopt, 5, int, int, fd, int, level, int, optname, char*, optval, int, optlen)

SHIM_SYSCALL_PASSTHRU(getsockopt, 5, int, int, fd, int, level, int, optname, char*, optval, int*, optlen)

//SHIM_SYSCALL_PASSTHRU(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls)

//SHIM_SYSCALL_PASSTHRU(fork, 0, int)

//SHIM_SYSCALL_PASSTHRU(execve, 3, int, const char*, file, const char**, argv, const char**, envp)

//SHIM_SYSCALL_PASSTHRU(exit, 1, int, int, error_code)

SHIM_SYSCALL_PASSTHRU(wait4, 4, pid_t, pid_t, pid, int*, stat_addr, int, option, struct __kernel_rusage*, ru)

//SHIM_SYSCALL_PASSTHRU(kill, 2, int, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHRU(uname, 1, int, struct old_utsname*, buf)

SHIM_SYSCALL_PASSTHRU(semget, 3, int, key_t, key, int, nsems, int, semflg)

SHIM_SYSCALL_PASSTHRU(semop, 3, int, int, semid, struct sembuf*, sops, unsigned int, nsops)

SHIM_SYSCALL_PASSTHRU(semctl, 4, int, int, semid, int, semnum, int, cmd, unsigned long, arg)

SHIM_SYSCALL_PASSTHRU(shmdt, 1, int, const void*, shmaddr)

SHIM_SYSCALL_PASSTHRU(msgget, 2, int, key_t, key, int, msgflg)

SHIM_SYSCALL_PASSTHRU(msgsnd, 4, int, int, msqid, const void*, msgp, size_t, msgsz, int, msgflg)

SHIM_SYSCALL_PASSTHRU(msgrcv, 5, int, int, msqid, void*, msgp, size_t, msgsz, long, msgtyp, int, msgflg)

//SHIM_SYSCALL_PASSTHRU(msgctl, 3, int, int, msqid, int, cmd, struct msqid_ds*, buf)

//SHIM_SYSCALL_PASSTHRU(fcntl, 3, int, int, fd, int, cmd, unsigned long, arg)

//SHIM_SYSCALL_PASSTHRU(flock, 2, int, int, fd, int, cmd)

SHIM_SYSCALL_PASSTHRU(fsync, 1, int, int, fd)

SHIM_SYSCALL_PASSTHRU(fdatasync, 1, int, int, fd)

// SHIM_SYSCALL_PASSTHRU(truncate, 2, int, const char*, path, loff_t, length)

// SHIM_SYSCALL_PASSTHRU(ftruncate, 2, int, int, fd, loff_t, length)

SHIM_SYSCALL_PASSTHRU(getdents, 3, size_t, int, fd, struct linux_dirent*, buf, size_t, count)

SHIM_SYSCALL_PASSTHRU(getcwd, 2, int, char*, buf, size_t, size)

//SHIM_SYSCALL_PASSTHRU(chdir, 1, int, const char*, filename)

//SHIM_SYSCALL_PASSTHRU(fchdir, 1, int, int, fd)

//SHIM_SYSCALL_PASSTHRU(rename, 2, int, const char*, oldname, const char*, newname)

SHIM_SYSCALL_PASSTHRU(mkdir, 2, int, const char*, pathname, int, mode)

SHIM_SYSCALL_PASSTHRU(rmdir, 1, int, const char*, pathname)

//SHIM_SYSCALL_PASSTHRU(creat, 2, int, const char*, path, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(link, 2, int, const char*, oldname, const char*, newname)

//SHIM_SYSCALL_PASSTHRU(unlink, 1, int, const char*, file)

//SHIM_SYSCALL_PASSTHRU(symlink, 2, int, const char*, old, const char*, new)

SHIM_SYSCALL_PASSTHRU(readlink, 3, int, const char*, path, char*, buf, size_t, bufsize)

//SHIM_SYSCALL_PASSTHRU(chmod, 2, int, const char*, filename, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(fchmod, 2, int, int, fd, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(chown, 3, int, const char*, filename, uid_t, user, gid_t, group)

//SHIM_SYSCALL_PASSTHRU(fchown, 3, int, int, fd, uid_t, user, gid_t, group)

//SHIM_SYSCALL_PASSTHRU(lchown, 3, int, const char*, filename, uid_t, user, gid_t, group)

SHIM_SYSCALL_PASSTHRU(umask, 1, mode_t, mode_t, mask)

SHIM_SYSCALL_PASSTHRU(gettimeofday, 2, int, struct __kernel_timeval*, tv, struct __kernel_timezone*, tz)

SHIM_SYSCALL_PASSTHRU(getrlimit, 2, int, int, resource, struct __kernel_rlimit*, rlim)

SHIM_SYSCALL_PASSTHRU(getrusage, 2, int, int, who, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHRU(sysinfo, 1, int, struct sysinfo*, info)

SHIM_SYSCALL_PASSTHRU(times, 1, int, struct tms*, tbuf)

//SHIM_SYSCALL_PASSTHRU(ptrace, 4, int, long, request, pid_t, pid, void*, addr, void*, data)

SHIM_SYSCALL_PASSTHRU(getuid, 0, uid_t)

SHIM_SYSCALL_PASSTHRU(syslog, 3, int, int, type, char*, buf, int, len)

SHIM_SYSCALL_PASSTHRU(getgid, 0, gid_t)

SHIM_SYSCALL_PASSTHRU(setuid, 1, int, uid_t, uid)

SHIM_SYSCALL_PASSTHRU(setgid, 1, int, gid_t, gid)

SHIM_SYSCALL_PASSTHRU(setgroups, 2, int, int, gidsetsize, gid_t*, grouplist)

SHIM_SYSCALL_PASSTHRU(getgroups, 2, int, int, gidsetsize, gid_t*, grouplist)

SHIM_SYSCALL_PASSTHRU(geteuid, 0, uid_t)

SHIM_SYSCALL_PASSTHRU(getegid, 0, gid_t)

SHIM_SYSCALL_PASSTHRU(setpgid, 2, int, pid_t, pid, pid_t, pgid)

SHIM_SYSCALL_PASSTHRU(getppid, 0, pid_t)

SHIM_SYSCALL_PASSTHRU(getpgrp, 0, pid_t)

SHIM_SYSCALL_PASSTHRU(setsid, 0, int)

SHIM_SYSCALL_PASSTHRU(setreuid, 2, int, uid_t, ruid, uid_t, euid)

SHIM_SYSCALL_PASSTHRU(setregid, 2, int, gid_t, rgid, gid_t, egid)

SHIM_SYSCALL_PASSTHRU(setresuid, 3, int, uid_t, ruid, uid_t, euid, uid_t, suid)

SHIM_SYSCALL_PASSTHRU(getresuid, 3, int, uid_t*, ruid, uid_t*, euid, uid_t*, suid)

SHIM_SYSCALL_PASSTHRU(setresgid, 3, int, gid_t, rgid, gid_t, egid, gid_t, sgid)

SHIM_SYSCALL_PASSTHRU(getresgid, 3, int, gid_t*, rgid, gid_t*, egid, gid_t*, sgid)

SHIM_SYSCALL_PASSTHRU(getpgid, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHRU(setfsuid, 1, int, uid_t, uid)

SHIM_SYSCALL_PASSTHRU(setfsgid, 1, int, gid_t, gid)

SHIM_SYSCALL_PASSTHRU(getsid, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHRU(capget, 2, int, cap_user_header_t, header, cap_user_data_t, dataptr)

SHIM_SYSCALL_PASSTHRU(capset, 2, int, cap_user_header_t, header, const cap_user_data_t, data)

//SHIM_SYSCALL_PASSTHRU(rt_sigpending, 2, int, __sigset_t*, set, size_t, sigsetsize)

//SHIM_SYSCALL_PASSTHRU(rt_sigtimedwait, 4, int, const __sigset_t*, uthese, siginfo_t*, uinfo, const struct timespec*, uts, size_t, sigsetsize)

//SHIM_SYSCALL_PASSTHRU(rt_sigqueueinfo, 3, int, int, pid, int, sig, siginfo_t*, uinfo)

//SHIM_SYSCALL_PASSTHRU(rt_sigsuspend, 1, int, const __sigset_t*, mask)

//SHIM_SYSCALL_PASSTHRU(sigaltstack, 2, int, const stack_t*, ss, stack_t*, oss)

//SHIM_SYSCALL_PASSTHRU(utime, 2, int, char*, filename, struct utimbuf*, times)

SHIM_SYSCALL_PASSTHRU(mknod, 3, int, const char*, filename, int, mode, unsigned, dev)

SHIM_SYSCALL_PASSTHRU(uselib, 1, int, const char*, library)

SHIM_SYSCALL_PASSTHRU(personality, 1, int, unsigned int, personality)

SHIM_SYSCALL_PASSTHRU(ustat, 2, int, unsigned, dev, struct __kernel_ustat*, ubuf)

SHIM_SYSCALL_PASSTHRU(statfs, 2, int, const char*, path, struct statfs*, buf)

SHIM_SYSCALL_PASSTHRU(fstatfs, 2, int, int, fd, struct statfs*, buf)

SHIM_SYSCALL_PASSTHRU(sysfs, 3, int, int, option, unsigned long, arg1, unsigned long, arg2)

SHIM_SYSCALL_PASSTHRU(getpriority, 2, int, int, which, int, who)

SHIM_SYSCALL_PASSTHRU(setpriority, 3, int, int, which, int, who, int, niceval)

SHIM_SYSCALL_PASSTHRU(sched_setparam, 2, int, pid_t, pid, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHRU(sched_getparam, 2, int, pid_t, pid, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHRU(sched_setscheduler, 3, int, pid_t, pid, int, policy, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHRU(sched_getscheduler, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHRU(sched_get_priority_max, 1, int, int, policy)

SHIM_SYSCALL_PASSTHRU(sched_get_priority_min, 1, int, int, policy)

SHIM_SYSCALL_PASSTHRU(sched_rr_get_interval, 2, int, pid_t, pid, struct timespec*, interval)

SHIM_SYSCALL_PASSTHRU(mlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHRU(munlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHRU(mlockall, 1, int, int, flags)

SHIM_SYSCALL_PASSTHRU(munlockall, 0, int)

SHIM_SYSCALL_PASSTHRU(vhangup, 0, int)

SHIM_SYSCALL_PASSTHRU(pivot_root, 2, int, const char*, new_root, const char*, put_old)

SHIM_SYSCALL_PASSTHRU(_sysctl, 1, int, struct __kernel_sysctl_args*, args)

//SHIM_SYSCALL_PASSTHRU(prctl, 5, int, int, option, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5)

//SHIM_SYSCALL_PASSTHRU(arch_prctl, 2, void*, int, code, void*, addr)

SHIM_SYSCALL_PASSTHRU(adjtimex, 1, int, struct ____kernel_timex*, txc_p)

SHIM_SYSCALL_PASSTHRU(setrlimit, 2, int, int, resource, struct __kernel_rlimit*, rlim)

SHIM_SYSCALL_PASSTHRU(chroot, 1, int, const char*, filename)

SHIM_SYSCALL_PASSTHRU(sync, 0, int)

SHIM_SYSCALL_PASSTHRU(acct, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHRU(settimeofday, 2, int, struct timeval*, tv, struct __kernel_timezone*, tz)

SHIM_SYSCALL_PASSTHRU(mount, 5, int, char*, dev_name, char*, dir_name, char*, type, unsigned long, flags, void*, data)

SHIM_SYSCALL_PASSTHRU(umount2, 2, int, const char*, target, int, flags)

SHIM_SYSCALL_PASSTHRU(swapon, 2, int, const char*, specialfile, int, swap_flags)

SHIM_SYSCALL_PASSTHRU(swapoff, 1, int, const char*, specialfile)

SHIM_SYSCALL_PASSTHRU(reboot, 4, int, int, magic1, int, magic2, int, cmd, void*, arg)

SHIM_SYSCALL_PASSTHRU(sethostname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHRU(setdomainname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHRU(iopl, 1, int, int, level)

SHIM_SYSCALL_PASSTHRU(ioperm, 3, int, unsigned long, from, unsigned long, num, int, on)

SHIM_SYSCALL_PASSTHRU(create_module, 2, int, const char*, name, size_t, size)

SHIM_SYSCALL_PASSTHRU(init_module, 3, int, void*, umod, unsigned long, len, const char*, uargs)

SHIM_SYSCALL_PASSTHRU(delete_module, 2, int, const char*, name_user, unsigned int, flags)

SHIM_SYSCALL_PASSTHRU(query_module, 5, int, const char*, name, int, which, void*, buf, size_t, bufsize, size_t*, retsize)

SHIM_SYSCALL_PASSTHRU(quotactl, 4, int, int, cmd, const char*, special, qid_t, id, void*, addr)

SHIM_SYSCALL_PASSTHRU(gettid, 0, pid_t)

SHIM_SYSCALL_PASSTHRU(readahead, 3, int, int, fd, loff_t, offset, size_t, count)

//SHIM_SYSCALL_PASSTHRU(setxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags)

//SHIM_SYSCALL_PASSTHRU(lsetxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags)

//SHIM_SYSCALL_PASSTHRU(fsetxattr, 5, int, int, fd, const char*, name, const void*, value, size_t, size, int, flags)

SHIM_SYSCALL_PASSTHRU(getxattr, 4, int, const char*, path, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHRU(lgetxattr, 4, int, const char*, path, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHRU(fgetxattr, 4, int, int, fd, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHRU(listxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHRU(llistxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHRU(flistxattr, 3, int, int, fd, char*, list, size_t, size)

//SHIM_SYSCALL_PASSTHRU(removexattr, 2, int, const char*, path, const char*, name)

//SHIM_SYSCALL_PASSTHRU(lremovexattr, 2, int, const char*, path, const char*, name)

//SHIM_SYSCALL_PASSTHRU(fremovexattr, 2, int, int, fd, const char*, name)

SHIM_SYSCALL_PASSTHRU(tkill, 2, int, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHRU(time, 1, time_t, time_t*, tloc)

SHIM_SYSCALL_PASSTHRU(futex, 6, int, int*, uaddr, int, op, int, val, void*, utime, int*, uaddr2, int, val3)

SHIM_SYSCALL_PASSTHRU(sched_setaffinity, 3, int, pid_t, pid, size_t, len, __kernel_cpu_set_t*, user_mask_ptr)

SHIM_SYSCALL_PASSTHRU(sched_getaffinity, 3, int, pid_t, pid, size_t, len, __kernel_cpu_set_t*, user_mask_ptr)

SHIM_SYSCALL_PASSTHRU(set_thread_area, 1, int, struct user_desc*, u_info)

/*
no io uring

SHIM_SYSCALL_PASSTHRU(io_setup, 2, int, unsigned, nr_reqs, aio_context_t*, ctx)

SHIM_SYSCALL_PASSTHRU(io_destroy, 1, int, aio_context_t, ctx)

SHIM_SYSCALL_PASSTHRU(io_getevents, 5, int, aio_context_t, ctx_id, long, min_nr, long, nr, struct io_event*, events, struct timespec*, timeout)

SHIM_SYSCALL_PASSTHRU(io_submit, 3, int, aio_context_t, ctx_id, long, nr, struct iocb**, iocbpp)

SHIM_SYSCALL_PASSTHRU(io_cancel, 3, int, aio_context_t, ctx_id, struct iocb*, iocb, struct io_event*, result)
*/

SHIM_SYSCALL_PASSTHRU(get_thread_area, 1, int, struct user_desc*, u_info)

SHIM_SYSCALL_PASSTHRU(lookup_dcookie, 3, int, unsigned long, cookie64, char*, buf, size_t, len)

//SHIM_SYSCALL_PASSTHRU(epoll_create, 1, int, int, size)

SHIM_SYSCALL_PASSTHRU(remap_file_pages, 5, int, void*, start, size_t, size, int, prot, ssize_t, pgoff, int, flags)

SHIM_SYSCALL_PASSTHRU(getdents64, 3, size_t, int, fd, struct linux_dirent64*, buf, size_t, count)

// this should be checked and ensure the tid address never get unmapped..?
SHIM_SYSCALL_PASSTHRU(set_tid_address, 1, int, int*, tidptr)

//SHIM_SYSCALL_PASSTHRU(restart_syscall, 0, int)

SHIM_SYSCALL_PASSTHRU(semtimedop, 4, int, int, semid, struct sembuf*, sops, unsigned int, nsops, const struct timespec*, timeout)

SHIM_SYSCALL_PASSTHRU(fadvise64, 4, int, int, fd, loff_t, offset, size_t, len, int, advice)

//SHIM_SYSCALL_PASSTHRU(timer_create, 3, int, clockid_t, which_clock, struct sigevent*, timer_event_spec, timer_t*, created_timer_id)

SHIM_SYSCALL_PASSTHRU(timer_settime, 4, int, timer_t, timer_id, int, flags, const struct __kernel_itimerspec*, new_setting, struct __kernel_itimerspec*, old_setting)

SHIM_SYSCALL_PASSTHRU(timer_gettime, 2, int, timer_t, timer_id, struct __kernel_itimerspec*, setting)

SHIM_SYSCALL_PASSTHRU(timer_getoverrun, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHRU(timer_delete, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHRU(clock_settime, 2, int, clockid_t, which_clock, const struct timespec*, tp)

SHIM_SYSCALL_PASSTHRU(clock_gettime, 2, int, clockid_t, which_clock, struct timespec*, tp)

SHIM_SYSCALL_PASSTHRU(clock_getres, 2, int, clockid_t, which_clock, struct timespec*, tp)

SHIM_SYSCALL_PASSTHRU(clock_nanosleep, 4, int, clockid_t, which_clock, int, flags, const struct timespec*, rqtp, struct timespec*, rmtp)

//SHIM_SYSCALL_PASSTHRU(exit_group, 1, int, int, error_code)

SHIM_SYSCALL_PASSTHRU(epoll_wait, 4, int, int, epfd, struct __kernel_epoll_event*, events, int, maxevents, int, timeout_ms)

SHIM_SYSCALL_PASSTHRU(epoll_ctl, 4, int, int, epfd, int, op, int, fd, struct __kernel_epoll_event*, event)

SHIM_SYSCALL_PASSTHRU(tgkill, 3, int, pid_t, tgid, pid_t, pid, int, sig)

//SHIM_SYSCALL_PASSTHRU(utimes, 2, int, char*, filename, struct timeval*, utimes)

SHIM_SYSCALL_PASSTHRU(mbind, 6, int, void*, start, unsigned long, len, int, mode, unsigned long*, nmask, unsigned long, maxnode, int, flags)

SHIM_SYSCALL_PASSTHRU(set_mempolicy, 3, int, int, mode, unsigned long*, nmask, unsigned long, maxnode)

SHIM_SYSCALL_PASSTHRU(get_mempolicy, 5, int, int*, policy, unsigned long*, nmask, unsigned long, maxnode, unsigned long, addr, unsigned long, flags)

SHIM_SYSCALL_PASSTHRU(mq_open, 4, int, const char*, name, int, oflag, mode_t, mode, struct __kernel_mq_attr*, attr)

SHIM_SYSCALL_PASSTHRU(mq_unlink, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHRU(mq_timedsend, 5, int, __kernel_mqd_t, mqdes, const char*, msg_ptr, size_t, msg_len, unsigned int, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHRU(mq_timedreceive, 5, int, __kernel_mqd_t, mqdes, char*, msg_ptr, size_t, msg_len, unsigned int*, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHRU(mq_notify, 2, int, __kernel_mqd_t, mqdes, const struct sigevent*, notification)

SHIM_SYSCALL_PASSTHRU(mq_getsetattr, 3, int, __kernel_mqd_t, mqdes, const struct __kernel_mq_attr*, mqstat, struct __kernel_mq_attr*, omqstat)

SHIM_SYSCALL_PASSTHRU(waitid, 5, int, int, which, pid_t, pid, siginfo_t*, infop, int, options, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHRU(ioprio_set, 3, int, int, which, int, who, int, ioprio)

SHIM_SYSCALL_PASSTHRU(ioprio_get, 2, int, int, which, int, who)

//SHIM_SYSCALL_PASSTHRU(inotify_init, 0, int)

SHIM_SYSCALL_PASSTHRU(inotify_add_watch, 3, int, int, fd, const char*, path, unsigned int, mask)

SHIM_SYSCALL_PASSTHRU(inotify_rm_watch, 2, int, int, fd, unsigned int, wd)

SHIM_SYSCALL_PASSTHRU(migrate_pages, 4, int, pid_t, pid, unsigned long, maxnode, const unsigned long*, from, const unsigned long*, to)

//SHIM_SYSCALL_PASSTHRU(openat, 4, int, int, dfd, const char*, filename, int, flags, int, mode)

SHIM_SYSCALL_PASSTHRU(mkdirat, 3, int, int, dfd, const char*, pathname, int, mode)

SHIM_SYSCALL_PASSTHRU(mknodat, 4, int, int, dfd, const char*, filename, int, mode, unsigned, dev)

//SHIM_SYSCALL_PASSTHRU(fchownat, 5, int, int, dfd, const char*, filename, uid_t, user, gid_t, group, int, flag)

//SHIM_SYSCALL_PASSTHRU(futimesat, 3, int, int, dfd, const char*, filename, struct timeval*, utimes)

SHIM_SYSCALL_PASSTHRU(newfstatat, 4, int, int, dfd, const char*, filename, struct stat*, statbuf, int, flag)

//SHIM_SYSCALL_PASSTHRU(unlinkat, 3, int, int, dfd, const char*, pathname, int, flag)

//SHIM_SYSCALL_PASSTHRU(renameat, 4, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname)

//SHIM_SYSCALL_PASSTHRU(linkat, 5, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname, int, flags)

//SHIM_SYSCALL_PASSTHRU(symlinkat, 3, int, const char*, oldname, int, newdfd, const char*, newname)

SHIM_SYSCALL_PASSTHRU(readlinkat, 4, int, int, dfd, const char*, path, char*, buf, int, bufsiz)

//SHIM_SYSCALL_PASSTHRU(fchmodat, 3, int, int, dfd, const char*, filename, mode_t, mode)

//SHIM_SYSCALL_PASSTHRU(faccessat, 3, int, int, dfd, const char*, filename, int, mode)

//SHIM_SYSCALL_PASSTHRU(pselect6, 6, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, const struct __kernel_timespec*, tsp, const __sigset_t*, sigmask)

SHIM_SYSCALL_PASSTHRU(ppoll, 5, int, struct pollfd*, fds, int, nfds, struct timespec*, tsp, const __sigset_t*, sigmask, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHRU(unshare, 1, int, int, unshare_flags)

SHIM_SYSCALL_PASSTHRU(set_robust_list, 2, int, struct robust_list_head*, head, size_t, len)

SHIM_SYSCALL_PASSTHRU(get_robust_list, 3, int, pid_t, pid, struct robust_list_head**, head, size_t*, len)

//SHIM_SYSCALL_PASSTHRU(splice, 6, int, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out, size_t, len, int, flags)

SHIM_SYSCALL_PASSTHRU(tee, 4, int, int, fdin, int, fdout, size_t, len, unsigned int, flags)

SHIM_SYSCALL_PASSTHRU(sync_file_range, 4, int, int, fd, loff_t, offset, loff_t, nbytes, int, flags)

// SHIM_SYSCALL_PASSTHRU(vmsplice, 4, int, int, fd, const struct iovec*, iov, unsigned long, nr_segs, int, flags)

SHIM_SYSCALL_PASSTHRU(move_pages, 6, int, pid_t, pid, unsigned long, nr_pages, void**, pages, const int*, nodes, int*, status, int, flags)

//SHIM_SYSCALL_PASSTHRU(utimensat, 4, int, int, dfd, const char*, filename, struct timespec*, utimes, int, flags)

SHIM_SYSCALL_PASSTHRU(epoll_pwait, 6, int, int, epfd, struct __kernel_epoll_event*, events, int, maxevents, int, timeout_ms, const __sigset_t*, sigmask, size_t, sigsetsize)

//SHIM_SYSCALL_PASSTHRU(signalfd, 3, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask)

//SHIM_SYSCALL_PASSTHRU(timerfd_create, 2, int, int, clockid, int, flags)

//SHIM_SYSCALL_PASSTHRU(eventfd, 1, int, int, count)

SHIM_SYSCALL_PASSTHRU(fallocate, 4, int, int, fd, int, mode, loff_t, offset, loff_t, len)

SHIM_SYSCALL_PASSTHRU(timerfd_settime, 4, int, int, ufd, int, flags, const struct __kernel_itimerspec*, utmr, struct __kernel_itimerspec*, otmr)

SHIM_SYSCALL_PASSTHRU(timerfd_gettime, 2, int, int, ufd, struct __kernel_itimerspec*, otmr)

//SHIM_SYSCALL_PASSTHRU(accept4, 4, int, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen, int, flags)

//SHIM_SYSCALL_PASSTHRU(signalfd4, 4, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask, int, flags)

//SHIM_SYSCALL_PASSTHRU(eventfd2, 2, int, int, count, int, flags)

//SHIM_SYSCALL_PASSTHRU(epoll_create1, 1, int, int, flags)

//SHIM_SYSCALL_PASSTHRU(dup3, 3, int, int, oldfd, int, newfd, int, flags)

//SHIM_SYSCALL_PASSTHRU(pipe2, 2, int, int*, fildes, int, flags)

//SHIM_SYSCALL_PASSTHRU(inotify_init1, 1, int, int, flags)

//SHIM_SYSCALL_PASSTHRU(preadv, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)

//SHIM_SYSCALL_PASSTHRU(pwritev, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)

SHIM_SYSCALL_PASSTHRU(rt_tgsigqueueinfo, 4, int, pid_t, tgid, pid_t, pid, int, sig, siginfo_t*, uinfo)

//SHIM_SYSCALL_PASSTHRU(perf_event_open, 5, int, struct perf_event_attr*, attr_uptr, pid_t, pid, int, cpu, int, group_fd, int, flags)

SHIM_SYSCALL_PASSTHRU(recvmmsg, 5, ssize_t, int, fd, struct mmsghdr*, msg, size_t, vlen, int, flags, struct __kernel_timespec*, timeout)

// SHIM_SYSCALL_PASSTHRU(fanotify_init, 2, int, int, flags, int, event_f_flags)

// SHIM_SYSCALL_PASSTHRU(fanotify_mark, 5, int, int, fanotify_fd, int, flags, unsigned long, mask, int, fd, const char*, pathname)

SHIM_SYSCALL_PASSTHRU(prlimit64, 4, int, pid_t, pid, int, resource, const struct __kernel_rlimit64*, new_rlim, struct __kernel_rlimit64*, old_rlim)

SHIM_SYSCALL_PASSTHRU(name_to_handle_at, 5, int, int, dfd, const char*, name, struct linux_file_handle*, handle, int*, mnt_id, int, flag)

//SHIM_SYSCALL_PASSTHRU(open_by_handle_at, 3, int, int, mountdirfd, struct linux_file_handle*, handle, int, flags)

SHIM_SYSCALL_PASSTHRU(clock_adjtime, 2, int, clockid_t, which_clock, struct timex*, tx)

SHIM_SYSCALL_PASSTHRU(syncfs, 1, int, int, fd)

SHIM_SYSCALL_PASSTHRU(sendmmsg, 4, ssize_t, int, fd, struct mmsghdr*, msg, size_t, vlen, int, flags)

SHIM_SYSCALL_PASSTHRU(setns, 2, int, int, fd, int, nstype)

SHIM_SYSCALL_PASSTHRU(getcpu, 3, int, unsigned*, cpu, unsigned*, node, struct getcpu_cache*, cache)

//SHIM_SYSCALL_PASSTHRU(process_vm_readv, 6, ssize_t, pid_t, pid, const struct iovec*, local_iov, unsigned long, liovcnt, const struct iovec*, remote_iov, unsigned long, riovcnt, unsigned long, flags)

//SHIM_SYSCALL_PASSTHRU(process_vm_writev, 6, ssize_t, pid_t, pid, const struct iovec*, local_iov, unsigned long, liovcnt, const struct iovec*, remote_iov, unsigned long, riovcnt, unsigned long, flag)

SHIM_SYSCALL_PASSTHRU(kcmp, 5, int, pid_t, pid1, pid_t, pid2, int, type, unsigned long, idx1, unsigned long, idx2)

SHIM_SYSCALL_PASSTHRU(finit_module, 3, int, int, fd, const char*, param_values, int, flags)

SHIM_SYSCALL_PASSTHRU(sched_setattr, 3, int, pid_t, pid, struct sched_attr*, attr, unsigned int, flags)

SHIM_SYSCALL_PASSTHRU(sched_getattr, 4, int, pid_t, pid, struct sched_attr*, attr, unsigned int, size, unsigned int, flags)

//SHIM_SYSCALL_PASSTHRU(renameat2, 5, int, int, olddirfd, const char*, oldpath, int, newdirfd, const char*, newpath, unsigned int, flags)

//SHIM_SYSCALL_PASSTHRU(seccomp, 3, int, int, operation, unsigned int, flags, void*, args)

SHIM_SYSCALL_PASSTHRU(getrandom, 3, ssize_t, void*, buf, size_t, buflen, unsigned int, flags)

//SHIM_SYSCALL_PASSTHRU(memfd_create, 2, int, const char*, name, unsigned int, flags)

SHIM_SYSCALL_PASSTHRU(kexec_file_load, 5, long, int, kernel_fd, int, initrd_fd, unsigned long, cmdline_len, const char*, cmdline, unsigned long, flags)

//SHIM_SYSCALL_PASSTHRU(bpf, 3, int, int, cmd, union bpf_attr*, attr, unsigned int, size)

//SHIM_SYSCALL_PASSTHRU(execveat, 5, int, int, dirfd, const char*, pathname, const char**, argv, const char**, envp, int, flags)

//SHIM_SYSCALL_PASSTHRU(userfaultfd, 1, int, int, flags)

SHIM_SYSCALL_PASSTHRU(membarrier, 2, int, int, cmd, int, flags)

SHIM_SYSCALL_PASSTHRU(mlock2, 3, int, const void*, addr, size_t, len, int, flags)

//SHIM_SYSCALL_PASSTHRU(copy_file_range, 6, ssize_t, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out, size_t, len, unsigned int, flags)

//SHIM_SYSCALL_PASSTHRU(preadv2, 5, ssize_t, int, fd, const struct iovec*, iov, int, iovcnt, off_t, offset, int, flags)

//SHIM_SYSCALL_PASSTHRU(pwritev2, 5, ssize_t, int, fd, const struct iovec*, iov, int, iovcnt, off_t, offset, int, flags)

//SHIM_SYSCALL_PASSTHRU(pkey_mprotect, 4, int, void*, addr, size_t, len, int, prot, int, pkey)

//SHIM_SYSCALL_PASSTHRU(pkey_alloc, 2, int, unsigned long, flags, unsigned long, access_rights)

//SHIM_SYSCALL_PASSTHRU(pkey_free, 1, int, int, pkey)

SHIM_SYSCALL_PASSTHRU(statx, 5, int, int, dirfd, const char*, pathname, int, flags, unsigned int, mask, struct statx*, statxbuf)
	
//SHIM_SYSCALL_PASSTHRU(io_pgetevents,

//SHIM_SYSCALL_PASSTHRU(rseq,

typedef int32_t key_serial_t;
SHIM_SYSCALL_PASSTHRU(add_key, 5, int, const char *, type, const char *, description, const void *, payload, size_t, plen, key_serial_t, keyring);

SHIM_SYSCALL_PASSTHRU(request_key, 4, int, const char *,type, const char *,description,
                                const char *,callout_info,
                                key_serial_t, dest_keyring);
SHIM_SYSCALL_PASSTHRU(keyctl, 5, int, int, operation, unsigned long, arg2,
                    unsigned long, arg3, unsigned long, arg4,
                    unsigned long, arg5);

int __pass_syscall = 0;
