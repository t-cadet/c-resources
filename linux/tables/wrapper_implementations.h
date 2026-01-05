//
// 1. PROCESS & THREAD LIFECYCLE
//
long fork_linux(void) {
  return clone_linux(SIGCHLD_linux, 0, 0, 0, 0);
}
long vfork_linux(void) {
  return clone_linux(CLONE_VFORK_linux | CLONE_VM_linux | SIGCHLD_linux, 0, 0, 0, 0);
}
long clone_linux(unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls) {
#if defined(__x86_64__)
  return Syscall5_linux(NR_clone_linux, clone_flags, newsp,  parent_tidptr, child_tidptr, tls, 0);
#else
  return Syscall5_linux(NR_clone_linux, clone_flags, newsp,  parent_tidptr, tls, child_tidptr, 0);
#endif
}
long clone3_linux(clone_args_linux *uargs) {
  return Syscall2_linux(NR_clone3_linux, uargs, sizeof(*uargs), 0);
}
long execve_linux(const char *filename, const char *const *argv, const char *const *envp) {
  return Syscall3_linux(NR_execve_linux, filename, argv, envp, 0);
}
long execveat_linux(int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags) {
  return Syscall5_linux(NR_execveat_linux, dfd, filename, argv, envp, flags, 0);
}
__attribute__((noreturn)) void exit_linux(int error_code) {
  Syscall1_linux(NR_exit_linux, error_code, 0);
  __builtin_unreachable();
}
__attribute__((noreturn)) void exit_group_linux(int error_code) {
  Syscall1_linux(NR_exit_group_linux, error_code, 0);
  __builtin_unreachable();
}
long wait4_linux(int pid, int *stat_addr, int options, rusage_linux *ru) {
#if !(defined(__riscv) && (__riscv_xlen == 32))
  return Syscall4_linux(NR_wait4_linux, pid, stat_addr, options, ru, 0);
#else
  int which = P_PID_linux;
  if (pid < -1) {
    which = P_PGID_linux;
    pid = -pid;
  } else if (pid == -1) {
    which = P_ALL_linux;
  } else if (pid == 0) {
    which = P_PGID_linux;
  }

  siginfo_t_linux infop;
  infop.si_pid_linux = 0;

  long ret = Syscall5_linux(NR_waitid_linux, which, pid, &infop, options | WEXITED_linux, ru, 0);

  if (ret >= 0) {
    ret = infop.si_pid_linux;
    if (infop.si_pid_linux && stat_addr) {
      switch (infop.si_code) {
        case CLD_EXITED_linux: *stat_addr = (infop.si_status_linux & 0xff) << 8; break;
        case CLD_KILLED_linux: *stat_addr = infop.si_status_linux & 0x7f; break;
        case CLD_DUMPED_linux: *stat_addr = (infop.si_status_linux & 0x7f) | 0x80; break;
        case CLD_TRAPPED_linux:
        case CLD_STOPPED_linux: *stat_addr = (infop.si_status_linux << 8) | 0x7f; break;
        case CLD_CONTINUED_linux: *stat_addr = 0xffff; break;
        default: *stat_addr = 0; break;
      }
    }
  }

  return ret;
#endif
}
long waitid_linux(int which, int pid, siginfo_t_linux *infop, int options, rusage_linux *ru) {
  return Syscall5_linux(NR_waitid_linux, which, pid, infop, options, ru, 0);
}
long waitpid_linux(int pid, int *stat_addr, int options) {
  return wait4_linux(pid, stat_addr, options, 0);
}
//
// 2. PROCESS ATTRIBUTES & CONTROL
//
// 2a. Process identity, process groups and sessions
long getpid_linux(void) {
  return Syscall0_linux(NR_getpid_linux, 0);
}
long getppid_linux(void) {
  return Syscall0_linux(NR_getppid_linux, 0);
}
long gettid_linux(void) {
  return Syscall0_linux(NR_gettid_linux, 0);
}
long getpgid_linux(int pid) {
  return Syscall1_linux(NR_getpgid_linux, pid, 0);
}
long setpgid_linux(int pid, int pgid) {
  return Syscall2_linux(NR_setpgid_linux, pid, pgid, 0);
}
long getpgrp_linux(void) {
  return getpgid_linux(0);
}
long getsid_linux(int pid) {
  return Syscall1_linux(NR_getsid_linux, pid, 0);
}
long setsid_linux(void) {
  return Syscall0_linux(NR_setsid_linux, 0);
}
long set_tid_address_linux(int *tidptr) {
  return Syscall1_linux(NR_set_tid_address_linux, tidptr, 0);
}
// 2b. Process control and personality
long prctl_linux(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
  return Syscall5_linux(NR_prctl_linux, option, arg2, arg3, arg4, arg5, 0);
}
long personality_linux(unsigned int personality) {
  return Syscall1_linux(NR_personality_linux, personality, 0);
}
//
// 3. SCHEDULING & PRIORITIES
//
long sched_setscheduler_linux(int pid, int policy, sched_param_linux *param) {
  return Syscall3_linux(NR_sched_setscheduler_linux, pid, policy, param, 0);
}
long sched_getscheduler_linux(int pid) {
  return Syscall1_linux(NR_sched_getscheduler_linux, pid, 0);
}
long sched_setparam_linux(int pid, sched_param_linux *param) {
  return Syscall2_linux(NR_sched_setparam_linux, pid, param, 0);
}
long sched_getparam_linux(int pid, sched_param_linux *param) {
  return Syscall2_linux(NR_sched_getparam_linux, pid, param, 0);
}
long sched_setattr_linux(int pid, sched_attr_linux *attr, unsigned int flags) {
  return Syscall3_linux(NR_sched_setattr_linux, pid, attr, flags, 0);
}
long sched_getattr_linux(int pid, sched_attr_linux *attr, unsigned int flags) {
  return Syscall4_linux(NR_sched_getattr_linux, pid, attr, sizeof(*attr), flags, 0);
}
long sched_yield_linux(void) {
  return Syscall0_linux(NR_sched_yield_linux, 0);
}
long sched_get_priority_max_linux(int policy) {
  return Syscall1_linux(NR_sched_get_priority_max_linux, policy, 0);
}
long sched_get_priority_min_linux(int policy) {
  return Syscall1_linux(NR_sched_get_priority_min_linux, policy, 0);
}
// Disabled wrapper: long sched_rr_get_interval_linux(int pid, __kernel_old_timespec_linux *interval);
long sched_rr_get_interval_time64_linux(int pid, __kernel_timespec_linux *interval) {
#if defined(__x86_64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall2_linux(NR_sched_rr_get_interval_linux, pid, interval, 0);
#else
  return Syscall2_linux(NR_sched_rr_get_interval_time64_linux, pid, interval, 0);
#endif
}
long sched_setaffinity_linux(int pid, unsigned int len, unsigned long *user_mask_ptr) {
  return Syscall3_linux(NR_sched_setaffinity_linux, pid, len, user_mask_ptr, 0);
}
long sched_getaffinity_linux(int pid, unsigned int len, unsigned long *user_mask_ptr) {
  return Syscall3_linux(NR_sched_getaffinity_linux, pid, len, user_mask_ptr, 0);
}
long nice_linux(int increment) {
  long ret = getpriority_linux(PRIO_PROCESS_linux, 0);
  if (ret < 0) return ret;
  return setpriority_linux(PRIO_PROCESS_linux, 0, (int)(20 - ret + increment));
}
long setpriority_linux(int which, int who, int niceval) {
  return Syscall3_linux(NR_setpriority_linux, which, who, niceval, 0);
}
long getpriority_linux(int which, int who) {
  return Syscall2_linux(NR_getpriority_linux, which, who, 0);
}
//
// 4. MEMORY MANAGEMENT
//
// 4a. Memory mapping, allocation, and unmapping
long brk_linux(void* brk) {
  return Syscall1_linux(NR_brk_linux, brk, 0);
}
long mmap_linux(void *addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long long off) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall6_linux(NR_mmap_linux, addr, len, prot, flags, fd, off, 0);
#else
  return Syscall6_linux(NR_mmap2_linux, addr, len, prot, flags, fd, off / 4096, 0);
#endif
}
long mmap2_linux(void *addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall6_linux(NR_mmap_linux, addr, len, prot, flags, fd, pgoff * 4096, 0);
#else
  return Syscall6_linux(NR_mmap2_linux, addr, len, prot, flags, fd, pgoff, 0);
#endif
}
long munmap_linux(void *addr, unsigned long len) {
  return Syscall2_linux(NR_munmap_linux, addr, len, 0);
}
long mremap_linux(void *addr, unsigned long old_len, unsigned long new_len, unsigned long flags, void *new_addr) {
  return Syscall5_linux(NR_mremap_linux, addr, old_len, new_len, flags, new_addr, 0);
}
long remap_file_pages_linux(void *start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) {
  return Syscall5_linux(NR_remap_file_pages_linux, start, size, prot, pgoff, flags, 0);
}
// 4b. Memory protection, locking, and usage hints
long mprotect_linux(void *start, unsigned long len, unsigned long prot) {
  return Syscall3_linux(NR_mprotect_linux, start, len, prot, 0);
}
long pkey_mprotect_linux(void* start, unsigned long len, unsigned long prot, int pkey) {
  return Syscall4_linux(NR_pkey_mprotect_linux, start, len, prot, pkey, 0);
}
long madvise_linux(void *start, unsigned long len, int behavior) {
  return Syscall3_linux(NR_madvise_linux, start, len, behavior, 0);
}
long process_madvise_linux(int pidfd, const iovec_linux *vec, unsigned long vlen, int behavior, unsigned int flags) {
  return Syscall5_linux(NR_process_madvise_linux, pidfd, vec, vlen, behavior, flags, 0);
}
long mlock_linux(void *start, unsigned long len) {
  return Syscall2_linux(NR_mlock_linux, start, len, 0);
}
long mlock2_linux(void *start, unsigned long len, int flags) {
  return Syscall3_linux(NR_mlock2_linux, start, len, flags, 0);
}
long munlock_linux(void *start, unsigned long len) {
  return Syscall2_linux(NR_munlock_linux, start, len, 0);
}
long mlockall_linux(int flags) {
  return Syscall1_linux(NR_mlockall_linux, flags, 0);
}
long munlockall_linux(void) {
  return Syscall0_linux(NR_munlockall_linux, 0);
}
long mincore_linux(const void* start, unsigned long len, void *vec) {
  return Syscall3_linux(NR_mincore_linux, start, len, vec, 0);
}
long msync_linux(void *start, unsigned long len, int flags) {
  return Syscall3_linux(NR_msync_linux, start, len, flags, 0);
}
long mseal_linux(void *start, unsigned long len, unsigned long flags) {
  return Syscall3_linux(NR_mseal_linux, start, len, flags, 0);
}
// 4c. NUMA memory policy and page migration
long mbind_linux(void* start, unsigned long len, unsigned long mode, const unsigned long *nmask, unsigned long maxnode, unsigned flags) {
  return Syscall6_linux(NR_mbind_linux, start, len, mode, nmask, maxnode, flags, 0);
}
long set_mempolicy_linux(int mode, const unsigned long *nmask, unsigned long maxnode) {
  return Syscall3_linux(NR_set_mempolicy_linux, mode, nmask, maxnode, 0);
}
long get_mempolicy_linux(int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) {
  return Syscall5_linux(NR_get_mempolicy_linux, policy, nmask, maxnode, addr, flags, 0);
}
long set_mempolicy_home_node_linux(void *start, unsigned long len, unsigned long home_node, unsigned long flags) {
  return Syscall4_linux(NR_set_mempolicy_home_node_linux, start, len, home_node, flags, 0);
}
long migrate_pages_linux(int pid, unsigned long maxnode, const unsigned long *from, const unsigned long *to) {
  return Syscall4_linux(NR_migrate_pages_linux, pid, maxnode, from, to, 0);
}
long move_pages_linux(int pid, unsigned long nr_pages, const void * *pages, const int *nodes, int *status, int flags) {
  return Syscall6_linux(NR_move_pages_linux, pid, nr_pages, pages, nodes, status, flags, 0);
}
// 4d. Anonymous file-backed memory regions
long memfd_create_linux(const char *uname_ptr, unsigned int flags) {
  return Syscall2_linux(NR_memfd_create_linux, uname_ptr, flags, 0);
}
#if !defined(__arm__)
long memfd_secret_linux(unsigned int flags) {
  return Syscall1_linux(NR_memfd_secret_linux, flags, 0);
}
#endif
// 4e. Memory protection key management
long pkey_alloc_linux(unsigned long flags, unsigned long init_val) {
  return Syscall2_linux(NR_pkey_alloc_linux, flags, init_val, 0);
}
long pkey_free_linux(int pkey) {
  return Syscall1_linux(NR_pkey_free_linux, pkey, 0);
}
// 4f. Control-flow integrity, shadow stack mapping
long map_shadow_stack_linux(void *addr, unsigned long size, unsigned int flags) {
  return Syscall3_linux(NR_map_shadow_stack_linux, addr, size, flags, 0);
}
// 4g. Advanced memory operations
long userfaultfd_linux(int flags) {
  return Syscall1_linux(NR_userfaultfd_linux, flags, 0);
}
long process_mrelease_linux(int pidfd, unsigned int flags) {
  return Syscall2_linux(NR_process_mrelease_linux, pidfd, flags, 0);
}
long membarrier_linux(int cmd, unsigned int flags, int cpu_id) {
  return Syscall3_linux(NR_membarrier_linux, cmd, flags, cpu_id, 0);
}
//
// 5. FILE I/O OPERATIONS
//
// 5a. Opening, creating, and closing files
long open_linux(const char *filename, int flags, unsigned int mode) {
  return openat_linux(AT_FDCWD_linux, filename, flags, mode);
}
long openat_linux(int dfd, const char *filename, int flags, unsigned int mode) {
  return Syscall4_linux(NR_openat_linux, dfd, filename, flags, mode, 0);
}
long openat2_linux(int dfd, const char *filename, open_how_linux *how) {
  return Syscall4_linux(NR_openat2_linux, dfd, filename, how, sizeof(*how), 0);
}
long creat_linux(const char *pathname, unsigned int mode) {
  return open_linux(pathname, O_CREAT_linux | O_WRONLY_linux | O_TRUNC_linux, mode);
}
long close_linux(unsigned int fd) {
  return Syscall1_linux(NR_close_linux, fd, 0);
}
long close_range_linux(unsigned int fd, unsigned int max_fd, unsigned int flags) {
  return Syscall3_linux(NR_close_range_linux, fd, max_fd, flags, 0);
}
long open_by_handle_at_linux(int mountdirfd, file_handle_linux *handle, int flags) {
  return Syscall3_linux(NR_open_by_handle_at_linux, mountdirfd, handle, flags, 0);
}
long name_to_handle_at_linux(int dfd, const char *name, file_handle_linux *handle, void *mnt_id, int flag) {
  return Syscall5_linux(NR_name_to_handle_at_linux, dfd, name, handle, mnt_id, flag, 0);
}
// 5b. Reading and writing file data
long read_linux(unsigned int fd, void *buf, unsigned long count) {
  return Syscall3_linux(NR_read_linux, fd, buf, count, 0);
}
long write_linux(unsigned int fd, const void *buf, unsigned long count) {
  return Syscall3_linux(NR_write_linux, fd, buf, count, 0);
}
long readv_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen) {
  return Syscall3_linux(NR_readv_linux, fd, vec, vlen, 0);
}
long writev_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen) {
  return Syscall3_linux(NR_writev_linux, fd, vec, vlen, 0);
}
long pread64_linux(unsigned int fd, void *buf, unsigned long count, long long pos) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_pread64_linux, fd, buf, count, pos, 0);
#elif defined(__i386__)
  return Syscall5_linux(NR_pread64_linux, fd, buf, count, LO32_bits(pos), HI32_bits(pos), 0);
#elif defined(__arm__) || (defined(__riscv) && (__riscv_xlen == 32))
  return Syscall6_linux(NR_pread64_linux, fd, buf, count, 0, LO32_bits(pos), HI32_bits(pos), 0);
#endif
}
long pwrite64_linux(unsigned int fd, const void *buf, unsigned long count, long long pos) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_pwrite64_linux, fd, buf, count, pos, 0);
#elif defined(__i386__)
  return Syscall5_linux(NR_pwrite64_linux, fd, buf, count, LO32_bits(pos), HI32_bits(pos), 0);
#elif defined(__arm__) || (defined(__riscv) && (__riscv_xlen == 32))
  return Syscall6_linux(NR_pwrite64_linux, fd, buf, count, 0, LO32_bits(pos), HI32_bits(pos), 0);
#endif
}
long preadv_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long long pos) {
  return Syscall5_linux(NR_preadv_linux, fd, vec, vlen, LO32_bits(pos), HI32_bits(pos), 0);
}
long pwritev_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long long pos) {
  return Syscall5_linux(NR_pwritev_linux, fd, vec, vlen, LO32_bits(pos), HI32_bits(pos), 0);
}
long preadv2_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long long pos, int flags) {
  return Syscall6_linux(NR_preadv2_linux, fd, vec, vlen, LO32_bits(pos), HI32_bits(pos), flags, 0);
}
long pwritev2_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long long pos, int flags) {
  return Syscall6_linux(NR_pwritev2_linux, fd, vec, vlen, LO32_bits(pos), HI32_bits(pos), flags, 0);
}
// 5c. Seeking and truncating files
// Disabled wrapper: long lseek_linux(unsigned int fd, long offset, unsigned int whence);
long llseek_linux(unsigned int fd, unsigned long long offset, long long *result, unsigned int whence) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  long ret = Syscall3_linux(NR_lseek_linux, fd, offset, whence, 0);
  if (ret >= 0 && result) {
    *result = ret;
    ret = 0;
  }
  return ret;
#elif defined(__riscv) && (__riscv_xlen == 32)
  return Syscall5_linux(NR_llseek_linux, fd, HI32_bits(offset), LO32_bits(offset), result, whence, 0);
#else
  return Syscall5_linux(NR__llseek_linux, fd, HI32_bits(offset), LO32_bits(offset), result, whence, 0);
#endif
}
// Disabled wrapper: long _llseek_linux(unsigned int fd, unsigned long offset_high, unsigned long offset_low, long long *result, unsigned int whence);
// Disabled wrapper: long truncate_linux(const char *path, long length);
long truncate64_linux(const char *path, long long length) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall2_linux(NR_truncate_linux, path, length, 0);
#elif defined(__i386__)
  return Syscall3_linux(NR_truncate64_linux, path, LO32_bits(length), HI32_bits(length), 0);
#elif defined(__arm__) || (defined(__riscv) && (__riscv_xlen == 32))
  return Syscall4_linux(NR_truncate64_linux, path, 0, LO32_bits(length), HI32_bits(length), 0);
#endif
}
// Disabled wrapper: long ftruncate_linux(unsigned int fd, long length);
long ftruncate64_linux(unsigned int fd, long long length) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall2_linux(NR_ftruncate_linux, fd, length, 0);
#elif defined(__i386__)
  return Syscall3_linux(NR_ftruncate64_linux, fd, LO32_bits(length), HI32_bits(length), 0);
#elif defined(__arm__) || (defined(__riscv) && (__riscv_xlen == 32))
  return Syscall4_linux(NR_ftruncate64_linux, fd, 0, LO32_bits(length), HI32_bits(length), 0);
#endif
}
// 5d. Zero-copy and specialized I/O
// Disabled wrapper: long sendfile_linux(int out_fd, int in_fd, long *offset, unsigned long count);
long sendfile64_linux(int out_fd, int in_fd, long long *offset, unsigned long count) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_sendfile_linux, out_fd, in_fd, offset, count, 0);
#else
  return Syscall4_linux(NR_sendfile64_linux, out_fd, in_fd, offset, count, 0);
#endif
}
long splice_linux(int fd_in, long long *off_in, int fd_out, long long *off_out, unsigned long len, unsigned int flags) {
  return Syscall6_linux(NR_splice_linux, fd_in, off_in, fd_out, off_out, len, flags, 0);
}
long tee_linux(int fdin, int fdout, unsigned long len, unsigned int flags) {
  return Syscall4_linux(NR_tee_linux, fdin, fdout, len, flags, 0);
}
long vmsplice_linux(int fd, const iovec_linux *iov, unsigned long nr_segs, unsigned int flags) {
  return Syscall4_linux(NR_vmsplice_linux, fd, iov, nr_segs, flags, 0);
}
long copy_file_range_linux(int fd_in, long long *off_in, int fd_out, long long *off_out, unsigned long len, unsigned int flags) {
  return Syscall6_linux(NR_copy_file_range_linux, fd_in, off_in, fd_out, off_out, len, flags, 0);
}
// 5e. I/O hints and space allocation
// Disabled wrapper: long fadvise64_linux(int fd, long long offset, unsigned long len, int advice);
long fadvise64_64_linux(int fd, long long offset, long long len, int advice) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_fadvise64_linux, fd, offset, len, advice, 0);
#elif defined(__i386__)
  return Syscall6_linux(NR_fadvise64_64_linux, fd, LO32_bits(offset), HI32_bits(offset), LO32_bits(len), HI32_bits(len), advice, 0);
#elif defined(__arm__)
  return Syscall6_linux(NR_arm_fadvise64_64_linux, fd, advice, LO32_bits(offset), HI32_bits(offset), LO32_bits(len), HI32_bits(len), 0);
#elif defined(__riscv) && (__riscv_xlen == 32)
   return Syscall6_linux(NR_fadvise64_64_linux, fd, advice, 0, LO32_bits(offset), HI32_bits(offset), LO32_bits(len), HI32_bits(len), 0);
#endif
}
// Disabled wrapper: long arm_fadvise64_64_linux(int fd, int advice, long long offset, long long len);
long readahead_linux(int fd, long long offset, unsigned long count) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall3_linux(NR_readahead_linux, fd, offset, count, 0);
#elif defined(__i386__)
  return Syscall4_linux(NR_readahead_linux, fd, LO32_bits(offset), HI32_bits(offset), count, 0);
#elif defined(__arm__) || (defined(__riscv) && (__riscv_xlen == 32))
  return Syscall5_linux(NR_readahead_linux, fd, 0, LO32_bits(offset), HI32_bits(offset), count, 0);
#endif
}
long fallocate_linux(int fd, int mode, long long offset, long long len) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_fallocate_linux, fd, mode, offset, len, 0);
#else
  return Syscall6_linux(NR_fallocate_linux, fd, mode, LO32_bits(offset), HI32_bits(offset), LO32_bits(len), HI32_bits(len), 0);
#endif
}
// 5f. Flushing file data to storage
long sync_linux(void) {
  return Syscall0_linux(NR_sync_linux, 0);
}
long syncfs_linux(int fd) {
  return Syscall1_linux(NR_syncfs_linux, fd, 0);
}
long fsync_linux(unsigned int fd) {
  return Syscall1_linux(NR_fsync_linux, fd, 0);
}
long fdatasync_linux(unsigned int fd) {
  return Syscall1_linux(NR_fdatasync_linux, fd, 0);
}
long sync_file_range_linux(int fd, long long offset, long long nbytes, unsigned int flags) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_sync_file_range_linux, fd, offset, nbytes, flags, 0);
#elif defined(__i386__)
  return Syscall6_linux(NR_sync_file_range_linux, fd, LO32_bits(offset), HI32_bits(offset), LO32_bits(nbytes), HI32_bits(nbytes), flags, 0);
#elif defined(__arm__)
  return Syscall6_linux(NR_arm_sync_file_range_linux, fd, flags, LO32_bits(offset), HI32_bits(offset), LO32_bits(nbytes), HI32_bits(nbytes), 0);
#elif defined(__riscv) && (__riscv_xlen == 32)
  return Syscall6_linux(NR_sync_file_range_linux, fd, flags, LO32_bits(offset), HI32_bits(offset), LO32_bits(nbytes), HI32_bits(nbytes), 0);
#endif
}
// Disabled wrapper: long arm_sync_file_range_linux(int fd, long long offset, long long nbytes, unsigned int flags);
//
// 6. FILE DESCRIPTOR MANAGEMENT
//
// 6a. Duplicating and controlling file descriptors
long dup_linux(unsigned int fildes) {
  return Syscall1_linux(NR_dup_linux, fildes, 0);
}
// Disabled wrapper: long dup2_linux(unsigned int oldfd, unsigned int newfd);
long dup3_linux(unsigned int oldfd, unsigned int newfd, int flags) {
  return Syscall3_linux(NR_dup3_linux, oldfd, newfd, flags, 0);
}
// Disabled wrapper: long fcntl_linux(unsigned int fd, unsigned int cmd, unsigned long arg);
long fcntl64_linux(unsigned int fd, unsigned int cmd, unsigned long arg) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall3_linux(NR_fcntl_linux, fd, cmd, arg, 0);
#else
  return Syscall3_linux(NR_fcntl64_linux, fd, cmd, arg, 0);
#endif
}
// 6b. Device-specific control operations
long ioctl_linux(unsigned int fd, unsigned int cmd, unsigned long arg) {
  return Syscall3_linux(NR_ioctl_linux, fd, cmd, arg, 0);
}
// 6c. I/O Multiplexing
// Disabled wrapper: long select_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timeval *tvp);
// Disabled wrapper: long _newselect_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timeval *tvp);
// Disabled wrapper: pselect6_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timespec_linux *tsp, void *sig);
long pselect6_time64_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_timespec_linux *tsp, void *sig) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall6_linux(NR_pselect6_linux, n, inp, outp, exp, tsp, sig, 0);
#else
  return Syscall6_linux(NR_pselect6_time64_linux, n, inp, outp, exp, tsp, sig, 0);
#endif
}
long poll_linux(pollfd_linux *ufds, unsigned int nfds, int timeout) {
  __kernel_timespec_linux ts;
  __kernel_timespec_linux *tsp = 0;
  if (timeout >= 0) {
    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;
    tsp = &ts;
  }
  return ppoll_time64_linux(ufds, nfds, tsp, 0);
}
// Disabled wrapper: long ppoll_linux(pollfd_linux *, unsigned int, __kernel_old_timespec_linux *, const unsigned long long *, unsigned long);
long ppoll_time64_linux(pollfd_linux *ufds, unsigned int nfds, __kernel_timespec_linux *tsp, const unsigned long long *sigmask) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall5_linux(NR_ppoll_linux, ufds, nfds, tsp, sigmask, sizeof(*sigmask), 0);
#else
  return Syscall5_linux(NR_ppoll_time64_linux, ufds, nfds, tsp, sigmask, sizeof(*sigmask), 0);
#endif
}
// 6d. Scalable I/O event notification
// Disabled wrapper: long epoll_create_linux(int size);
long epoll_create1_linux(int flags) {
  return Syscall1_linux(NR_epoll_create1_linux, flags, 0);
}
long epoll_ctl_linux(int epfd, int op, int fd, epoll_event_linux *event) {
  return Syscall4_linux(NR_epoll_ctl_linux, epfd, op, fd, event, 0);
}
long epoll_wait_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout) {
  return epoll_pwait_linux(epfd, events, maxevents, timeout, 0);
}
long epoll_pwait_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout, const unsigned long long *sigmask) {
  return Syscall6_linux(NR_epoll_pwait_linux, epfd, events, maxevents, timeout, sigmask, sizeof(*sigmask), 0);
}
long epoll_pwait2_linux(int epfd, epoll_event_linux *events, int maxevents, const __kernel_timespec_linux *timeout, const unsigned long long *sigmask) {
  return Syscall6_linux(NR_epoll_pwait2_linux, epfd, events, maxevents, timeout, sigmask, sizeof(*sigmask), 0);
}
// Disabled wrapper: long epoll_ctl_old_linux(int epfd, int op, int fd, epoll_event_linux *event);
// Disabled wrapper: long epoll_wait_old_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout);
//
// 7. FILE METADATA
//
// 7a. Getting file attributes and status
// Disabled wrapper: long stat_linux(const char *filename, __old_kernel_stat *statbuf);
// Disabled wrapper: long fstat_linux(unsigned int fd, __old_kernel_stat *statbuf);
// Disabled wrapper: long lstat_linux(const char *filename, __old_kernel_stat *statbuf);
// Disabled wrapper: long stat64_linux(const char *filename, stat64_t_linux *statbuf);
// Disabled wrapper: long fstat64_linux(unsigned long fd, stat64_t_linux *statbuf);
// Disabled wrapper: long lstat64_linux(const char *filename, stat64_t_linux *statbuf);
// Disabled wrapper: long newfstatat_linux(int dfd, const char *filename, stat_t_linux *statbuf, int flag);
// Disabled wrapper: long fstatat64_linux(int dfd, const char *filename, stat64_t_linux *statbuf, int flag);
long statx_linux(int dfd, const char *path, unsigned flags, unsigned mask, statx_t_linux *buffer) {
  return Syscall5_linux(NR_statx_linux, dfd, path, flags, mask, buffer, 0);
}
// Disabled wrapper: long oldstat_linux(const char *filename, __old_kernel_stat *statbuf);
// Disabled wrapper: long oldfstat_linux(unsigned int fd, __old_kernel_stat *statbuf);
// Disabled wrapper: long oldlstat_linux(const char *filename, __old_kernel_stat *statbuf);
long file_getattr_linux(int dfd, const char *filename, file_attr_linux *attr, unsigned int at_flags) {
  return Syscall5_linux(NR_file_getattr_linux, dfd, filename, attr, sizeof(*attr), at_flags, 0);
}
// 7b. Changing file permissions and ownership
long chmod_linux(const char *filename, unsigned int mode) {
  return fchmodat_linux(AT_FDCWD_linux, filename, mode);
}
long fchmod_linux(unsigned int fd, unsigned int mode) {
  return Syscall2_linux(NR_fchmod_linux, fd, mode, 0);
}
long fchmodat_linux(int dfd, const char *filename, unsigned int mode) {
  return Syscall3_linux(NR_fchmodat_linux, dfd, filename, mode, 0);
}
long fchmodat2_linux(int dfd, const char *filename, unsigned int mode, unsigned int flags) {
  return Syscall4_linux(NR_fchmodat2_linux, dfd, filename, mode, flags, 0);
}
long umask_linux(int mask) {
  return Syscall1_linux(NR_umask_linux, mask, 0);
}
// Disabled wrapper: long chown_linux(const char *filename, unsigned int user, unsigned int group);
// Disabled wrapper: long fchown_linux(unsigned int fd, unsigned int user, unsigned int group);
// Disabled wrapper: long lchown_linux(const char *filename, unsigned int user, unsigned int group);
long chown32_linux(const char *filename, unsigned int user, unsigned int group) {
  return fchownat_linux(AT_FDCWD_linux, filename, user, group, 0);
}
long fchown32_linux(unsigned int fd, unsigned int user, unsigned int group) {
  return fchownat_linux(fd, "", user, group, AT_EMPTY_PATH_linux);
}
long lchown32_linux(const char *filename, unsigned int user, unsigned int group) {
  return fchownat_linux(AT_FDCWD_linux, filename, user, group, AT_SYMLINK_NOFOLLOW_linux);
}
long fchownat_linux(int dfd, const char *filename, unsigned int user, unsigned int group, int flag) {
  return Syscall5_linux(NR_fchownat_linux, dfd, filename, user, group, flag, 0);
}
long file_setattr_linux(int dfd, const char *filename, file_attr_linux *attr, unsigned int at_flags) {
  return Syscall5_linux(NR_file_setattr_linux, dfd, filename, attr, sizeof(*attr), at_flags, 0);
}
// 7c. File access and modification times
// Disabled wrapper: long utime_linux(char *filename, utimbuf_linux *times);
// Disabled wrapper: long utimes_linux(char *filename, __kernel_old_timeval *utimes);
// Disabled wrapper: long futimesat_linux(int dfd, const char *filename, __kernel_old_timeval *utimes);
// Disabled wrapper: long utimensat_linux(int dfd, const char *filename, __kernel_old_timespec_linux *utimes, int flags);
long utimensat_time64_linux(int dfd, const char *filename, __kernel_timespec_linux *t, int flags) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_utimensat_linux, dfd, filename, t, flags, 0);
#else
  return Syscall4_linux(NR_utimensat_time64_linux, dfd, filename, t, flags, 0);
#endif
}
// 7d. Testing file accessibility
long access_linux(const char *filename, int mode) {
  return faccessat_linux(AT_FDCWD_linux, filename, mode);
}
long faccessat_linux(int dfd, const char *filename, int mode) {
  return Syscall3_linux(NR_faccessat_linux, dfd, filename, mode, 0);
}
long faccessat2_linux(int dfd, const char *filename, int mode, int flags) {
  return Syscall4_linux(NR_faccessat2_linux, dfd, filename, mode, flags, 0);
}
// 7e. Getting, setting, and listing extended attributes
long setxattr_linux(const char *path, const char *name, const void *value, unsigned long size, int flags) {
  return Syscall5_linux(NR_setxattr_linux, path, name, value, size, flags, 0);
}
long lsetxattr_linux(const char *path, const char *name, const void *value, unsigned long size, int flags) {
  return Syscall5_linux(NR_lsetxattr_linux, path, name, value, size, flags, 0);
}
long fsetxattr_linux(int fd, const char *name, const void *value, unsigned long size, int flags) {
  return Syscall5_linux(NR_fsetxattr_linux, fd, name, value, size, flags, 0);
}
long setxattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name, const xattr_args_linux *args, unsigned long size) {
  return Syscall6_linux(NR_setxattrat_linux, dfd, path, at_flags, name, args, size, 0);
}
long getxattr_linux(const char *path, const char *name, void *value, unsigned long size) {
  return Syscall4_linux(NR_getxattr_linux, path, name, value, size, 0);
}
long lgetxattr_linux(const char *path, const char *name, void *value, unsigned long size) {
  return Syscall4_linux(NR_lgetxattr_linux, path, name, value, size, 0);
}
long fgetxattr_linux(int fd, const char *name, void *value, unsigned long size) {
  return Syscall4_linux(NR_fgetxattr_linux, fd, name, value, size, 0);
}
long getxattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name, xattr_args_linux *args, unsigned long size) {
  return Syscall6_linux(NR_getxattrat_linux, dfd, path, at_flags, name, args, size, 0);
}
long listxattr_linux(const char *path, char *list, unsigned long size) {
  return Syscall3_linux(NR_listxattr_linux, path, list, size, 0);
}
long llistxattr_linux(const char *path, char *list, unsigned long size) {
  return Syscall3_linux(NR_llistxattr_linux, path, list, size, 0);
}
long flistxattr_linux(int fd, char *list, unsigned long size) {
  return Syscall3_linux(NR_flistxattr_linux, fd, list, size, 0);
}
long listxattrat_linux(int dfd, const char *path, unsigned int at_flags, char *list, unsigned long size) {
  return Syscall5_linux(NR_listxattrat_linux, dfd, path, at_flags, list, size, 0);
}
long removexattr_linux(const char *path, const char *name) {
  return Syscall2_linux(NR_removexattr_linux, path, name, 0);
}
long lremovexattr_linux(const char *path, const char *name) {
  return Syscall2_linux(NR_lremovexattr_linux, path, name, 0);
}
long fremovexattr_linux(int fd, const char *name) {
  return Syscall2_linux(NR_fremovexattr_linux, fd, name, 0);
}
long removexattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name) {
  return Syscall4_linux(NR_removexattrat_linux, dfd, path, at_flags, name, 0);
}
// 7f. Advisory file locking
long flock_linux(unsigned int fd, unsigned int cmd) {
  return Syscall2_linux(NR_flock_linux, fd, cmd, 0);
}
//
// 8. DIRECTORY & NAMESPACE OPERATIONS
//
// 8a. Creating, removing, and reading directories
long mkdir_linux(const char *pathname, unsigned int mode) {
  return mkdirat_linux(AT_FDCWD_linux, pathname, mode);
}
long mkdirat_linux(int dfd, const char * pathname, unsigned int mode) {
  return Syscall3_linux(NR_mkdirat_linux, dfd, pathname, mode, 0);
}
long rmdir_linux(const char *pathname) {
  return unlinkat_linux(AT_FDCWD_linux, pathname, AT_REMOVEDIR_linux);
}
// Disabled wrapper: long getdents_linux(unsigned int fd, linux_dirent_linux *dirent, unsigned int count);
long getdents64_linux(unsigned int fd, linux_dirent64_linux *dirent, unsigned int count) {
  return Syscall3_linux(NR_getdents64_linux, fd, dirent, count, 0);
}
// Disabled wrapper: long readdir_linux(unsigned int fd, old_linux_dirent_linux *dirent, unsigned int count);
// 8b. Getting and changing current directory
long getcwd_linux(char *buf, unsigned long size) {
  return Syscall2_linux(NR_getcwd_linux, buf, size, 0);
}
long chdir_linux(const char *filename) {
  return Syscall1_linux(NR_chdir_linux, filename, 0);
}
long fchdir_linux(unsigned int fd) {
  return Syscall1_linux(NR_fchdir_linux, fd, 0);
}
// 8c. Creating and managing hard and symbolic links
long link_linux(const char *oldname, const char *newname) {
  return linkat_linux(AT_FDCWD_linux, oldname, AT_FDCWD_linux, newname, 0);
}
long linkat_linux(int olddfd, const char *oldname, int newdfd, const char *newname, int flags) {
  return Syscall5_linux(NR_linkat_linux, olddfd, oldname, newdfd, newname, flags, 0);
}
long unlink_linux(const char *pathname) {
  return unlinkat_linux(AT_FDCWD_linux, pathname, 0);
}
long unlinkat_linux(int dfd, const char * pathname, int flag) {
  return Syscall3_linux(NR_unlinkat_linux, dfd, pathname, flag, 0);
}
long symlink_linux(const char *old, const char *newname) {
  return symlinkat_linux(old, AT_FDCWD_linux, newname);
}
long symlinkat_linux(const char * oldname, int newdfd, const char * newname) {
  return Syscall3_linux(NR_symlinkat_linux, oldname, newdfd, newname, 0);
}
long readlink_linux(const char *path, char *buf, int bufsiz) {
  return readlinkat_linux(AT_FDCWD_linux, path, buf, bufsiz);
}
long readlinkat_linux(int dfd, const char *path, char *buf, int bufsiz) {
  return Syscall4_linux(NR_readlinkat_linux, dfd, path, buf, bufsiz, 0);
}
long rename_linux(const char *oldname, const char *newname) {
  return renameat2_linux(AT_FDCWD_linux, oldname, AT_FDCWD_linux, newname, 0);
}
long renameat_linux(int olddfd, const char * oldname, int newdfd, const char * newname) {
  return renameat2_linux(olddfd, oldname, newdfd, newname, 0);
}
long renameat2_linux(int olddfd, const char *oldname, int newdfd, const char *newname, unsigned int flags) {
  return Syscall5_linux(NR_renameat2_linux, olddfd, oldname, newdfd, newname, flags, 0);
}
// 8d. Creating device and named pipe nodes
long mknod_linux(const char *filename, unsigned int mode, unsigned dev) {
  return mknodat_linux(AT_FDCWD_linux, filename, mode, dev);
}
long mknodat_linux(int dfd, const char * filename, unsigned int mode, unsigned dev) {
  return Syscall4_linux(NR_mknodat_linux, dfd, filename, mode, dev, 0);
}
//
// 9. FILE SYSTEM OPERATIONS
//
// 9a. Mounting filesystems and changing root
long mount_linux(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data) {
  return Syscall5_linux(NR_mount_linux, dev_name, dir_name, type, flags, data, 0);
}
long umount_linux(char *name, int flags) {
  return umount2_linux(name, 0);
}
long umount2_linux(char *name, int flags) {
  return Syscall2_linux(NR_umount2_linux, name, flags, 0);
}
long pivot_root_linux(const char *new_root, const char *put_old) {
  return Syscall2_linux(NR_pivot_root_linux, new_root, put_old, 0);
}
long chroot_linux(const char *filename) {
  return Syscall1_linux(NR_chroot_linux, filename, 0);
}
long mount_setattr_linux(int dfd, const char *path, unsigned int flags, mount_attr_linux *uattr) {
  return Syscall5_linux(NR_mount_setattr_linux, dfd, path, flags, uattr, sizeof(*uattr), 0);
}
long move_mount_linux(int from_dfd, const char *from_path, int to_dfd, const char *to_path, unsigned int ms_flags) {
  return Syscall5_linux(NR_move_mount_linux, from_dfd, from_path, to_dfd, to_path, ms_flags, 0);
}
long open_tree_linux(int dfd, const char *path, unsigned flags) {
  return Syscall3_linux(NR_open_tree_linux, dfd, path, flags, 0);
}
long open_tree_attr_linux(int dfd, const char *path, unsigned flags, mount_attr_linux *uattr) {
  return Syscall5_linux(NR_open_tree_attr_linux, dfd, path, flags, uattr, sizeof(*uattr), 0);
}
long fsconfig_linux(int fs_fd, unsigned int cmd, const char *key, const void *value, int aux) {
  return Syscall5_linux(NR_fsconfig_linux, fs_fd, cmd, key, value, aux, 0);
}
long fsmount_linux(int fs_fd, unsigned int flags, unsigned int ms_flags) {
  return Syscall3_linux(NR_fsmount_linux, fs_fd, flags, ms_flags, 0);
}
long fsopen_linux(const char *fs_name, unsigned int flags) {
  return Syscall2_linux(NR_fsopen_linux, fs_name, flags, 0);
}
long fspick_linux(int dfd, const char *path, unsigned int flags) {
  return Syscall3_linux(NR_fspick_linux, dfd, path, flags, 0);
}
// 9b. Getting filesystem statistics
// Disabled wrapper: long statfs_linux(const char * path, statfs_t_linux *buf);
// Disabled wrapper: long fstatfs_linux(unsigned int fd, statfs_t_linux *buf);
long statfs64_linux(const char *path, statfs64_t_linux *buf) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall2_linux(NR_statfs_linux, path, buf, 0);
#else
  return Syscall3_linux(NR_statfs64_linux, path, sizeof(*buf), buf, 0);
#endif
}
long fstatfs64_linux(unsigned int fd, statfs64_t_linux *buf) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall2_linux(NR_fstatfs_linux, fd, buf, 0);
#else
  return Syscall3_linux(NR_fstatfs64_linux, fd, sizeof(*buf), buf, 0);
#endif
}
// Disabled wrapper: long ustat_linux(unsigned dev, ustat *ubuf);
long statmount_linux(const mnt_id_req_linux *req, statmount_t_linux *buf, unsigned long bufsize, unsigned int flags) {
  return Syscall4_linux(NR_statmount_linux, req, buf, bufsize, flags, 0);
}
long listmount_linux(const mnt_id_req_linux *req, unsigned long long *mnt_ids, unsigned long nr_mnt_ids, unsigned int flags) {
  return Syscall4_linux(NR_listmount_linux, req, mnt_ids, nr_mnt_ids, flags, 0);
}
// 9c. Disk quota control
long quotactl_linux(unsigned int cmd, const char *special, unsigned int id, void *addr) {
  return Syscall4_linux(NR_quotactl_linux, cmd, special, id, addr, 0);
}
long quotactl_fd_linux(unsigned int fd, unsigned int cmd, unsigned int id, void *addr) {
  return Syscall4_linux(NR_quotactl_fd_linux, fd, cmd, id, addr, 0);
}
//
// 10. FILE SYSTEM MONITORING
//
// 10a. Monitoring filesystem events
long inotify_init_linux(void) {
  return inotify_init1_linux(0);
}
long inotify_init1_linux(int flags) {
  return Syscall1_linux(NR_inotify_init1_linux, flags, 0);
}
long inotify_add_watch_linux(int fd, const char *path, unsigned int mask) {
  return Syscall3_linux(NR_inotify_add_watch_linux, fd, path, mask, 0);
}
long inotify_rm_watch_linux(int fd, int wd) {
  return Syscall2_linux(NR_inotify_rm_watch_linux, fd, wd, 0);
}
// 10b. Filesystem-wide event notification
long fanotify_init_linux(unsigned int flags, unsigned int event_f_flags) {
  return Syscall2_linux(NR_fanotify_init_linux, flags, event_f_flags, 0);
}
long fanotify_mark_linux(int fanotify_fd, unsigned int flags, unsigned long long mask, int fd, const char *pathname) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall5_linux(NR_fanotify_mark_linux, fanotify_fd, flags, mask, fd, pathname, 0);
#else
  return Syscall6_linux(NR_fanotify_mark_linux, fanotify_fd, flags, LO32_bits(mask), HI32_bits(mask), fd, pathname, 0);
#endif
}
//
// 11. SIGNALS
//
// 11a. Setting up signal handlers
long signal_linux(int sig, void (*handler)(int)) {
  sigaction_t_linux act, oact;
  act.sa_handler_linux = handler;
  act.sa_flags = SA_RESTART_linux;
  act.sa_mask = 0;
  act.sa_restorer = 0;
  long ret = rt_sigaction_linux(sig, &act, &oact);
  return ret < 0 ? ret : (long)oact.sa_handler_linux;
}
// Disabled wrapper: long sigaction_linux(int sig, const old_sigaction_linux *act, old_sigaction_linux *oact);
long rt_sigaction_linux(int sig, const sigaction_t_linux *act, sigaction_t_linux *oact) {
  return Syscall4_linux(NR_rt_sigaction_linux, sig, act, oact, sizeof(act->sa_mask), 0);
}
// 11b. Sending signals to processes
long kill_linux(int pid, int sig) {
  return Syscall2_linux(NR_kill_linux, pid, sig, 0);
}
// Disabled wrapper: long tkill_linux(int pid, int sig);
long tgkill_linux(int tgid, int pid, int sig) {
  return Syscall3_linux(NR_tgkill_linux, tgid, pid, sig, 0);
}
long rt_sigqueueinfo_linux(int pid, int sig, siginfo_t_linux *uinfo) {
  return Syscall3_linux(NR_rt_sigqueueinfo_linux, pid, sig, uinfo, 0);
}
long rt_tgsigqueueinfo_linux(int tgid, int pid, int sig, siginfo_t_linux *uinfo) {
  return Syscall4_linux(NR_rt_tgsigqueueinfo_linux, tgid, pid, sig, uinfo, 0);
}
// 11c. Blocking and unblocking signals
// Disabled wrapper: long sigprocmask_linux(int how, unsigned long *set, unsigned long *oset);
long rt_sigprocmask_linux(int how, unsigned long long *set, unsigned long long *oset) {
  return Syscall4_linux(NR_rt_sigprocmask_linux, how, set, oset, sizeof(*set), 0);
}
// Disabled wrapper: long sgetmask_linux(void);
// Disabled wrapper: long ssetmask_linux(int newmask);
// 11d. Waiting for and querying signals
// Disabled wrapper: long sigpending_linux(unsigned long *uset);
long rt_sigpending_linux(unsigned long long *set) {
  return Syscall2_linux(NR_rt_sigpending_linux, set, sizeof(*set), 0);
}
// Disabled wrapper: long sigsuspend_linux(unsigned long mask);
long rt_sigsuspend_linux(unsigned long long *unewset) {
  return Syscall2_linux(NR_rt_sigsuspend_linux, unewset, sizeof(*unewset), 0);
}
long pause_linux(void) {
  unsigned long long mask = 0;
  long ret = rt_sigprocmask_linux(SIG_BLOCK_linux, 0, &mask);
  if (ret < 0) return ret;
  return rt_sigsuspend_linux(&mask);
}
// Disabled wrapper: long rt_sigtimedwait_linux(const unsigned long long *uthese, siginfo_t_linux *uinfo, const __kernel_old_timespec_linux *uts, unsigned long sigsetsize);
long rt_sigtimedwait_time64_linux(unsigned long long *uthese, siginfo_t_linux *uinfo, __kernel_timespec_linux *uts) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_rt_sigtimedwait_linux, uthese, uinfo, uts, sizeof(*uthese), 0);
#else
  return Syscall4_linux(NR_rt_sigtimedwait_time64_linux, uthese, uinfo, uts, sizeof(*uthese), 0);
#endif
}
// 11e. Alternate signal stack and return from handlers
long sigaltstack_linux(const stack_t_linux *uss, stack_t_linux *uoss) {
  return Syscall2_linux(NR_sigaltstack_linux, uss, uoss, 0);
}
// Disabled wrapper: long sigreturn_linux(void);
long rt_sigreturn_linux(void) {
  return Syscall0_linux(NR_rt_sigreturn_linux, 0);
}
// 11f. Signal delivery via file descriptors
long signalfd_linux(int ufd, unsigned long long *user_mask) {
  return signalfd4_linux(ufd, user_mask, 0);
}
long signalfd4_linux(int ufd, unsigned long long *user_mask, int flags) {
  return Syscall4_linux(NR_signalfd4_linux, ufd, user_mask, sizeof(*user_mask), flags, 0);
}
//
// 12. PIPES & FIFOs
//
long pipe_linux(int *fildes) {
  return pipe2_linux(fildes, 0);
}
long pipe2_linux(int *fildes, int flags) {
  return Syscall2_linux(NR_pipe2_linux, fildes, flags, 0);
}
//
// 13. INTER-PROCESS COMMUNICATION
//
// 13a. System V IPC - Shared Memory
long shmget_linux(int key, unsigned long size, int flag) {
  return Syscall3_linux(NR_shmget_linux, key, size, flag, 0);
}
long shmat_linux(int shmid, const void *shmaddr, int shmflg) {
  return Syscall3_linux(NR_shmat_linux, shmid, shmaddr, shmflg, 0);
}
long shmdt_linux(const void *shmaddr) {
  return Syscall1_linux(NR_shmdt_linux, shmaddr, 0);
}
long shmctl_linux(int shmid, int cmd, shmid_ds_linux *buf) {
  return Syscall3_linux(NR_shmctl_linux, shmid, cmd | IPC_64_linux, buf, 0);
}
// 13b. System V IPC - Message Queues
long msgget_linux(int key, int msgflg) {
  return Syscall2_linux(NR_msgget_linux, key, msgflg, 0);
}
long msgsnd_linux(int msqid, const void *msgp, unsigned long msgsz, int msgflg) {
  return Syscall4_linux(NR_msgsnd_linux, msqid, msgp, msgsz, msgflg, 0);
}
long msgrcv_linux(int msqid, void *msgp, unsigned long msgsz, long msgtyp, int msgflg) {
  return Syscall5_linux(NR_msgrcv_linux, msqid, msgp, msgsz, msgtyp, msgflg, 0);
}
long msgctl_linux(int msqid, int cmd, msqid_ds_linux *buf) {
  return Syscall3_linux(NR_msgctl_linux, msqid, cmd | IPC_64_linux, buf, 0);
}
// 13c. System V IPC - Semaphores
long semget_linux(int key, int nsems, int semflg) {
  return Syscall3_linux(NR_semget_linux, key, nsems, semflg, 0);
}
long semop_linux(int semid, sembuf_linux *sops, unsigned nsops) {
  return semtimedop_time64_linux(semid, sops, nsops, 0);
}
long semctl_linux(int semid, int semnum, int cmd, unsigned long arg) {
  return Syscall4_linux(NR_semctl_linux, semid, semnum, cmd | IPC_64_linux, arg, 0);
}
// Disabled wrapper: long semtimedop_linux(int semid, sembuf_linux *sops, unsigned nsops, const __kernel_old_timespec_linux *timeout);
long semtimedop_time64_linux(int semid, sembuf_linux *tsops, unsigned int nsops, const __kernel_timespec_linux *timeout) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall4_linux(NR_semtimedop_linux, semid, tsops, nsops, timeout, 0);
#else
  return Syscall4_linux(NR_semtimedop_time64_linux, semid, tsops, nsops, timeout, 0);
#endif
}
// 13d. POSIX Message Queues
long mq_open_linux(const char *name, int oflag, unsigned int mode, mq_attr_linux *attr) {
  return Syscall4_linux(NR_mq_open_linux, name, oflag, mode, attr, 0);
}
long mq_unlink_linux(const char *name) {
  return Syscall1_linux(NR_mq_unlink_linux, name, 0);
}
// Disabled wrapper: long mq_timedsend_linux(int mqdes, const char *msg_ptr, unsigned long msg_len, unsigned int msg_prio, const __kernel_old_timespec_linux *abs_timeout);
long mq_timedsend_time64_linux(int mqdes, const void *msg_ptr, unsigned long msg_len, unsigned int msg_prio, const __kernel_timespec_linux *u_abs_timeout) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall5_linux(NR_mq_timedsend_linux, mqdes, msg_ptr, msg_len, msg_prio, u_abs_timeout, 0);
#else
  return Syscall5_linux(NR_mq_timedsend_time64_linux, mqdes, msg_ptr, msg_len, msg_prio, u_abs_timeout, 0);
#endif
}
// Disabled wrapper: long mq_timedreceive_linux(int mqdes, char *msg_ptr, unsigned long msg_len, unsigned int *msg_prio, const __kernel_old_timespec_linux *abs_timeout);
long mq_timedreceive_time64_linux(int mqdes, void *msg_ptr, unsigned long msg_len, unsigned int *u_msg_prio, const __kernel_timespec_linux *u_abs_timeout) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall5_linux(NR_mq_timedreceive_linux, mqdes, msg_ptr, msg_len, u_msg_prio, u_abs_timeout, 0);
#else
  return Syscall5_linux(NR_mq_timedreceive_time64_linux, mqdes, msg_ptr, msg_len, u_msg_prio, u_abs_timeout, 0);
#endif
}
long mq_notify_linux(int mqdes, const sigevent_linux *notification) {
  return Syscall2_linux(NR_mq_notify_linux, mqdes, notification, 0);
}
long mq_getsetattr_linux(int mqdes, const mq_attr_linux *mqstat, mq_attr_linux *omqstat) {
  return Syscall3_linux(NR_mq_getsetattr_linux, mqdes, mqstat, omqstat, 0);
}
// 13e. Synchronization Primitives - Futexes
// Disabled wrapper: long futex_linux(unsigned int *uaddr, int op, unsigned int val, const __kernel_old_timespec_linux *utime, unsigned int *uaddr2, unsigned int val3);
long futex_time64_linux(unsigned int *uaddr, int op, unsigned int val, const __kernel_timespec_linux *utime, unsigned int *uaddr2, unsigned int val3) {
#if defined(__x86_64__) || defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
  return Syscall6_linux(NR_futex_linux, uaddr, op, val, utime, uaddr2, val3, 0);
#else
  return Syscall6_linux(NR_futex_time64_linux, uaddr, op, val, utime, uaddr2, val3, 0);
#endif
}
long futex_wait_linux(void *uaddr, unsigned long val, unsigned long mask, unsigned int flags, const __kernel_timespec_linux *timespec, int clockid) {
  return Syscall6_linux(NR_futex_wait_linux, uaddr, val, mask, flags, timespec, clockid, 0);
}
long futex_wake_linux(void *uaddr, unsigned long mask, int nr, unsigned int flags) {
  return Syscall4_linux(NR_futex_wake_linux, uaddr, mask, nr, flags, 0);
}
long futex_waitv_linux(const futex_waitv_t_linux *waiters, unsigned int nr_futexes, unsigned int flags, const __kernel_timespec_linux *timeout, int clockid) {
  return Syscall5_linux(NR_futex_waitv_linux, waiters, nr_futexes, flags, timeout, clockid, 0);
}
long futex_requeue_linux(const futex_waitv_t_linux *waiters, unsigned int flags, int nr_wake, int nr_requeue) {
  return Syscall4_linux(NR_futex_requeue_linux, waiters, flags, nr_wake, nr_requeue, 0);
}
long set_robust_list_linux(robust_list_head_linux *head) {
  return Syscall2_linux(NR_set_robust_list_linux, head, sizeof(*head), 0);
}
long get_robust_list_linux(int pid, robust_list_head_linux * *head_ptr, unsigned long *len_ptr) {
  return Syscall3_linux(NR_get_robust_list_linux, pid, head_ptr, len_ptr, 0);
}
// 13f. Synchronization Primitives - Event Notification
long eventfd_linux(unsigned int count) {
  return eventfd2_linux(count, 0);
}
long eventfd2_linux(unsigned int count, int flags) {
  return Syscall2_linux(NR_eventfd2_linux, count, flags, 0);
}
#if 0 // WIP
//
// 14. SOCKETS & NETWORKING
//
// 14a. Creating and configuring sockets
long socket_linux(int family, int type, int protocol) {
  return Syscall3_linux(NR_socket_linux, family, type, protocol, 0);
}
long socketpair_linux(int family, int type, int protocol, int *usockvec) {
  return Syscall4_linux(NR_socketpair_linux, family, type, protocol, usockvec, 0);
}
long bind_linux(int fd, sockaddr_linux *umyaddr, int addrlen) {
  return Syscall3_linux(NR_bind_linux, fd, umyaddr, addrlen, 0);
}
long listen_linux(int fd, int backlog) {
  return Syscall2_linux(NR_listen_linux, fd, backlog, 0);
}
long accept_linux(int fd, sockaddr_linux *upeer_sockaddr, int *upeer_addrlen) {
  return Syscall3_linux(NR_accept_linux, fd, upeer_sockaddr, upeer_addrlen, 0);
}
long accept4_linux(int fd, sockaddr_linux *upeer_sockaddr, int *upeer_addrlen, int flags) {
  return Syscall4_linux(NR_accept4_linux, fd, upeer_sockaddr, upeer_addrlen, flags, 0);
}
long connect_linux(int fd, sockaddr_linux *uservaddr, int addrlen) {
  return Syscall3_linux(NR_connect_linux, fd, uservaddr, addrlen, 0);
}
long shutdown_linux(int fd, int how) {
  return Syscall2_linux(NR_shutdown_linux, fd, how, 0);
}
long socketcall_linux(int call, unsigned long *args) {
  return Syscall2_linux(NR_socketcall_linux, call, args, 0);
}
// 14b. Sending and receiving data on sockets
long send_linux(int fd, void *buff, unsigned long len, unsigned int flags) {
  return Syscall4_linux(NR_send_linux, fd, buff, len, flags, 0);
}
long sendto_linux(int fd, void *buff, unsigned long len, unsigned int flags, sockaddr_linux *addr, int addr_len) {
  return Syscall6_linux(NR_sendto_linux, fd, buff, len, flags, addr, addr_len, 0);
}
long sendmsg_linux(int fd, user_msghdr *msg, unsigned flags) {
  return Syscall3_linux(NR_sendmsg_linux, fd, msg, flags, 0);
}
long sendmmsg_linux(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags) {
  return Syscall4_linux(NR_sendmmsg_linux, fd, msg, vlen, flags, 0);
}
long recv_linux(int fd, void *ubuf, unsigned long size, unsigned int flags) {
  return Syscall4_linux(NR_recv_linux, fd, ubuf, size, flags, 0);
}
long recvfrom_linux(int fd, void *ubuf, unsigned long size, unsigned int flags, sockaddr_linux *addr, int *addr_len) {
  return Syscall6_linux(NR_recvfrom_linux, fd, ubuf, size, flags, addr, addr_len, 0);
}
long recvmsg_linux(int fd, user_msghdr *msg, unsigned flags) {
  return Syscall3_linux(NR_recvmsg_linux, fd, msg, flags, 0);
}
// Disabled wrapper: long recvmmsg_linux(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags, __kernel_old_timespec_linux *timeout);
long recvmmsg_time64_linux(int fd, mmsghdr *mmsg, unsigned int vlen, unsigned int flags, __kernel_timespec_linux *timeout) {
  return Syscall5_linux(NR_recvmmsg_time64_linux, fd, mmsg, vlen, flags, timeout, 0);
}
// 14c. Getting and setting socket options
long getsockopt_linux(int fd, int level, int optname, char *optval, int *optlen) {
  return Syscall5_linux(NR_getsockopt_linux, fd, level, optname, optval, optlen, 0);
}
long setsockopt_linux(int fd, int level, int optname, char *optval, int optlen) {
  return Syscall5_linux(NR_setsockopt_linux, fd, level, optname, optval, optlen, 0);
}
long getsockname_linux(int fd, sockaddr_linux *usockaddr, int *usockaddr_len) {
  return Syscall3_linux(NR_getsockname_linux, fd, usockaddr, usockaddr_len, 0);
}
long getpeername_linux(int fd, sockaddr_linux *usockaddr, int *usockaddr_len) {
  return Syscall3_linux(NR_getpeername_linux, fd, usockaddr, usockaddr_len, 0);
}
//
// 15. ASYNCHRONOUS I/O
//
// 15a. AIO: asynchronous I/O interface
long io_setup_linux(unsigned nr_reqs, aio_context_t *ctx) {
  return Syscall2_linux(NR_io_setup_linux, nr_reqs, ctx, 0);
}
long io_destroy_linux(aio_context_t ctx) {
  return Syscall1_linux(NR_io_destroy_linux, ctx, 0);
}
long io_submit_linux(aio_context_t ctx_id, long nr, iocb * *iocbpp) {
  return Syscall3_linux(NR_io_submit_linux, ctx_id, nr, iocbpp, 0);
}
long io_cancel_linux(aio_context_t ctx_id, iocb *iocb, io_event *result) {
  return Syscall3_linux(NR_io_cancel_linux, ctx_id, iocb, result, 0);
}
long io_getevents_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_timespec_linux *timeout) {
  return Syscall5_linux(NR_io_getevents_linux, ctx_id, min_nr, nr, events, timeout, 0);
}
// Disabled wrapper: long io_pgetevents_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_old_timespec_linux *timeout, const __aio_sigset *sig);
long io_pgetevents_time64_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_timespec_linux *timeout, const __aio_sigset *sig) {
  return Syscall6_linux(NR_io_pgetevents_time64_linux, ctx_id, min_nr, nr, events, timeout, sig, 0);
}
// 15b. io_uring: high-performance asynchronous I/O
long io_uring_setup_linux(unsigned int entries, io_uring_params *p) {
  return Syscall2_linux(NR_io_uring_setup_linux, entries, p, 0);
}
long io_uring_enter_linux(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, const void *argp, unsigned long argsz) {
  return Syscall6_linux(NR_io_uring_enter_linux, fd, to_submit, min_complete, flags, argp, argsz, 0);
}
long io_uring_register_linux(unsigned int fd, unsigned int op, void *arg, unsigned int nr_args) {
  return Syscall4_linux(NR_io_uring_register_linux, fd, op, arg, nr_args, 0);
}
//
// 16. TIME & CLOCKS
//
// 16a. Reading current time from various clocks
long time_linux(__kernel_old_time_t *tloc) {
  return Syscall1_linux(NR_time_linux, tloc, 0);
}
long gettimeofday_linux(__kernel_old_timeval *tv, timezone *tz) {
  return Syscall2_linux(NR_gettimeofday_linux, tv, tz, 0);
}
// Disabled wrapper: long clock_gettime_linux(int which_clock, __kernel_old_timespec_linux *tp);
long clock_gettime64_linux(int which_clock, __kernel_timespec_linux *tp) {
  return Syscall2_linux(NR_clock_gettime64_linux, which_clock, tp, 0);
}
// Disabled wrapper: long clock_getres_linux(int which_clock, __kernel_old_timespec_linux *tp);
long clock_getres_time64_linux(int which_clock, __kernel_timespec_linux *tp) {
  return Syscall2_linux(NR_clock_getres_time64_linux, which_clock, tp, 0);
}
// 16b. Setting system time and adjusting clocks
long settimeofday_linux(__kernel_old_timeval *tv, timezone *tz) {
  return Syscall2_linux(NR_settimeofday_linux, tv, tz, 0);
}
// Disabled wrapper: long clock_settime_linux(int which_clock, const __kernel_old_timespec_linux *tp);
long clock_settime64_linux(int which_clock, const __kernel_timespec_linux *tp) {
  return Syscall2_linux(NR_clock_settime64_linux, which_clock, tp, 0);
}
long stime_linux(__kernel_old_time_t *tptr) {
  return Syscall1_linux(NR_stime_linux, tptr, 0);
}
long adjtimex_linux(__kernel_timex *txc_p) {
  return Syscall1_linux(NR_adjtimex_linux, txc_p, 0);
}
long clock_adjtime_linux(int which_clock, __kernel_timex *tx) {
  return Syscall2_linux(NR_clock_adjtime_linux, which_clock, tx, 0);
}
long clock_adjtime64_linux(int which_clock, __kernel_timex *tx) {
  return Syscall2_linux(NR_clock_adjtime64_linux, which_clock, tx, 0);
}
// 16c. Suspending execution for a period of time
long nanosleep_linux(__kernel_timespec_linux *rqtp, __kernel_timespec_linux *rmtp) {
  return Syscall2_linux(NR_nanosleep_linux, rqtp, rmtp, 0);
}
// Disabled wrapper: long clock_nanosleep_linux(int which_clock, int flags, const __kernel_old_timespec_linux *rqtp, __kernel_old_timespec_linux *rmtp);
long clock_nanosleep_time64_linux(int which_clock, int flags, const __kernel_timespec_linux *rqtp, __kernel_timespec_linux *rmtp) {
  return Syscall4_linux(NR_clock_nanosleep_time64_linux, which_clock, flags, rqtp, rmtp, 0);
}
// 16d. Setting periodic or one-shot timers
long alarm_linux(unsigned int seconds) {
  return Syscall1_linux(NR_alarm_linux, seconds, 0);
}
long setitimer_linux(int which, __kernel_old_itimerval *value, __kernel_old_itimerval *ovalue) {
  return Syscall3_linux(NR_setitimer_linux, which, value, ovalue, 0);
}
long getitimer_linux(int which, __kernel_old_itimerval *value) {
  return Syscall2_linux(NR_getitimer_linux, which, value, 0);
}
// 16e. Per-process timers with precise control
long timer_create_linux(int which_clock, sigevent_linux *timer_event_spec, timer_t * created_timer_id) {
  return Syscall3_linux(NR_timer_create_linux, which_clock, timer_event_spec, created_timer_id, 0);
}
// Disabled wrapper: long timer_settime_linux(timer_t timer_id, int flags, const __kernel_itimerspec *new_setting, __kernel_itimerspec *old_setting);
long timer_settime64_linux(timer_t timerid, int flags, const __kernel_timespec_linux *new_setting, __kernel_timespec_linux *old_setting) {
  return Syscall4_linux(NR_timer_settime64_linux, timerid, flags, new_setting, old_setting, 0);
}
// Disabled wrapper: long timer_gettime_linux(timer_t timer_id, __kernel_itimerspec *setting);
long timer_gettime64_linux(timer_t timerid, __kernel_timespec_linux *setting) {
  return Syscall2_linux(NR_timer_gettime64_linux, timerid, setting, 0);
}
long timer_getoverrun_linux(timer_t timer_id) {
  return Syscall1_linux(NR_timer_getoverrun_linux, timer_id, 0);
}
long timer_delete_linux(timer_t timer_id) {
  return Syscall1_linux(NR_timer_delete_linux, timer_id, 0);
}
// 16f. Timers accessible via file descriptors
long timerfd_create_linux(int clockid, int flags) {
  return Syscall2_linux(NR_timerfd_create_linux, clockid, flags, 0);
}
// Disabled wrapper: long timerfd_settime_linux(int ufd, int flags, const __kernel_itimerspec *utmr, __kernel_itimerspec *otmr);
long timerfd_settime64_linux(int ufd, int flags, const __kernel_timespec_linux *utmr, __kernel_timespec_linux *otmr) {
  return Syscall4_linux(NR_timerfd_settime64_linux, ufd, flags, utmr, otmr, 0);
}
// Disabled wrapper: long timerfd_gettime_linux(int ufd, __kernel_itimerspec *otmr);
long timerfd_gettime64_linux(int ufd, __kernel_timespec_linux *otmr) {
  return Syscall2_linux(NR_timerfd_gettime64_linux, ufd, otmr, 0);
}
//
// 17. RANDOM NUMBERS
//
long getrandom_linux(char *buf, unsigned long count, unsigned int flags) {
  return Syscall3_linux(NR_getrandom_linux, buf, count, flags, 0);
}
//
// 18. USER & GROUP IDENTITY
//
// 18a. Getting and setting user IDs
long getuid_linux(void) {
  return Syscall0_linux(NR_getuid_linux, 0);
}
long geteuid_linux(void) {
  return Syscall0_linux(NR_geteuid_linux, 0);
}
long setuid_linux(unsigned int uid) {
  return Syscall1_linux(NR_setuid_linux, uid, 0);
}
long setreuid_linux(unsigned int ruid, unsigned int euid) {
  return Syscall2_linux(NR_setreuid_linux, ruid, euid, 0);
}
long setresuid_linux(unsigned int ruid, unsigned int euid, unsigned int suid) {
  return Syscall3_linux(NR_setresuid_linux, ruid, euid, suid, 0);
}
long getresuid_linux(unsigned int *ruid, unsigned int *euid, unsigned int *suid) {
  return Syscall3_linux(NR_getresuid_linux, ruid, euid, suid, 0);
}
long setfsuid_linux(unsigned int uid) {
  return Syscall1_linux(NR_setfsuid_linux, uid, 0);
}
long getuid32_linux(void) {
  return Syscall0_linux(NR_getuid32_linux, 0);
}
long geteuid32_linux(void) {
  return Syscall0_linux(NR_geteuid32_linux, 0);
}
long setuid32_linux(unsigned int uid) {
  return Syscall1_linux(NR_setuid32_linux, uid, 0);
}
long setreuid32_linux(unsigned int ruid, unsigned int euid) {
  return Syscall2_linux(NR_setreuid32_linux, ruid, euid, 0);
}
long setresuid32_linux(unsigned int ruid, unsigned int euid, unsigned int suid) {
  return Syscall3_linux(NR_setresuid32_linux, ruid, euid, suid, 0);
}
long getresuid32_linux(unsigned int *ruid, unsigned int *euid, unsigned int *suid) {
  return Syscall3_linux(NR_getresuid32_linux, ruid, euid, suid, 0);
}
long setfsuid32_linux(unsigned int uid) {
  return Syscall1_linux(NR_setfsuid32_linux, uid, 0);
}
// 18b. Getting and setting group IDs
long getgid_linux(void) {
  return Syscall0_linux(NR_getgid_linux, 0);
}
long getegid_linux(void) {
  return Syscall0_linux(NR_getegid_linux, 0);
}
long setgid_linux(unsigned int gid) {
  return Syscall1_linux(NR_setgid_linux, gid, 0);
}
long setregid_linux(unsigned int rgid, unsigned int egid) {
  return Syscall2_linux(NR_setregid_linux, rgid, egid, 0);
}
long setresgid_linux(unsigned int rgid, unsigned int egid, unsigned int sgid) {
  return Syscall3_linux(NR_setresgid_linux, rgid, egid, sgid, 0);
}
long getresgid_linux(unsigned int *rgid, unsigned int *egid, unsigned int *sgid) {
  return Syscall3_linux(NR_getresgid_linux, rgid, egid, sgid, 0);
}
long setfsgid_linux(unsigned int gid) {
  return Syscall1_linux(NR_setfsgid_linux, gid, 0);
}
long getgid32_linux(void) {
  return Syscall0_linux(NR_getgid32_linux, 0);
}
long getegid32_linux(void) {
  return Syscall0_linux(NR_getegid32_linux, 0);
}
long setgid32_linux(unsigned int gid) {
  return Syscall1_linux(NR_setgid32_linux, gid, 0);
}
long setregid32_linux(unsigned int rgid, unsigned int egid) {
  return Syscall2_linux(NR_setregid32_linux, rgid, egid, 0);
}
long setresgid32_linux(unsigned int rgid, unsigned int egid, unsigned int sgid) {
  return Syscall3_linux(NR_setresgid32_linux, rgid, egid, sgid, 0);
}
long getresgid32_linux(unsigned int *rgid, unsigned int *egid, unsigned int *sgid) {
  return Syscall3_linux(NR_getresgid32_linux, rgid, egid, sgid, 0);
}
long setfsgid32_linux(unsigned int gid) {
  return Syscall1_linux(NR_setfsgid32_linux, gid, 0);
}
// 18c. Managing supplementary group list
long getgroups_linux(int gidsetsize, unsigned int *grouplist) {
  return Syscall2_linux(NR_getgroups_linux, gidsetsize, grouplist, 0);
}
long setgroups_linux(int gidsetsize, unsigned int *grouplist) {
  return Syscall2_linux(NR_setgroups_linux, gidsetsize, grouplist, 0);
}
long getgroups32_linux(int gidsetsize, unsigned int *grouplist) {
  return Syscall2_linux(NR_getgroups32_linux, gidsetsize, grouplist, 0);
}
long setgroups32_linux(int gidsetsize, unsigned int *grouplist) {
  return Syscall2_linux(NR_setgroups32_linux, gidsetsize, grouplist, 0);
}
//
// 19. CAPABILITIES & SECURITY
//
// 19a. Fine-grained privilege control
long capget_linux(cap_user_header_t header, cap_user_data_t dataptr) {
  return Syscall2_linux(NR_capget_linux, header, dataptr, 0);
}
long capset_linux(cap_user_header_t header, const cap_user_data_t data) {
  return Syscall2_linux(NR_capset_linux, header, data, 0);
}
// 19b. Syscall filtering and sandboxing
long seccomp_linux(unsigned int op, unsigned int flags, void *uargs) {
  return Syscall3_linux(NR_seccomp_linux, op, flags, uargs, 0);
}
// 19c. Linux Security Module interfaces
long security_linux(void) {
  return Syscall0_linux(NR_security_linux, 0);
}
long lsm_get_self_attr_linux(unsigned int attr, lsm_ctx *ctx, unsigned int *size, unsigned int flags) {
  return Syscall4_linux(NR_lsm_get_self_attr_linux, attr, ctx, size, flags, 0);
}
long lsm_set_self_attr_linux(unsigned int attr, lsm_ctx *ctx, unsigned int size, unsigned int flags) {
  return Syscall4_linux(NR_lsm_set_self_attr_linux, attr, ctx, size, flags, 0);
}
long lsm_list_modules_linux(unsigned long long *ids, unsigned int *size, unsigned int flags) {
  return Syscall3_linux(NR_lsm_list_modules_linux, ids, size, flags, 0);
}
// 19d. Unprivileged access control
long landlock_create_ruleset_linux(const landlock_ruleset_attr *attr, unsigned long size, __u32 flags) {
  return Syscall3_linux(NR_landlock_create_ruleset_linux, attr, size, flags, 0);
}
long landlock_add_rule_linux(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, __u32 flags) {
  return Syscall4_linux(NR_landlock_add_rule_linux, ruleset_fd, rule_type, rule_attr, flags, 0);
}
long landlock_restrict_self_linux(int ruleset_fd, __u32 flags) {
  return Syscall2_linux(NR_landlock_restrict_self_linux, ruleset_fd, flags, 0);
}
// 19e. Kernel key retention service
long add_key_linux(const char *_type, const char *_description, const void *_payload, unsigned long plen, key_serial_t destringid) {
  return Syscall5_linux(NR_add_key_linux, _type, _description, _payload, plen, destringid, 0);
}
long request_key_linux(const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid) {
  return Syscall4_linux(NR_request_key_linux, _type, _description, _callout_info, destringid, 0);
}
long keyctl_linux(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
  return Syscall5_linux(NR_keyctl_linux, cmd, arg2, arg3, arg4, arg5, 0);
}
//
// 20. RESOURCE LIMITS & ACCOUNTING
//
// 20a. Getting and setting process resource limits
long getrlimit_linux(unsigned int resource, rlimit *rlim) {
  return Syscall2_linux(NR_getrlimit_linux, resource, rlim, 0);
}
long setrlimit_linux(unsigned int resource, rlimit *rlim) {
  return Syscall2_linux(NR_setrlimit_linux, resource, rlim, 0);
}
long prlimit64_linux(int pid, unsigned int resource, const rlimit64 *new_rlim, rlimit64 *old_rlim) {
  return Syscall4_linux(NR_prlimit64_linux, pid, resource, new_rlim, old_rlim, 0);
}
long ugetrlimit_linux(unsigned int resource, rlimit *rlim) {
  return Syscall2_linux(NR_ugetrlimit_linux, resource, rlim, 0);
}
long ulimit_linux(int cmd, long newval) {
  return Syscall2_linux(NR_ulimit_linux, cmd, newval, 0);
}
// 20b. Getting resource usage and time statistics
long getrusage_linux(int who, rusage_linux *ru) {
  return Syscall2_linux(NR_getrusage_linux, who, ru, 0);
}
long times_linux(tms *tbuf) {
  return Syscall1_linux(NR_times_linux, tbuf, 0);
}
// 20c. System-wide process accounting
long acct_linux(const char *name) {
  return Syscall1_linux(NR_acct_linux, name, 0);
}
//
// 21. NAMESPACES & CONTAINERS
//
long unshare_linux(unsigned long unshare_flags) {
  return Syscall1_linux(NR_unshare_linux, unshare_flags, 0);
}
long setns_linux(int fd, int nstype) {
  return Syscall2_linux(NR_setns_linux, fd, nstype, 0);
}
long listns_linux(const ns_id_req *req, unsigned long long *ns_ids, unsigned long nr_ns_ids, unsigned int flags) {
  return Syscall4_linux(NR_listns_linux, req, ns_ids, nr_ns_ids, flags, 0);
}
//
// 22. PROCESS INSPECTION & CONTROL
//
// 22a. Process comparison
long kcmp_linux(int pid1, int pid2, int type, unsigned long idx1, unsigned long idx2) {
  return Syscall5_linux(NR_kcmp_linux, pid1, pid2, type, idx1, idx2, 0);
}
// 22b. Process file descriptors
long pidfd_open_linux(int pid, unsigned int flags) {
  return Syscall2_linux(NR_pidfd_open_linux, pid, flags, 0);
}
long pidfd_getfd_linux(int pidfd, int fd, unsigned int flags) {
  return Syscall3_linux(NR_pidfd_getfd_linux, pidfd, fd, flags, 0);
}
long pidfd_send_signal_linux(int pidfd, int sig, siginfo_t_linux *info, unsigned int flags) {
  return Syscall4_linux(NR_pidfd_send_signal_linux, pidfd, sig, info, flags, 0);
}
// 22c. Process memory access
long process_vm_readv_linux(int pid, const iovec_linux *lvec, unsigned long liovcnt, const iovec_linux *rvec, unsigned long riovcnt, unsigned long flags) {
  return Syscall6_linux(NR_process_vm_readv_linux, pid, lvec, liovcnt, rvec, riovcnt, flags, 0);
}
long process_vm_writev_linux(int pid, const iovec_linux *lvec, unsigned long liovcnt, const iovec_linux *rvec, unsigned long riovcnt, unsigned long flags) {
  return Syscall6_linux(NR_process_vm_writev_linux, pid, lvec, liovcnt, rvec, riovcnt, flags, 0);
}
// 22d. Process tracing
long ptrace_linux(long request, long pid, unsigned long addr, unsigned long data) {
  return Syscall4_linux(NR_ptrace_linux, request, pid, addr, data, 0);
}
//
// 23. SYSTEM INFORMATION
//
// 23a. System name and domain information
long uname_linux(old_utsname *) {
  return Syscall1_linux(NR_uname_linux, , 0);
}
long olduname_linux(oldold_utsname *) {
  return Syscall1_linux(NR_olduname_linux, , 0);
}
long oldolduname_linux(oldold_utsname *name) {
  return Syscall1_linux(NR_oldolduname_linux, name, 0);
}
long gethostname_linux(char *name, int len) {
  return Syscall2_linux(NR_gethostname_linux, name, len, 0);
}
long sethostname_linux(char *name, int len) {
  return Syscall2_linux(NR_sethostname_linux, name, len, 0);
}
long setdomainname_linux(char *name, int len) {
  return Syscall2_linux(NR_setdomainname_linux, name, len, 0);
}
// 23b. Overall system information and statistics
long sysinfo_linux(sysinfo *info) {
  return Syscall1_linux(NR_sysinfo_linux, info, 0);
}
// 23c. Reading kernel log messages
long syslog_linux(int type, char *buf, int len) {
  return Syscall3_linux(NR_syslog_linux, type, buf, len, 0);
}
// 23d. Getting CPU and NUMA node information
long getcpu_linux(unsigned *cpu, unsigned *node, getcpu_cache *cache) {
  return Syscall3_linux(NR_getcpu_linux, cpu, node, cache, 0);
}
// 23e. Kernel filesystem information interface
long sysfs_linux(int option, unsigned long arg1, unsigned long arg2) {
  return Syscall3_linux(NR_sysfs_linux, option, arg1, arg2, 0);
}
//
// 24. KERNEL MODULES
//
long create_module_linux(const char *name, unsigned long size) {
  return Syscall2_linux(NR_create_module_linux, name, size, 0);
}
long init_module_linux(void *umod, unsigned long len, const char *uargs) {
  return Syscall3_linux(NR_init_module_linux, umod, len, uargs, 0);
}
long finit_module_linux(int fd, const char *uargs, int flags) {
  return Syscall3_linux(NR_finit_module_linux, fd, uargs, flags, 0);
}
long delete_module_linux(const char *name_user, unsigned int flags) {
  return Syscall2_linux(NR_delete_module_linux, name_user, flags, 0);
}
long query_module_linux(const char *name, int which, void *buf, unsigned long bufsize, unsigned long *ret) {
  return Syscall5_linux(NR_query_module_linux, name, which, buf, bufsize, ret, 0);
}
long get_kernel_syms_linux(kernel_sym *table) {
  return Syscall1_linux(NR_get_kernel_syms_linux, table, 0);
}
//
// 25. SYSTEM CONTROL & ADMINISTRATION
//
// 25a. Rebooting and shutting down the system
long reboot_linux(int magic1, int magic2, unsigned int cmd, void *arg) {
  return Syscall4_linux(NR_reboot_linux, magic1, magic2, cmd, arg, 0);
}
// 25b. Enabling and disabling swap areas
long swapon_linux(const char *specialfile, int swap_flags) {
  return Syscall2_linux(NR_swapon_linux, specialfile, swap_flags, 0);
}
long swapoff_linux(const char *specialfile) {
  return Syscall1_linux(NR_swapoff_linux, specialfile, 0);
}
// 25c. Loading and executing new kernels
long kexec_load_linux(unsigned long entry, unsigned long nr_segments, kexec_segment *segments, unsigned long flags) {
  return Syscall4_linux(NR_kexec_load_linux, entry, nr_segments, segments, flags, 0);
}
long kexec_file_load_linux(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags) {
  return Syscall5_linux(NR_kexec_file_load_linux, kernel_fd, initrd_fd, cmdline_len, cmdline_ptr, flags, 0);
}
// 25d. Other system administration operations
long vhangup_linux(void) {
  return Syscall0_linux(NR_vhangup_linux, 0);
}
//
// 26. PERFORMANCE MONITORING & TRACING
//
// 26a. Hardware and software performance monitoring
long perf_event_open_linux(perf_event_attr *attr_uptr, int pid, int cpu, int group_fd, unsigned long flags) {
  return Syscall5_linux(NR_perf_event_open_linux, attr_uptr, pid, cpu, group_fd, flags, 0);
}
// 26b. Userspace dynamic tracing
long uprobe_linux(void) {
  return Syscall0_linux(NR_uprobe_linux, 0);
}
long uretprobe_linux(void) {
  return Syscall0_linux(NR_uretprobe_linux, 0);
}
// 26c. Programmable Kernel Extensions (eBPF)
long bpf_linux(int cmd, union bpf_attr *attr, unsigned int size) {
  return Syscall3_linux(NR_bpf_linux, cmd, attr, size, 0);
}
//
// 27. DEVICE & HARDWARE ACCESS
//
// 27a. Direct hardware I/O port access
long ioperm_linux(unsigned long from, unsigned long num, int on) {
  return Syscall3_linux(NR_ioperm_linux, from, num, on, 0);
}
long iopl_linux(unsigned int level) {
  return Syscall1_linux(NR_iopl_linux, level, 0);
}
// 27b. Setting I/O scheduling priority
long ioprio_set_linux(int which, int who, int ioprio) {
  return Syscall3_linux(NR_ioprio_set_linux, which, who, ioprio, 0);
}
long ioprio_get_linux(int which, int who) {
  return Syscall2_linux(NR_ioprio_get_linux, which, who, 0);
}
// 27c. PCI device configuration access
long pciconfig_read_linux(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf) {
  return Syscall5_linux(NR_pciconfig_read_linux, bus, dfn, off, len, buf, 0);
}
long pciconfig_write_linux(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf) {
  return Syscall5_linux(NR_pciconfig_write_linux, bus, dfn, off, len, buf, 0);
}
long pciconfig_iobase_linux(long which, unsigned long bus, unsigned long devfn) {
  return Syscall3_linux(NR_pciconfig_iobase_linux, which, bus, devfn, 0);
}
// 27d. CPU cache control operations
long cacheflush_linux(unsigned long start, unsigned long end, int flags) {
  return Syscall3_linux(NR_cacheflush_linux, start, end, flags, 0);
}
long cachestat_linux(unsigned int fd, cachestat_range *cstat_range, cachestat *cstat, unsigned int flags) {
  return Syscall4_linux(NR_cachestat_linux, fd, cstat_range, cstat, flags, 0);
}
//
// 28. ARCHITECTURE-SPECIFIC OPERATIONS
//
// 28a. x86 architecture operations
long arch_prctl_linux(int option, unsigned long addr) {
  return Syscall2_linux(NR_arch_prctl_linux, option, addr, 0);
}
long modify_ldt_linux(int func, void *ptr, unsigned long bytecount) {
  return Syscall3_linux(NR_modify_ldt_linux, func, ptr, bytecount, 0);
}
long set_thread_area_linux(user_desc *u_info) {
  return Syscall1_linux(NR_set_thread_area_linux, u_info, 0);
}
long get_thread_area_linux(user_desc *u_info) {
  return Syscall1_linux(NR_get_thread_area_linux, u_info, 0);
}
long vm86_linux(unsigned long cmd, unsigned long arg) {
  return Syscall2_linux(NR_vm86_linux, cmd, arg, 0);
}
long vm86old_linux(vm86_struct *user_vm86) {
  return Syscall1_linux(NR_vm86old_linux, user_vm86, 0);
}
// 28b. ARM architecture operations
long set_tls_linux(unsigned long val) {
  return Syscall1_linux(NR_set_tls_linux, val, 0);
}
long get_tls_linux(void) {
  return Syscall0_linux(NR_get_tls_linux, 0);
}
// 28c. RISC-V architecture operations
long riscv_flush_icache_linux(uintptr_t start, uintptr_t end, uintptr_t flags) {
  return Syscall3_linux(NR_riscv_flush_icache_linux, start, end, flags, 0);
}
long riscv_hwprobe_linux(riscv_hwprobe *pairs, unsigned long pair_count, unsigned long cpu_count, unsigned long *cpumask, unsigned int flags) {
  return Syscall5_linux(NR_riscv_hwprobe_linux, pairs, pair_count, cpu_count, cpumask, flags, 0);
}
// 28d. Intel MPX support (deprecated)
long mpx_linux(void) {
  return Syscall0_linux(NR_mpx_linux, 0);
}
//
// 29. ADVANCED EXECUTION CONTROL
//
// 29a. Restartable sequences
long rseq_linux(rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig) {
  return Syscall4_linux(NR_rseq_linux, rseq, rseq_len, flags, sig, 0);
}
// 29b. Restart syscall
long restart_syscall_linux(void) {
  return Syscall0_linux(NR_restart_syscall_linux, 0);
}
// 29c. Directory entry cache
long lookup_dcookie_linux(unsigned long long cookie64, char *buf, unsigned long len) {
  return Syscall3_linux(NR_lookup_dcookie_linux, cookie64, buf, len, 0);
}
//
// 30. LEGACY, OBSOLETE & UNIMPLEMENTED
//
long _sysctl_linux(__sysctl_args *args) {
  return Syscall1_linux(NR__sysctl_linux, args, 0);
}
long ipc_linux(unsigned int call, int first, unsigned long second, unsigned long third, void *ptr, long fifth) {
  return Syscall6_linux(NR_ipc_linux, call, first, second, third, ptr, fifth, 0);
}
long profil_linux(unsigned short *sample_buffer, unsigned long size, unsigned long offset, unsigned int scale) {
  return Syscall4_linux(NR_profil_linux, sample_buffer, size, offset, scale, 0);
}
long prof_linux(void) {
  return Syscall0_linux(NR_prof_linux, 0);
}
long afs_syscall_linux(void) {
  return Syscall0_linux(NR_afs_syscall_linux, 0);
}
long break_linux(void) {
  return Syscall0_linux(NR_break_linux, 0);
}
long ftime_linux(void) {
  return Syscall0_linux(NR_ftime_linux, 0);
}
long gtty_linux(void) {
  return Syscall0_linux(NR_gtty_linux, 0);
}
long idle_linux(void) {
  return Syscall0_linux(NR_idle_linux, 0);
}
long lock_linux(void) {
  return Syscall0_linux(NR_lock_linux, 0);
}
long nfsservctl_linux(int cmd, nfsctl_arg *arg, union nfsctl_res *res) {
  return Syscall3_linux(NR_nfsservctl_linux, cmd, arg, res, 0);
}
long getpmsg_linux(int fd, strbuf *ctlptr, strbuf *dataptr, int *bandp, int *flagsp) {
  return Syscall5_linux(NR_getpmsg_linux, fd, ctlptr, dataptr, bandp, flagsp, 0);
}
long putpmsg_linux(int fd, strbuf *ctlptr, strbuf *dataptr, int band, int flags) {
  return Syscall5_linux(NR_putpmsg_linux, fd, ctlptr, dataptr, band, flags, 0);
}
long stty_linux(void) {
  return Syscall0_linux(NR_stty_linux, 0);
}
long tuxcall_linux(void) {
  return Syscall0_linux(NR_tuxcall_linux, 0);
}
long vserver_linux(void) {
  return Syscall0_linux(NR_vserver_linux, 0);
}
long bdflush_linux(int func, long data) {
  return Syscall2_linux(NR_bdflush_linux, func, data, 0);
}
long uselib_linux(const char *library) {
  return Syscall1_linux(NR_uselib_linux, library, 0);
}
#endif // WIP
