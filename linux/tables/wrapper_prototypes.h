//
// 1. PROCESS & THREAD LIFECYCLE
//
long fork_linux(void);
long vfork_linux(void);
long clone_linux(unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls);
long clone3_linux(clone_args_linux *uargs, unsigned long size);
long execve_linux(const char *filename, const char *const *argv, const char *const *envp);
long execveat_linux(int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags);
__attribute__((noreturn)) void exit_linux(int error_code);
__attribute__((noreturn)) void exit_group_linux(int error_code);
long wait4_linux(int pid, int *stat_addr, int options, rusage_linux *ru);
long waitid_linux(int which, int pid, siginfo_t_linux *infop, int options, rusage_linux *ru);
long waitpid_linux(int pid, int *stat_addr, int options);
//
// 2. PROCESS ATTRIBUTES & CONTROL
//
// 2a. Process identity, process groups and sessions
long getpid_linux(void);
long getppid_linux(void);
long gettid_linux(void);
long getpgid_linux(int pid);
long setpgid_linux(int pid, int pgid);
long getpgrp_linux(void);
long getsid_linux(int pid);
long setsid_linux(void);
long set_tid_address_linux(int *tidptr);
// 2b. Process control and personality
long prctl_linux(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
long personality_linux(unsigned int personality);
//
// 3. SCHEDULING & PRIORITIES
//
long sched_setscheduler_linux(int pid, int policy, sched_param_linux *param);
long sched_getscheduler_linux(int pid);
long sched_setparam_linux(int pid, sched_param_linux *param);
long sched_getparam_linux(int pid, sched_param_linux *param);
long sched_setattr_linux(int pid, sched_attr_linux *attr, unsigned int flags);
long sched_getattr_linux(int pid, sched_attr_linux *attr, unsigned int size, unsigned int flags);
long sched_yield_linux(void);
long sched_get_priority_max_linux(int policy);
long sched_get_priority_min_linux(int policy);
// Disabled wrapper: long sched_rr_get_interval_linux(int pid, __kernel_old_timespec_linux *interval);
long sched_rr_get_interval_time64_linux(int pid, __kernel_timespec_linux *interval);
long sched_setaffinity_linux(int pid, unsigned int len, unsigned long *user_mask_ptr);
long sched_getaffinity_linux(int pid, unsigned int len, unsigned long *user_mask_ptr);
long nice_linux(int increment);
long setpriority_linux(int which, int who, int niceval);
long getpriority_linux(int which, int who);
//
// 4. MEMORY MANAGEMENT
//
// 4a. Memory mapping, allocation, and unmapping
long brk_linux(unsigned long brk);
long mmap_linux(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long long off);
long mmap2_linux(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
long munmap_linux(unsigned long addr, unsigned long len);
long mremap_linux(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
long remap_file_pages_linux(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
// 4b. Memory protection, locking, and usage hints
long mprotect_linux(unsigned long start, unsigned long len, unsigned long prot);
long pkey_mprotect_linux(unsigned long start, unsigned long len, unsigned long prot, int pkey);
long madvise_linux(unsigned long start, unsigned long len, int behavior);
long process_madvise_linux(int pidfd, const iovec_linux *vec, unsigned long vlen, int behavior, unsigned int flags);
long mlock_linux(unsigned long start, unsigned long len);
long mlock2_linux(unsigned long start, unsigned long len, int flags);
long munlock_linux(unsigned long start, unsigned long len);
long mlockall_linux(int flags);
long munlockall_linux(void);
long mincore_linux(unsigned long start, unsigned long len, unsigned char * vec);
long msync_linux(unsigned long start, unsigned long len, int flags);
long mseal_linux(unsigned long start, unsigned long len, unsigned long flags);
// 4c. NUMA memory policy and page migration
long mbind_linux(unsigned long start, unsigned long len, unsigned long mode, const unsigned long *nmask, unsigned long maxnode, unsigned flags);
long set_mempolicy_linux(int mode, const unsigned long *nmask, unsigned long maxnode);
long get_mempolicy_linux(int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
long set_mempolicy_home_node_linux(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
long migrate_pages_linux(int pid, unsigned long maxnode, const unsigned long *from, const unsigned long *to);
long move_pages_linux(int pid, unsigned long nr_pages, const void * *pages, const int *nodes, int *status, int flags);
// 4d. Anonymous file-backed memory regions
long memfd_create_linux(const char *uname_ptr, unsigned int flags);
#if !defined(__arm__)
long memfd_secret_linux(unsigned int flags);
#endif
// 4e. Memory protection key management
long pkey_alloc_linux(unsigned long flags, unsigned long init_val);
long pkey_free_linux(int pkey);
// 4f. Control-flow integrity, shadow stack mapping
long map_shadow_stack_linux(unsigned long addr, unsigned long size, unsigned int flags);
// 4g. Advanced memory operations
long userfaultfd_linux(int flags);
long process_mrelease_linux(int pidfd, unsigned int flags);
long membarrier_linux(int cmd, unsigned int flags, int cpu_id);
//
// 5. FILE I/O OPERATIONS
//
// 5a. Opening, creating, and closing files
long open_linux(const char *filename, int flags, unsigned short mode);
long openat_linux(int dfd, const char *filename, int flags, unsigned short mode);
long openat2_linux(int dfd, const char *filename, open_how_linux *how, unsigned long size);
long creat_linux(const char *pathname, unsigned short mode);
long close_linux(unsigned int fd);
long close_range_linux(unsigned int fd, unsigned int max_fd, unsigned int flags);
long open_by_handle_at_linux(int mountdirfd, file_handle_linux *handle, int flags);
long name_to_handle_at_linux(int dfd, const char *name, file_handle_linux *handle, void *mnt_id, int flag);
// 5b. Reading and writing file data
long read_linux(unsigned int fd, char *buf, unsigned long count);
long write_linux(unsigned int fd, const char *buf, unsigned long count);
long readv_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen);
long writev_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen);
long pread64_linux(unsigned int fd, char *buf, unsigned long count, long long pos);
long pwrite64_linux(unsigned int fd, const char *buf, unsigned long count, long long pos);
long preadv_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long pwritev_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long preadv2_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags);
long pwritev2_linux(unsigned long fd, const iovec_linux *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags);
// 5c. Seeking and truncating files
// Disabled wrapper: long lseek_linux(unsigned int fd, long offset, unsigned int whence);
long llseek_linux(unsigned int fd, unsigned long long offset, long long *result, unsigned int whence);
// Disabled wrapper: long _llseek_linux(unsigned int fd, unsigned long offset_high, unsigned long offset_low, long long *result, unsigned int whence);
// Disabled wrapper: long truncate_linux(const char *path, long length);
long truncate64_linux(const char *path, long long length);
// Disabled wrapper: long ftruncate_linux(unsigned int fd, long length);
long ftruncate64_linux(unsigned int fd, long long length);
// 5d. Zero-copy and specialized I/O
// Disabled wrapper: long sendfile_linux(int out_fd, int in_fd, long *offset, unsigned long count);
long sendfile64_linux(int out_fd, int in_fd, long long *offset, unsigned long count);
long splice_linux(int fd_in, long long *off_in, int fd_out, long long *off_out, unsigned long len, unsigned int flags);
long tee_linux(int fdin, int fdout, unsigned long len, unsigned int flags);
long vmsplice_linux(int fd, const iovec_linux *iov, unsigned long nr_segs, unsigned int flags);
long copy_file_range_linux(int fd_in, long long *off_in, int fd_out, long long *off_out, unsigned long len, unsigned int flags);
// 5e. I/O hints and space allocation
// Disabled wrapper: long fadvise64_linux(int fd, long long offset, unsigned long len, int advice);
long fadvise64_64_linux(int fd, long long offset, long long len, int advice);
// Disabled wrapper: long arm_fadvise64_64_linux(int fd, int advice, long long offset, long long len);
long readahead_linux(int fd, long long offset, unsigned long count);
long fallocate_linux(int fd, int mode, long long offset, long long len);
// 5f. Flushing file data to storage
long sync_linux(void);
long syncfs_linux(int fd);
long fsync_linux(unsigned int fd);
long fdatasync_linux(unsigned int fd);
long sync_file_range_linux(int fd, long long offset, long long nbytes, unsigned int flags);
// Disabled wrapper: long arm_sync_file_range_linux(int fd, long long offset, long long nbytes, unsigned int flags);
//
// 6. FILE DESCRIPTOR MANAGEMENT
//
// 6a. Duplicating and controlling file descriptors
long dup_linux(unsigned int fildes);
// Disabled wrapper: long dup2_linux(unsigned int oldfd, unsigned int newfd);
long dup3_linux(unsigned int oldfd, unsigned int newfd, int flags);
// Disabled wrapper: long fcntl_linux(unsigned int fd, unsigned int cmd, unsigned long arg);
long fcntl64_linux(unsigned int fd, unsigned int cmd, unsigned long arg);
// 6b. Device-specific control operations
long ioctl_linux(unsigned int fd, unsigned int cmd, unsigned long arg);
// 6c. I/O Multiplexing
// Disabled wrapper: long select_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timeval *tvp);
// Disabled wrapper: long _newselect_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timeval *tvp);
// Disabled wrapper: pselect6_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_old_timespec_linux *tsp, void *sig);
long pselect6_time64_linux(int n, fd_set_linux *inp, fd_set_linux *outp, fd_set_linux *exp, __kernel_timespec_linux *tsp, void *sig);
long poll_linux(pollfd_linux *ufds, unsigned int nfds, int timeout);
// Disabled wrapper: long ppoll_linux(pollfd_linux *, unsigned int, __kernel_old_timespec_linux *, const sigset_t_linux *, unsigned long);
long ppoll_time64_linux(pollfd_linux *ufds, unsigned int nfds, __kernel_timespec_linux *tsp, const sigset_t_linux *sigmask, unsigned long sigsetsize);
// 6d. Scalable I/O event notification
// Disabled wrapper: long epoll_create_linux(int size);
long epoll_create1_linux(int flags);
long epoll_ctl_linux(int epfd, int op, int fd, epoll_event_linux *event);
long epoll_wait_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout);
long epoll_pwait_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout, const sigset_t_linux *sigmask, unsigned long sigsetsize);
long epoll_pwait2_linux(int epfd, epoll_event_linux *events, int maxevents, const __kernel_timespec_linux *timeout, const sigset_t_linux *sigmask, unsigned long sigsetsize);
// Disabled wrapper: long epoll_ctl_old_linux(int epfd, int op, int fd, epoll_event_linux *event);
// Disabled wrapper: long epoll_wait_old_linux(int epfd, epoll_event_linux *events, int maxevents, int timeout);
#if 0 // WIP
//
// 7. FILE METADATA
//
// 7a. Getting file attributes and status
long stat_linux(const char *filename, __old_kernel_stat *statbuf);
long fstat_linux(unsigned int fd, __old_kernel_stat *statbuf);
long lstat_linux(const char *filename, __old_kernel_stat *statbuf);
long stat64_linux(const char *filename, stat64 *statbuf);
long fstat64_linux(unsigned long fd, stat64 *statbuf);
long lstat64_linux(const char *filename, stat64 *statbuf);
long newfstatat_linux(int dfd, const char *filename, stat *statbuf, int flag);
long fstatat64_linux(int dfd, const char *filename, stat64 *statbuf, int flag);
long statx_linux(int dfd, const char *path, unsigned flags, unsigned mask, statx *buffer);
long oldstat_linux(const char *filename, __old_kernel_stat *statbuf);
long oldfstat_linux(unsigned int fd, __old_kernel_stat *statbuf);
long oldlstat_linux(const char *filename, __old_kernel_stat *statbuf);
long file_getattr_linux(int dfd, const char *filename, file_attr *attr, unsigned long usize, unsigned int at_flags);
// 7b. Changing file permissions and ownership
long chmod_linux(const char *filename, unsigned short mode);
long fchmod_linux(unsigned int fd, unsigned short mode);
long fchmodat_linux(int dfd, const char *filename, unsigned short mode);
long fchmodat2_linux(int dfd, const char *filename, unsigned short mode, unsigned int flags);
long umask_linux(int mask);
long chown_linux(const char *filename, uid_t user, gid_t group);
long fchown_linux(unsigned int fd, uid_t user, gid_t group);
long lchown_linux(const char *filename, uid_t user, gid_t group);
long chown32_linux(const char *filename, uid_t user, gid_t group);
long fchown32_linux(unsigned int fd, uid_t user, gid_t group);
long lchown32_linux(const char *filename, uid_t user, gid_t group);
long fchownat_linux(int dfd, const char *filename, uid_t user, gid_t group, int flag);
long file_setattr_linux(int dfd, const char *filename, file_attr *attr, unsigned long usize, unsigned int at_flags);
// 7c. File access and modification times
long utime_linux(char *filename, utimbuf *times);
long utimes_linux(char *filename, __kernel_old_timeval *utimes);
long futimesat_linux(int dfd, const char *filename, __kernel_old_timeval *utimes);
// Disabled wrapper: long utimensat_linux(int dfd, const char *filename, __kernel_old_timespec_linux *utimes, int flags);
long utimensat_time64_linux(int dfd, const char *filename, __kernel_timespec_linux *t, int flags);
// 7d. Testing file accessibility
long access_linux(const char *filename, int mode);
long faccessat_linux(int dfd, const char *filename, int mode);
long faccessat2_linux(int dfd, const char *filename, int mode, int flags);
// 7e. Getting, setting, and listing extended attributes
long setxattr_linux(const char *path, const char *name, const void *value, unsigned long size, int flags);
long lsetxattr_linux(const char *path, const char *name, const void *value, unsigned long size, int flags);
long fsetxattr_linux(int fd, const char *name, const void *value, unsigned long size, int flags);
long setxattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name, const xattr_args *args, unsigned long size);
long getxattr_linux(const char *path, const char *name, void *value, unsigned long size);
long lgetxattr_linux(const char *path, const char *name, void *value, unsigned long size);
long fgetxattr_linux(int fd, const char *name, void *value, unsigned long size);
long getxattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name, xattr_args *args, unsigned long size);
long listxattr_linux(const char *path, char *list, unsigned long size);
long llistxattr_linux(const char *path, char *list, unsigned long size);
long flistxattr_linux(int fd, char *list, unsigned long size);
long listxattrat_linux(int dfd, const char *path, unsigned int at_flags, char *list, unsigned long size);
long removexattr_linux(const char *path, const char *name);
long lremovexattr_linux(const char *path, const char *name);
long fremovexattr_linux(int fd, const char *name);
long removexattrat_linux(int dfd, const char *path, unsigned int at_flags, const char *name);
// 7f. Advisory file locking
long flock_linux(unsigned int fd, unsigned int cmd);
//
// 8. DIRECTORY & NAMESPACE OPERATIONS
//
// 8a. Creating, removing, and reading directories
long mkdir_linux(const char *pathname, unsigned short mode);
long mkdirat_linux(int dfd, const char * pathname, unsigned short mode);
long rmdir_linux(const char *pathname);
long getdents_linux(unsigned int fd, linux_dirent *dirent, unsigned int count);
long getdents64_linux(unsigned int fd, linux_dirent64 *dirent, unsigned int count);
long readdir_linux(unsigned int fd, old_linux_dirent *dirent, unsigned int count);
// 8b. Getting and changing current directory
long getcwd_linux(char *buf, unsigned long size);
long chdir_linux(const char *filename);
long fchdir_linux(unsigned int fd);
// 8c. Creating and managing hard and symbolic links
long link_linux(const char *oldname, const char *newname);
long linkat_linux(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
long unlink_linux(const char *pathname);
long unlinkat_linux(int dfd, const char * pathname, int flag);
long symlink_linux(const char *old, const char *new);
long symlinkat_linux(const char * oldname, int newdfd, const char * newname);
long readlink_linux(const char *path, char *buf, int bufsiz);
long readlinkat_linux(int dfd, const char *path, char *buf, int bufsiz);
long rename_linux(const char *oldname, const char *newname);
long renameat_linux(int olddfd, const char * oldname, int newdfd, const char * newname);
long renameat2_linux(int olddfd, const char *oldname, int newdfd, const char *newname, unsigned int flags);
// 8d. Creating device and named pipe nodes
long mknod_linux(const char *filename, unsigned short mode, unsigned dev);
long mknodat_linux(int dfd, const char * filename, unsigned short mode, unsigned dev);
//
// 9. FILE SYSTEM OPERATIONS
//
// 9a. Mounting filesystems and changing root
long mount_linux(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);
long umount_linux(char *name, int flags);
long umount2_linux(char *name, int flags);
long pivot_root_linux(const char *new_root, const char *put_old);
long chroot_linux(const char *filename);
long mount_setattr_linux(int dfd, const char *path, unsigned int flags, mount_attr *uattr, unsigned long usize);
long move_mount_linux(int from_dfd, const char *from_path, int to_dfd, const char *to_path, unsigned int ms_flags);
long open_tree_linux(int dfd, const char *path, unsigned flags);
long open_tree_attr_linux(int dfd, const char *path, unsigned flags, mount_attr *uattr, unsigned long usize);
long fsconfig_linux(int fs_fd, unsigned int cmd, const char *key, const void *value, int aux);
long fsmount_linux(int fs_fd, unsigned int flags, unsigned int ms_flags);
long fsopen_linux(const char *fs_name, unsigned int flags);
long fspick_linux(int dfd, const char *path, unsigned int flags);
// 9b. Getting filesystem statistics
long statfs_linux(const char * path, statfs *buf);
long fstatfs_linux(unsigned int fd, statfs *buf);
long statfs64_linux(const char *path, unsigned long sz, statfs64 *buf);
long fstatfs64_linux(unsigned int fd, unsigned long sz, statfs64 *buf);
long ustat_linux(unsigned dev, ustat *ubuf);
long statmount_linux(const mnt_id_req *req, statmount *buf, unsigned long bufsize, unsigned int flags);
long listmount_linux(const mnt_id_req *req, u64 *mnt_ids, unsigned long nr_mnt_ids, unsigned int flags);
// 9c. Disk quota control
long quotactl_linux(unsigned int cmd, const char *special, qid_t id, void *addr);
long quotactl_fd_linux(unsigned int fd, unsigned int cmd, qid_t id, void *addr);
//
// 10. FILE SYSTEM MONITORING
//
// 10a. Monitoring filesystem events
long inotify_init_linux(void);
long inotify_init1_linux(int flags);
long inotify_add_watch_linux(int fd, const char *path, u32 mask);
long inotify_rm_watch_linux(int fd, __s32 wd);
// 10b. Filesystem-wide event notification
long fanotify_init_linux(unsigned int flags, unsigned int event_f_flags);
long fanotify_mark_linux(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char *pathname);
//
// 11. SIGNALS
//
// 11a. Setting up signal handlers
long signal_linux(int sig, __sighandler_t handler);
long sigaction_linux(int sig, const old_sigaction *act, old_sigaction *oact);
long rt_sigaction_linux(int sig, const sigaction *act, sigaction *oact, unsigned long sigsetsize);
// 11b. Sending signals to processes
long kill_linux(int pid, int sig);
long tkill_linux(int pid, int sig);
long tgkill_linux(int tgid, int pid, int sig);
long rt_sigqueueinfo_linux(int pid, int sig, siginfo_t *uinfo);
long rt_tgsigqueueinfo_linux(int tgid, int pid, int sig, siginfo_t *uinfo);
// 11c. Blocking and unblocking signals
long sigprocmask_linux(int how, old_sigset_t *set, old_sigset_t *oset);
long rt_sigprocmask_linux(int how, sigset_t_linux *set, sigset_t_linux *oset, unsigned long sigsetsize);
long sgetmask_linux(void);
long ssetmask_linux(int newmask);
// 11d. Waiting for and querying signals
long sigpending_linux(old_sigset_t *uset);
long rt_sigpending_linux(sigset_t_linux *set, unsigned long sigsetsize);
long sigsuspend_linux(old_sigset_t mask);
long rt_sigsuspend_linux(sigset_t_linux *unewset, unsigned long sigsetsize);
long pause_linux(void);
// Disabled wrapper: long rt_sigtimedwait_linux(const sigset_t_linux *uthese, siginfo_t *uinfo, const __kernel_old_timespec_linux *uts, unsigned long sigsetsize);
long rt_sigtimedwait_time64_linux(compat_sigset_t *uthese, compat_siginfo *uinfo, __kernel_timespec_linux *uts, compat_size_t sigsetsize);
// 11e. Alternate signal stack and return from handlers
long sigaltstack_linux(const sigaltstack *uss, sigaltstack *uoss);
long sigreturn_linux(pt_regs *regs);
long rt_sigreturn_linux(pt_regs *regs);
// 11f. Signal delivery via file descriptors
long signalfd_linux(int ufd, sigset_t_linux *user_mask, unsigned long sizemask);
long signalfd4_linux(int ufd, sigset_t_linux *user_mask, unsigned long sizemask, int flags);
//
// 12. PIPES & FIFOs
//
long pipe_linux(int *fildes);
long pipe2_linux(int *fildes, int flags);
//
// 13. INTER-PROCESS COMMUNICATION
//
// 13a. System V IPC - Shared Memory
long shmget_linux(key_t key, unsigned long size, int flag);
long shmat_linux(int shmid, char *shmaddr, int shmflg);
long shmdt_linux(char *shmaddr);
long shmctl_linux(int shmid, int cmd, shmid_ds *buf);
// 13b. System V IPC - Message Queues
long msgget_linux(key_t key, int msgflg);
long msgsnd_linux(int msqid, msgbuf *msgp, unsigned long msgsz, int msgflg);
long msgrcv_linux(int msqid, msgbuf *msgp, unsigned long msgsz, long msgtyp, int msgflg);
long msgctl_linux(int msqid, int cmd, msqid_ds *buf);
// 13c. System V IPC - Semaphores
long semget_linux(key_t key, int nsems, int semflg);
long semop_linux(int semid, sembuf *sops, unsigned nsops);
long semctl_linux(int semid, int semnum, int cmd, unsigned long arg);
// Disabled wrapper: long semtimedop_linux(int semid, sembuf *sops, unsigned nsops, const __kernel_old_timespec_linux *timeout);
long semtimedop_time64_linux(int semid, sembuf *tsops, unsigned int nsops, const __kernel_timespec_linux *timeout);
// 13d. POSIX Message Queues
long mq_open_linux(const char *name, int oflag, unsigned short mode, mq_attr *attr);
long mq_unlink_linux(const char *name);
// Disabled wrapper: long mq_timedsend_linux(mqd_t mqdes, const char *msg_ptr, unsigned long msg_len, unsigned int msg_prio, const __kernel_old_timespec_linux *abs_timeout);
long mq_timedsend_time64_linux(mqd_t mqdes, const char *u_msg_ptr, unsigned long msg_len, unsigned int msg_prio, const __kernel_timespec_linux *u_abs_timeout);
// Disabled wrapper: long mq_timedreceive_linux(mqd_t mqdes, char *msg_ptr, unsigned long msg_len, unsigned int *msg_prio, const __kernel_old_timespec_linux *abs_timeout);
long mq_timedreceive_time64_linux(mqd_t mqdes, char *u_msg_ptr, unsigned long msg_len, unsigned int *u_msg_prio, const __kernel_timespec_linux *u_abs_timeout);
long mq_notify_linux(mqd_t mqdes, const sigevent *notification);
long mq_getsetattr_linux(mqd_t mqdes, const mq_attr *mqstat, mq_attr *omqstat);
// 13e. Synchronization Primitives - Futexes
// Disabled wrapper: long futex_linux(u32 *uaddr, int op, u32 val, const __kernel_old_timespec_linux *utime, u32 *uaddr2, u32 val3);
long futex_time64_linux(u32 *uaddr, int op, u32 val, const __kernel_timespec_linux *utime, u32 *uaddr2, u32 val3);
long futex_wait_linux(void *uaddr, unsigned long val, unsigned long mask, unsigned int flags, __kernel_timespec_linux *timespec, clockid_t clockid);
long futex_wake_linux(void *uaddr, unsigned long mask, int nr, unsigned int flags);
long futex_waitv_linux(futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, __kernel_timespec_linux *timeout, clockid_t clockid);
long futex_requeue_linux(futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue);
long set_robust_list_linux(robust_list_head *head, unsigned long len);
long get_robust_list_linux(int pid, robust_list_head * *head_ptr, unsigned long *len_ptr);
// 13f. Synchronization Primitives - Event Notification
long eventfd_linux(unsigned int count);
long eventfd2_linux(unsigned int count, int flags);
//
// 14. SOCKETS & NETWORKING
//
// 14a. Creating and configuring sockets
long socket_linux(int family, int type, int protocol);
long socketpair_linux(int family, int type, int protocol, int *usockvec);
long bind_linux(int fd, sockaddr_linux *umyaddr, int addrlen);
long listen_linux(int fd, int backlog);
long accept_linux(int fd, sockaddr_linux *upeer_sockaddr, int *upeer_addrlen);
long accept4_linux(int fd, sockaddr_linux *upeer_sockaddr, int *upeer_addrlen, int flags);
long connect_linux(int fd, sockaddr_linux *uservaddr, int addrlen);
long shutdown_linux(int fd, int how);
long socketcall_linux(int call, unsigned long *args);
// 14b. Sending and receiving data on sockets
long send_linux(int fd, void *buff, unsigned long len, unsigned int flags);
long sendto_linux(int fd, void *buff, unsigned long len, unsigned int flags, sockaddr_linux *addr, int addr_len);
long sendmsg_linux(int fd, user_msghdr *msg, unsigned flags);
long sendmmsg_linux(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags);
long recv_linux(int fd, void *ubuf, unsigned long size, unsigned int flags);
long recvfrom_linux(int fd, void *ubuf, unsigned long size, unsigned int flags, sockaddr_linux *addr, int *addr_len);
long recvmsg_linux(int fd, user_msghdr *msg, unsigned flags);
// Disabled wrapper: long recvmmsg_linux(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags, __kernel_old_timespec_linux *timeout);
long recvmmsg_time64_linux(int fd, mmsghdr *mmsg, unsigned int vlen, unsigned int flags, __kernel_timespec_linux *timeout);
// 14c. Getting and setting socket options
long getsockopt_linux(int fd, int level, int optname, char *optval, int *optlen);
long setsockopt_linux(int fd, int level, int optname, char *optval, int optlen);
long getsockname_linux(int fd, sockaddr_linux *usockaddr, int *usockaddr_len);
long getpeername_linux(int fd, sockaddr_linux *usockaddr, int *usockaddr_len);
//
// 15. ASYNCHRONOUS I/O
//
// 15a. AIO: asynchronous I/O interface
long io_setup_linux(unsigned nr_reqs, aio_context_t *ctx);
long io_destroy_linux(aio_context_t ctx);
long io_submit_linux(aio_context_t ctx_id, long nr, iocb * *iocbpp);
long io_cancel_linux(aio_context_t ctx_id, iocb *iocb, io_event *result);
long io_getevents_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_timespec_linux *timeout);
// Disabled wrapper: long io_pgetevents_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_old_timespec_linux *timeout, const __aio_sigset *sig);
long io_pgetevents_time64_linux(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_timespec_linux *timeout, const __aio_sigset *sig);
// 15b. io_uring: high-performance asynchronous I/O
long io_uring_setup_linux(u32 entries, io_uring_params *p);
long io_uring_enter_linux(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void *argp, unsigned long argsz);
long io_uring_register_linux(unsigned int fd, unsigned int op, void *arg, unsigned int nr_args);
//
// 16. TIME & CLOCKS
//
// 16a. Reading current time from various clocks
long time_linux(__kernel_old_time_t *tloc);
long gettimeofday_linux(__kernel_old_timeval *tv, timezone *tz);
// Disabled wrapper: long clock_gettime_linux(clockid_t which_clock, __kernel_old_timespec_linux *tp);
long clock_gettime64_linux(clockid_t which_clock, __kernel_timespec_linux *tp);
// Disabled wrapper: long clock_getres_linux(clockid_t which_clock, __kernel_old_timespec_linux *tp);
long clock_getres_time64_linux(clockid_t which_clock, __kernel_timespec_linux *tp);
// 16b. Setting system time and adjusting clocks
long settimeofday_linux(__kernel_old_timeval *tv, timezone *tz);
// Disabled wrapper: long clock_settime_linux(clockid_t which_clock, const __kernel_old_timespec_linux *tp);
long clock_settime64_linux(clockid_t which_clock, const __kernel_timespec_linux *tp);
long stime_linux(__kernel_old_time_t *tptr);
long adjtimex_linux(__kernel_timex *txc_p);
long clock_adjtime_linux(clockid_t which_clock, __kernel_timex *tx);
long clock_adjtime64_linux(clockid_t which_clock, __kernel_timex *tx);
// 16c. Suspending execution for a period of time
long nanosleep_linux(__kernel_timespec_linux *rqtp, __kernel_timespec_linux *rmtp);
// Disabled wrapper: long clock_nanosleep_linux(clockid_t which_clock, int flags, const __kernel_old_timespec_linux *rqtp, __kernel_old_timespec_linux *rmtp);
long clock_nanosleep_time64_linux(clockid_t which_clock, int flags, const __kernel_timespec_linux *rqtp, __kernel_timespec_linux *rmtp);
// 16d. Setting periodic or one-shot timers
long alarm_linux(unsigned int seconds);
long setitimer_linux(int which, __kernel_old_itimerval *value, __kernel_old_itimerval *ovalue);
long getitimer_linux(int which, __kernel_old_itimerval *value);
// 16e. Per-process timers with precise control
long timer_create_linux(clockid_t which_clock, sigevent *timer_event_spec, timer_t * created_timer_id);
// Disabled wrapper: long timer_settime_linux(timer_t timer_id, int flags, const __kernel_itimerspec *new_setting, __kernel_itimerspec *old_setting);
long timer_settime64_linux(timer_t timerid, int flags, const __kernel_timespec_linux *new_setting, __kernel_timespec_linux *old_setting);
// Disabled wrapper: long timer_gettime_linux(timer_t timer_id, __kernel_itimerspec *setting);
long timer_gettime64_linux(timer_t timerid, __kernel_timespec_linux *setting);
long timer_getoverrun_linux(timer_t timer_id);
long timer_delete_linux(timer_t timer_id);
// 16f. Timers accessible via file descriptors
long timerfd_create_linux(int clockid, int flags);
// Disabled wrapper: long timerfd_settime_linux(int ufd, int flags, const __kernel_itimerspec *utmr, __kernel_itimerspec *otmr);
long timerfd_settime64_linux(int ufd, int flags, const __kernel_timespec_linux *utmr, __kernel_timespec_linux *otmr);
// Disabled wrapper: long timerfd_gettime_linux(int ufd, __kernel_itimerspec *otmr);
long timerfd_gettime64_linux(int ufd, __kernel_timespec_linux *otmr);
//
// 17. RANDOM NUMBERS
//
long getrandom_linux(char *buf, unsigned long count, unsigned int flags);
//
// 18. USER & GROUP IDENTITY
//
// 18a. Getting and setting user IDs
long getuid_linux(void);
long geteuid_linux(void);
long setuid_linux(uid_t uid);
long setreuid_linux(uid_t ruid, uid_t euid);
long setresuid_linux(uid_t ruid, uid_t euid, uid_t suid);
long getresuid_linux(uid_t *ruid, uid_t *euid, uid_t *suid);
long setfsuid_linux(uid_t uid);
long getuid32_linux(void);
long geteuid32_linux(void);
long setuid32_linux(uid_t uid);
long setreuid32_linux(uid_t ruid, uid_t euid);
long setresuid32_linux(uid_t ruid, uid_t euid, uid_t suid);
long getresuid32_linux(uid_t *ruid, uid_t *euid, uid_t *suid);
long setfsuid32_linux(uid_t uid);
// 18b. Getting and setting group IDs
long getgid_linux(void);
long getegid_linux(void);
long setgid_linux(gid_t gid);
long setregid_linux(gid_t rgid, gid_t egid);
long setresgid_linux(gid_t rgid, gid_t egid, gid_t sgid);
long getresgid_linux(gid_t *rgid, gid_t *egid, gid_t *sgid);
long setfsgid_linux(gid_t gid);
long getgid32_linux(void);
long getegid32_linux(void);
long setgid32_linux(gid_t gid);
long setregid32_linux(gid_t rgid, gid_t egid);
long setresgid32_linux(gid_t rgid, gid_t egid, gid_t sgid);
long getresgid32_linux(gid_t *rgid, gid_t *egid, gid_t *sgid);
long setfsgid32_linux(gid_t gid);
// 18c. Managing supplementary group list
long getgroups_linux(int gidsetsize, gid_t *grouplist);
long setgroups_linux(int gidsetsize, gid_t *grouplist);
long getgroups32_linux(int gidsetsize, gid_t *grouplist);
long setgroups32_linux(int gidsetsize, gid_t *grouplist);
//
// 19. CAPABILITIES & SECURITY
//
// 19a. Fine-grained privilege control
long capget_linux(cap_user_header_t header, cap_user_data_t dataptr);
long capset_linux(cap_user_header_t header, const cap_user_data_t data);
// 19b. Syscall filtering and sandboxing
long seccomp_linux(unsigned int op, unsigned int flags, void *uargs);
// 19c. Linux Security Module interfaces
long security_linux(void);
long lsm_get_self_attr_linux(unsigned int attr, lsm_ctx *ctx, u32 *size, u32 flags);
long lsm_set_self_attr_linux(unsigned int attr, lsm_ctx *ctx, u32 size, u32 flags);
long lsm_list_modules_linux(u64 *ids, u32 *size, u32 flags);
// 19d. Unprivileged access control
long landlock_create_ruleset_linux(const landlock_ruleset_attr *attr, unsigned long size, __u32 flags);
long landlock_add_rule_linux(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, __u32 flags);
long landlock_restrict_self_linux(int ruleset_fd, __u32 flags);
// 19e. Kernel key retention service
long add_key_linux(const char *_type, const char *_description, const void *_payload, unsigned long plen, key_serial_t destringid);
long request_key_linux(const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid);
long keyctl_linux(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
//
// 20. RESOURCE LIMITS & ACCOUNTING
//
// 20a. Getting and setting process resource limits
long getrlimit_linux(unsigned int resource, rlimit *rlim);
long setrlimit_linux(unsigned int resource, rlimit *rlim);
long prlimit64_linux(int pid, unsigned int resource, const rlimit64 *new_rlim, rlimit64 *old_rlim);
long ugetrlimit_linux(unsigned int resource, rlimit *rlim);
long ulimit_linux(int cmd, long newval);
// 20b. Getting resource usage and time statistics
long getrusage_linux(int who, rusage_linux *ru);
long times_linux(tms *tbuf);
// 20c. System-wide process accounting
long acct_linux(const char *name);
//
// 21. NAMESPACES & CONTAINERS
//
long unshare_linux(unsigned long unshare_flags);
long setns_linux(int fd, int nstype);
long listns_linux(const ns_id_req *req, u64 *ns_ids, unsigned long nr_ns_ids, unsigned int flags);
//
// 22. PROCESS INSPECTION & CONTROL
//
// 22a. Process comparison
long kcmp_linux(int pid1, int pid2, int type, unsigned long idx1, unsigned long idx2);
// 22b. Process file descriptors
long pidfd_open_linux(int pid, unsigned int flags);
long pidfd_getfd_linux(int pidfd, int fd, unsigned int flags);
long pidfd_send_signal_linux(int pidfd, int sig, siginfo_t *info, unsigned int flags);
// 22c. Process memory access
long process_vm_readv_linux(int pid, const iovec_linux *lvec, unsigned long liovcnt, const iovec_linux *rvec, unsigned long riovcnt, unsigned long flags);
long process_vm_writev_linux(int pid, const iovec_linux *lvec, unsigned long liovcnt, const iovec_linux *rvec, unsigned long riovcnt, unsigned long flags);
// 22d. Process tracing
long ptrace_linux(long request, long pid, unsigned long addr, unsigned long data);
//
// 23. SYSTEM INFORMATION
//
// 23a. System name and domain information
long uname_linux(old_utsname *);
long olduname_linux(oldold_utsname *);
long oldolduname_linux(oldold_utsname *name);
long gethostname_linux(char *name, int len);
long sethostname_linux(char *name, int len);
long setdomainname_linux(char *name, int len);
// 23b. Overall system information and statistics
long sysinfo_linux(sysinfo *info);
// 23c. Reading kernel log messages
long syslog_linux(int type, char *buf, int len);
// 23d. Getting CPU and NUMA node information
long getcpu_linux(unsigned *cpu, unsigned *node, getcpu_cache *cache);
// 23e. Kernel filesystem information interface
long sysfs_linux(int option, unsigned long arg1, unsigned long arg2);
//
// 24. KERNEL MODULES
//
long create_module_linux(const char *name, unsigned long size);
long init_module_linux(void *umod, unsigned long len, const char *uargs);
long finit_module_linux(int fd, const char *uargs, int flags);
long delete_module_linux(const char *name_user, unsigned int flags);
long query_module_linux(const char *name, int which, void *buf, unsigned long bufsize, unsigned long *ret);
long get_kernel_syms_linux(kernel_sym *table);
//
// 25. SYSTEM CONTROL & ADMINISTRATION
//
// 25a. Rebooting and shutting down the system
long reboot_linux(int magic1, int magic2, unsigned int cmd, void *arg);
// 25b. Enabling and disabling swap areas
long swapon_linux(const char *specialfile, int swap_flags);
long swapoff_linux(const char *specialfile);
// 25c. Loading and executing new kernels
long kexec_load_linux(unsigned long entry, unsigned long nr_segments, kexec_segment *segments, unsigned long flags);
long kexec_file_load_linux(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags);
// 25d. Other system administration operations
long vhangup_linux(void);
//
// 26. PERFORMANCE MONITORING & TRACING
//
// 26a. Hardware and software performance monitoring
long perf_event_open_linux(perf_event_attr *attr_uptr, int pid, int cpu, int group_fd, unsigned long flags);
// 26b. Userspace dynamic tracing
long uprobe_linux(void);
long uretprobe_linux(void);
// 26c. Programmable Kernel Extensions (eBPF)
long bpf_linux(int cmd, union bpf_attr *attr, unsigned int size);
//
// 27. DEVICE & HARDWARE ACCESS
//
// 27a. Direct hardware I/O port access
long ioperm_linux(unsigned long from, unsigned long num, int on);
long iopl_linux(unsigned int level);
// 27b. Setting I/O scheduling priority
long ioprio_set_linux(int which, int who, int ioprio);
long ioprio_get_linux(int which, int who);
// 27c. PCI device configuration access
long pciconfig_read_linux(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf);
long pciconfig_write_linux(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf);
long pciconfig_iobase_linux(long which, unsigned long bus, unsigned long devfn);
// 27d. CPU cache control operations
long cacheflush_linux(unsigned long start, unsigned long end, int flags);
long cachestat_linux(unsigned int fd, cachestat_range *cstat_range, cachestat *cstat, unsigned int flags);
//
// 28. ARCHITECTURE-SPECIFIC OPERATIONS
//
// 28a. x86 architecture operations
long arch_prctl_linux(int option, unsigned long addr);
long modify_ldt_linux(int func, void *ptr, unsigned long bytecount);
long set_thread_area_linux(user_desc *u_info);
long get_thread_area_linux(user_desc *u_info);
long vm86_linux(unsigned long cmd, unsigned long arg);
long vm86old_linux(vm86_struct *user_vm86);
// 28b. ARM architecture operations
long set_tls_linux(unsigned long val);
long get_tls_linux(void);
// 28c. RISC-V architecture operations
long riscv_flush_icache_linux(uintptr_t start, uintptr_t end, uintptr_t flags);
long riscv_hwprobe_linux(riscv_hwprobe *pairs, unsigned long pair_count, unsigned long cpu_count, unsigned long *cpumask, unsigned int flags);
// 28d. Intel MPX support (deprecated)
long mpx_linux(void);
//
// 29. ADVANCED EXECUTION CONTROL
//
// 29a. Restartable sequences
long rseq_linux(rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig);
// 29b. Restart syscall
long restart_syscall_linux(void);
// 29c. Directory entry cache
long lookup_dcookie_linux(u64 cookie64, char *buf, unsigned long len);
//
// 30. LEGACY, OBSOLETE & UNIMPLEMENTED
//
long _sysctl_linux(__sysctl_args *args);
long ipc_linux(unsigned int call, int first, unsigned long second, unsigned long third, void *ptr, long fifth);
long profil_linux(unsigned short *sample_buffer, unsigned long size, unsigned long offset, unsigned int scale);
long prof_linux(void);
long afs_syscall_linux(void);
long break_linux(void);
long ftime_linux(void);
long gtty_linux(void);
long idle_linux(void);
long lock_linux(void);
long nfsservctl_linux(int cmd, nfsctl_arg *arg, union nfsctl_res *res);
long getpmsg_linux(int fd, strbuf *ctlptr, strbuf *dataptr, int *bandp, int *flagsp);
long putpmsg_linux(int fd, strbuf *ctlptr, strbuf *dataptr, int band, int flags);
long stty_linux(void);
long tuxcall_linux(void);
long vserver_linux(void);
long bdflush_linux(int func, long data);
long uselib_linux(const char *library);
#endif // WIP
