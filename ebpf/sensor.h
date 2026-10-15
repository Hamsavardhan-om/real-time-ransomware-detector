#ifndef __SENSOR_H__
#define __SENSOR_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

/* Tracepoint Argument Structures (Aligned to Linux Kernel ABI) */
struct trace_entry_t {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct sys_enter_openat_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int dfd;
    const char *filename;
    long int flags;
    long int mode;
};

struct sys_enter_openat2_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int dfd;
    const char *filename;
    void *how;
    size_t usize;
};

struct sys_exit_openat_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int ret;
};

struct sys_exit_openat2_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int ret;
};

struct sys_enter_write_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned long fd;
    const char *buf;
    size_t count;
};

struct sys_enter_pwrite64_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned long fd;
    const char *buf;
    size_t count;
    loff_t pos;
};

struct sys_enter_read_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned long fd;
    char *buf;
    size_t count;
};

struct sys_enter_dup2_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned int oldfd;
    unsigned int newfd;
};

struct sys_enter_dup3_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
};

struct sys_enter_close_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    unsigned long fd;
};

struct sys_enter_unlink_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    const char *pathname;
};

struct sys_enter_unlinkat_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int dfd;
    const char *pathname;
    long int flag;
};

struct sys_enter_rename_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    const char *oldname;
    const char *newname;
};

struct sys_enter_renameat2_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int olddfd;
    const char *oldname;
    long int newdfd;
    const char *newname;
    unsigned int flags;
};

struct sys_enter_renameat_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int olddfd;
    const char *oldname;
    long int newdfd;
    const char *newname;
};

struct sys_enter_execve_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct sys_enter_connect_args {
    struct trace_entry_t ent;
    int __syscall_nr;
    long int fd;
    struct sockaddr *uservaddr;
    long int addrlen;
};

struct sched_process_exec_args {
    struct trace_entry_t ent;
    unsigned int filename_loc;
    pid_t pid;
    pid_t old_pid;
};

struct sched_process_exit_args {
    struct trace_entry_t ent;
    char comm[16];
    pid_t pid;
    int prio;
    bool group_dead;
};

#endif /* __SENSOR_H__ */
