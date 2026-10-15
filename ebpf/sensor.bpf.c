#include "sensor.h"

char LICENSE[] SEC("license") = "GPL";

/* High-performance ring buffer for sending events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

/* Map tracking active (pid, fd) -> path mappings */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_FD);
    __type(key, struct fd_key_t);
    __type(value, struct fd_val_t);
} fd_map SEC(".maps");

/* In-flight openat filename storage between sys_enter and sys_exit */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct fd_val_t);
} open_inflight_map SEC(".maps");

/* Runtime configuration map (0: collector_pid, 1: target_pid) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

static __always_inline int is_filtered(__u32 pid) {
    __u32 key = 0;
    __u32 *collector_pid = bpf_map_lookup_elem(&config_map, &key);
    if (collector_pid && *collector_pid != 0 && *collector_pid == pid) {
        return 1;
    }

    key = 1;
    __u32 *target_pid = bpf_map_lookup_elem(&config_map, &key);
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 1;
    }

    return 0;
}

static __always_inline void fill_common_fields(struct event_t *e, __u32 event_type, __u32 pid, __u32 uid) {
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->uid = uid;
    e->event_type = event_type;
    e->bytes = 0;
    e->dst_ip = 0;
    e->dst_port = 0;
    e->protocol = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    } else {
        e->ppid = 0;
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->path[0] = '\0';
    e->old_path[0] = '\0';
}

/* 1. Hook sys_enter_openat */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct sys_enter_openat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_val_t val = {};
    if (ctx->filename) {
        bpf_probe_read_user_str(val.path, sizeof(val.path), ctx->filename);
        bpf_map_update_elem(&open_inflight_map, &pid_tgid, &val, BPF_ANY);
    }
    return 0;
}

/* 2. Hook sys_enter_openat2 (modern glibc / runtimes) */
SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_sys_enter_openat2(struct sys_enter_openat2_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_val_t val = {};
    if (ctx->filename) {
        bpf_probe_read_user_str(val.path, sizeof(val.path), ctx->filename);
        bpf_map_update_elem(&open_inflight_map, &pid_tgid, &val, BPF_ANY);
    }
    return 0;
}

/* 3. Hook sys_exit_openat */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct sys_exit_openat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    long ret = ctx->ret;
    struct fd_val_t *val = bpf_map_lookup_elem(&open_inflight_map, &pid_tgid);
    if (!val)
        return 0;

    if (ret >= 0) {
        struct fd_key_t key = {
            .pid = pid,
            .fd = (__u32)ret,
        };
        bpf_map_update_elem(&fd_map, &key, val, BPF_ANY);

        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common_fields(e, EVENT_FILE_OPEN, pid, bpf_get_current_uid_gid());
            __builtin_memcpy(e->path, val->path, sizeof(e->path));
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&open_inflight_map, &pid_tgid);
    return 0;
}

/* 4. Hook sys_exit_openat2 */
SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_sys_exit_openat2(struct sys_exit_openat2_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    long ret = ctx->ret;
    struct fd_val_t *val = bpf_map_lookup_elem(&open_inflight_map, &pid_tgid);
    if (!val)
        return 0;

    if (ret >= 0) {
        struct fd_key_t key = {
            .pid = pid,
            .fd = (__u32)ret,
        };
        bpf_map_update_elem(&fd_map, &key, val, BPF_ANY);

        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common_fields(e, EVENT_FILE_OPEN, pid, bpf_get_current_uid_gid());
            __builtin_memcpy(e->path, val->path, sizeof(e->path));
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&open_inflight_map, &pid_tgid);
    return 0;
}

/* 5. Hook sys_enter_dup2: propagate fd path mapping (for shell redirection & pipes) */
SEC("tracepoint/syscalls/sys_enter_dup2")
int tp_sys_enter_dup2(struct sys_enter_dup2_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t old_key = { .pid = pid, .fd = ctx->oldfd };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &old_key);
    if (val) {
        struct fd_key_t new_key = { .pid = pid, .fd = ctx->newfd };
        bpf_map_update_elem(&fd_map, &new_key, val, BPF_ANY);
    }
    return 0;
}

/* 6. Hook sys_enter_dup3: propagate fd path mapping */
SEC("tracepoint/syscalls/sys_enter_dup3")
int tp_sys_enter_dup3(struct sys_enter_dup3_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t old_key = { .pid = pid, .fd = ctx->oldfd };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &old_key);
    if (val) {
        struct fd_key_t new_key = { .pid = pid, .fd = ctx->newfd };
        bpf_map_update_elem(&fd_map, &new_key, val, BPF_ANY);
    }
    return 0;
}

/* 7. Hook sys_enter_write: look up path, capture bytes, emit FILE_WRITE */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct sys_enter_write_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t key = {
        .pid = pid,
        .fd = (__u32)ctx->fd,
    };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_WRITE, pid, bpf_get_current_uid_gid());
        e->bytes = ctx->count;
        __builtin_memcpy(e->path, val->path, sizeof(e->path));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 8. Hook sys_enter_pwrite64: direct offset writes */
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tp_sys_enter_pwrite64(struct sys_enter_pwrite64_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t key = {
        .pid = pid,
        .fd = (__u32)ctx->fd,
    };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_WRITE, pid, bpf_get_current_uid_gid());
        e->bytes = ctx->count;
        __builtin_memcpy(e->path, val->path, sizeof(e->path));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 9. Hook sys_enter_read: look up path, capture bytes, emit FILE_READ */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct sys_enter_read_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t key = {
        .pid = pid,
        .fd = (__u32)ctx->fd,
    };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_READ, pid, bpf_get_current_uid_gid());
        e->bytes = ctx->count;
        __builtin_memcpy(e->path, val->path, sizeof(e->path));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 10. Hook sys_enter_close: emit FILE_CLOSE and clean up fd_map */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_sys_enter_close(struct sys_enter_close_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct fd_key_t key = {
        .pid = pid,
        .fd = (__u32)ctx->fd,
    };
    struct fd_val_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_CLOSE, pid, bpf_get_current_uid_gid());
        __builtin_memcpy(e->path, val->path, sizeof(e->path));
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&fd_map, &key);
    return 0;
}

/* 11. Hook sys_enter_unlink: emit FILE_DELETE */
SEC("tracepoint/syscalls/sys_enter_unlink")
int tp_sys_enter_unlink(struct sys_enter_unlink_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_DELETE, pid, bpf_get_current_uid_gid());
        if (ctx->pathname)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->pathname);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 12. Hook sys_enter_unlinkat: emit FILE_DELETE */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_sys_enter_unlinkat(struct sys_enter_unlinkat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_DELETE, pid, bpf_get_current_uid_gid());
        if (ctx->pathname)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->pathname);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 13. Hook sys_enter_rename: emit FILE_RENAME */
SEC("tracepoint/syscalls/sys_enter_rename")
int tp_sys_enter_rename(struct sys_enter_rename_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_RENAME, pid, bpf_get_current_uid_gid());
        if (ctx->oldname)
            bpf_probe_read_user_str(e->old_path, sizeof(e->old_path), ctx->oldname);
        if (ctx->newname)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->newname);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 14. Hook sys_enter_renameat2: emit FILE_RENAME */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_sys_enter_renameat2(struct sys_enter_renameat2_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_RENAME, pid, bpf_get_current_uid_gid());
        if (ctx->oldname)
            bpf_probe_read_user_str(e->old_path, sizeof(e->old_path), ctx->oldname);
        if (ctx->newname)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->newname);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 13. Hook sys_enter_renameat: fallback for renameat */
SEC("tracepoint/syscalls/sys_enter_renameat")
int tp_sys_enter_renameat(struct sys_enter_renameat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_FILE_RENAME, pid, bpf_get_current_uid_gid());
        if (ctx->oldname)
            bpf_probe_read_user_str(e->old_path, sizeof(e->old_path), ctx->oldname);
        if (ctx->newname)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->newname);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 14. Hook sys_enter_execve: emit PROCESS_EXEC */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct sys_enter_execve_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_PROCESS_EXEC, pid, bpf_get_current_uid_gid());
        if (ctx->filename)
            bpf_probe_read_user_str(e->path, sizeof(e->path), ctx->filename);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 15. Hook sched_process_exit: emit PROCESS_EXIT */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct sched_process_exit_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        fill_common_fields(e, EVENT_PROCESS_EXIT, pid, bpf_get_current_uid_gid());
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 16. Hook sys_enter_connect: emit NET_CONNECT for IPv4 */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct sys_enter_connect_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (is_filtered(pid))
        return 0;

    if (!ctx->uservaddr)
        return 0;

    struct sockaddr_in sin = {};
    if (bpf_probe_read_user(&sin, sizeof(sin), ctx->uservaddr) == 0) {
        if (sin.sin_family == 2 /* AF_INET */) {
            struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                fill_common_fields(e, EVENT_NET_CONNECT, pid, bpf_get_current_uid_gid());
                e->dst_ip = sin.sin_addr.s_addr;
                e->dst_port = __builtin_bswap16(sin.sin_port);
                e->protocol = 6; /* TCP */
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 0;
}
