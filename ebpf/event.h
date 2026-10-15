#ifndef __EVENT_H__
#define __EVENT_H__

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 64
#define MAX_ENTRIES_FD 16384

/* Event Types corresponding to RansomShield Specification */
enum rs_event_type_t {
    EVENT_UNKNOWN = 0,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_RENAME,
    EVENT_FILE_DELETE,
    EVENT_FILE_CREATE,
    EVENT_FILE_OPEN,
    EVENT_FILE_CLOSE,
    EVENT_PROCESS_EXEC,
    EVENT_PROCESS_EXIT,
    EVENT_NET_CONNECT,
};

/* Unified event sent to user space via BPF ring buffer */
struct event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    __s64 bytes;
    __u32 dst_ip;        /* IPv4 address in network order */
    __u16 dst_port;      /* Destination port */
    __u16 protocol;      /* IPPROTO_TCP / UDP */
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    char old_path[MAX_PATH_LEN];
};

/* Key for fd_map tracking */
struct fd_key_t {
    __u32 pid;
    __u32 fd;
};

/* Value for fd_map: cached path string */
struct fd_val_t {
    char path[MAX_PATH_LEN];
};

#endif /* __EVENT_H__ */
