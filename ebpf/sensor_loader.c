#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"

static volatile bool exiting = false;
static char g_watch_dir[512] = "";
static FILE *g_out_file = NULL;
static bool g_stdout_mode = true;
static unsigned long g_event_count = 0;

static void sig_handler(int sig) {
    exiting = true;
}

static const char *event_type_to_str(enum rs_event_type_t type) {
    switch (type) {
        case EVENT_FILE_READ:   return "FILE_READ";
        case EVENT_FILE_WRITE:  return "FILE_WRITE";
        case EVENT_FILE_RENAME: return "FILE_RENAME";
        case EVENT_FILE_DELETE: return "FILE_DELETE";
        case EVENT_FILE_CREATE: return "FILE_CREATE";
        case EVENT_FILE_OPEN:   return "FILE_OPEN";
        case EVENT_FILE_CLOSE:  return "FILE_CLOSE";
        case EVENT_PROCESS_EXEC: return "PROCESS_EXEC";
        case EVENT_PROCESS_EXIT: return "PROCESS_EXIT";
        case EVENT_NET_CONNECT: return "NET_CONNECT";
        default:                return "OTHER";
    }
}

/* Escape string for valid JSON output */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_size; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            dst[j++] = '\\';
            dst[j++] = src[i];
        } else if (src[i] == '\n') {
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (src[i] == '\r') {
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (src[i] == '\t') {
            dst[j++] = '\\';
            dst[j++] = 't';
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    if (!e || data_sz < sizeof(*e))
        return 0;

    /* Watch directory filter for file events */
    if (g_watch_dir[0] != '\0') {
        if (e->event_type >= EVENT_FILE_READ && e->event_type <= EVENT_FILE_CLOSE) {
            if (strstr(e->path, g_watch_dir) == NULL &&
                (e->old_path[0] == '\0' || strstr(e->old_path, g_watch_dir) == NULL)) {
                return 0; // Out of scope
            }
        }
    }

    /* Compute precise epoch timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double timestamp = (double)ts.tv_sec + ((double)ts.tv_nsec / 1e9);

    /* Resolve executable binary path if available */
    char exe_path[512] = "";
    char proc_link[64];
    snprintf(proc_link, sizeof(proc_link), "/proc/%u/exe", e->pid);
    ssize_t len = readlink(proc_link, exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
    } else {
        snprintf(exe_path, sizeof(exe_path), "%s", e->comm);
    }

    char esc_comm[128], esc_exe[512], esc_path[512], esc_old_path[512];
    json_escape(e->comm, esc_comm, sizeof(esc_comm));
    json_escape(exe_path, esc_exe, sizeof(esc_exe));
    json_escape(e->path, esc_path, sizeof(esc_path));
    json_escape(e->old_path, esc_old_path, sizeof(esc_old_path));

    char json_buf[2048];
    const char *ev_type_str = event_type_to_str((enum rs_event_type_t)e->event_type);

    if (e->event_type == EVENT_NET_CONNECT) {
        char ip_str[INET_ADDRSTRLEN] = "0.0.0.0";
        struct in_addr addr;
        addr.s_addr = e->dst_ip;
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        snprintf(json_buf, sizeof(json_buf),
            "{\"timestamp\": %.6f, \"pid\": %u, \"ppid\": %u, \"process\": \"%s\", "
            "\"exe\": \"%s\", \"event_type\": \"%s\", \"path\": null, \"bytes\": 0, "
            "\"dst_ip\": \"%s\", \"dst_port\": %u, \"protocol\": \"TCP\", \"success\": true, "
            "\"extra\": {}}\n",
            timestamp, e->pid, e->ppid, esc_comm, esc_exe, ev_type_str, ip_str, e->dst_port);
    } else if (e->event_type == EVENT_FILE_RENAME) {
        snprintf(json_buf, sizeof(json_buf),
            "{\"timestamp\": %.6f, \"pid\": %u, \"ppid\": %u, \"process\": \"%s\", "
            "\"exe\": \"%s\", \"event_type\": \"%s\", \"path\": \"%s\", \"bytes\": 0, "
            "\"dst_ip\": null, \"dst_port\": null, \"protocol\": null, \"success\": true, "
            "\"extra\": {\"old_path\": \"%s\"}}\n",
            timestamp, e->pid, e->ppid, esc_comm, esc_exe, ev_type_str, esc_path, esc_old_path);
    } else {
        snprintf(json_buf, sizeof(json_buf),
            "{\"timestamp\": %.6f, \"pid\": %u, \"ppid\": %u, \"process\": \"%s\", "
            "\"exe\": \"%s\", \"event_type\": \"%s\", \"path\": \"%s\", \"bytes\": %lld, "
            "\"dst_ip\": null, \"dst_port\": null, \"protocol\": null, \"success\": true, "
            "\"extra\": {}}\n",
            timestamp, e->pid, e->ppid, esc_comm, esc_exe, ev_type_str, esc_path, (long long)e->bytes);
    }

    g_event_count++;

    if (g_stdout_mode) {
        fputs(json_buf, stdout);
        fflush(stdout);
    }

    if (g_out_file) {
        fputs(json_buf, g_out_file);
        fflush(g_out_file);
    }

    return 0;
}

int main(int argc, char **argv) {
    const char *bpf_file = "ebpf/sensor.bpf.o";
    const char *out_filename = NULL;
    __u32 collector_pid = getpid();
    __u32 target_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watch-dir") == 0 && i + 1 < argc) {
            strncpy(g_watch_dir, argv[++i], sizeof(g_watch_dir) - 1);
        } else if (strcmp(argv[i], "--jsonl") == 0 && i + 1 < argc) {
            out_filename = argv[++i];
        } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
            bpf_file = argv[++i];
        } else if (strcmp(argv[i], "--target-pid") == 0 && i + 1 < argc) {
            target_pid = (__u32)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--collector-pid") == 0 && i + 1 < argc) {
            collector_pid = (__u32)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-stdout") == 0) {
            g_stdout_mode = false;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n"
                   "  --watch-dir <path>       Filter file events to path containing this substring\n"
                   "  --jsonl <file>           Output events to JSONL file\n"
                   "  --bpf <file>             Path to sensor.bpf.o\n"
                   "  --target-pid <pid>       Only monitor events from this PID\n"
                   "  --collector-pid <pid>    Explicitly set collector PID to ignore\n"
                   "  --no-stdout              Disable streaming to stdout\n", argv[0]);
            return 0;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (out_filename) {
        g_out_file = fopen(out_filename, "a");
        if (!g_out_file) {
            fprintf(stderr, "Error opening output file '%s': %s\n", out_filename, strerror(errno));
            return 1;
        }
    }

    struct bpf_object *obj = bpf_object__open_file(bpf_file, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object '%s': %s\n", bpf_file, strerror(errno));
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d (%s)\n", err, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Configure config_map */
    struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "config_map");
    if (cfg_map) {
        int cfg_fd = bpf_map__fd(cfg_map);
        __u32 k0 = 0, k1 = 1;
        bpf_map_update_elem(cfg_fd, &k0, &collector_pid, BPF_ANY);
        bpf_map_update_elem(cfg_fd, &k1, &target_pid, BPF_ANY);
    }

    /* Attach all BPF programs */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "Warning: failed to attach program '%s': %s\n",
                    bpf_program__name(prog), strerror(errno));
        }
    }

    /* Find ring buffer map */
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "rb");
    if (!rb_map) {
        fprintf(stderr, "Failed to find 'rb' ring buffer map\n");
        bpf_object__close(obj);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "[+] RansomShield eBPF Sensor loaded successfully.\n");
    fprintf(stderr, "[+] Collector PID: %u (filtered from kernel events)\n", collector_pid);
    if (g_watch_dir[0] != '\0')
        fprintf(stderr, "[+] Monitored Directory Filter: %s\n", g_watch_dir);
    if (target_pid > 0)
        fprintf(stderr, "[+] Target PID Filter: %u\n", target_pid);
    if (out_filename)
        fprintf(stderr, "[+] Logging to JSONL: %s\n", out_filename);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    /* Drain any remaining events in ring buffer before exiting */
    ring_buffer__consume(rb);

    fprintf(stderr, "\n[*] Shutting down sensor. Total events captured: %lu\n", g_event_count);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    if (g_out_file)
        fclose(g_out_file);

    return 0;
}
