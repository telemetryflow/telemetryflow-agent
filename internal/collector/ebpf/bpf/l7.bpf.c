// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - L7 RED (Request/Error/Latency) BPF program
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Attaches to: tracepoint/syscalls/sys_enter_read, tracepoint/syscalls/sys_exit_read
//              tracepoint/syscalls/sys_enter_write, tracepoint/syscalls/sys_exit_write
//
// Observes application-layer HTTP/1.x traffic per PID+connection to compute:
//   - Request count (per interval)
//   - Error count (5xx responses)
//   - Latency from write(request) → read(response) in nanoseconds
//
// gRPC, MySQL, Redis, PostgreSQL wire-protocol parsing: TODO (stubbed)
//
// Requires: Linux 5.8+ (ring buffer), CO-RE (BTF), CAP_BPF / CAP_SYS_ADMIN.
//
// NOTE: This program is compiled by bpf2go when clang is available on the
// build host. The Go loader is gated behind the same linux build tag.

#include "headers/common.h"

// =========================================================================
// Constants
// =========================================================================

#define L7_MAX_ENTRIES    65536
#define L7_BUF_SIZE       256    // bytes we capture from each read/write
#define L7_RING_BUF_SIZE  (1 << 22)  // 4 MB ring buffer

// HTTP method prefixes (first 8 bytes cover GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS)
#define HTTP_GET     0x20544547  // "GET "
#define HTTP_POST    0x54534f50  // "POST"
#define HTTP_PUT     0x20545550  // "PUT "
#define HTTP_DELETE  0x454c4544  // "DELE"
#define HTTP_HEAD    0x44414548  // "HEAD"
#define HTTP_PATCH   0x54415050  // "PATC"
#define HTTP_OPTION  0x4954504f  // "OPTI"

// HTTP response prefix: "HTTP/1"
#define HTTP_RESP_PREFIX 0x50545448  // "HTTP"

// L7 protocol identifiers emitted in events
#define PROTO_UNKNOWN  0
#define PROTO_HTTP1    1
// Future: PROTO_HTTP2, PROTO_GRPC, PROTO_MYSQL, PROTO_REDIS, PROTO_PG

// =========================================================================
// Map key/value structs
// =========================================================================

// Key: PID + file-descriptor (identifies a connection)
struct l7_conn_key {
    __u32 pid;
    __u32 fd;
};

// In-flight write context: tracks when a request write started.
struct l7_inflight_entry {
    __u64 write_ts;  // ktime_get_ns() at write start (request sent)
};

// Aggregated per-connection stats stored in l7_stats map.
struct l7_stat_val {
    __u64 requests;   // total request count in this interval
    __u64 errors;     // 5xx / protocol-error count
    __u64 latency_ns; // sum of request→response latencies (ns)
    __u64 latency_count; // number of completed req/resp pairs (for avg/p99 in userspace)
};

// Event pushed to userspace via ring buffer for each completed request.
struct l7_event {
    __u32 pid;
    __u32 fd;
    __u8  protocol;  // PROTO_* above
    __u8  is_error;  // 1 if 5xx or protocol error
    __u8  _pad[2];
    __u64 latency_ns;
};

// =========================================================================
// BPF Maps
// =========================================================================

// Per-connection in-flight request start timestamps (keyed by pid+fd).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, L7_MAX_ENTRIES);
    __type(key, struct l7_conn_key);
    __type(value, struct l7_inflight_entry);
} l7_inflight SEC(".maps");

// Aggregated L7 stats per pid+fd (read by userspace on interval tick).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, L7_MAX_ENTRIES);
    __type(key, struct l7_conn_key);
    __type(value, struct l7_stat_val);
} l7_stats SEC(".maps");

// Ring buffer: completed request events pushed to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, L7_RING_BUF_SIZE);
} l7_events SEC(".maps");

// Scratch map for read tracepoint: stores fd per tid so sys_exit_read
// can correlate the response back to the right connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, L7_MAX_ENTRIES);
    __type(key, __u64);   // tid
    __type(value, __u32); // fd
} l7_read_fd SEC(".maps");

// =========================================================================
// Helpers
// =========================================================================

// classify_http1_request: returns 1 if the buffer looks like an HTTP/1.x
// request (starts with a known method).
static __always_inline int classify_http1_request(const char *buf)
{
    __u32 prefix;
    if (bpf_probe_read_user(&prefix, sizeof(prefix), buf) < 0)
        return 0;
    return (prefix == HTTP_GET   ||
            prefix == HTTP_POST  ||
            prefix == HTTP_PUT   ||
            prefix == HTTP_DELETE||
            prefix == HTTP_HEAD  ||
            prefix == HTTP_PATCH ||
            prefix == HTTP_OPTION);
}

// classify_http1_response: returns 1 if the buffer looks like an HTTP/1.x
// response header ("HTTP/1.x NNN").  Also detects 5xx via the status code.
// *is_error is set to 1 for 5xx responses.
static __always_inline int classify_http1_response(const char *buf, __u8 *is_error)
{
    __u32 prefix;
    if (bpf_probe_read_user(&prefix, sizeof(prefix), buf) < 0)
        return 0;
    if (prefix != HTTP_RESP_PREFIX)
        return 0;
    // Read status code: "HTTP/1.x NNN" → byte at offset 9 is the hundreds digit
    __u8 status_hundreds;
    if (bpf_probe_read_user(&status_hundreds, 1, buf + 9) < 0)
        return 0;
    *is_error = (status_hundreds == '5') ? 1 : 0;
    return 1;
}

// =========================================================================
// Tracepoint handlers — sys_enter_write
// When a process writes to a socket fd, treat it as a request if the data
// looks like an HTTP request.
// =========================================================================

struct sys_write_args {
    __u64 unused; // common fields
    int   fd;
    const char __user *buf;
    size_t count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int l7_enter_write(struct sys_write_args *ctx)
{
    if (ctx->count < 4)
        return 0;

    // Only process if buf looks like HTTP/1.x request
    if (!classify_http1_request(ctx->buf))
        return 0;

    __u64 tid  = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(tid >> 32);
    __u32 fd   = (__u32)ctx->fd;

    struct l7_conn_key key = { .pid = pid, .fd = fd };
    struct l7_inflight_entry entry = { .write_ts = bpf_ktime_get_ns() };

    bpf_map_update_elem(&l7_inflight, &key, &entry, BPF_ANY);
    return 0;
}

// =========================================================================
// Tracepoint handlers — sys_enter_read / sys_exit_read
// sys_enter_read: capture fd so sys_exit can match it.
// sys_exit_read:  check if the buffer is an HTTP response; if so, compute
//                 latency against the in-flight write timestamp.
// =========================================================================

struct sys_read_enter_args {
    __u64 unused;
    int   fd;
    char __user *buf;
    size_t count;
};

SEC("tracepoint/syscalls/sys_enter_read")
int l7_enter_read(struct sys_read_enter_args *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 fd  = (__u32)ctx->fd;
    bpf_map_update_elem(&l7_read_fd, &tid, &fd, BPF_ANY);
    return 0;
}

struct sys_read_exit_args {
    __u64 unused;
    long  ret;        // bytes read; also holds the buf pointer in some kernels
    // NOTE: we need the user buf to inspect content.
    // On modern kernels with BTF we can read pt_regs via BPF_CORE_READ.
    // For the tracepoint variant we rely on a per-tid scratch map populated
    // at sys_enter_read that also stores the buf pointer.
    // This simplified version only tracks fd and latency timing; full buf
    // inspection requires uprobe or the newer sys_exit tracepoint with buf
    // stored in a scratch map (see TODO below).
};

// Scratch map: tid → user buf pointer saved at sys_enter_read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, L7_MAX_ENTRIES);
    __type(key, __u64);   // tid
    __type(value, __u64); // user buf pointer
} l7_read_buf SEC(".maps");

// Extended sys_enter_read that also saves the user buffer pointer.
struct sys_read_enter_args_full {
    __u64 unused;
    int   fd;
    __u64 buf;   // char __user *buf (as pointer-sized integer)
    size_t count;
};

// We redefine the SEC to also capture buf. In practice bpf2go will merge these.
// Using a separate program name for buf capture:
SEC("tracepoint/syscalls/sys_enter_read")
int l7_enter_read_buf(struct sys_read_enter_args_full *ctx)
{
    __u64 tid  = bpf_get_current_pid_tgid();
    __u64 bufp = ctx->buf;
    bpf_map_update_elem(&l7_read_buf, &tid, &bufp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int l7_exit_read(struct sys_read_exit_args *ctx)
{
    if (ctx->ret <= 0)
        goto cleanup;

    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(tid >> 32);

    // Retrieve the fd we saved at enter.
    __u32 *fdp = bpf_map_lookup_elem(&l7_read_fd, &tid);
    if (!fdp)
        goto cleanup;
    __u32 fd = *fdp;

    // Retrieve the buffer pointer we saved at enter.
    __u64 *bufpp = bpf_map_lookup_elem(&l7_read_buf, &tid);
    if (!bufpp)
        goto cleanup;

    __u8 is_error = 0;
    if (!classify_http1_response((const char *)(long)(*bufpp), &is_error))
        goto cleanup;

    // Look up in-flight entry to compute latency.
    struct l7_conn_key key = { .pid = pid, .fd = fd };
    struct l7_inflight_entry *inf = bpf_map_lookup_elem(&l7_inflight, &key);
    __u64 latency_ns = 0;
    if (inf && inf->write_ts > 0) {
        __u64 now = bpf_ktime_get_ns();
        latency_ns = (now > inf->write_ts) ? (now - inf->write_ts) : 0;
        bpf_map_delete_elem(&l7_inflight, &key);
    }

    // Update aggregated stats map.
    struct l7_stat_val *sv = bpf_map_lookup_elem(&l7_stats, &key);
    if (sv) {
        __sync_fetch_and_add(&sv->requests, 1);
        if (is_error)
            __sync_fetch_and_add(&sv->errors, 1);
        __sync_fetch_and_add(&sv->latency_ns, latency_ns);
        __sync_fetch_and_add(&sv->latency_count, 1);
    } else {
        struct l7_stat_val new_sv = {
            .requests     = 1,
            .errors       = is_error ? 1 : 0,
            .latency_ns   = latency_ns,
            .latency_count = 1,
        };
        bpf_map_update_elem(&l7_stats, &key, &new_sv, BPF_NOEXIST);
    }

    // Also push a per-event record to the ring buffer for high-fidelity consumers.
    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (ev) {
        ev->pid        = pid;
        ev->fd         = fd;
        ev->protocol   = PROTO_HTTP1;
        ev->is_error   = is_error;
        ev->latency_ns = latency_ns;
        bpf_ringbuf_submit(ev, 0);
    }

cleanup:
    bpf_map_delete_elem(&l7_read_fd, &tid);
    bpf_map_delete_elem(&l7_read_buf, &tid);
    return 0;
}

// TODO: gRPC — attach to sys_enter_write and parse HTTP/2 frames (magic prefix + HEADERS frame)
// TODO: MySQL  — parse COM_QUERY (0x03) command byte; detect error packet (0xff)
// TODO: Redis  — parse RESP protocol (first byte '*' for arrays, '+'/'-'/'$' etc.)
// TODO: PostgreSQL — parse message type byte 'Q' (simple query); 'E' (error)

char LICENSE[] SEC("license") = "GPL";
