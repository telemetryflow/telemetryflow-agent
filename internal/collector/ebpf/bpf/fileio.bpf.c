// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - File I/O tracing BPF program
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Attaches to: kprobe/vfs_read, kretprobe/vfs_read,
//              kprobe/vfs_write, kretprobe/vfs_write,
//              kprobe/vfs_open
// Tracks: VFS operation count, bytes, and latency per PID+operation.

#include "headers/common.h"

// Operation types
#define OP_READ  0
#define OP_WRITE 1
#define OP_OPEN  2

// Entry timestamp tracking for latency measurement
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);       // tid
	__type(value, struct ts_entry);
} fileio_start SEC(".maps");

// Aggregated file I/O statistics
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct fileio_key);
	__type(value, struct fileio_val);
} fileio_stats SEC(".maps");

// Helper: record entry timestamp
static __always_inline void record_start(__u64 tid)
{
	struct ts_entry entry = {};
	entry.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&fileio_start, &tid, &entry, BPF_ANY);
}

// Helper: compute duration and update stats
static __always_inline void update_stats(__u32 pid, __u32 operation, __u64 bytes)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct ts_entry *entry = bpf_map_lookup_elem(&fileio_start, &tid);
	__u64 duration_ns = 0;
	if (entry) {
		duration_ns = bpf_ktime_get_ns() - entry->ts;
		bpf_map_delete_elem(&fileio_start, &tid);
	}

	struct fileio_key key = {};
	key.pid = pid;
	key.operation = operation;

	struct fileio_val *val = bpf_map_lookup_elem(&fileio_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
		__sync_fetch_and_add(&val->bytes, bytes);
		__sync_fetch_and_add(&val->total_ns, duration_ns);
	} else {
		struct fileio_val new_val = {};
		new_val.count = 1;
		new_val.bytes = bytes;
		new_val.total_ns = duration_ns;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&fileio_stats, &key, &new_val, BPF_NOEXIST);
	}
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry)
{
	__u64 tid = bpf_get_current_pid_tgid();
	record_start(tid);
	return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vfs_read_exit, ssize_t ret)
{
	__u32 pid = GET_PID();
	__u64 bytes = (ret > 0) ? (__u64)ret : 0;
	update_stats(pid, OP_READ, bytes);
	return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry)
{
	__u64 tid = bpf_get_current_pid_tgid();
	record_start(tid);
	return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(vfs_write_exit, ssize_t ret)
{
	__u32 pid = GET_PID();
	__u64 bytes = (ret > 0) ? (__u64)ret : 0;
	update_stats(pid, OP_WRITE, bytes);
	return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open_entry)
{
	__u32 pid = GET_PID();
	// No latency tracking for open — just count
	struct fileio_key key = {};
	key.pid = pid;
	key.operation = OP_OPEN;

	struct fileio_val *val = bpf_map_lookup_elem(&fileio_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
	} else {
		struct fileio_val new_val = {};
		new_val.count = 1;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&fileio_stats, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
