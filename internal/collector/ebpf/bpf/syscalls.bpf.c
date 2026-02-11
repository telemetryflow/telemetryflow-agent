// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - Syscall tracing BPF program
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
//
// Attaches to: tracepoint/raw_syscalls/sys_enter, tracepoint/raw_syscalls/sys_exit
// Tracks: syscall invocation count, latency, and error count per PID+syscall_nr.

#include "headers/common.h"

// Per-CPU map to store entry timestamps for latency calculation
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);       // tid
	__type(value, struct ts_entry);
} syscall_start SEC(".maps");

// Per-CPU map to store syscall number for exit handler
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);       // tid
	__type(value, __u32);     // syscall_nr
} syscall_nr_map SEC(".maps");

// Aggregated syscall statistics: key=(pid, syscall_nr), value=(count, total_ns, errors)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct syscall_key);
	__type(value, struct syscall_val);
} syscall_stats SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	__u32 syscall_nr = (__u32)ctx->id;

	// Filter out high syscall numbers
	if (syscall_nr >= MAX_SYSCALL_NR)
		return 0;

	// Record entry timestamp
	struct ts_entry entry = {};
	entry.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&syscall_start, &tid, &entry, BPF_ANY);

	// Store syscall number for the exit handler
	bpf_map_update_elem(&syscall_nr_map, &tid, &syscall_nr, BPF_ANY);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	__u32 pid = GET_PID();

	// Look up entry timestamp
	struct ts_entry *entry = bpf_map_lookup_elem(&syscall_start, &tid);
	if (!entry)
		return 0;

	// Look up syscall number
	__u32 *nr_ptr = bpf_map_lookup_elem(&syscall_nr_map, &tid);
	if (!nr_ptr)
		goto cleanup;

	__u64 duration_ns = bpf_ktime_get_ns() - entry->ts;
	long ret = ctx->ret;

	// Update aggregated stats
	struct syscall_key key = {};
	key.pid = pid;
	key.syscall_nr = *nr_ptr;

	struct syscall_val *val = bpf_map_lookup_elem(&syscall_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
		__sync_fetch_and_add(&val->total_ns, duration_ns);
		if (ret < 0)
			__sync_fetch_and_add(&val->errors, 1);
	} else {
		struct syscall_val new_val = {};
		new_val.count = 1;
		new_val.total_ns = duration_ns;
		new_val.errors = (ret < 0) ? 1 : 0;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&syscall_stats, &key, &new_val, BPF_NOEXIST);
	}

cleanup:
	bpf_map_delete_elem(&syscall_start, &tid);
	bpf_map_delete_elem(&syscall_nr_map, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
