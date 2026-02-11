// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - Scheduler tracing BPF program
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
//
// Attaches to: tracepoint/sched/sched_switch, tracepoint/sched/sched_process_fork
// Tracks: context switches, runqueue latency, on-CPU time per PID.

#include "headers/common.h"

// Tracepoint context for sched_switch (when vmlinux.h is not available)
#ifndef HAS_VMLINUX_H
struct sched_switch_args {
	__u64 unused;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};
#endif

// Track when a task was enqueued (for runqueue latency)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);       // pid
	__type(value, struct ts_entry);
} sched_enqueue SEC(".maps");

// Track when a task started running (for on-CPU time)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);       // pid
	__type(value, struct ts_entry);
} sched_oncpu SEC(".maps");

// Aggregated scheduler statistics
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sched_key);
	__type(value, struct sched_val);
} sched_stats SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct sched_switch_args *ctx)
{
	__u64 now = bpf_ktime_get_ns();

	// === Handle the task being switched OUT (prev) ===
	__u32 prev_pid = (__u32)ctx->prev_pid;
	if (prev_pid > 0) {
		// Calculate on-CPU time for prev
		struct ts_entry *oncpu = bpf_map_lookup_elem(&sched_oncpu, &prev_pid);
		if (oncpu) {
			__u64 oncpu_ns = now - oncpu->ts;

			struct sched_key key = { .pid = prev_pid };
			struct sched_val *val = bpf_map_lookup_elem(&sched_stats, &key);
			if (val) {
				__sync_fetch_and_add(&val->context_switches, 1);
				__sync_fetch_and_add(&val->oncpu_ns, oncpu_ns);
			} else {
				struct sched_val new_val = {};
				new_val.context_switches = 1;
				new_val.oncpu_ns = oncpu_ns;
				bpf_probe_read_kernel_str(new_val.comm, sizeof(new_val.comm), ctx->prev_comm);
				bpf_map_update_elem(&sched_stats, &key, &new_val, BPF_NOEXIST);
			}
			bpf_map_delete_elem(&sched_oncpu, &prev_pid);
		}

		// Record enqueue time for runqueue latency tracking
		struct ts_entry enqueue = { .ts = now };
		bpf_map_update_elem(&sched_enqueue, &prev_pid, &enqueue, BPF_ANY);
	}

	// === Handle the task being switched IN (next) ===
	__u32 next_pid = (__u32)ctx->next_pid;
	if (next_pid > 0) {
		// Calculate runqueue latency
		struct ts_entry *enqueue = bpf_map_lookup_elem(&sched_enqueue, &next_pid);
		if (enqueue) {
			__u64 runq_ns = now - enqueue->ts;

			struct sched_key key = { .pid = next_pid };
			struct sched_val *val = bpf_map_lookup_elem(&sched_stats, &key);
			if (val) {
				// Store latest runqueue latency (not cumulative)
				val->runq_latency_ns = runq_ns;
			}
			bpf_map_delete_elem(&sched_enqueue, &next_pid);
		}

		// Record on-CPU start time
		struct ts_entry oncpu = { .ts = now };
		bpf_map_update_elem(&sched_oncpu, &next_pid, &oncpu, BPF_ANY);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
