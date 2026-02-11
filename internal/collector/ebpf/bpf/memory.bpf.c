// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - Memory event tracing BPF program
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
//
// Attaches to: tracepoint/exceptions/page_fault_user,
//              tracepoint/exceptions/page_fault_kernel
// Tracks: total page faults, major faults, minor faults per PID.

#include "headers/common.h"

// Tracepoint context for page faults (when vmlinux.h is not available)
#ifndef HAS_VMLINUX_H
struct page_fault_args {
	__u64 unused;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};
#endif

// Aggregated memory statistics
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct mem_key);
	__type(value, struct mem_val);
} mem_stats SEC(".maps");

// Helper: update page fault counter
static __always_inline void record_page_fault(int is_major)
{
	__u32 pid = GET_PID();
	if (pid == 0)
		return;

	struct mem_key key = { .pid = pid };
	struct mem_val *val = bpf_map_lookup_elem(&mem_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->page_faults, 1);
		if (is_major)
			__sync_fetch_and_add(&val->major_faults, 1);
		else
			__sync_fetch_and_add(&val->minor_faults, 1);
	} else {
		struct mem_val new_val = {};
		new_val.page_faults = 1;
		new_val.major_faults = is_major ? 1 : 0;
		new_val.minor_faults = is_major ? 0 : 1;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&mem_stats, &key, &new_val, BPF_NOEXIST);
	}
}

SEC("tracepoint/exceptions/page_fault_user")
int page_fault_user(struct page_fault_args *ctx)
{
	// User-space page faults are typically minor unless backed by disk
	// Error code bit 4 indicates major fault on some architectures
	int is_major = (ctx->error_code & 0x10) ? 1 : 0;
	record_page_fault(is_major);
	return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int page_fault_kernel(struct page_fault_args *ctx)
{
	int is_major = (ctx->error_code & 0x10) ? 1 : 0;
	record_page_fault(is_major);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
