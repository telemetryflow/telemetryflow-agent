// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - TCP state transition tracing BPF program
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
//
// Attaches to: tracepoint/sock/inet_sock_set_state
// Tracks: TCP state transitions (ESTABLISHED→CLOSE_WAIT, SYN_SENT→ESTABLISHED, etc.)

#include "headers/common.h"

// Tracepoint context for inet_sock_set_state
#ifndef HAS_VMLINUX_H
struct inet_sock_set_state_args {
	__u64 unused;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};
#endif

// TCP state transition counts per (pid, old_state, new_state)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tcpstate_key);
	__type(value, struct tcpstate_val);
} tcpstate_stats SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct inet_sock_set_state_args *ctx)
{
	__u32 pid = GET_PID();

	// Only track TCP (protocol = 6)
	if (ctx->protocol != 6)
		return 0;

	struct tcpstate_key key = {};
	key.pid = pid;
	key.old_state = (__u32)ctx->oldstate;
	key.new_state = (__u32)ctx->newstate;

	struct tcpstate_val *val = bpf_map_lookup_elem(&tcpstate_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
	} else {
		struct tcpstate_val new_val = {};
		new_val.count = 1;
		bpf_map_update_elem(&tcpstate_stats, &key, &new_val, BPF_NOEXIST);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
