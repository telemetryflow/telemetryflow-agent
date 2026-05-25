// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - Network monitoring BPF program
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Attaches to: kprobe/tcp_connect, kprobe/tcp_close, kprobe/tcp_sendmsg,
//              kprobe/tcp_recvmsg, kprobe/tcp_retransmit_skb,
//              kprobe/udp_sendmsg, kprobe/udp_recvmsg
// Tracks: TCP connections, bytes sent/recv, RTT, retransmits, UDP packets.

#include "headers/common.h"

// TCP connection statistics per PID
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct net_key);
	__type(value, struct tcp_val);
} tcp_stats SEC(".maps");

// UDP packet statistics per PID
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct net_key);
	__type(value, struct udp_val);
} udp_stats SEC(".maps");

// Helper: get or create TCP stats entry
static __always_inline struct tcp_val *get_tcp_val(__u32 pid)
{
	struct net_key key = { .pid = pid };
	struct tcp_val *val = bpf_map_lookup_elem(&tcp_stats, &key);
	if (val)
		return val;

	struct tcp_val new_val = {};
	bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
	bpf_map_update_elem(&tcp_stats, &key, &new_val, BPF_NOEXIST);
	return bpf_map_lookup_elem(&tcp_stats, &key);
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	__u32 pid = GET_PID();
	struct tcp_val *val = get_tcp_val(pid);
	if (val)
		__sync_fetch_and_add(&val->connections, 1);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	__u32 pid = GET_PID();
	struct tcp_val *val = get_tcp_val(pid);
	if (val)
		__sync_fetch_and_add(&val->bytes_sent, size);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg, struct sock *sk, struct msghdr *msg,
	       size_t len, int flags, int *addr_len)
{
	__u32 pid = GET_PID();
	struct tcp_val *val = get_tcp_val(pid);
	if (val)
		__sync_fetch_and_add(&val->bytes_recv, len);
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retransmit_skb, struct sock *sk)
{
	__u32 pid = GET_PID();
	struct tcp_val *val = get_tcp_val(pid);
	if (val)
		__sync_fetch_and_add(&val->retransmits, 1);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	__u32 pid = GET_PID();
	struct net_key key = { .pid = pid };

	struct udp_val *val = bpf_map_lookup_elem(&udp_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->packets_sent, 1);
	} else {
		struct udp_val new_val = {};
		new_val.packets_sent = 1;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&udp_stats, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg, struct sock *sk, struct msghdr *msg,
	       size_t len, int flags, int *addr_len)
{
	__u32 pid = GET_PID();
	struct net_key key = { .pid = pid };

	struct udp_val *val = bpf_map_lookup_elem(&udp_stats, &key);
	if (val) {
		__sync_fetch_and_add(&val->packets_recv, 1);
	} else {
		struct udp_val new_val = {};
		new_val.packets_recv = 1;
		bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
		bpf_map_update_elem(&udp_stats, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
