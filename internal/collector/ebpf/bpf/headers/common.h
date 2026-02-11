// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// TelemetryFlow Agent - eBPF common headers
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.

#ifndef __TFO_COMMON_H
#define __TFO_COMMON_H

// vmlinux.h provides all kernel type definitions via BTF.
// Generated at build time with: bpftool btf dump file /sys/kernel/btf/vmlinux format c
// If vmlinux.h is not available, fall back to minimal type definitions below.
#ifdef HAS_VMLINUX_H
#include "vmlinux.h"
#else
// Minimal kernel type stubs for CO-RE
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

// Tracepoint context structures
struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	__u64 unused;
	long id;
	long ret;
};

// Socket/TCP structures
struct sock_common {
	unsigned char skc_state;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

#endif // HAS_VMLINUX_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// =========================================================================
// Constants
// =========================================================================

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_SYSCALL_NR 512

// =========================================================================
// Shared key/value structures for BPF hash maps
// =========================================================================

// Key for per-process + syscall aggregation
struct syscall_key {
	__u32 pid;
	__u32 syscall_nr;
};

// Value for syscall statistics
struct syscall_val {
	__u64 count;
	__u64 total_ns;
	__u64 errors;
	char comm[TASK_COMM_LEN];
};

// Key for per-process network aggregation
struct net_key {
	__u32 pid;
};

// Value for TCP connection statistics
struct tcp_val {
	__u64 connections;
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u64 rtt_ns;
	__u64 retransmits;
	char comm[TASK_COMM_LEN];
};

// Value for UDP packet statistics
struct udp_val {
	__u64 packets_sent;
	__u64 packets_recv;
	char comm[TASK_COMM_LEN];
};

// Key for file I/O aggregation (pid + operation type)
struct fileio_key {
	__u32 pid;
	__u32 operation; // 0=read, 1=write, 2=open
};

// Value for file I/O statistics
struct fileio_val {
	__u64 count;
	__u64 bytes;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
};

// Key for scheduler aggregation
struct sched_key {
	__u32 pid;
};

// Value for scheduler statistics
struct sched_val {
	__u64 context_switches;
	__u64 runq_latency_ns;
	__u64 oncpu_ns;
	__u64 migrations;
	char comm[TASK_COMM_LEN];
};

// Key for memory aggregation
struct mem_key {
	__u32 pid;
};

// Value for memory statistics
struct mem_val {
	__u64 page_faults;
	__u64 major_faults;
	__u64 minor_faults;
	char comm[TASK_COMM_LEN];
};

// Key for TCP state transitions
struct tcpstate_key {
	__u32 pid;
	__u32 old_state;
	__u32 new_state;
};

// Value for TCP state transition counts
struct tcpstate_val {
	__u64 count;
};

// =========================================================================
// Per-CPU scratch space for latency tracking
// =========================================================================

struct ts_entry {
	__u64 ts;
};

// =========================================================================
// Helper macros
// =========================================================================

// Get current PID (thread group ID)
#define GET_PID() ((__u32)(bpf_get_current_pid_tgid() >> 32))

// Get current TID
#define GET_TID() ((__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF))

#endif // __TFO_COMMON_H
