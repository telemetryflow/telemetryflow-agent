//go:build linux

// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ebpf

import "strconv"

// syscallName returns the human-readable name for a Linux syscall number (amd64).
// Common syscalls are mapped; unknown numbers return "syscall_<NR>".
func syscallName(nr uint32) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return "syscall_" + strconv.FormatUint(uint64(nr), 10)
}

// syscallNames maps Linux amd64 syscall numbers to names.
// Only the most common/interesting syscalls are included.
var syscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	28:  "madvise",
	32:  "dup",
	33:  "dup2",
	35:  "nanosleep",
	39:  "getpid",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	95:  "umask",
	200: "tkill",
	202: "futex",
	217: "getdents64",
	228: "clock_gettime",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	257: "openat",
	262: "newfstatat",
	263: "unlinkat",
	268: "fchmodat",
	281: "epoll_pwait",
	288: "accept4",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	302: "prlimit64",
	318: "getrandom",
	332: "statx",
	435: "clone3",
	437: "openat2",
	439: "faccessat2",
}

// tcpStateName returns the human-readable TCP state name.
// Values match the Linux kernel TCP state enum (include/net/tcp_states.h).
func tcpStateName(state uint32) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return "unknown_" + strconv.FormatUint(uint64(state), 10)
}

// tcpStateNames maps TCP state numbers to names.
var tcpStateNames = map[uint32]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}
