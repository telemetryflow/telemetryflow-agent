package ebpf

// Generate eBPF bytecode from C source files.
// Requires: clang, llvm (for BPF compilation)
// Install bpf2go: go install github.com/cilium/ebpf/cmd/bpf2go@latest
//
// Each directive compiles a .bpf.c file into Go source + .o bytecode
// for both little-endian (el) and big-endian (eb) architectures.
//
// The -I flag includes the headers directory for common.h.
// The -target flag tells bpf2go to produce linux-native BPF objects.
//
// Run: go generate ./internal/collector/ebpf/...

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type syscall_key -type syscall_val syscalls bpf/syscalls.bpf.c -- -I bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type net_key -type tcp_val -type udp_val network bpf/network.bpf.c -- -I bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type fileio_key -type fileio_val fileio bpf/fileio.bpf.c -- -I bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type sched_key -type sched_val scheduler bpf/scheduler.bpf.c -- -I bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type mem_key -type mem_val memory bpf/memory.bpf.c -- -I bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc clang -type tcpstate_key -type tcpstate_val tcpstate bpf/tcpstate.bpf.c -- -I bpf
