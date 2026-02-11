//go:build linux

package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// bpfPrograms holds all loaded eBPF programs and maps.
// Fields are populated during loadPrograms() and cleaned up in closePrograms().
type bpfPrograms struct {
	// Links (tracepoint/kprobe attachments)
	links []link.Link

	// Syscall maps
	syscallStats *ebpf.Map

	// Network maps
	tcpStats *ebpf.Map
	udpStats *ebpf.Map

	// FileIO maps
	fileioStats *ebpf.Map

	// Scheduler maps
	schedStats *ebpf.Map

	// Memory maps
	memStats *ebpf.Map

	// TCP State maps
	tcpstateStats *ebpf.Map
}

// programs holds the currently loaded BPF programs.
// nil when programs are not loaded.
var programs *bpfPrograms

// loadProgramsLinux loads and attaches eBPF programs to tracepoints/kprobes.
// This is called from linux.go's loadPrograms() method.
func (c *EBPFCollector) loadProgramsLinux() error {
	// Check if BPF filesystem is available
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}

	c.logger.Info("Loading eBPF programs",
		zap.String("pin_path", c.cfg.raw.PinPath),
		zap.String("btf_path", c.cfg.raw.BTFPath),
	)

	progs := &bpfPrograms{}

	// NOTE: In production, this is where we would:
	// 1. Load compiled BPF objects via cilium/ebpf (from bpf2go-generated code)
	// 2. Attach programs to tracepoints/kprobes
	// 3. Store map references for reading in sub-collectors
	//
	// For now, we create maps manually as a placeholder until bpf2go
	// code generation is run on a Linux CI machine.
	//
	// Example of what the production code looks like:
	//
	//   spec, err := loadSyscalls()
	//   if err != nil { return err }
	//   objs := syscallsObjects{}
	//   if err := spec.LoadAndAssign(&objs, nil); err != nil { return err }
	//   tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.SysEnter, nil)
	//   progs.links = append(progs.links, tp)
	//   progs.syscallStats = objs.SyscallStats

	if c.cfg.raw.CollectSyscalls {
		if err := c.loadSyscallPrograms(progs); err != nil {
			c.logger.Warn("Failed to load syscall programs, disabling", zap.Error(err))
		}
	}

	if c.cfg.raw.CollectNetwork {
		if err := c.loadNetworkPrograms(progs); err != nil {
			c.logger.Warn("Failed to load network programs, disabling", zap.Error(err))
		}
	}

	if c.cfg.raw.CollectFileIO {
		if err := c.loadFileIOPrograms(progs); err != nil {
			c.logger.Warn("Failed to load file I/O programs, disabling", zap.Error(err))
		}
	}

	if c.cfg.raw.CollectScheduler {
		if err := c.loadSchedulerPrograms(progs); err != nil {
			c.logger.Warn("Failed to load scheduler programs, disabling", zap.Error(err))
		}
	}

	if c.cfg.raw.CollectMemory {
		if err := c.loadMemoryPrograms(progs); err != nil {
			c.logger.Warn("Failed to load memory programs, disabling", zap.Error(err))
		}
	}

	if c.cfg.raw.CollectTCPEvents {
		if err := c.loadTCPStatePrograms(progs); err != nil {
			c.logger.Warn("Failed to load TCP state programs, disabling", zap.Error(err))
		}
	}

	programs = progs
	c.logger.Info("eBPF programs loaded successfully",
		zap.Int("links", len(progs.links)),
	)
	return nil
}

// closeProgramsLinux detaches and closes all eBPF programs and maps.
func (c *EBPFCollector) closeProgramsLinux() {
	if programs == nil {
		return
	}

	for _, l := range programs.links {
		if err := l.Close(); err != nil {
			c.logger.Debug("Failed to close BPF link", zap.Error(err))
		}
	}

	closeMaps(
		programs.syscallStats,
		programs.tcpStats,
		programs.udpStats,
		programs.fileioStats,
		programs.schedStats,
		programs.memStats,
		programs.tcpstateStats,
	)

	programs = nil
	c.logger.Debug("eBPF programs closed")
}

// closeMaps closes a list of eBPF maps, ignoring nil entries.
func closeMaps(maps ...*ebpf.Map) {
	for _, m := range maps {
		if m != nil {
			m.Close()
		}
	}
}

// loadSyscallPrograms loads syscall tracepoint programs.
// Placeholder: will be populated when bpf2go generates the loader.
func (c *EBPFCollector) loadSyscallPrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading syscall BPF programs")
	// TODO(phase3): Load bpf2go-generated syscalls objects
	// TODO(phase3): Attach to tracepoint/raw_syscalls/sys_enter + sys_exit
	return nil
}

// loadNetworkPrograms loads network kprobe programs.
func (c *EBPFCollector) loadNetworkPrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading network BPF programs")
	// TODO(phase3): Load bpf2go-generated network objects
	// TODO(phase3): Attach kprobes to tcp_connect, tcp_sendmsg, etc.
	return nil
}

// loadFileIOPrograms loads file I/O kprobe programs.
func (c *EBPFCollector) loadFileIOPrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading file I/O BPF programs")
	// TODO(phase3): Load bpf2go-generated fileio objects
	// TODO(phase3): Attach kprobes to vfs_read, vfs_write, vfs_open
	return nil
}

// loadSchedulerPrograms loads scheduler tracepoint programs.
func (c *EBPFCollector) loadSchedulerPrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading scheduler BPF programs")
	// TODO(phase3): Load bpf2go-generated scheduler objects
	// TODO(phase3): Attach to tracepoint/sched/sched_switch
	return nil
}

// loadMemoryPrograms loads memory tracepoint programs.
func (c *EBPFCollector) loadMemoryPrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading memory BPF programs")
	// TODO(phase3): Load bpf2go-generated memory objects
	// TODO(phase3): Attach to tracepoint/exceptions/page_fault_user + kernel
	return nil
}

// loadTCPStatePrograms loads TCP state tracepoint programs.
func (c *EBPFCollector) loadTCPStatePrograms(progs *bpfPrograms) error {
	c.logger.Debug("Loading TCP state BPF programs")
	// TODO(phase3): Load bpf2go-generated tcpstate objects
	// TODO(phase3): Attach to tracepoint/sock/inet_sock_set_state
	return nil
}
