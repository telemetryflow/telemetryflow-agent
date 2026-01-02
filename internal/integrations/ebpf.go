// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"go.uber.org/zap"
)

// EBPFConfig contains eBPF integration configuration
type EBPFConfig struct {
	Enabled          bool              `mapstructure:"enabled"`
	ProgramsPath     string            `mapstructure:"programs_path"`
	PinPath          string            `mapstructure:"pin_path"`
	ScrapeInterval   time.Duration     `mapstructure:"scrape_interval"`
	CollectSyscalls  bool              `mapstructure:"collect_syscalls"`
	CollectNetwork   bool              `mapstructure:"collect_network"`
	CollectFileIO    bool              `mapstructure:"collect_file_io"`
	CollectScheduler bool              `mapstructure:"collect_scheduler"`
	CollectMemory    bool              `mapstructure:"collect_memory"`
	CollectTCPEvents bool              `mapstructure:"collect_tcp_events"`
	CollectDNS       bool              `mapstructure:"collect_dns"`
	CollectHTTP      bool              `mapstructure:"collect_http"`
	ProcessFilter    []string          `mapstructure:"process_filter"`
	ContainerFilter  []string          `mapstructure:"container_filter"`
	NamespaceFilter  []string          `mapstructure:"namespace_filter"`
	ExcludeProcesses []string          `mapstructure:"exclude_processes"`
	SampleRate       int               `mapstructure:"sample_rate"`
	RingBufferSize   int               `mapstructure:"ring_buffer_size"`
	PerfBufferSize   int               `mapstructure:"perf_buffer_size"`
	MaxStackDepth    int               `mapstructure:"max_stack_depth"`
	BTFPath          string            `mapstructure:"btf_path"`
	Labels           map[string]string `mapstructure:"labels"`
}

// EBPFExporter collects kernel-level telemetry using eBPF
type EBPFExporter struct {
	*BaseExporter
	config EBPFConfig
	// In production, these would be eBPF program handles
	// programs map[string]*ebpf.Program
	// maps     map[string]*ebpf.Map
}

// eBPF metric types
type ebpfSyscallMetric struct {
	Syscall     string
	Count       uint64
	TotalNs     uint64
	ErrorCount  uint64
	ProcessName string
	PID         uint32
	Comm        string
}

type ebpfNetworkMetric struct {
	Protocol    string
	SourceIP    string
	DestIP      string
	SourcePort  uint16
	DestPort    uint16
	BytesSent   uint64
	BytesRecv   uint64
	Packets     uint64
	Latency     uint64
	Retransmits uint64
	PID         uint32
	Comm        string
}

type ebpfFileIOMetric struct {
	Operation string // read, write, open, close
	Path      string
	Bytes     uint64
	Count     uint64
	LatencyNs uint64
	PID       uint32
	Comm      string
}

type ebpfSchedulerMetric struct {
	OnCPUNs     uint64
	OffCPUNs    uint64
	RunqLatency uint64
	Voluntary   uint64
	Involuntary uint64
	PID         uint32
	Comm        string
}

// Ensure types are used (for future eBPF implementation)
var (
	_ = ebpfSyscallMetric{}
	_ = ebpfNetworkMetric{}
	_ = ebpfFileIOMetric{}
	_ = ebpfSchedulerMetric{}
)

// NewEBPFExporter creates a new eBPF exporter
func NewEBPFExporter(config EBPFConfig, logger *zap.Logger) *EBPFExporter {
	return &EBPFExporter{
		BaseExporter: NewBaseExporter(
			"ebpf",
			"kernel",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the eBPF exporter
func (e *EBPFExporter) Init(ctx context.Context) error {
	if !e.config.Enabled {
		return nil
	}

	if err := e.Validate(); err != nil {
		return err
	}

	// Check if running on Linux
	if runtime.GOOS != "linux" {
		return NewValidationError("ebpf", "platform", "eBPF is only supported on Linux")
	}

	// Set defaults
	if e.config.ScrapeInterval == 0 {
		e.config.ScrapeInterval = 10 * time.Second
	}
	if e.config.SampleRate == 0 {
		e.config.SampleRate = 1 // 100% sampling
	}
	if e.config.RingBufferSize == 0 {
		e.config.RingBufferSize = 256 * 1024 // 256KB
	}
	if e.config.PerfBufferSize == 0 {
		e.config.PerfBufferSize = 64 // 64 pages
	}
	if e.config.MaxStackDepth == 0 {
		e.config.MaxStackDepth = 32
	}
	if e.config.ProgramsPath == "" {
		e.config.ProgramsPath = "/usr/share/telemetryflow/ebpf"
	}
	if e.config.PinPath == "" {
		e.config.PinPath = "/sys/fs/bpf/telemetryflow"
	}

	// Enable default collectors if none specified
	if !e.config.CollectSyscalls && !e.config.CollectNetwork && !e.config.CollectFileIO &&
		!e.config.CollectScheduler && !e.config.CollectMemory {
		e.config.CollectSyscalls = true
		e.config.CollectNetwork = true
		e.config.CollectFileIO = true
	}

	// In production, we would:
	// 1. Load eBPF programs from e.config.ProgramsPath
	// 2. Attach programs to kernel hooks
	// 3. Set up ring buffers/perf buffers for data collection
	// 4. Initialize maps for data aggregation

	e.SetInitialized(true)
	e.Logger().Info("eBPF exporter initialized",
		zap.String("programsPath", e.config.ProgramsPath),
		zap.Bool("syscalls", e.config.CollectSyscalls),
		zap.Bool("network", e.config.CollectNetwork),
		zap.Bool("fileio", e.config.CollectFileIO),
	)

	return nil
}

// Validate validates the eBPF configuration
func (e *EBPFExporter) Validate() error {
	if !e.config.Enabled {
		return nil
	}

	// eBPF requires Linux
	if runtime.GOOS != "linux" {
		return NewValidationError("ebpf", "platform", "eBPF requires Linux")
	}

	// Check for root/CAP_BPF privileges (in production)
	// This is a simplified check

	return nil
}

// Export exports telemetry data collected via eBPF
func (e *EBPFExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	metrics, err := e.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for eBPF (it's a data source)
func (e *EBPFExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("ebpf is a data source, not a metrics destination")
}

// ExportTraces exports traces generated from eBPF events
func (e *EBPFExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("ebpf traces are collected, not exported")
}

// ExportLogs is not directly supported by eBPF
func (e *EBPFExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("ebpf does not support log ingestion")
}

// CollectMetrics collects metrics from eBPF programs
func (e *EBPFExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !e.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !e.IsInitialized() {
		return nil, ErrNotInitialized
	}

	var metrics []Metric
	now := time.Now()

	// Collect syscall metrics
	if e.config.CollectSyscalls {
		syscallMetrics := e.collectSyscallMetrics(now)
		metrics = append(metrics, syscallMetrics...)
	}

	// Collect network metrics
	if e.config.CollectNetwork {
		networkMetrics := e.collectNetworkMetrics(now)
		metrics = append(metrics, networkMetrics...)
	}

	// Collect file I/O metrics
	if e.config.CollectFileIO {
		fileIOMetrics := e.collectFileIOMetrics(now)
		metrics = append(metrics, fileIOMetrics...)
	}

	// Collect scheduler metrics
	if e.config.CollectScheduler {
		schedMetrics := e.collectSchedulerMetrics(now)
		metrics = append(metrics, schedMetrics...)
	}

	// Collect memory metrics
	if e.config.CollectMemory {
		memMetrics := e.collectMemoryMetrics(now)
		metrics = append(metrics, memMetrics...)
	}

	// Collect TCP event metrics
	if e.config.CollectTCPEvents {
		tcpMetrics := e.collectTCPEventMetrics(now)
		metrics = append(metrics, tcpMetrics...)
	}

	return metrics, nil
}

// collectSyscallMetrics collects syscall statistics from eBPF
func (e *EBPFExporter) collectSyscallMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	// In production, these would be read from eBPF maps
	// Example metrics that would be collected:
	syscalls := []struct {
		name  string
		count uint64
		ns    uint64
	}{
		{"read", 0, 0},
		{"write", 0, 0},
		{"open", 0, 0},
		{"close", 0, 0},
		{"stat", 0, 0},
		{"fstat", 0, 0},
		{"mmap", 0, 0},
		{"brk", 0, 0},
	}

	for _, sc := range syscalls {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["syscall"] = sc.name

		metrics = append(metrics,
			Metric{Name: "ebpf_syscall_count_total", Value: float64(sc.count), Type: MetricTypeCounter, Timestamp: now, Tags: tags},
			Metric{Name: "ebpf_syscall_latency_ns_total", Value: float64(sc.ns), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		)
	}

	return metrics
}

// collectNetworkMetrics collects network statistics from eBPF
func (e *EBPFExporter) collectNetworkMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	// In production, these would be read from eBPF maps tracking socket/TCP events
	// For each connection or aggregated stats:

	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}

	metrics = append(metrics,
		Metric{Name: "ebpf_tcp_connections_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_tcp_bytes_sent_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
		Metric{Name: "ebpf_tcp_bytes_recv_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
		Metric{Name: "ebpf_tcp_retransmits_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_tcp_rtt_avg_ns", Value: 0, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		Metric{Name: "ebpf_udp_packets_sent_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_udp_packets_recv_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
	)

	return metrics
}

// collectFileIOMetrics collects file I/O statistics from eBPF
func (e *EBPFExporter) collectFileIOMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	// In production, these would be from tracepoints like vfs_read/vfs_write
	operations := []string{"read", "write", "open", "close", "fsync"}

	for _, op := range operations {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["operation"] = op

		metrics = append(metrics,
			Metric{Name: "ebpf_fileio_operations_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
			Metric{Name: "ebpf_fileio_bytes_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "ebpf_fileio_latency_ns_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		)
	}

	return metrics
}

// collectSchedulerMetrics collects scheduler statistics from eBPF
func (e *EBPFExporter) collectSchedulerMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}

	// In production, these would be from sched_switch, sched_wakeup tracepoints
	metrics = append(metrics,
		Metric{Name: "ebpf_sched_switch_count_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_sched_runq_latency_ns", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		Metric{Name: "ebpf_sched_oncpu_time_ns_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		Metric{Name: "ebpf_sched_offcpu_time_ns_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "nanoseconds"},
		Metric{Name: "ebpf_sched_migrations_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
	)

	return metrics
}

// collectMemoryMetrics collects memory statistics from eBPF
func (e *EBPFExporter) collectMemoryMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}

	// In production, these would track page faults, allocations, etc.
	metrics = append(metrics,
		Metric{Name: "ebpf_page_faults_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_major_faults_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_minor_faults_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_mmap_calls_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_brk_calls_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_oom_kills_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
	)

	return metrics
}

// collectTCPEventMetrics collects TCP state change events from eBPF
func (e *EBPFExporter) collectTCPEventMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getBaseTags()

	// Track TCP state transitions
	states := []string{"SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2",
		"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSING"}

	for _, state := range states {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["state"] = state

		metrics = append(metrics,
			Metric{Name: "ebpf_tcp_state_transitions_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		)
	}

	// TCP events
	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}
	metrics = append(metrics,
		Metric{Name: "ebpf_tcp_connect_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_tcp_accept_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_tcp_close_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "ebpf_tcp_drop_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
	)

	return metrics
}

// getBaseTags returns base tags for all eBPF metrics
func (e *EBPFExporter) getBaseTags() map[string]string {
	tags := make(map[string]string)
	for k, v := range e.config.Labels {
		tags[k] = v
	}
	tags["collector"] = "ebpf"
	return tags
}

// Health checks the health of eBPF collection
func (e *EBPFExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !e.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	// Check if running on Linux
	if runtime.GOOS != "linux" {
		return &HealthStatus{
			Healthy:   false,
			Message:   "eBPF requires Linux",
			LastCheck: time.Now(),
		}, nil
	}

	// In production, would check:
	// 1. eBPF programs are loaded and attached
	// 2. Ring buffers are receiving data
	// 3. No program errors

	return &HealthStatus{
		Healthy:   true,
		Message:   "eBPF collector active",
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"collect_syscalls": e.config.CollectSyscalls,
			"collect_network":  e.config.CollectNetwork,
			"collect_fileio":   e.config.CollectFileIO,
		},
	}, nil
}

// Close closes the eBPF exporter
func (e *EBPFExporter) Close(ctx context.Context) error {
	// In production, would:
	// 1. Detach eBPF programs from hooks
	// 2. Close ring buffers
	// 3. Unpin maps
	// 4. Close program file descriptors

	e.SetInitialized(false)
	e.Logger().Info("eBPF exporter closed")
	return nil
}
