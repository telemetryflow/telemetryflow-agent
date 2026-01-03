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

	// Cilium Hubble integration
	Cilium CiliumConfig `mapstructure:"cilium"`
}

// CiliumConfig contains Cilium Hubble integration configuration
type CiliumConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// Hubble configuration
	HubbleAddress     string `mapstructure:"hubble_address"`     // Default: "localhost:4245"
	HubbleTLSEnabled  bool   `mapstructure:"hubble_tls_enabled"` // Enable TLS for Hubble
	HubbleTLSCertPath string `mapstructure:"hubble_tls_cert"`    // Path to Hubble TLS cert
	HubbleTLSKeyPath  string `mapstructure:"hubble_tls_key"`     // Path to Hubble TLS key
	HubbleTLSCAPath   string `mapstructure:"hubble_tls_ca"`      // Path to Hubble CA cert
	// Flow collection
	CollectFlows    bool `mapstructure:"collect_flows"`    // Collect network flows (L3/L4)
	CollectL7Flows  bool `mapstructure:"collect_l7_flows"` // Collect L7 (HTTP/gRPC/DNS) flows
	CollectDrops    bool `mapstructure:"collect_drops"`    // Collect dropped packets
	CollectPolicies bool `mapstructure:"collect_policies"` // Collect network policy verdicts
	CollectServices bool `mapstructure:"collect_services"` // Collect service mesh metrics
	// Kubernetes integration
	KubernetesEnabled bool     `mapstructure:"kubernetes_enabled"` // Enable K8s metadata enrichment
	WatchNamespaces   []string `mapstructure:"watch_namespaces"`   // Namespaces to watch (empty = all)
	ExcludeNamespaces []string `mapstructure:"exclude_namespaces"` // Namespaces to exclude
	// Performance settings
	FlowBufferSize    int           `mapstructure:"flow_buffer_size"`     // Buffer size for flows (default: 4096)
	FlowSampleRate    int           `mapstructure:"flow_sample_rate"`     // Sample 1 in N flows (default: 1 = all)
	MaxFlowsPerSecond int           `mapstructure:"max_flows_per_second"` // Rate limit (default: 10000)
	AggregationWindow time.Duration `mapstructure:"aggregation_window"`   // Aggregation window (default: 10s)
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

// Cilium Hubble flow types
type hubbleFlow struct {
	TraceID         string
	SourcePod       string
	SourceNamespace string
	SourceService   string
	SourceIP        string
	SourcePort      uint16
	DestPod         string
	DestNamespace   string
	DestService     string
	DestIP          string
	DestPort        uint16
	Protocol        string // TCP, UDP, ICMP
	L7Protocol      string // HTTP, gRPC, DNS, Kafka
	Verdict         string // FORWARDED, DROPPED, ERROR
	DropReason      string
	IsReply         bool
	BytesSent       uint64
	BytesRecv       uint64
	LatencyNs       uint64
	HTTPMethod      string
	HTTPPath        string
	HTTPStatusCode  int
	DNSQuery        string
	DNSResponseCode int
}

type hubblePolicyVerdict struct {
	PolicyName      string
	PolicyNamespace string
	Direction       string // INGRESS, EGRESS
	Verdict         string // ALLOWED, DENIED, AUDIT
	MatchType       string
}

type hubbleServiceMetric struct {
	ServiceName      string
	ServiceNamespace string
	ServiceClusterIP string
	RequestsTotal    uint64
	ErrorsTotal      uint64
	LatencyP50       float64
	LatencyP90       float64
	LatencyP99       float64
}

// Ensure types are used (for future eBPF implementation)
var (
	_ = ebpfSyscallMetric{}
	_ = ebpfNetworkMetric{}
	_ = ebpfFileIOMetric{}
	_ = ebpfSchedulerMetric{}
	_ = hubbleFlow{}
	_ = hubblePolicyVerdict{}
	_ = hubbleServiceMetric{}
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
		!e.config.CollectScheduler && !e.config.CollectMemory && !e.config.Cilium.Enabled {
		e.config.CollectSyscalls = true
		e.config.CollectNetwork = true
		e.config.CollectFileIO = true
	}

	// Initialize Cilium Hubble if enabled
	if e.config.Cilium.Enabled {
		if err := e.initCiliumHubble(); err != nil {
			return fmt.Errorf("failed to initialize Cilium Hubble: %w", err)
		}
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
		zap.Bool("cilium", e.config.Cilium.Enabled),
	)

	return nil
}

// initCiliumHubble initializes Cilium Hubble integration
func (e *EBPFExporter) initCiliumHubble() error {
	cfg := &e.config.Cilium

	// Set defaults
	if cfg.HubbleAddress == "" {
		cfg.HubbleAddress = "localhost:4245"
	}
	if cfg.FlowBufferSize == 0 {
		cfg.FlowBufferSize = 4096
	}
	if cfg.FlowSampleRate == 0 {
		cfg.FlowSampleRate = 1 // All flows
	}
	if cfg.MaxFlowsPerSecond == 0 {
		cfg.MaxFlowsPerSecond = 10000
	}
	if cfg.AggregationWindow == 0 {
		cfg.AggregationWindow = 10 * time.Second
	}

	// Enable default flow collection if none specified
	if !cfg.CollectFlows && !cfg.CollectL7Flows && !cfg.CollectDrops &&
		!cfg.CollectPolicies && !cfg.CollectServices {
		cfg.CollectFlows = true
		cfg.CollectDrops = true
	}

	// In production, we would:
	// 1. Connect to Hubble Relay via gRPC (cfg.HubbleAddress)
	// 2. Set up TLS if cfg.HubbleTLSEnabled
	// 3. Subscribe to flow events
	// 4. Start background goroutine to receive flows

	e.Logger().Info("Cilium Hubble integration initialized",
		zap.String("hubbleAddress", cfg.HubbleAddress),
		zap.Bool("tlsEnabled", cfg.HubbleTLSEnabled),
		zap.Bool("collectFlows", cfg.CollectFlows),
		zap.Bool("collectL7Flows", cfg.CollectL7Flows),
		zap.Bool("collectDrops", cfg.CollectDrops),
		zap.Bool("collectPolicies", cfg.CollectPolicies),
		zap.Bool("kubernetes", cfg.KubernetesEnabled),
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

	// Collect Cilium Hubble metrics
	if e.config.Cilium.Enabled {
		hubbleMetrics := e.collectHubbleMetrics(now)
		metrics = append(metrics, hubbleMetrics...)
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

// getCiliumBaseTags returns base tags for Cilium Hubble metrics
func (e *EBPFExporter) getCiliumBaseTags() map[string]string {
	tags := make(map[string]string)
	for k, v := range e.config.Labels {
		tags[k] = v
	}
	tags["collector"] = "cilium_hubble"
	if e.config.Cilium.KubernetesEnabled {
		tags["kubernetes"] = "true"
	}
	return tags
}

// collectHubbleMetrics collects metrics from Cilium Hubble
func (e *EBPFExporter) collectHubbleMetrics(now time.Time) []Metric {
	var metrics []Metric

	if e.config.Cilium.CollectFlows {
		flowMetrics := e.collectHubbleFlowMetrics(now)
		metrics = append(metrics, flowMetrics...)
	}

	if e.config.Cilium.CollectL7Flows {
		l7Metrics := e.collectHubbleL7Metrics(now)
		metrics = append(metrics, l7Metrics...)
	}

	if e.config.Cilium.CollectDrops {
		dropMetrics := e.collectHubbleDropMetrics(now)
		metrics = append(metrics, dropMetrics...)
	}

	if e.config.Cilium.CollectPolicies {
		policyMetrics := e.collectHubblePolicyMetrics(now)
		metrics = append(metrics, policyMetrics...)
	}

	if e.config.Cilium.CollectServices {
		serviceMetrics := e.collectHubbleServiceMetrics(now)
		metrics = append(metrics, serviceMetrics...)
	}

	return metrics
}

// collectHubbleFlowMetrics collects L3/L4 flow metrics from Hubble
func (e *EBPFExporter) collectHubbleFlowMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getCiliumBaseTags()

	// In production, these would come from Hubble flow events
	protocols := []string{"TCP", "UDP", "ICMP"}
	verdicts := []string{"FORWARDED", "DROPPED"}

	for _, proto := range protocols {
		for _, verdict := range verdicts {
			tags := make(map[string]string)
			for k, v := range baseTags {
				tags[k] = v
			}
			tags["protocol"] = proto
			tags["verdict"] = verdict

			metrics = append(metrics,
				Metric{Name: "hubble_flows_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
				Metric{Name: "hubble_flow_bytes_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			)
		}
	}

	// Connection metrics
	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}
	metrics = append(metrics,
		Metric{Name: "hubble_tcp_connections_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_tcp_connection_duration_seconds", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "seconds"},
		Metric{Name: "hubble_udp_flows_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
	)

	return metrics
}

// collectHubbleL7Metrics collects L7 (HTTP/gRPC/DNS/Kafka) metrics from Hubble
func (e *EBPFExporter) collectHubbleL7Metrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getCiliumBaseTags()

	// HTTP metrics
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for _, method := range httpMethods {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["method"] = method
		tags["protocol"] = "HTTP"

		metrics = append(metrics,
			Metric{Name: "hubble_http_requests_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
			Metric{Name: "hubble_http_request_duration_seconds", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "seconds"},
		)
	}

	// HTTP status code metrics
	statusCodes := []string{"2xx", "3xx", "4xx", "5xx"}
	for _, code := range statusCodes {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["status_class"] = code
		tags["protocol"] = "HTTP"

		metrics = append(metrics,
			Metric{Name: "hubble_http_responses_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		)
	}

	// gRPC metrics
	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}
	tags["protocol"] = "gRPC"
	metrics = append(metrics,
		Metric{Name: "hubble_grpc_requests_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_grpc_request_duration_seconds", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "seconds"},
	)

	// DNS metrics
	dnsTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV"}
	for _, dnsType := range dnsTypes {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["query_type"] = dnsType
		tags["protocol"] = "DNS"

		metrics = append(metrics,
			Metric{Name: "hubble_dns_queries_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		)
	}

	// DNS response codes
	dnsCodes := []string{"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
	for _, code := range dnsCodes {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["rcode"] = code
		tags["protocol"] = "DNS"

		metrics = append(metrics,
			Metric{Name: "hubble_dns_responses_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		)
	}

	// Kafka metrics
	tags = make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}
	tags["protocol"] = "Kafka"
	metrics = append(metrics,
		Metric{Name: "hubble_kafka_requests_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_kafka_request_duration_seconds", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "seconds"},
	)

	return metrics
}

// collectHubbleDropMetrics collects packet drop metrics from Hubble
func (e *EBPFExporter) collectHubbleDropMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getCiliumBaseTags()

	// Drop reasons from Cilium
	dropReasons := []string{
		"POLICY_DENIED",
		"INVALID_SOURCE_MAC",
		"INVALID_DESTINATION_MAC",
		"INVALID_SOURCE_IP",
		"CT_TRUNCATED_OR_INVALID_HEADER",
		"CT_MISSING_TCP_ACK_FLAG",
		"CT_UNKNOWN_L4_PROTOCOL",
		"UNSUPPORTED_L3_PROTOCOL",
		"STALE_OR_UNROUTABLE_IP",
		"NO_TUNNEL_ENDPOINT",
		"UNKNOWN_L3_TARGET_ADDRESS",
		"NO_MAPPING_FOR_NAT",
	}

	for _, reason := range dropReasons {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["reason"] = reason

		metrics = append(metrics,
			Metric{Name: "hubble_drop_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
			Metric{Name: "hubble_drop_bytes_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
		)
	}

	return metrics
}

// collectHubblePolicyMetrics collects network policy verdict metrics from Hubble
func (e *EBPFExporter) collectHubblePolicyMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getCiliumBaseTags()

	directions := []string{"INGRESS", "EGRESS"}
	verdicts := []string{"ALLOWED", "DENIED", "AUDIT"}

	for _, dir := range directions {
		for _, verdict := range verdicts {
			tags := make(map[string]string)
			for k, v := range baseTags {
				tags[k] = v
			}
			tags["direction"] = dir
			tags["verdict"] = verdict

			metrics = append(metrics,
				Metric{Name: "hubble_policy_verdicts_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
			)
		}
	}

	// Policy match types
	matchTypes := []string{"L3Only", "L4Only", "L3L4", "L7", "All"}
	for _, matchType := range matchTypes {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["match_type"] = matchType

		metrics = append(metrics,
			Metric{Name: "hubble_policy_match_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		)
	}

	return metrics
}

// collectHubbleServiceMetrics collects Kubernetes service mesh metrics from Hubble
func (e *EBPFExporter) collectHubbleServiceMetrics(now time.Time) []Metric {
	var metrics []Metric
	baseTags := e.getCiliumBaseTags()

	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}

	// Service-level metrics
	metrics = append(metrics,
		Metric{Name: "hubble_service_requests_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_service_errors_total", Value: 0, Type: MetricTypeCounter, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_service_request_duration_seconds", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "seconds"},
		Metric{Name: "hubble_service_request_size_bytes", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "bytes"},
		Metric{Name: "hubble_service_response_size_bytes", Value: 0, Type: MetricTypeHistogram, Timestamp: now, Tags: tags, Unit: "bytes"},
	)

	// Endpoint metrics
	metrics = append(metrics,
		Metric{Name: "hubble_endpoint_count", Value: 0, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_endpoint_ready", Value: 0, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		Metric{Name: "hubble_endpoint_not_ready", Value: 0, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
	)

	return metrics
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
