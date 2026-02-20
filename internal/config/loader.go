package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Loader handles configuration loading from multiple sources
type Loader struct {
	configPaths []string
	envPrefix   string
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{
		configPaths: []string{
			".",
			"./configs",
			"/etc/tfo-agent",
			"$HOME/.tfo-agent",
		},
		envPrefix: "TFAGENT",
	}
}

// WithConfigPaths replaces the default config search paths
func (l *Loader) WithConfigPaths(paths ...string) *Loader {
	l.configPaths = paths
	return l
}

// WithEnvPrefix sets the environment variable prefix
func (l *Loader) WithEnvPrefix(prefix string) *Loader {
	l.envPrefix = prefix
	return l
}

// Load loads the configuration from file and environment
func (l *Loader) Load(configFile string) (*Config, error) {
	v := viper.New()

	// Set defaults
	l.setDefaults(v)

	// Configure file search
	v.SetConfigName("tfo-agent")
	v.SetConfigType("yaml")

	// Add config paths
	for _, path := range l.configPaths {
		expandedPath := os.ExpandEnv(path)
		v.AddConfigPath(expandedPath)
	}

	// If explicit config file provided, use it
	if configFile != "" {
		v.SetConfigFile(configFile)
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults + env
	}

	// Configure environment variables
	v.SetEnvPrefix(l.envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Bind environment variables explicitly for nested configs
	l.bindEnvVars(v)

	// Unmarshal into config struct
	cfg := DefaultConfig()
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Auto-detect hostname if not set
	if cfg.Agent.Hostname == "" {
		hostname, err := os.Hostname()
		if err == nil {
			cfg.Agent.Hostname = hostname
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// LoadFromFile loads configuration from a specific file
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %w", err)
	}
	return l.Load(absPath)
}

// setDefaults sets default values in viper
func (l *Loader) setDefaults(v *viper.Viper) {
	defaults := DefaultConfig()

	// TelemetryFlow
	v.SetDefault("telemetryflow.endpoint", defaults.TelemetryFlow.Endpoint)
	v.SetDefault("telemetryflow.protocol", defaults.TelemetryFlow.Protocol)
	v.SetDefault("telemetryflow.timeout", defaults.TelemetryFlow.Timeout)
	v.SetDefault("telemetryflow.tls.enabled", defaults.TelemetryFlow.TLS.Enabled)
	v.SetDefault("telemetryflow.tls.skip_verify", defaults.TelemetryFlow.TLS.SkipVerify)
	v.SetDefault("telemetryflow.retry.enabled", defaults.TelemetryFlow.Retry.Enabled)
	v.SetDefault("telemetryflow.retry.max_attempts", defaults.TelemetryFlow.Retry.MaxAttempts)
	v.SetDefault("telemetryflow.retry.initial_interval", defaults.TelemetryFlow.Retry.InitialInterval)
	v.SetDefault("telemetryflow.retry.max_interval", defaults.TelemetryFlow.Retry.MaxInterval)

	// Agent
	v.SetDefault("agent.id", defaults.Agent.ID)
	v.SetDefault("agent.hostname", defaults.Agent.Hostname)

	// API
	v.SetDefault("api.endpoint", defaults.API.Endpoint)
	v.SetDefault("api.timeout", defaults.API.Timeout)
	v.SetDefault("api.retry_attempts", defaults.API.RetryAttempts)
	v.SetDefault("api.retry_delay", defaults.API.RetryDelay)
	v.SetDefault("api.tls.enabled", defaults.API.TLS.Enabled)
	v.SetDefault("api.tls.skip_verify", defaults.API.TLS.SkipVerify)

	// Heartbeat
	v.SetDefault("heartbeat.interval", defaults.Heartbeat.Interval)
	v.SetDefault("heartbeat.timeout", defaults.Heartbeat.Timeout)
	v.SetDefault("heartbeat.include_system_info", defaults.Heartbeat.IncludeSystemInfo)

	// Collectors
	v.SetDefault("collectors.system.enabled", defaults.Collector.System.Enabled)
	v.SetDefault("collectors.system.interval", defaults.Collector.System.Interval)
	v.SetDefault("collectors.system.cpu", defaults.Collector.System.CPU)
	v.SetDefault("collectors.system.memory", defaults.Collector.System.Memory)
	v.SetDefault("collectors.system.disk", defaults.Collector.System.Disk)
	v.SetDefault("collectors.system.network", defaults.Collector.System.Network)
	v.SetDefault("collectors.logs.enabled", defaults.Collector.Logs.Enabled)
	v.SetDefault("collectors.process.enabled", defaults.Collector.Process.Enabled)
	v.SetDefault("collectors.process.interval", defaults.Collector.Process.Interval)

	// Kubernetes collector
	v.SetDefault("collectors.kubernetes.enabled", defaults.Collector.Kubernetes.Enabled)
	v.SetDefault("collectors.kubernetes.interval", defaults.Collector.Kubernetes.Interval)
	v.SetDefault("collectors.kubernetes.nodes", defaults.Collector.Kubernetes.Nodes)
	v.SetDefault("collectors.kubernetes.pods", defaults.Collector.Kubernetes.Pods)
	v.SetDefault("collectors.kubernetes.deployments", defaults.Collector.Kubernetes.Deployments)
	v.SetDefault("collectors.kubernetes.namespaces_collect", defaults.Collector.Kubernetes.NamespacesCollect)
	v.SetDefault("collectors.kubernetes.storage", defaults.Collector.Kubernetes.Storage)
	v.SetDefault("collectors.kubernetes.services", defaults.Collector.Kubernetes.Services)
	v.SetDefault("collectors.kubernetes.workloads", defaults.Collector.Kubernetes.Workloads)
	v.SetDefault("collectors.kubernetes.metrics_api", defaults.Collector.Kubernetes.MetricsAPI)
	v.SetDefault("collectors.kubernetes.sync_to_backend", defaults.Collector.Kubernetes.SyncToBackend)
	v.SetDefault("collectors.kubernetes.sync_interval", defaults.Collector.Kubernetes.SyncInterval)

	// Node Exporter collector
	v.SetDefault("collectors.node_exporter.enabled", defaults.Collector.NodeExporter.Enabled)
	v.SetDefault("collectors.node_exporter.interval", defaults.Collector.NodeExporter.Interval)
	v.SetDefault("collectors.node_exporter.cpu", defaults.Collector.NodeExporter.CPU)
	v.SetDefault("collectors.node_exporter.memory", defaults.Collector.NodeExporter.Memory)
	v.SetDefault("collectors.node_exporter.diskio", defaults.Collector.NodeExporter.DiskIO)
	v.SetDefault("collectors.node_exporter.filesystem", defaults.Collector.NodeExporter.Filesystem)
	v.SetDefault("collectors.node_exporter.network", defaults.Collector.NodeExporter.Network)
	v.SetDefault("collectors.node_exporter.loadavg", defaults.Collector.NodeExporter.LoadAvg)
	v.SetDefault("collectors.node_exporter.thermal", defaults.Collector.NodeExporter.Thermal)
	v.SetDefault("collectors.node_exporter.textfile", defaults.Collector.NodeExporter.Textfile)
	v.SetDefault("collectors.node_exporter.conntrack", defaults.Collector.NodeExporter.Conntrack)
	v.SetDefault("collectors.node_exporter.psi", defaults.Collector.NodeExporter.PSI)
	v.SetDefault("collectors.node_exporter.vmstat", defaults.Collector.NodeExporter.VMStat)
	v.SetDefault("collectors.node_exporter.sockstat", defaults.Collector.NodeExporter.Sockstat)
	v.SetDefault("collectors.node_exporter.entropy", defaults.Collector.NodeExporter.Entropy)
	v.SetDefault("collectors.node_exporter.filedesc", defaults.Collector.NodeExporter.FileDesc)
	v.SetDefault("collectors.node_exporter.stat", defaults.Collector.NodeExporter.Stat)
	v.SetDefault("collectors.node_exporter.filesystem_mount_exclude", defaults.Collector.NodeExporter.FilesystemMountExclude)
	v.SetDefault("collectors.node_exporter.filesystem_type_exclude", defaults.Collector.NodeExporter.FilesystemTypeExclude)
	v.SetDefault("collectors.node_exporter.network_device_exclude", defaults.Collector.NodeExporter.NetworkDeviceExclude)
	v.SetDefault("collectors.node_exporter.disk_device_exclude", defaults.Collector.NodeExporter.DiskDeviceExclude)
	v.SetDefault("collectors.node_exporter.textfile_path", defaults.Collector.NodeExporter.TextfilePath)

	// eBPF collector
	v.SetDefault("collectors.ebpf.enabled", defaults.Collector.EBPF.Enabled)
	v.SetDefault("collectors.ebpf.interval", defaults.Collector.EBPF.Interval)
	v.SetDefault("collectors.ebpf.collect_syscalls", defaults.Collector.EBPF.CollectSyscalls)
	v.SetDefault("collectors.ebpf.collect_network", defaults.Collector.EBPF.CollectNetwork)
	v.SetDefault("collectors.ebpf.collect_file_io", defaults.Collector.EBPF.CollectFileIO)
	v.SetDefault("collectors.ebpf.collect_scheduler", defaults.Collector.EBPF.CollectScheduler)
	v.SetDefault("collectors.ebpf.collect_memory", defaults.Collector.EBPF.CollectMemory)
	v.SetDefault("collectors.ebpf.collect_tcp_events", defaults.Collector.EBPF.CollectTCPEvents)
	v.SetDefault("collectors.ebpf.sample_rate", defaults.Collector.EBPF.SampleRate)
	v.SetDefault("collectors.ebpf.ring_buffer_size", defaults.Collector.EBPF.RingBufferSize)
	v.SetDefault("collectors.ebpf.perf_buffer_size", defaults.Collector.EBPF.PerfBufferSize)
	v.SetDefault("collectors.ebpf.pin_path", defaults.Collector.EBPF.PinPath)
	v.SetDefault("collectors.ebpf.cilium.enabled", defaults.Collector.EBPF.Cilium.Enabled)
	v.SetDefault("collectors.ebpf.cilium.hubble_address", defaults.Collector.EBPF.Cilium.HubbleAddress)

	// Prometheus server
	v.SetDefault("prometheus_server.enabled", defaults.PrometheusServer.Enabled)
	v.SetDefault("prometheus_server.port", defaults.PrometheusServer.Port)
	v.SetDefault("prometheus_server.path", defaults.PrometheusServer.Path)
	v.SetDefault("prometheus_server.include_go_metrics", defaults.PrometheusServer.IncludeGoMetrics)
	v.SetDefault("prometheus_server.include_process_metrics", defaults.PrometheusServer.IncludeProcessMetrics)
	v.SetDefault("prometheus_server.metric_prefix", defaults.PrometheusServer.MetricPrefix)
	v.SetDefault("prometheus_server.read_timeout", defaults.PrometheusServer.ReadTimeout)
	v.SetDefault("prometheus_server.write_timeout", defaults.PrometheusServer.WriteTimeout)

	// Exporter
	v.SetDefault("exporter.otlp.enabled", defaults.Exporter.OTLP.Enabled)
	v.SetDefault("exporter.otlp.batch_size", defaults.Exporter.OTLP.BatchSize)
	v.SetDefault("exporter.otlp.flush_interval", defaults.Exporter.OTLP.FlushInterval)
	v.SetDefault("exporter.otlp.compression", defaults.Exporter.OTLP.Compression)
	v.SetDefault("exporter.otlp.metrics_endpoint", defaults.Exporter.OTLP.MetricsEndpoint)
	v.SetDefault("exporter.otlp.logs_endpoint", defaults.Exporter.OTLP.LogsEndpoint)

	// Buffer
	v.SetDefault("buffer.enabled", defaults.Buffer.Enabled)
	v.SetDefault("buffer.max_size_mb", defaults.Buffer.MaxSizeMB)
	v.SetDefault("buffer.path", defaults.Buffer.Path)
	v.SetDefault("buffer.flush_interval", defaults.Buffer.FlushInterval)

	// Logging
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("logging.max_size_mb", defaults.Logging.MaxSizeMB)
	v.SetDefault("logging.max_backups", defaults.Logging.MaxBackups)
	v.SetDefault("logging.max_age_days", defaults.Logging.MaxAgeDays)
}

// bindEnvVars explicitly binds environment variables
func (l *Loader) bindEnvVars(v *viper.Viper) {
	// Critical env vars that need explicit binding
	envBindings := map[string]string{
		// TelemetryFlow
		"telemetryflow.endpoint":       "TELEMETRYFLOW_ENDPOINT",
		"telemetryflow.protocol":       "TELEMETRYFLOW_PROTOCOL",
		"telemetryflow.api_key_id":     "TELEMETRYFLOW_API_KEY_ID",
		"telemetryflow.api_key_secret": "TELEMETRYFLOW_API_KEY_SECRET",

		// Agent
		"agent.id":           "TELEMETRYFLOW_ID",
		"agent.hostname":     "TELEMETRYFLOW_HOSTNAME",
		"api.endpoint":       "TELEMETRYFLOW_API_ENDPOINT",
		"api.api_key_id":     "TELEMETRYFLOW_API_KEY_ID",
		"api.api_key_secret": "TELEMETRYFLOW_API_KEY_SECRET",
		"api.workspace_id":   "TELEMETRYFLOW_WORKSPACE_ID",
		"api.tenant_id":      "TELEMETRYFLOW_TENANT_ID",
		"heartbeat.interval": "TELEMETRYFLOW_HEARTBEAT_INTERVAL",
		"logging.level":      "TELEMETRYFLOW_LOG_LEVEL",
		"logging.format":     "TELEMETRYFLOW_LOG_FORMAT",
		"buffer.path":        "TELEMETRYFLOW_BUFFER_PATH",

		// Kubernetes collector
		"collectors.kubernetes.enabled":          "TELEMETRYFLOW_K8S_ENABLED",
		"collectors.kubernetes.kubeconfig":       "TELEMETRYFLOW_K8S_KUBECONFIG",
		"collectors.kubernetes.namespaces":       "TELEMETRYFLOW_K8S_NAMESPACES",
		"collectors.kubernetes.cluster_name":     "TELEMETRYFLOW_K8S_CLUSTER_NAME",
		"collectors.kubernetes.cluster_provider": "TELEMETRYFLOW_K8S_CLUSTER_PROVIDER",

		// Node Exporter collector
		"collectors.node_exporter.enabled":       "TELEMETRYFLOW_NODE_EXPORTER_ENABLED",
		"collectors.node_exporter.textfile_path": "TELEMETRYFLOW_NODE_EXPORTER_TEXTFILE_PATH",

		// eBPF collector
		"collectors.ebpf.enabled":  "TELEMETRYFLOW_EBPF_ENABLED",
		"collectors.ebpf.btf_path": "TELEMETRYFLOW_EBPF_BTF_PATH",
		"collectors.ebpf.pin_path": "TELEMETRYFLOW_EBPF_PIN_PATH",

		// Prometheus server
		"prometheus_server.enabled": "TELEMETRYFLOW_PROMETHEUS_ENABLED",
		"prometheus_server.port":    "TELEMETRYFLOW_PROMETHEUS_PORT",
	}

	for key, env := range envBindings {
		_ = v.BindEnv(key, env)
	}
}

// GetConfigFilePath returns the path of the loaded config file
func GetConfigFilePath() string {
	return viper.ConfigFileUsed()
}
