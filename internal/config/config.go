// Package config provides configuration management for the TelemetryFlow agent.
package config

import (
	"time"
)

// Config represents the complete agent configuration
type Config struct {
	TelemetryFlow TelemetryFlowConfig `mapstructure:"telemetryflow"`
	Agent         AgentConfig         `mapstructure:"agent"`
	Heartbeat     HeartbeatConfig     `mapstructure:"heartbeat"`
	Collector     CollectorConfig     `mapstructure:"collectors"`
	Exporter      ExporterConfig      `mapstructure:"exporter"`
	Buffer        BufferConfig        `mapstructure:"buffer"`
	Logging       LoggingConfig       `mapstructure:"logging"`

	// Deprecated: Use TelemetryFlow instead. Kept for backward compatibility.
	API APIConfig `mapstructure:"api"`
}

// TelemetryFlowConfig contains TelemetryFlow backend connection settings
type TelemetryFlowConfig struct {
	// APIKeyID is the API key identifier (format: tfk_xxx)
	APIKeyID string `mapstructure:"api_key_id"`

	// APIKeySecret is the API key secret (format: tfs_xxx)
	APIKeySecret string `mapstructure:"api_key_secret"`

	// Endpoint is the TelemetryFlow backend endpoint (host:port)
	Endpoint string `mapstructure:"endpoint"`

	// Protocol is the transport protocol (grpc or http)
	Protocol string `mapstructure:"protocol"`

	// TLS contains TLS/SSL settings
	TLS TLSConfig `mapstructure:"tls"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// Retry contains retry settings
	Retry RetryConfig `mapstructure:"retry"`
}

// RetryConfig contains retry settings
type RetryConfig struct {
	// Enabled enables retry logic
	Enabled bool `mapstructure:"enabled"`

	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int `mapstructure:"max_attempts"`

	// InitialInterval is the initial delay between retries
	InitialInterval time.Duration `mapstructure:"initial_interval"`

	// MaxInterval is the maximum delay between retries
	MaxInterval time.Duration `mapstructure:"max_interval"`
}

// AgentConfig contains agent identification settings
type AgentConfig struct {
	// ID is the unique agent identifier (auto-generated if empty)
	ID string `mapstructure:"id"`

	// Hostname is the agent hostname (auto-detected if empty)
	Hostname string `mapstructure:"hostname"`

	// Name is the human-readable agent name
	Name string `mapstructure:"name"`

	// Description is a human-readable description
	Description string `mapstructure:"description"`

	// Version is the agent version (auto-populated at build time)
	Version string `mapstructure:"version"`

	// Tags are custom key-value labels for the agent
	Tags map[string]string `mapstructure:"tags"`
}

// APIConfig contains backend API connection settings
type APIConfig struct {
	// Endpoint is the TelemetryFlow backend URL
	Endpoint string `mapstructure:"endpoint"`

	// APIKeyID is the API key identifier (tfk-xxx)
	APIKeyID string `mapstructure:"api_key_id"`

	// APIKeySecret is the API key secret (tfs-xxx)
	APIKeySecret string `mapstructure:"api_key_secret"`

	// WorkspaceID is the workspace identifier
	WorkspaceID string `mapstructure:"workspace_id"`

	// TenantID is the tenant/organization identifier
	TenantID string `mapstructure:"tenant_id"`

	// TLS contains TLS/SSL settings
	TLS TLSConfig `mapstructure:"tls"`

	// Timeout is the HTTP request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// RetryAttempts is the number of retry attempts for failed requests
	RetryAttempts int `mapstructure:"retry_attempts"`

	// RetryDelay is the initial delay between retries
	RetryDelay time.Duration `mapstructure:"retry_delay"`
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	// Enabled enables TLS for API connections
	Enabled bool `mapstructure:"enabled"`

	// SkipVerify skips certificate verification (insecure)
	SkipVerify bool `mapstructure:"skip_verify"`

	// CertFile is the path to client certificate
	CertFile string `mapstructure:"cert_file"`

	// KeyFile is the path to client private key
	KeyFile string `mapstructure:"key_file"`

	// CAFile is the path to CA certificate
	CAFile string `mapstructure:"ca_file"`
}

// HeartbeatConfig contains heartbeat settings
type HeartbeatConfig struct {
	// Interval is the heartbeat interval
	Interval time.Duration `mapstructure:"interval"`

	// Timeout is the heartbeat request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// IncludeSystemInfo includes system metrics in heartbeat
	IncludeSystemInfo bool `mapstructure:"include_system_info"`
}

// CollectorConfig contains all collector settings
type CollectorConfig struct {
	// System contains system metrics collector settings
	System SystemCollectorConfig `mapstructure:"system"`

	// Logs contains log collector settings
	Logs LogCollectorConfig `mapstructure:"logs"`

	// Process contains process collector settings
	Process ProcessCollectorConfig `mapstructure:"process"`
}

// SystemCollectorConfig contains system metrics collector settings
type SystemCollectorConfig struct {
	// Enabled enables the system collector
	Enabled bool `mapstructure:"enabled"`

	// Interval is the collection interval
	Interval time.Duration `mapstructure:"interval"`

	// CPU enables CPU metrics collection
	CPU bool `mapstructure:"cpu"`

	// Memory enables memory metrics collection
	Memory bool `mapstructure:"memory"`

	// Disk enables disk metrics collection
	Disk bool `mapstructure:"disk"`

	// Network enables network metrics collection
	Network bool `mapstructure:"network"`

	// DiskPaths specifies disk paths to monitor (empty = all)
	DiskPaths []string `mapstructure:"disk_paths"`
}

// LogCollectorConfig contains log collector settings
type LogCollectorConfig struct {
	// Enabled enables the log collector
	Enabled bool `mapstructure:"enabled"`

	// Paths is a list of log file paths to collect
	Paths []string `mapstructure:"paths"`

	// IncludePatterns is a list of patterns to include
	IncludePatterns []string `mapstructure:"include_patterns"`

	// ExcludePatterns is a list of patterns to exclude
	ExcludePatterns []string `mapstructure:"exclude_patterns"`
}

// ProcessCollectorConfig contains process collector settings
type ProcessCollectorConfig struct {
	// Enabled enables the process collector
	Enabled bool `mapstructure:"enabled"`

	// Interval is the collection interval
	Interval time.Duration `mapstructure:"interval"`

	// Processes is a list of process names to monitor
	Processes []string `mapstructure:"processes"`
}

// ExporterConfig contains exporter settings
type ExporterConfig struct {
	// OTLP contains OTLP exporter settings
	OTLP OTLPExporterConfig `mapstructure:"otlp"`
}

// OTLPExporterConfig contains OTLP exporter settings
type OTLPExporterConfig struct {
	// Enabled enables the OTLP exporter
	Enabled bool `mapstructure:"enabled"`

	// BatchSize is the maximum batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Compression is the compression algorithm (none, gzip)
	Compression string `mapstructure:"compression"`

	// MetricsEndpoint is the metrics OTLP endpoint (default: /api/v2/otlp/metrics)
	MetricsEndpoint string `mapstructure:"metrics_endpoint"`

	// LogsEndpoint is the logs OTLP endpoint (default: /api/v2/otlp/logs)
	LogsEndpoint string `mapstructure:"logs_endpoint"`
}

// BufferConfig contains retry buffer settings
type BufferConfig struct {
	// Enabled enables the disk buffer
	Enabled bool `mapstructure:"enabled"`

	// MaxSizeMB is the maximum buffer size in megabytes
	MaxSizeMB int64 `mapstructure:"max_size_mb"`

	// Path is the buffer directory path
	Path string `mapstructure:"path"`

	// MaxAge is the maximum age of buffered entries
	MaxAge time.Duration `mapstructure:"max_age"`

	// FlushInterval is the buffer flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	// Level is the log level (debug, info, warn, error)
	Level string `mapstructure:"level"`

	// Format is the log format (json, text)
	Format string `mapstructure:"format"`

	// File is the log file path (empty = stdout)
	File string `mapstructure:"file"`

	// MaxSizeMB is the max log file size before rotation
	MaxSizeMB int `mapstructure:"max_size_mb"`

	// MaxBackups is the number of old log files to keep
	MaxBackups int `mapstructure:"max_backups"`

	// MaxAgeDays is the max age in days for log files
	MaxAgeDays int `mapstructure:"max_age_days"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		TelemetryFlow: TelemetryFlowConfig{
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Timeout:  30 * time.Second,
			TLS: TLSConfig{
				Enabled:    true,
				SkipVerify: false,
			},
			Retry: RetryConfig{
				Enabled:         true,
				MaxAttempts:     3,
				InitialInterval: time.Second,
				MaxInterval:     30 * time.Second,
			},
		},
		Agent: AgentConfig{
			ID:          "",
			Hostname:    "",
			Name:        "TelemetryFlow Agent",
			Description: "TelemetryFlow Agent - Community Enterprise Observability Platform",
			Tags: map[string]string{
				"environment": "production",
			},
		},
		// Deprecated: Use TelemetryFlow instead
		API: APIConfig{
			Endpoint:      "http://localhost:3100",
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    time.Second,
			TLS: TLSConfig{
				Enabled:    false,
				SkipVerify: false,
			},
		},
		Heartbeat: HeartbeatConfig{
			Interval:          60 * time.Second,
			Timeout:           10 * time.Second,
			IncludeSystemInfo: true,
		},
		Collector: CollectorConfig{
			System: SystemCollectorConfig{
				Enabled:  true,
				Interval: 15 * time.Second,
				CPU:      true,
				Memory:   true,
				Disk:     true,
				Network:  true,
			},
			Logs: LogCollectorConfig{
				Enabled: false,
				Paths:   []string{},
			},
			Process: ProcessCollectorConfig{
				Enabled:  false,
				Interval: 30 * time.Second,
			},
		},
		Exporter: ExporterConfig{
			OTLP: OTLPExporterConfig{
				Enabled:         true,
				BatchSize:       100,
				FlushInterval:   10 * time.Second,
				Compression:     "gzip",
				MetricsEndpoint: "/api/v2/otlp/metrics",
				LogsEndpoint:    "/api/v2/otlp/logs",
			},
		},
		Buffer: BufferConfig{
			Enabled:       true,
			MaxSizeMB:     100,
			Path:          "/var/lib/tfo-agent/buffer",
			MaxAge:        24 * time.Hour,
			FlushInterval: 5 * time.Second,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			File:       "",
			MaxSizeMB:  100,
			MaxBackups: 3,
			MaxAgeDays: 7,
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Check TelemetryFlow config first, fall back to legacy API config
	if c.TelemetryFlow.Endpoint == "" && c.API.Endpoint == "" {
		return ErrMissingEndpoint
	}
	if c.Heartbeat.Interval < time.Second {
		return ErrInvalidHeartbeatInterval
	}
	// Validate protocol if TelemetryFlow is configured
	if c.TelemetryFlow.Endpoint != "" && c.TelemetryFlow.Protocol != "" {
		if c.TelemetryFlow.Protocol != "grpc" && c.TelemetryFlow.Protocol != "http" {
			return ErrInvalidProtocol
		}
	}
	return nil
}

// GetEffectiveEndpoint returns the endpoint to use (prefers TelemetryFlow over legacy API)
func (c *Config) GetEffectiveEndpoint() string {
	if c.TelemetryFlow.Endpoint != "" {
		return c.TelemetryFlow.Endpoint
	}
	return c.API.Endpoint
}

// GetEffectiveAPIKeyID returns the API key ID to use
func (c *Config) GetEffectiveAPIKeyID() string {
	if c.TelemetryFlow.APIKeyID != "" {
		return c.TelemetryFlow.APIKeyID
	}
	return c.API.APIKeyID
}

// GetEffectiveAPIKeySecret returns the API key secret to use
func (c *Config) GetEffectiveAPIKeySecret() string {
	if c.TelemetryFlow.APIKeySecret != "" {
		return c.TelemetryFlow.APIKeySecret
	}
	return c.API.APIKeySecret
}

// Errors
var (
	ErrMissingEndpoint          = configError("telemetryflow.endpoint or api.endpoint is required")
	ErrInvalidHeartbeatInterval = configError("heartbeat.interval must be at least 1 second")
	ErrInvalidProtocol          = configError("telemetryflow.protocol must be 'grpc' or 'http'")
)

type configError string

func (e configError) Error() string {
	return string(e)
}
