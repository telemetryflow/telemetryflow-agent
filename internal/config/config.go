// Package config provides configuration management for the TelemetryFlow agent.
package config

import (
	"time"
)

// Config represents the complete agent configuration
type Config struct {
	TelemetryFlow TelemetryFlowConfig  `mapstructure:"telemetryflow"`
	Agent         AgentConfig          `mapstructure:"agent"`
	Heartbeat     HeartbeatConfig      `mapstructure:"heartbeat"`
	Collector     CollectorConfig      `mapstructure:"collectors"`
	Exporter      ExporterConfig       `mapstructure:"exporter"`
	Buffer        BufferConfig         `mapstructure:"buffer"`
	Logging       LoggingConfig        `mapstructure:"logging"`
	Security      SecurityConfig       `mapstructure:"security"`
	AutoUpdate    AutoUpdateConfig     `mapstructure:"auto_update"`
	Retention     RetentionConfig      `mapstructure:"retention"`
	Resources     ResourceLimitsConfig `mapstructure:"resources"`
	Cache         CacheConfig          `mapstructure:"cache"`
	Integrations  IntegrationsConfig   `mapstructure:"integrations"`

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

	// WorkspaceID is the workspace identifier
	WorkspaceID string `mapstructure:"workspace_id"`

	// TenantID is the tenant identifier
	TenantID string `mapstructure:"tenant_id"`
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

	// EndpointVersion is the OTLP endpoint version (v1 for OTEL standard, v2 for TFO Platform)
	// v1: /v1/metrics, /v1/traces, /v1/logs (OTEL community standard)
	// v2: /v2/metrics, /v2/traces, /v2/logs (TelemetryFlow Platform)
	EndpointVersion string `mapstructure:"endpoint_version"`

	// MetricsEndpoint is the metrics OTLP endpoint path (default based on endpoint_version)
	MetricsEndpoint string `mapstructure:"metrics_endpoint"`

	// TracesEndpoint is the traces OTLP endpoint path (default based on endpoint_version)
	TracesEndpoint string `mapstructure:"traces_endpoint"`

	// LogsEndpoint is the logs OTLP endpoint path (default based on endpoint_version)
	LogsEndpoint string `mapstructure:"logs_endpoint"`

	// Metrics enables metrics export
	Metrics OTLPSignalConfig `mapstructure:"metrics"`

	// Traces enables traces export
	Traces OTLPSignalConfig `mapstructure:"traces"`

	// Logs enables logs export
	Logs OTLPSignalConfig `mapstructure:"logs"`
}

// OTLPSignalConfig contains configuration for individual OTLP signal types
type OTLPSignalConfig struct {
	// Enabled enables this signal type export
	Enabled bool `mapstructure:"enabled"`

	// Endpoint overrides the default endpoint for this signal type
	Endpoint string `mapstructure:"endpoint"`
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

	// IncludeStackTrace includes stack traces in error logs
	IncludeStackTrace bool `mapstructure:"include_stack_trace"`

	// SamplingInitial is the initial sampling rate for logs
	SamplingInitial int `mapstructure:"sampling_initial"`

	// SamplingThereafter is the subsequent sampling rate
	SamplingThereafter int `mapstructure:"sampling_thereafter"`
}

// SecurityConfig contains security and encryption settings
type SecurityConfig struct {
	// Enabled enables security features
	Enabled bool `mapstructure:"enabled"`

	// EncryptionAtRest enables encryption for buffered/cached data
	EncryptionAtRest EncryptionConfig `mapstructure:"encryption_at_rest"`

	// SecureIngestion contains secure data ingestion settings
	SecureIngestion SecureIngestionConfig `mapstructure:"secure_ingestion"`

	// APIKeyRotation enables automatic API key rotation
	APIKeyRotation APIKeyRotationConfig `mapstructure:"api_key_rotation"`

	// AuditLog enables security audit logging
	AuditLog AuditLogConfig `mapstructure:"audit_log"`
}

// EncryptionConfig contains encryption at rest settings
type EncryptionConfig struct {
	// Enabled enables encryption at rest
	Enabled bool `mapstructure:"enabled"`

	// Algorithm is the encryption algorithm (aes-256-gcm, chacha20-poly1305)
	Algorithm string `mapstructure:"algorithm"`

	// KeyFile is the path to encryption key file
	KeyFile string `mapstructure:"key_file"`

	// KeyRotationInterval is how often to rotate encryption keys
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
}

// SecureIngestionConfig contains secure data ingestion settings
type SecureIngestionConfig struct {
	// RequireTLS requires TLS for all connections
	RequireTLS bool `mapstructure:"require_tls"`

	// MinTLSVersion is the minimum TLS version (1.2, 1.3)
	MinTLSVersion string `mapstructure:"min_tls_version"`

	// ValidateServerCert validates server certificates
	ValidateServerCert bool `mapstructure:"validate_server_cert"`

	// MutualTLS enables mutual TLS authentication
	MutualTLS bool `mapstructure:"mutual_tls"`

	// AllowedCipherSuites is a list of allowed cipher suites
	AllowedCipherSuites []string `mapstructure:"allowed_cipher_suites"`

	// DataSanitization enables PII/sensitive data sanitization
	DataSanitization DataSanitizationConfig `mapstructure:"data_sanitization"`
}

// DataSanitizationConfig contains data sanitization settings
type DataSanitizationConfig struct {
	// Enabled enables data sanitization
	Enabled bool `mapstructure:"enabled"`

	// SanitizePatterns is a list of regex patterns to sanitize
	SanitizePatterns []string `mapstructure:"sanitize_patterns"`

	// RedactFields is a list of field names to redact
	RedactFields []string `mapstructure:"redact_fields"`

	// HashPII hashes PII instead of removing it
	HashPII bool `mapstructure:"hash_pii"`
}

// APIKeyRotationConfig contains API key rotation settings
type APIKeyRotationConfig struct {
	// Enabled enables automatic API key rotation
	Enabled bool `mapstructure:"enabled"`

	// RotationInterval is how often to rotate API keys
	RotationInterval time.Duration `mapstructure:"rotation_interval"`

	// GracePeriod is how long old keys remain valid after rotation
	GracePeriod time.Duration `mapstructure:"grace_period"`
}

// AuditLogConfig contains audit logging settings
type AuditLogConfig struct {
	// Enabled enables audit logging
	Enabled bool `mapstructure:"enabled"`

	// File is the audit log file path
	File string `mapstructure:"file"`

	// IncludeDataAccess logs data access events
	IncludeDataAccess bool `mapstructure:"include_data_access"`

	// IncludeConfigChanges logs configuration changes
	IncludeConfigChanges bool `mapstructure:"include_config_changes"`
}

// AutoUpdateConfig contains auto-update/firmware patching settings
type AutoUpdateConfig struct {
	// Enabled enables automatic updates
	Enabled bool `mapstructure:"enabled"`

	// Channel is the update channel (stable, beta, canary)
	Channel string `mapstructure:"channel"`

	// CheckInterval is how often to check for updates
	CheckInterval time.Duration `mapstructure:"check_interval"`

	// AutoRestart automatically restarts agent after update
	AutoRestart bool `mapstructure:"auto_restart"`

	// MaintenanceWindow is the allowed update time window
	MaintenanceWindow MaintenanceWindowConfig `mapstructure:"maintenance_window"`

	// UpdateServer is the update server URL
	UpdateServer string `mapstructure:"update_server"`

	// SignatureVerification verifies update signatures
	SignatureVerification bool `mapstructure:"signature_verification"`

	// PublicKeyFile is the path to update signature public key
	PublicKeyFile string `mapstructure:"public_key_file"`

	// RollbackOnFailure automatically rolls back failed updates
	RollbackOnFailure bool `mapstructure:"rollback_on_failure"`

	// MaxRollbackVersions is the number of versions to keep for rollback
	MaxRollbackVersions int `mapstructure:"max_rollback_versions"`

	// SecurityPatchOnly only applies security patches automatically
	SecurityPatchOnly bool `mapstructure:"security_patch_only"`

	// NotifyBeforeUpdate sends notification before applying update
	NotifyBeforeUpdate bool `mapstructure:"notify_before_update"`

	// WebhookURL is the webhook to notify before/after updates
	WebhookURL string `mapstructure:"webhook_url"`
}

// MaintenanceWindowConfig contains maintenance window settings
type MaintenanceWindowConfig struct {
	// Enabled enables maintenance window restrictions
	Enabled bool `mapstructure:"enabled"`

	// StartTime is the start of maintenance window (HH:MM format)
	StartTime string `mapstructure:"start_time"`

	// EndTime is the end of maintenance window (HH:MM format)
	EndTime string `mapstructure:"end_time"`

	// DaysOfWeek are allowed days (0=Sunday, 1=Monday, etc.)
	DaysOfWeek []int `mapstructure:"days_of_week"`

	// Timezone is the timezone for maintenance window
	Timezone string `mapstructure:"timezone"`
}

// RetentionConfig contains data retention settings
type RetentionConfig struct {
	// Metrics contains metrics retention settings
	Metrics RetentionPolicyConfig `mapstructure:"metrics"`

	// Traces contains traces retention settings
	Traces RetentionPolicyConfig `mapstructure:"traces"`

	// Logs contains logs retention settings
	Logs RetentionPolicyConfig `mapstructure:"logs"`

	// LocalBuffer contains local buffer retention settings
	LocalBuffer LocalBufferRetentionConfig `mapstructure:"local_buffer"`
}

// RetentionPolicyConfig contains retention policy for a signal type
type RetentionPolicyConfig struct {
	// Enabled enables retention policy
	Enabled bool `mapstructure:"enabled"`

	// Duration is how long to retain data (Community default: 15 days)
	Duration time.Duration `mapstructure:"duration"`

	// MaxSizeGB is the maximum storage size in GB (0 = unlimited)
	MaxSizeGB int64 `mapstructure:"max_size_gb"`

	// Compression enables compression for older data
	Compression bool `mapstructure:"compression"`

	// CompressionAfter compresses data after this duration
	CompressionAfter time.Duration `mapstructure:"compression_after"`

	// Downsampling enables downsampling for older data
	Downsampling DownsamplingConfig `mapstructure:"downsampling"`
}

// DownsamplingConfig contains downsampling settings
type DownsamplingConfig struct {
	// Enabled enables downsampling
	Enabled bool `mapstructure:"enabled"`

	// After downsamples data older than this duration
	After time.Duration `mapstructure:"after"`

	// Resolution is the target resolution after downsampling
	Resolution time.Duration `mapstructure:"resolution"`
}

// LocalBufferRetentionConfig contains local buffer retention settings
type LocalBufferRetentionConfig struct {
	// MaxAge is the maximum age for buffered data
	MaxAge time.Duration `mapstructure:"max_age"`

	// MaxSizeMB is the maximum buffer size in MB
	MaxSizeMB int64 `mapstructure:"max_size_mb"`

	// CleanupInterval is how often to clean up old data
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

// ResourceLimitsConfig contains resource limit settings for lightweight operation
type ResourceLimitsConfig struct {
	// Enabled enables resource limiting
	Enabled bool `mapstructure:"enabled"`

	// CPU contains CPU limit settings
	CPU CPULimitConfig `mapstructure:"cpu"`

	// Memory contains memory limit settings
	Memory MemoryLimitConfig `mapstructure:"memory"`

	// Disk contains disk I/O limit settings
	Disk DiskLimitConfig `mapstructure:"disk"`

	// Network contains network bandwidth limit settings
	Network NetworkLimitConfig `mapstructure:"network"`

	// LightweightMode enables lightweight mode (reduced collection)
	LightweightMode bool `mapstructure:"lightweight_mode"`

	// AdaptiveCollection adjusts collection based on system load
	AdaptiveCollection AdaptiveCollectionConfig `mapstructure:"adaptive_collection"`
}

// CPULimitConfig contains CPU limit settings
type CPULimitConfig struct {
	// MaxPercent is the maximum CPU usage percentage (0-100)
	MaxPercent float64 `mapstructure:"max_percent"`

	// ThrottleThreshold is the CPU threshold to start throttling
	ThrottleThreshold float64 `mapstructure:"throttle_threshold"`

	// NumCores limits the number of cores to use (0 = all)
	NumCores int `mapstructure:"num_cores"`
}

// MemoryLimitConfig contains memory limit settings
type MemoryLimitConfig struct {
	// MaxMB is the maximum memory usage in MB
	MaxMB int64 `mapstructure:"max_mb"`

	// SoftLimitMB is the soft memory limit (triggers GC)
	SoftLimitMB int64 `mapstructure:"soft_limit_mb"`

	// GCPercent is the Go GC percentage (GOGC)
	GCPercent int `mapstructure:"gc_percent"`
}

// DiskLimitConfig contains disk I/O limit settings
type DiskLimitConfig struct {
	// MaxWriteMBps is the maximum write speed in MB/s
	MaxWriteMBps int64 `mapstructure:"max_write_mbps"`

	// MaxReadMBps is the maximum read speed in MB/s
	MaxReadMBps int64 `mapstructure:"max_read_mbps"`

	// MaxIOPS is the maximum I/O operations per second
	MaxIOPS int64 `mapstructure:"max_iops"`
}

// NetworkLimitConfig contains network bandwidth limit settings
type NetworkLimitConfig struct {
	// MaxBandwidthMbps is the maximum bandwidth in Mbps
	MaxBandwidthMbps int64 `mapstructure:"max_bandwidth_mbps"`

	// MaxConnectionsPerSecond is the maximum new connections per second
	MaxConnectionsPerSecond int64 `mapstructure:"max_connections_per_second"`

	// RateLimitRequests limits requests per second
	RateLimitRequests int64 `mapstructure:"rate_limit_requests"`
}

// AdaptiveCollectionConfig contains adaptive collection settings
type AdaptiveCollectionConfig struct {
	// Enabled enables adaptive collection
	Enabled bool `mapstructure:"enabled"`

	// HighLoadThreshold is the system load threshold for reduced collection
	HighLoadThreshold float64 `mapstructure:"high_load_threshold"`

	// ReducedInterval is the collection interval during high load
	ReducedInterval time.Duration `mapstructure:"reduced_interval"`

	// ReducedMetrics is the list of metrics to skip during high load
	ReducedMetrics []string `mapstructure:"reduced_metrics"`
}

// CacheConfig contains internal cache settings
type CacheConfig struct {
	// Enabled enables internal caching
	Enabled bool `mapstructure:"enabled"`

	// TTL is the default cache TTL
	TTL time.Duration `mapstructure:"ttl"`

	// MaxSizeMB is the maximum cache size in MB
	MaxSizeMB int64 `mapstructure:"max_size_mb"`

	// MaxEntries is the maximum number of cache entries
	MaxEntries int64 `mapstructure:"max_entries"`

	// EvictionPolicy is the cache eviction policy (lru, lfu, fifo)
	EvictionPolicy string `mapstructure:"eviction_policy"`

	// PersistToDisk enables cache persistence to disk
	PersistToDisk bool `mapstructure:"persist_to_disk"`

	// PersistPath is the path for cache persistence
	PersistPath string `mapstructure:"persist_path"`

	// StaleIfError returns stale data on collection errors
	StaleIfError bool `mapstructure:"stale_if_error"`

	// StaleTTL is how long stale data can be served
	StaleTTL time.Duration `mapstructure:"stale_ttl"`

	// PreloadOnStart preloads cache from disk on startup
	PreloadOnStart bool `mapstructure:"preload_on_start"`
}

// =============================================================================
// 3rd Party Integrations Configuration
// =============================================================================

// IntegrationsConfig contains all 3rd party integration settings
type IntegrationsConfig struct {
	// Prometheus contains Prometheus Remote Write settings
	Prometheus PrometheusIntegration `mapstructure:"prometheus"`

	// Datadog contains Datadog integration settings
	Datadog DatadogIntegration `mapstructure:"datadog"`

	// NewRelic contains New Relic integration settings
	NewRelic NewRelicIntegration `mapstructure:"new_relic"`

	// Splunk contains Splunk HEC integration settings
	Splunk SplunkIntegration `mapstructure:"splunk"`

	// Elasticsearch contains Elasticsearch integration settings
	Elasticsearch ElasticsearchIntegration `mapstructure:"elasticsearch"`

	// InfluxDB contains InfluxDB integration settings
	InfluxDB InfluxDBIntegration `mapstructure:"influxdb"`

	// Kafka contains Kafka integration settings
	Kafka KafkaIntegration `mapstructure:"kafka"`

	// CloudWatch contains AWS CloudWatch integration settings
	CloudWatch CloudWatchIntegration `mapstructure:"cloudwatch"`

	// Loki contains Grafana Loki integration settings
	Loki LokiIntegration `mapstructure:"loki"`

	// Jaeger contains Jaeger integration settings
	Jaeger JaegerIntegration `mapstructure:"jaeger"`

	// Zipkin contains Zipkin integration settings
	Zipkin ZipkinIntegration `mapstructure:"zipkin"`

	// Webhook contains generic webhook integration settings
	Webhook WebhookIntegration `mapstructure:"webhook"`

	// Custom contains custom/plugin integrations
	Custom []CustomIntegration `mapstructure:"custom"`
}

// PrometheusIntegration contains Prometheus Remote Write settings
type PrometheusIntegration struct {
	// Enabled enables Prometheus Remote Write
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the Prometheus Remote Write endpoint
	Endpoint string `mapstructure:"endpoint"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BasicAuth contains basic auth settings
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`

	// BatchSize is the batch size for remote write
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// Headers are additional HTTP headers
	Headers map[string]string `mapstructure:"headers"`

	// ExternalLabels are labels added to all metrics
	ExternalLabels map[string]string `mapstructure:"external_labels"`

	// MetricRelabelConfigs for metric transformation
	MetricRelabelConfigs []RelabelConfig `mapstructure:"metric_relabel_configs"`
}

// DatadogIntegration contains Datadog integration settings
type DatadogIntegration struct {
	// Enabled enables Datadog integration
	Enabled bool `mapstructure:"enabled"`

	// APIKey is the Datadog API key
	APIKey string `mapstructure:"api_key"`

	// APPKey is the Datadog application key (optional)
	APPKey string `mapstructure:"app_key"`

	// Site is the Datadog site (us1, us3, us5, eu1, ap1)
	Site string `mapstructure:"site"`

	// Endpoint overrides the default Datadog endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Tags are additional tags added to all data
	Tags []string `mapstructure:"tags"`

	// HostTags are host-level tags
	HostTags map[string]string `mapstructure:"host_tags"`

	// Metrics enables metrics export
	Metrics DatadogSignalConfig `mapstructure:"metrics"`

	// Logs enables logs export
	Logs DatadogSignalConfig `mapstructure:"logs"`

	// APM enables APM/traces export
	APM DatadogSignalConfig `mapstructure:"apm"`

	// Profiling enables profiling data export
	Profiling DatadogSignalConfig `mapstructure:"profiling"`
}

// DatadogSignalConfig contains Datadog signal-specific settings
type DatadogSignalConfig struct {
	// Enabled enables this signal type
	Enabled bool `mapstructure:"enabled"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// NewRelicIntegration contains New Relic integration settings
type NewRelicIntegration struct {
	// Enabled enables New Relic integration
	Enabled bool `mapstructure:"enabled"`

	// APIKey is the New Relic Ingest API key
	APIKey string `mapstructure:"api_key"`

	// AccountID is the New Relic account ID
	AccountID string `mapstructure:"account_id"`

	// Region is the New Relic region (US, EU)
	Region string `mapstructure:"region"`

	// Endpoint overrides the default New Relic endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// Traces enables traces export
	Traces bool `mapstructure:"traces"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// Attributes are additional attributes
	Attributes map[string]string `mapstructure:"attributes"`
}

// SplunkIntegration contains Splunk HEC integration settings
type SplunkIntegration struct {
	// Enabled enables Splunk integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the Splunk HEC endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Token is the Splunk HEC token
	Token string `mapstructure:"token"`

	// Index is the target Splunk index
	Index string `mapstructure:"index"`

	// Source is the event source
	Source string `mapstructure:"source"`

	// SourceType is the event source type
	SourceType string `mapstructure:"source_type"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// Traces enables traces export
	Traces bool `mapstructure:"traces"`
}

// ElasticsearchIntegration contains Elasticsearch integration settings
type ElasticsearchIntegration struct {
	// Enabled enables Elasticsearch integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoints is the list of Elasticsearch endpoints
	Endpoints []string `mapstructure:"endpoints"`

	// Index is the index name pattern
	Index string `mapstructure:"index"`

	// Pipeline is the ingest pipeline name
	Pipeline string `mapstructure:"pipeline"`

	// Username is the username for basic auth
	Username string `mapstructure:"username"`

	// Password is the password for basic auth
	Password string `mapstructure:"password"`

	// APIKey is the Elasticsearch API key
	APIKey string `mapstructure:"api_key"`

	// CloudID is the Elastic Cloud ID
	CloudID string `mapstructure:"cloud_id"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// Traces enables traces export
	Traces bool `mapstructure:"traces"`
}

// InfluxDBIntegration contains InfluxDB integration settings
type InfluxDBIntegration struct {
	// Enabled enables InfluxDB integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the InfluxDB endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Token is the InfluxDB token
	Token string `mapstructure:"token"`

	// Org is the InfluxDB organization
	Org string `mapstructure:"org"`

	// Bucket is the InfluxDB bucket
	Bucket string `mapstructure:"bucket"`

	// Version is the InfluxDB version (1, 2)
	Version int `mapstructure:"version"`

	// Username is the username for InfluxDB 1.x
	Username string `mapstructure:"username"`

	// Password is the password for InfluxDB 1.x
	Password string `mapstructure:"password"`

	// Database is the database name for InfluxDB 1.x
	Database string `mapstructure:"database"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Precision is the timestamp precision (ns, us, ms, s)
	Precision string `mapstructure:"precision"`

	// Tags are additional tags
	Tags map[string]string `mapstructure:"tags"`
}

// KafkaIntegration contains Kafka integration settings
type KafkaIntegration struct {
	// Enabled enables Kafka integration
	Enabled bool `mapstructure:"enabled"`

	// Brokers is the list of Kafka brokers
	Brokers []string `mapstructure:"brokers"`

	// Topic is the Kafka topic for metrics
	Topic string `mapstructure:"topic"`

	// LogsTopic is the Kafka topic for logs
	LogsTopic string `mapstructure:"logs_topic"`

	// TracesTopic is the Kafka topic for traces
	TracesTopic string `mapstructure:"traces_topic"`

	// SASL contains SASL authentication settings
	SASL KafkaSASLConfig `mapstructure:"sasl"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// Compression is the compression codec (none, gzip, snappy, lz4, zstd)
	Compression string `mapstructure:"compression"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Encoding is the message encoding (json, protobuf)
	Encoding string `mapstructure:"encoding"`

	// PartitionKey is the partition key strategy
	PartitionKey string `mapstructure:"partition_key"`
}

// KafkaSASLConfig contains Kafka SASL settings
type KafkaSASLConfig struct {
	// Enabled enables SASL authentication
	Enabled bool `mapstructure:"enabled"`

	// Mechanism is the SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)
	Mechanism string `mapstructure:"mechanism"`

	// Username is the SASL username
	Username string `mapstructure:"username"`

	// Password is the SASL password
	Password string `mapstructure:"password"`
}

// CloudWatchIntegration contains AWS CloudWatch integration settings
type CloudWatchIntegration struct {
	// Enabled enables CloudWatch integration
	Enabled bool `mapstructure:"enabled"`

	// Region is the AWS region
	Region string `mapstructure:"region"`

	// AccessKeyID is the AWS access key ID
	AccessKeyID string `mapstructure:"access_key_id"`

	// SecretAccessKey is the AWS secret access key
	SecretAccessKey string `mapstructure:"secret_access_key"`

	// RoleARN is the IAM role ARN to assume
	RoleARN string `mapstructure:"role_arn"`

	// Namespace is the CloudWatch namespace for metrics
	Namespace string `mapstructure:"namespace"`

	// LogGroup is the CloudWatch Logs group name
	LogGroup string `mapstructure:"log_group"`

	// LogStream is the CloudWatch Logs stream name
	LogStream string `mapstructure:"log_stream"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Dimensions are additional metric dimensions
	Dimensions map[string]string `mapstructure:"dimensions"`
}

// LokiIntegration contains Grafana Loki integration settings
type LokiIntegration struct {
	// Enabled enables Loki integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the Loki endpoint
	Endpoint string `mapstructure:"endpoint"`

	// TenantID is the Loki tenant ID
	TenantID string `mapstructure:"tenant_id"`

	// BasicAuth contains basic auth settings
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Labels are additional labels
	Labels map[string]string `mapstructure:"labels"`

	// Headers are additional HTTP headers
	Headers map[string]string `mapstructure:"headers"`
}

// JaegerIntegration contains Jaeger integration settings
type JaegerIntegration struct {
	// Enabled enables Jaeger integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the Jaeger collector endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Protocol is the transport protocol (grpc, http/thrift)
	Protocol string `mapstructure:"protocol"`

	// AgentEndpoint is the Jaeger agent endpoint (UDP)
	AgentEndpoint string `mapstructure:"agent_endpoint"`

	// Username is the username for basic auth
	Username string `mapstructure:"username"`

	// Password is the password for basic auth
	Password string `mapstructure:"password"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// ServiceName is the service name for traces
	ServiceName string `mapstructure:"service_name"`

	// Tags are additional trace tags
	Tags map[string]string `mapstructure:"tags"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`
}

// ZipkinIntegration contains Zipkin integration settings
type ZipkinIntegration struct {
	// Enabled enables Zipkin integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the Zipkin collector endpoint
	Endpoint string `mapstructure:"endpoint"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// ServiceName is the service name for traces
	ServiceName string `mapstructure:"service_name"`

	// Tags are additional trace tags
	Tags map[string]string `mapstructure:"tags"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`
}

// WebhookIntegration contains generic webhook integration settings
type WebhookIntegration struct {
	// Enabled enables webhook integration
	Enabled bool `mapstructure:"enabled"`

	// Endpoints is the list of webhook endpoints
	Endpoints []WebhookEndpoint `mapstructure:"endpoints"`
}

// WebhookEndpoint contains a single webhook endpoint configuration
type WebhookEndpoint struct {
	// Name is the endpoint name
	Name string `mapstructure:"name"`

	// URL is the webhook URL
	URL string `mapstructure:"url"`

	// Method is the HTTP method (POST, PUT)
	Method string `mapstructure:"method"`

	// Headers are additional HTTP headers
	Headers map[string]string `mapstructure:"headers"`

	// TLS contains TLS settings
	TLS TLSConfig `mapstructure:"tls"`

	// BasicAuth contains basic auth settings
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`

	// Encoding is the payload encoding (json, protobuf)
	Encoding string `mapstructure:"encoding"`

	// BatchSize is the batch size
	BatchSize int `mapstructure:"batch_size"`

	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// RetryAttempts is the number of retry attempts
	RetryAttempts int `mapstructure:"retry_attempts"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// Traces enables traces export
	Traces bool `mapstructure:"traces"`
}

// CustomIntegration contains custom/plugin integration settings
type CustomIntegration struct {
	// Name is the integration name
	Name string `mapstructure:"name"`

	// Type is the integration type (plugin, script, exec)
	Type string `mapstructure:"type"`

	// Path is the path to plugin/script
	Path string `mapstructure:"path"`

	// Config is the integration-specific configuration
	Config map[string]interface{} `mapstructure:"config"`

	// Enabled enables this integration
	Enabled bool `mapstructure:"enabled"`

	// Metrics enables metrics export
	Metrics bool `mapstructure:"metrics"`

	// Logs enables logs export
	Logs bool `mapstructure:"logs"`

	// Traces enables traces export
	Traces bool `mapstructure:"traces"`
}

// BasicAuthConfig contains basic auth settings
type BasicAuthConfig struct {
	// Username is the username
	Username string `mapstructure:"username"`

	// Password is the password
	Password string `mapstructure:"password"`
}

// RelabelConfig for metric relabeling (Prometheus-style)
type RelabelConfig struct {
	// SourceLabels is the list of source labels
	SourceLabels []string `mapstructure:"source_labels"`

	// Separator is the separator for source labels
	Separator string `mapstructure:"separator"`

	// Regex is the regex to match
	Regex string `mapstructure:"regex"`

	// TargetLabel is the target label
	TargetLabel string `mapstructure:"target_label"`

	// Replacement is the replacement value
	Replacement string `mapstructure:"replacement"`

	// Action is the relabel action (replace, keep, drop, hashmod, labelmap, labeldrop, labelkeep)
	Action string `mapstructure:"action"`

	// Modulus for hashmod action
	Modulus uint64 `mapstructure:"modulus"`
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
				EndpointVersion: "v2", // TelemetryFlow Platform (v2) by default
				MetricsEndpoint: "/v2/metrics",
				TracesEndpoint:  "/v2/traces",
				LogsEndpoint:    "/v2/logs",
				Metrics: OTLPSignalConfig{
					Enabled: true,
				},
				Traces: OTLPSignalConfig{
					Enabled: false, // Disabled by default, enable when needed
				},
				Logs: OTLPSignalConfig{
					Enabled: false, // Disabled by default, enable when needed
				},
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
			Level:              "info",
			Format:             "json",
			File:               "",
			MaxSizeMB:          100,
			MaxBackups:         3,
			MaxAgeDays:         7,
			IncludeStackTrace:  false,
			SamplingInitial:    100,
			SamplingThereafter: 100,
		},
		Security: SecurityConfig{
			Enabled: true,
			EncryptionAtRest: EncryptionConfig{
				Enabled:             false,
				Algorithm:           "aes-256-gcm",
				KeyRotationInterval: 24 * time.Hour * 30, // 30 days
			},
			SecureIngestion: SecureIngestionConfig{
				RequireTLS:         true,
				MinTLSVersion:      "1.2",
				ValidateServerCert: true,
				MutualTLS:          false,
				AllowedCipherSuites: []string{
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				},
				DataSanitization: DataSanitizationConfig{
					Enabled: false,
					RedactFields: []string{
						"password", "secret", "token", "api_key", "apikey",
						"authorization", "credential", "private_key",
					},
					HashPII: false,
				},
			},
			APIKeyRotation: APIKeyRotationConfig{
				Enabled:          false,
				RotationInterval: 24 * time.Hour * 90, // 90 days
				GracePeriod:      24 * time.Hour,
			},
			AuditLog: AuditLogConfig{
				Enabled:              false,
				File:                 "/var/log/tfo-agent/audit.log",
				IncludeDataAccess:    false,
				IncludeConfigChanges: true,
			},
		},
		AutoUpdate: AutoUpdateConfig{
			Enabled:               true,
			Channel:               "stable",
			CheckInterval:         1 * time.Hour,
			AutoRestart:           true,
			UpdateServer:          "https://updates.telemetryflow.id",
			SignatureVerification: true,
			RollbackOnFailure:     true,
			MaxRollbackVersions:   3,
			SecurityPatchOnly:     false,
			NotifyBeforeUpdate:    true,
			MaintenanceWindow: MaintenanceWindowConfig{
				Enabled:    true,
				StartTime:  "02:00",
				EndTime:    "05:00",
				DaysOfWeek: []int{0, 1, 2, 3, 4, 5, 6}, // All days
				Timezone:   "UTC",
			},
		},
		Retention: RetentionConfig{
			Metrics: RetentionPolicyConfig{
				Enabled:          true,
				Duration:         15 * 24 * time.Hour, // 15 days (Community Edition)
				MaxSizeGB:        0,                   // Unlimited
				Compression:      true,
				CompressionAfter: 24 * time.Hour, // Compress after 1 day
				Downsampling: DownsamplingConfig{
					Enabled:    true,
					After:      7 * 24 * time.Hour, // After 7 days
					Resolution: 5 * time.Minute,    // 5 minute resolution
				},
			},
			Traces: RetentionPolicyConfig{
				Enabled:          true,
				Duration:         15 * 24 * time.Hour, // 15 days (Community Edition)
				MaxSizeGB:        0,
				Compression:      true,
				CompressionAfter: 24 * time.Hour,
			},
			Logs: RetentionPolicyConfig{
				Enabled:          true,
				Duration:         15 * 24 * time.Hour, // 15 days (Community Edition)
				MaxSizeGB:        0,
				Compression:      true,
				CompressionAfter: 24 * time.Hour,
			},
			LocalBuffer: LocalBufferRetentionConfig{
				MaxAge:          48 * time.Hour,
				MaxSizeMB:       500,
				CleanupInterval: 1 * time.Hour,
			},
		},
		Resources: ResourceLimitsConfig{
			Enabled: true,
			CPU: CPULimitConfig{
				MaxPercent:        5.0, // Max 5% CPU usage
				ThrottleThreshold: 3.0, // Start throttling at 3%
				NumCores:          0,   // Use all cores
			},
			Memory: MemoryLimitConfig{
				MaxMB:       128, // Max 128MB memory
				SoftLimitMB: 100, // Soft limit 100MB
				GCPercent:   50,  // Aggressive GC
			},
			Disk: DiskLimitConfig{
				MaxWriteMBps: 10,
				MaxReadMBps:  20,
				MaxIOPS:      100,
			},
			Network: NetworkLimitConfig{
				MaxBandwidthMbps:        10,
				MaxConnectionsPerSecond: 10,
				RateLimitRequests:       100,
			},
			LightweightMode: false,
			AdaptiveCollection: AdaptiveCollectionConfig{
				Enabled:           true,
				HighLoadThreshold: 80.0, // 80% system load
				ReducedInterval:   60 * time.Second,
				ReducedMetrics: []string{
					"disk_partitions",
					"network_interfaces",
					"cpu_per_core",
				},
			},
		},
		Cache: CacheConfig{
			Enabled:        true,
			TTL:            5 * time.Second,
			MaxSizeMB:      50,
			MaxEntries:     10000,
			EvictionPolicy: "lru",
			PersistToDisk:  true,
			PersistPath:    "/var/lib/tfo-agent/cache",
			StaleIfError:   true,
			StaleTTL:       60 * time.Second,
			PreloadOnStart: true,
		},
		Integrations: IntegrationsConfig{
			// All integrations disabled by default
			// Enable specific integrations as needed
			Prometheus: PrometheusIntegration{
				Enabled:       false,
				BatchSize:     500,
				FlushInterval: 30 * time.Second,
				Timeout:       30 * time.Second,
			},
			Datadog: DatadogIntegration{
				Enabled: false,
				Site:    "us1",
				Metrics: DatadogSignalConfig{
					Enabled:       false,
					BatchSize:     100,
					FlushInterval: 10 * time.Second,
				},
				Logs: DatadogSignalConfig{
					Enabled:       false,
					BatchSize:     100,
					FlushInterval: 5 * time.Second,
				},
				APM: DatadogSignalConfig{
					Enabled:       false,
					BatchSize:     100,
					FlushInterval: 5 * time.Second,
				},
			},
			NewRelic: NewRelicIntegration{
				Enabled:   false,
				Region:    "US",
				BatchSize: 100,
				Timeout:   30 * time.Second,
			},
			Splunk: SplunkIntegration{
				Enabled:    false,
				BatchSize:  100,
				Timeout:    30 * time.Second,
				SourceType: "tfo-agent",
			},
			Elasticsearch: ElasticsearchIntegration{
				Enabled:       false,
				Index:         "telemetryflow-%Y.%m.%d",
				BatchSize:     100,
				FlushInterval: 10 * time.Second,
			},
			InfluxDB: InfluxDBIntegration{
				Enabled:       false,
				Version:       2,
				Precision:     "ns",
				BatchSize:     1000,
				FlushInterval: 10 * time.Second,
			},
			Kafka: KafkaIntegration{
				Enabled:       false,
				Topic:         "telemetryflow-metrics",
				LogsTopic:     "telemetryflow-logs",
				TracesTopic:   "telemetryflow-traces",
				Compression:   "snappy",
				BatchSize:     100,
				FlushInterval: 5 * time.Second,
				Encoding:      "json",
			},
			CloudWatch: CloudWatchIntegration{
				Enabled:       false,
				Namespace:     "TelemetryFlow",
				BatchSize:     100,
				FlushInterval: 60 * time.Second,
			},
			Loki: LokiIntegration{
				Enabled:       false,
				BatchSize:     100,
				FlushInterval: 5 * time.Second,
			},
			Jaeger: JaegerIntegration{
				Enabled:   false,
				Protocol:  "grpc",
				BatchSize: 100,
			},
			Zipkin: ZipkinIntegration{
				Enabled:   false,
				BatchSize: 100,
				Timeout:   30 * time.Second,
			},
			Webhook: WebhookIntegration{
				Enabled: false,
			},
			Custom: []CustomIntegration{},
		},
	}
}

// Days is a helper to convert days to time.Duration
func Days(n int) time.Duration {
	return time.Duration(n) * 24 * time.Hour
}

// Hours is a helper to convert hours to time.Duration
func Hours(n int) time.Duration {
	return time.Duration(n) * time.Hour
}

// RetentionDays returns the retention duration in days
func (r *RetentionPolicyConfig) RetentionDays() int {
	return int(r.Duration / (24 * time.Hour))
}

// SetRetentionDays sets the retention duration from days
func (r *RetentionPolicyConfig) SetRetentionDays(days int) {
	r.Duration = time.Duration(days) * 24 * time.Hour
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Check TelemetryFlow endpoint
	if c.TelemetryFlow.Endpoint == "" {
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
	// Validate endpoint version if specified
	if c.Exporter.OTLP.EndpointVersion != "" {
		if c.Exporter.OTLP.EndpointVersion != "v1" && c.Exporter.OTLP.EndpointVersion != "v2" {
			return ErrInvalidEndpointVersion
		}
	}
	return nil
}

// GetEffectiveEndpoint returns the TelemetryFlow endpoint
func (c *Config) GetEffectiveEndpoint() string {
	return c.TelemetryFlow.Endpoint
}

// GetEffectiveAPIKeyID returns the TelemetryFlow API key ID
func (c *Config) GetEffectiveAPIKeyID() string {
	return c.TelemetryFlow.APIKeyID
}

// GetEffectiveAPIKeySecret returns the TelemetryFlow API key secret
func (c *Config) GetEffectiveAPIKeySecret() string {
	return c.TelemetryFlow.APIKeySecret
}

// GetEffectiveTimeout returns the timeout to use
func (c *Config) GetEffectiveTimeout() time.Duration {
	if c.TelemetryFlow.Timeout > 0 {
		return c.TelemetryFlow.Timeout
	}
	return 30 * time.Second
}

// GetEffectiveRetryAttempts returns the retry attempts to use
func (c *Config) GetEffectiveRetryAttempts() int {
	if c.TelemetryFlow.Retry.MaxAttempts > 0 {
		return c.TelemetryFlow.Retry.MaxAttempts
	}
	return 3
}

// GetEffectiveRetryDelay returns the retry delay to use
func (c *Config) GetEffectiveRetryDelay() time.Duration {
	if c.TelemetryFlow.Retry.InitialInterval > 0 {
		return c.TelemetryFlow.Retry.InitialInterval
	}
	return time.Second
}

// GetEffectiveTLSConfig returns the TelemetryFlow TLS config
func (c *Config) GetEffectiveTLSConfig() TLSConfig {
	return c.TelemetryFlow.TLS
}

// GetEffectiveWorkspaceID returns the workspace ID
func (c *Config) GetEffectiveWorkspaceID() string {
	return c.TelemetryFlow.WorkspaceID
}

// GetEffectiveTenantID returns the tenant ID
func (c *Config) GetEffectiveTenantID() string {
	return c.TelemetryFlow.TenantID
}

// GetMetricsEndpointPath returns the metrics endpoint path based on version
func (c *Config) GetMetricsEndpointPath() string {
	if c.Exporter.OTLP.Metrics.Endpoint != "" {
		return c.Exporter.OTLP.Metrics.Endpoint
	}
	if c.Exporter.OTLP.MetricsEndpoint != "" {
		return c.Exporter.OTLP.MetricsEndpoint
	}
	return c.getDefaultEndpointPath("metrics")
}

// GetTracesEndpointPath returns the traces endpoint path based on version
func (c *Config) GetTracesEndpointPath() string {
	if c.Exporter.OTLP.Traces.Endpoint != "" {
		return c.Exporter.OTLP.Traces.Endpoint
	}
	if c.Exporter.OTLP.TracesEndpoint != "" {
		return c.Exporter.OTLP.TracesEndpoint
	}
	return c.getDefaultEndpointPath("traces")
}

// GetLogsEndpointPath returns the logs endpoint path based on version
func (c *Config) GetLogsEndpointPath() string {
	if c.Exporter.OTLP.Logs.Endpoint != "" {
		return c.Exporter.OTLP.Logs.Endpoint
	}
	if c.Exporter.OTLP.LogsEndpoint != "" {
		return c.Exporter.OTLP.LogsEndpoint
	}
	return c.getDefaultEndpointPath("logs")
}

// getDefaultEndpointPath returns the default endpoint path for a signal type
func (c *Config) getDefaultEndpointPath(signalType string) string {
	version := c.Exporter.OTLP.EndpointVersion
	if version == "" {
		version = "v2" // Default to TFO Platform v2
	}
	return "/" + version + "/" + signalType
}

// GetEndpointVersion returns the configured endpoint version (v1 or v2)
func (c *Config) GetEndpointVersion() string {
	if c.Exporter.OTLP.EndpointVersion == "" {
		return "v2"
	}
	return c.Exporter.OTLP.EndpointVersion
}

// IsMetricsEnabled returns whether metrics export is enabled
func (c *Config) IsMetricsEnabled() bool {
	return c.Exporter.OTLP.Enabled && c.Exporter.OTLP.Metrics.Enabled
}

// IsTracesEnabled returns whether traces export is enabled
func (c *Config) IsTracesEnabled() bool {
	return c.Exporter.OTLP.Enabled && c.Exporter.OTLP.Traces.Enabled
}

// IsLogsEnabled returns whether logs export is enabled
func (c *Config) IsLogsEnabled() bool {
	return c.Exporter.OTLP.Enabled && c.Exporter.OTLP.Logs.Enabled
}

// Errors
var (
	ErrMissingEndpoint          = configError("telemetryflow.endpoint is required")
	ErrInvalidHeartbeatInterval = configError("heartbeat.interval must be at least 1 second")
	ErrInvalidProtocol          = configError("telemetryflow.protocol must be 'grpc' or 'http'")
	ErrInvalidEndpointVersion   = configError("exporter.otlp.endpoint_version must be 'v1' or 'v2'")
)

type configError string

func (e configError) Error() string {
	return string(e)
}
