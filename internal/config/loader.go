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

// WithConfigPaths adds additional config search paths
func (l *Loader) WithConfigPaths(paths ...string) *Loader {
	l.configPaths = append(l.configPaths, paths...)
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
	}

	for key, env := range envBindings {
		_ = v.BindEnv(key, env)
	}
}

// GetConfigFilePath returns the path of the loaded config file
func GetConfigFilePath() string {
	return viper.ConfigFileUsed()
}
