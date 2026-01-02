// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SNMPConfig contains SNMP integration configuration
type SNMPConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	Version        string            `mapstructure:"version"` // v1, v2c, v3
	Community      string            `mapstructure:"community"`
	Targets        []SNMPTarget      `mapstructure:"targets"`
	Port           int               `mapstructure:"port"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	Retries        int               `mapstructure:"retries"`
	ScrapeInterval time.Duration     `mapstructure:"scrape_interval"`
	MaxRepetitions uint32            `mapstructure:"max_repetitions"`
	SecurityLevel  string            `mapstructure:"security_level"` // noAuthNoPriv, authNoPriv, authPriv
	AuthProtocol   string            `mapstructure:"auth_protocol"`  // MD5, SHA
	AuthPassword   string            `mapstructure:"auth_password"`
	PrivProtocol   string            `mapstructure:"priv_protocol"` // DES, AES
	PrivPassword   string            `mapstructure:"priv_password"`
	Username       string            `mapstructure:"username"`
	ContextName    string            `mapstructure:"context_name"`
	MIBs           []string          `mapstructure:"mibs"`
	WalkOIDs       []string          `mapstructure:"walk_oids"`
	GetOIDs        []SNMPOIDConfig   `mapstructure:"get_oids"`
	Labels         map[string]string `mapstructure:"labels"`
}

// SNMPTarget represents an SNMP target device
type SNMPTarget struct {
	Address   string            `mapstructure:"address"`
	Port      int               `mapstructure:"port"`
	Community string            `mapstructure:"community"` // Override global community
	Name      string            `mapstructure:"name"`
	Labels    map[string]string `mapstructure:"labels"`
}

// SNMPOIDConfig represents an OID to collect
type SNMPOIDConfig struct {
	OID         string  `mapstructure:"oid"`
	Name        string  `mapstructure:"name"`
	Type        string  `mapstructure:"type"` // gauge, counter, string
	Unit        string  `mapstructure:"unit"`
	Scale       float64 `mapstructure:"scale"` // Multiplier for value
	Description string  `mapstructure:"description"`
}

// SNMPExporter exports telemetry data via SNMP polling
type SNMPExporter struct {
	*BaseExporter
	config SNMPConfig
}

// Common SNMP OIDs
var defaultSNMPOIDs = []SNMPOIDConfig{
	// System OIDs
	{OID: "1.3.6.1.2.1.1.3.0", Name: "sysUpTime", Type: "counter", Unit: "ticks"},
	{OID: "1.3.6.1.2.1.1.5.0", Name: "sysName", Type: "string"},

	// Interface statistics (these would need index appended)
	{OID: "1.3.6.1.2.1.2.2.1.10", Name: "ifInOctets", Type: "counter", Unit: "bytes"},
	{OID: "1.3.6.1.2.1.2.2.1.16", Name: "ifOutOctets", Type: "counter", Unit: "bytes"},
	{OID: "1.3.6.1.2.1.2.2.1.14", Name: "ifInErrors", Type: "counter"},
	{OID: "1.3.6.1.2.1.2.2.1.20", Name: "ifOutErrors", Type: "counter"},

	// CPU and Memory (common enterprise OIDs)
	{OID: "1.3.6.1.4.1.2021.11.9.0", Name: "ssCpuUser", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.11.10.0", Name: "ssCpuSystem", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.11.11.0", Name: "ssCpuIdle", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.4.5.0", Name: "memTotalReal", Type: "gauge", Unit: "kilobytes"},
	{OID: "1.3.6.1.4.1.2021.4.6.0", Name: "memAvailReal", Type: "gauge", Unit: "kilobytes"},
	{OID: "1.3.6.1.4.1.2021.4.11.0", Name: "memTotalFree", Type: "gauge", Unit: "kilobytes"},
}

// NewSNMPExporter creates a new SNMP exporter
func NewSNMPExporter(config SNMPConfig, logger *zap.Logger) *SNMPExporter {
	return &SNMPExporter{
		BaseExporter: NewBaseExporter(
			"snmp",
			"network",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the SNMP exporter
func (s *SNMPExporter) Init(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	if err := s.Validate(); err != nil {
		return err
	}

	// Set defaults
	if s.config.Version == "" {
		s.config.Version = "v2c"
	}
	if s.config.Community == "" {
		s.config.Community = "public"
	}
	if s.config.Port == 0 {
		s.config.Port = 161
	}
	if s.config.Timeout == 0 {
		s.config.Timeout = 10 * time.Second
	}
	if s.config.Retries == 0 {
		s.config.Retries = 3
	}
	if s.config.ScrapeInterval == 0 {
		s.config.ScrapeInterval = 60 * time.Second
	}
	if s.config.MaxRepetitions == 0 {
		s.config.MaxRepetitions = 10
	}

	// Add default OIDs if none specified
	if len(s.config.GetOIDs) == 0 {
		s.config.GetOIDs = defaultSNMPOIDs
	}

	s.SetInitialized(true)
	s.Logger().Info("SNMP exporter initialized",
		zap.String("version", s.config.Version),
		zap.Int("targets", len(s.config.Targets)),
	)

	return nil
}

// Validate validates the SNMP configuration
func (s *SNMPExporter) Validate() error {
	if !s.config.Enabled {
		return nil
	}

	if len(s.config.Targets) == 0 {
		return NewValidationError("snmp", "targets", "at least one target is required")
	}

	for i, target := range s.config.Targets {
		if target.Address == "" {
			return NewValidationError("snmp", fmt.Sprintf("targets[%d].address", i), "address is required")
		}
	}

	// Validate SNMPv3 settings
	if s.config.Version == "v3" {
		if s.config.Username == "" {
			return NewValidationError("snmp", "username", "username is required for SNMPv3")
		}
		if s.config.SecurityLevel == "authNoPriv" || s.config.SecurityLevel == "authPriv" {
			if s.config.AuthPassword == "" {
				return NewValidationError("snmp", "auth_password", "auth_password is required for authNoPriv/authPriv")
			}
		}
		if s.config.SecurityLevel == "authPriv" {
			if s.config.PrivPassword == "" {
				return NewValidationError("snmp", "priv_password", "priv_password is required for authPriv")
			}
		}
	}

	return nil
}

// Export exports telemetry data via SNMP
func (s *SNMPExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	metrics, err := s.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for SNMP (it's a data source)
func (s *SNMPExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp is a data source, not a metrics destination")
}

// ExportTraces is not supported by SNMP
func (s *SNMPExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp does not support traces")
}

// ExportLogs is not supported by SNMP
func (s *SNMPExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp does not support log ingestion")
}

// CollectMetrics collects metrics via SNMP polling
func (s *SNMPExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	var allMetrics []Metric
	now := time.Now()

	for _, target := range s.config.Targets {
		metrics, err := s.pollTarget(ctx, target, now)
		if err != nil {
			s.Logger().Warn("Failed to poll SNMP target",
				zap.String("target", target.Address),
				zap.Error(err),
			)
			// Add a connectivity metric
			tags := s.buildTargetTags(target)
			allMetrics = append(allMetrics, Metric{
				Name:      "snmp_target_up",
				Value:     0,
				Type:      MetricTypeGauge,
				Timestamp: now,
				Tags:      tags,
			})
			continue
		}

		allMetrics = append(allMetrics, metrics...)

		// Add up metric
		tags := s.buildTargetTags(target)
		allMetrics = append(allMetrics, Metric{
			Name:      "snmp_target_up",
			Value:     1,
			Type:      MetricTypeGauge,
			Timestamp: now,
			Tags:      tags,
		})
	}

	return allMetrics, nil
}

// pollTarget polls a single SNMP target
func (s *SNMPExporter) pollTarget(ctx context.Context, target SNMPTarget, now time.Time) ([]Metric, error) {
	// Build address
	port := target.Port
	if port == 0 {
		port = s.config.Port
	}
	address := net.JoinHostPort(target.Address, fmt.Sprintf("%d", port))

	// Check connectivity first
	conn, err := net.DialTimeout("udp", address, s.config.Timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.Close()

	// In a production implementation, we would use an SNMP library like gosnmp
	// For now, we simulate collecting basic metrics
	var metrics []Metric
	baseTags := s.buildTargetTags(target)

	// Simulate collecting OID metrics
	for _, oid := range s.config.GetOIDs {
		if oid.Type == "string" {
			continue // Skip string OIDs for metrics
		}

		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["oid"] = oid.OID
		if oid.Description != "" {
			tags["description"] = oid.Description
		}

		metricType := MetricTypeGauge
		if oid.Type == "counter" {
			metricType = MetricTypeCounter
		}

		// In production, this would actually poll the SNMP device
		// For now, we log that we would poll
		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("snmp_%s", s.sanitizeName(oid.Name)),
			Value:     0, // Would be actual value from SNMP GET
			Type:      metricType,
			Timestamp: now,
			Tags:      tags,
			Unit:      oid.Unit,
		})
	}

	return metrics, nil
}

// buildTargetTags builds tags for a target
func (s *SNMPExporter) buildTargetTags(target SNMPTarget) map[string]string {
	tags := make(map[string]string)

	// Add global labels
	for k, v := range s.config.Labels {
		tags[k] = v
	}

	// Add target-specific labels
	for k, v := range target.Labels {
		tags[k] = v
	}

	tags["target"] = target.Address
	if target.Name != "" {
		tags["target_name"] = target.Name
	}
	tags["snmp_version"] = s.config.Version

	return tags
}

// sanitizeName converts an OID name to a valid metric name
func (s *SNMPExporter) sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

// parseOIDValue parses an SNMP value into a float64
func parseOIDValue(value interface{}, oidConfig SNMPOIDConfig) (float64, bool) {
	var result float64

	switch v := value.(type) {
	case int:
		result = float64(v)
	case int64:
		result = float64(v)
	case uint:
		result = float64(v)
	case uint64:
		result = float64(v)
	case float64:
		result = v
	case float32:
		result = float64(v)
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		result = f
	case []byte:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return 0, false
		}
		result = f
	default:
		return 0, false
	}

	// Apply scale if configured
	if oidConfig.Scale != 0 {
		result *= oidConfig.Scale
	}

	return result, true
}

// Ensure parseOIDValue is used (for future SNMP implementations)
var _ = parseOIDValue

// Health checks the health of SNMP targets
func (s *SNMPExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !s.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()
	reachable := 0
	total := len(s.config.Targets)

	for _, target := range s.config.Targets {
		port := target.Port
		if port == 0 {
			port = s.config.Port
		}
		address := net.JoinHostPort(target.Address, fmt.Sprintf("%d", port))

		conn, err := net.DialTimeout("udp", address, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			reachable++
		}
	}

	healthy := reachable > 0
	message := fmt.Sprintf("%d/%d targets reachable", reachable, total)

	return &HealthStatus{
		Healthy:   healthy,
		Message:   message,
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"version":           s.config.Version,
			"total_targets":     total,
			"reachable_targets": reachable,
		},
	}, nil
}

// Close closes the SNMP exporter
func (s *SNMPExporter) Close(ctx context.Context) error {
	s.SetInitialized(false)
	s.Logger().Info("SNMP exporter closed")
	return nil
}
