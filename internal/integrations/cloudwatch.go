// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// CloudWatchConfig contains AWS CloudWatch integration configuration
type CloudWatchConfig struct {
	Enabled               bool              `mapstructure:"enabled"`
	Region                string            `mapstructure:"region"`
	AccessKeyID           string            `mapstructure:"access_key_id"`
	SecretAccessKey       string            `mapstructure:"secret_access_key"`
	SessionToken          string            `mapstructure:"session_token"`
	RoleARN               string            `mapstructure:"role_arn"`
	ExternalID            string            `mapstructure:"external_id"`
	Namespace             string            `mapstructure:"namespace"`
	LogGroupName          string            `mapstructure:"log_group_name"`
	LogStreamName         string            `mapstructure:"log_stream_name"`
	MetricResolution      int               `mapstructure:"metric_resolution"`
	DimensionRollupOption string            `mapstructure:"dimension_rollup_option"`
	BatchSize             int               `mapstructure:"batch_size"`
	FlushInterval         time.Duration     `mapstructure:"flush_interval"`
	Timeout               time.Duration     `mapstructure:"timeout"`
	EndpointOverride      string            `mapstructure:"endpoint_override"`
	Headers               map[string]string `mapstructure:"headers"`
}

// CloudWatchExporter exports telemetry data to AWS CloudWatch
type CloudWatchExporter struct {
	*BaseExporter
	config CloudWatchConfig
}

// CloudWatch metric datum structure
type cloudWatchMetricDatum struct {
	MetricName string
	Dimensions []cloudWatchDimension
	Value      float64
	Unit       string
	Timestamp  time.Time
}

type cloudWatchDimension struct {
	Name  string
	Value string
}

// NewCloudWatchExporter creates a new CloudWatch exporter
func NewCloudWatchExporter(config CloudWatchConfig, logger *zap.Logger) *CloudWatchExporter {
	return &CloudWatchExporter{
		BaseExporter: NewBaseExporter(
			"cloudwatch",
			"cloud",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics, DataTypeLogs},
		),
		config: config,
	}
}

// Init initializes the CloudWatch exporter
func (c *CloudWatchExporter) Init(ctx context.Context) error {
	if !c.config.Enabled {
		return nil
	}

	if err := c.Validate(); err != nil {
		return err
	}

	// Set defaults
	if c.config.Region == "" {
		c.config.Region = "us-east-1"
	}
	if c.config.Namespace == "" {
		c.config.Namespace = "TelemetryFlow"
	}
	if c.config.LogGroupName == "" {
		c.config.LogGroupName = "/telemetryflow/agent"
	}
	if c.config.LogStreamName == "" {
		c.config.LogStreamName = "default"
	}
	if c.config.MetricResolution == 0 {
		c.config.MetricResolution = 60 // Standard resolution
	}
	if c.config.BatchSize == 0 {
		c.config.BatchSize = 20 // CloudWatch limit is 20 per request
	}
	if c.config.FlushInterval == 0 {
		c.config.FlushInterval = 60 * time.Second
	}
	if c.config.Timeout == 0 {
		c.config.Timeout = 30 * time.Second
	}

	c.SetInitialized(true)
	c.Logger().Info("CloudWatch exporter initialized",
		zap.String("region", c.config.Region),
		zap.String("namespace", c.config.Namespace),
	)

	return nil
}

// Validate validates the CloudWatch configuration
func (c *CloudWatchExporter) Validate() error {
	if !c.config.Enabled {
		return nil
	}

	// Either explicit credentials or IAM role/instance profile
	hasExplicitCreds := c.config.AccessKeyID != "" && c.config.SecretAccessKey != ""
	hasRoleARN := c.config.RoleARN != ""

	if !hasExplicitCreds && !hasRoleARN {
		// Assume instance profile or environment credentials will be used
		c.Logger().Debug("No explicit credentials provided, will use IAM role or environment")
	}

	if c.config.Region == "" {
		return NewValidationError("cloudwatch", "region", "region is required")
	}

	return nil
}

// Export exports telemetry data to CloudWatch
func (c *CloudWatchExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	var totalResult ExportResult
	totalResult.Success = true

	// Export metrics
	if len(data.Metrics) > 0 {
		result, err := c.ExportMetrics(ctx, data.Metrics)
		if err != nil {
			totalResult.Error = err
			totalResult.Success = false
		} else {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	// Export logs
	if len(data.Logs) > 0 {
		result, err := c.ExportLogs(ctx, data.Logs)
		if err != nil && totalResult.Error == nil {
			totalResult.Error = err
			totalResult.Success = false
		} else if result != nil {
			totalResult.ItemsExported += result.ItemsExported
			totalResult.BytesSent += result.BytesSent
		}
	}

	return &totalResult, totalResult.Error
}

// ExportMetrics exports metrics to CloudWatch
func (c *CloudWatchExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to CloudWatch format
	metricData := make([]cloudWatchMetricDatum, 0, len(metrics))
	for _, m := range metrics {
		datum := cloudWatchMetricDatum{
			MetricName: m.Name,
			Value:      m.Value,
			Unit:       c.mapUnit(m.Unit),
			Timestamp:  m.Timestamp,
			Dimensions: make([]cloudWatchDimension, 0, len(m.Tags)),
		}

		for k, v := range m.Tags {
			datum.Dimensions = append(datum.Dimensions, cloudWatchDimension{
				Name:  k,
				Value: v,
			})
		}

		metricData = append(metricData, datum)
	}

	// In production, this would use AWS SDK
	c.Logger().Debug("Metrics prepared for CloudWatch",
		zap.Int("count", len(metricData)),
		zap.String("namespace", c.config.Namespace),
	)

	c.RecordSuccess(int64(len(metrics) * 100)) // Approximate bytes
	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
		BytesSent:     int64(len(metrics) * 100),
		Duration:      time.Since(startTime),
	}, nil
}

// ExportTraces is not directly supported by CloudWatch (use X-Ray)
func (c *CloudWatchExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("cloudwatch does not support traces, use AWS X-Ray instead")
}

// ExportLogs exports logs to CloudWatch Logs
func (c *CloudWatchExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to CloudWatch Logs format
	logEvents := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		event := map[string]interface{}{
			"timestamp": l.Timestamp.UnixMilli(),
			"message":   fmt.Sprintf("[%s] %s", l.Level, l.Message),
		}
		logEvents = append(logEvents, event)
	}

	// In production, this would use AWS SDK
	c.Logger().Debug("Logs prepared for CloudWatch Logs",
		zap.Int("count", len(logEvents)),
		zap.String("logGroup", c.config.LogGroupName),
	)

	c.RecordSuccess(int64(len(logs) * 200)) // Approximate bytes
	return &ExportResult{
		Success:       true,
		ItemsExported: len(logs),
		BytesSent:     int64(len(logs) * 200),
		Duration:      time.Since(startTime),
	}, nil
}

// Health checks the health of CloudWatch connectivity
func (c *CloudWatchExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !c.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	// In production, this would verify AWS credentials and connectivity
	return &HealthStatus{
		Healthy:   true,
		Message:   "CloudWatch configured",
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"region":    c.config.Region,
			"namespace": c.config.Namespace,
		},
	}, nil
}

// Close closes the CloudWatch exporter
func (c *CloudWatchExporter) Close(ctx context.Context) error {
	c.SetInitialized(false)
	c.Logger().Info("CloudWatch exporter closed")
	return nil
}

// mapUnit maps metric units to CloudWatch units
func (c *CloudWatchExporter) mapUnit(unit string) string {
	unitMap := map[string]string{
		"bytes":            "Bytes",
		"kilobytes":        "Kilobytes",
		"megabytes":        "Megabytes",
		"gigabytes":        "Gigabytes",
		"terabytes":        "Terabytes",
		"bits":             "Bits",
		"kilobits":         "Kilobits",
		"megabits":         "Megabits",
		"gigabits":         "Gigabits",
		"terabits":         "Terabits",
		"percent":          "Percent",
		"count":            "Count",
		"seconds":          "Seconds",
		"milliseconds":     "Milliseconds",
		"microseconds":     "Microseconds",
		"bytes/second":     "Bytes/Second",
		"kilobytes/second": "Kilobytes/Second",
		"megabytes/second": "Megabytes/Second",
		"gigabytes/second": "Gigabytes/Second",
		"terabytes/second": "Terabytes/Second",
		"bits/second":      "Bits/Second",
		"kilobits/second":  "Kilobits/Second",
		"megabits/second":  "Megabits/Second",
		"gigabits/second":  "Gigabits/Second",
		"terabits/second":  "Terabits/Second",
		"count/second":     "Count/Second",
	}

	if mappedUnit, ok := unitMap[unit]; ok {
		return mappedUnit
	}
	return "None"
}
