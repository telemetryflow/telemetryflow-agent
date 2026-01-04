// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// JaegerConfig contains Jaeger integration configuration
type JaegerConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	CollectorEndpoint string            `mapstructure:"collector_endpoint"`
	AgentHost         string            `mapstructure:"agent_host"`
	AgentPort         int               `mapstructure:"agent_port"`
	Username          string            `mapstructure:"username"`
	Password          string            `mapstructure:"password"`
	ServiceName       string            `mapstructure:"service_name"`
	Tags              map[string]string `mapstructure:"tags"`
	BatchSize         int               `mapstructure:"batch_size"`
	FlushInterval     time.Duration     `mapstructure:"flush_interval"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	Headers           map[string]string `mapstructure:"headers"`
}

// JaegerExporter exports traces to Jaeger
type JaegerExporter struct {
	*BaseExporter
	config     JaegerConfig
	httpClient *http.Client
}

// Jaeger Thrift-over-HTTP format structures
type jaegerBatch struct {
	Process jaegerProcess `json:"process"`
	Spans   []jaegerSpan  `json:"spans"`
}

type jaegerProcess struct {
	ServiceName string      `json:"serviceName"`
	Tags        []jaegerTag `json:"tags,omitempty"`
}

type jaegerSpan struct {
	TraceID       string      `json:"traceID"`
	SpanID        string      `json:"spanID"`
	ParentSpanID  string      `json:"parentSpanID,omitempty"`
	OperationName string      `json:"operationName"`
	References    []jaegerRef `json:"references,omitempty"`
	Flags         int         `json:"flags"`
	StartTime     int64       `json:"startTime"`
	Duration      int64       `json:"duration"`
	Tags          []jaegerTag `json:"tags,omitempty"`
	Logs          []jaegerLog `json:"logs,omitempty"`
}

type jaegerTag struct {
	Key   string      `json:"key"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type jaegerRef struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

type jaegerLog struct {
	Timestamp int64       `json:"timestamp"`
	Fields    []jaegerTag `json:"fields"`
}

// NewJaegerExporter creates a new Jaeger exporter
func NewJaegerExporter(config JaegerConfig, logger *zap.Logger) *JaegerExporter {
	return &JaegerExporter{
		BaseExporter: NewBaseExporter(
			"jaeger",
			"tracing",
			config.Enabled,
			logger,
			[]DataType{DataTypeTraces},
		),
		config: config,
	}
}

// Init initializes the Jaeger exporter
func (j *JaegerExporter) Init(ctx context.Context) error {
	if !j.config.Enabled {
		return nil
	}

	if err := j.Validate(); err != nil {
		return err
	}

	// Set defaults
	if j.config.ServiceName == "" {
		j.config.ServiceName = "telemetryflow-agent"
	}
	if j.config.BatchSize == 0 {
		j.config.BatchSize = 100
	}
	if j.config.FlushInterval == 0 {
		j.config.FlushInterval = time.Second
	}
	if j.config.Timeout == 0 {
		j.config.Timeout = 30 * time.Second
	}
	if j.config.AgentPort == 0 {
		j.config.AgentPort = 6831
	}

	// Create HTTP client for collector
	j.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: j.config.Timeout,
	}

	j.SetInitialized(true)
	j.Logger().Info("Jaeger exporter initialized",
		zap.String("collectorEndpoint", j.config.CollectorEndpoint),
		zap.String("serviceName", j.config.ServiceName),
	)

	return nil
}

// Validate validates the Jaeger configuration
func (j *JaegerExporter) Validate() error {
	if !j.config.Enabled {
		return nil
	}

	if j.config.CollectorEndpoint == "" && j.config.AgentHost == "" {
		return NewValidationError("jaeger", "collector_endpoint", "collector_endpoint or agent_host is required")
	}

	return nil
}

// Export exports telemetry data to Jaeger
func (j *JaegerExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !j.config.Enabled {
		return nil, ErrNotEnabled
	}

	if len(data.Traces) > 0 {
		return j.ExportTraces(ctx, data.Traces)
	}

	return &ExportResult{Success: true}, nil
}

// ExportMetrics is not supported by Jaeger
func (j *JaegerExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("jaeger does not support metrics export")
}

// ExportTraces exports traces to Jaeger
func (j *JaegerExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	if !j.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !j.IsInitialized() {
		return nil, ErrNotInitialized
	}

	startTime := time.Now()

	// Convert to Jaeger format
	spans := make([]jaegerSpan, 0, len(traces))
	for _, t := range traces {
		span := jaegerSpan{
			TraceID:       t.TraceID,
			SpanID:        t.SpanID,
			ParentSpanID:  t.ParentSpanID,
			OperationName: t.OperationName,
			StartTime:     t.StartTime.UnixMicro(),
			Duration:      t.Duration.Microseconds(),
			Tags:          make([]jaegerTag, 0),
		}

		// Add tags
		for k, v := range t.Tags {
			span.Tags = append(span.Tags, jaegerTag{
				Key:   k,
				Type:  "string",
				Value: v,
			})
		}

		// Add error tag if status is error
		if t.Status == TraceStatusError {
			span.Tags = append(span.Tags, jaegerTag{
				Key:   "error",
				Type:  "bool",
				Value: true,
			})
		}

		// Add span logs
		for _, log := range t.Logs {
			jLog := jaegerLog{
				Timestamp: log.Timestamp.UnixMicro(),
				Fields: []jaegerTag{
					{Key: "message", Type: "string", Value: log.Message},
				},
			}
			for k, v := range log.Fields {
				jLog.Fields = append(jLog.Fields, jaegerTag{
					Key:   k,
					Type:  "string",
					Value: v,
				})
			}
			span.Logs = append(span.Logs, jLog)
		}

		spans = append(spans, span)
	}

	// Build process tags
	processTags := make([]jaegerTag, 0, len(j.config.Tags))
	for k, v := range j.config.Tags {
		processTags = append(processTags, jaegerTag{
			Key:   k,
			Type:  "string",
			Value: v,
		})
	}

	batch := jaegerBatch{
		Process: jaegerProcess{
			ServiceName: j.config.ServiceName,
			Tags:        processTags,
		},
		Spans: spans,
	}

	body, err := json.Marshal(batch)
	if err != nil {
		j.RecordError(err)
		return &ExportResult{Success: false, Error: err}, err
	}

	result, err := j.sendRequest(ctx, body)
	result.Duration = time.Since(startTime)
	result.ItemsExported = len(traces)

	if err != nil {
		j.RecordError(err)
		return result, err
	}

	j.RecordSuccess(result.BytesSent)
	return result, nil
}

// ExportLogs is not supported by Jaeger
func (j *JaegerExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("jaeger does not support logs export")
}

// Health checks the health of Jaeger
func (j *JaegerExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !j.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check collector endpoint
	if j.config.CollectorEndpoint != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", j.config.CollectorEndpoint, nil)
		if err != nil {
			return &HealthStatus{
				Healthy:   false,
				Message:   err.Error(),
				LastCheck: time.Now(),
				LastError: err,
			}, nil
		}

		resp, err := j.httpClient.Do(req)
		if err != nil {
			return &HealthStatus{
				Healthy:   false,
				Message:   fmt.Sprintf("connection failed: %v", err),
				LastCheck: time.Now(),
				LastError: err,
				Latency:   time.Since(startTime),
			}, nil
		}
		defer func() { _ = resp.Body.Close() }()

		return &HealthStatus{
			Healthy:   resp.StatusCode < 500,
			Message:   fmt.Sprintf("status: %d", resp.StatusCode),
			LastCheck: time.Now(),
			Latency:   time.Since(startTime),
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   fmt.Sprintf("agent configured at %s:%d", j.config.AgentHost, j.config.AgentPort),
		LastCheck: time.Now(),
	}, nil
}

// Close closes the Jaeger exporter
func (j *JaegerExporter) Close(ctx context.Context) error {
	if j.httpClient != nil {
		j.httpClient.CloseIdleConnections()
	}
	j.SetInitialized(false)
	j.Logger().Info("Jaeger exporter closed")
	return nil
}

// sendRequest sends spans to Jaeger collector
func (j *JaegerExporter) sendRequest(ctx context.Context, body []byte) (*ExportResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", j.config.CollectorEndpoint, bytes.NewReader(body))
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Set authentication
	if j.config.Username != "" && j.config.Password != "" {
		req.SetBasicAuth(j.config.Username, j.config.Password)
	}

	// Add custom headers
	for k, v := range j.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("jaeger collector error: status=%d body=%s", resp.StatusCode, string(respBody))
		return &ExportResult{Success: false, Error: err, BytesSent: int64(len(body))}, err
	}

	return &ExportResult{
		Success:   true,
		BytesSent: int64(len(body)),
	}, nil
}
