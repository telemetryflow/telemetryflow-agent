// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Manager orchestrates all integration exporters
type Manager struct {
	exporters map[string]Exporter
	logger    *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// ManagerConfig contains manager configuration
type ManagerConfig struct {
	Logger *zap.Logger

	// Individual integration configs
	Prometheus    *PrometheusConfig
	Datadog       *DatadogConfig
	NewRelic      *NewRelicConfig
	Splunk        *SplunkConfig
	Elasticsearch *ElasticsearchConfig
	InfluxDB      *InfluxDBConfig
	Kafka         *KafkaConfig
	CloudWatch    *CloudWatchConfig
	Loki          *LokiConfig
	Jaeger        *JaegerConfig
	Zipkin        *ZipkinConfig
	Webhook       *WebhookConfig
	Blackbox      *BlackboxConfig
	Percona       *PerconaConfig
	Telegraf      *TelegrafConfig
	Alloy         *AlloyConfig
	GCP           *GCPConfig
	Azure         *AzureConfig
	Alibaba       *AlibabaConfig
	Proxmox       *ProxmoxConfig
	VMware        *VMwareConfig
	AzureArc      *AzureArcConfig
	Cisco         *CiscoConfig
	SNMP          *SNMPConfig
	EBPF          *EBPFConfig
	Nutanix       *NutanixConfig
	MQTT          *MQTTConfig
}

// NewManager creates a new integration manager
func NewManager(cfg ManagerConfig) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	m := &Manager{
		exporters: make(map[string]Exporter),
		logger:    logger,
		stopChan:  make(chan struct{}),
	}

	// Register all configured exporters
	if cfg.Prometheus != nil && cfg.Prometheus.Enabled {
		m.RegisterExporter(NewPrometheusExporter(*cfg.Prometheus, logger))
	}
	if cfg.Datadog != nil && cfg.Datadog.Enabled {
		m.RegisterExporter(NewDatadogExporter(*cfg.Datadog, logger))
	}
	if cfg.NewRelic != nil && cfg.NewRelic.Enabled {
		m.RegisterExporter(NewNewRelicExporter(*cfg.NewRelic, logger))
	}
	if cfg.Splunk != nil && cfg.Splunk.Enabled {
		m.RegisterExporter(NewSplunkExporter(*cfg.Splunk, logger))
	}
	if cfg.Elasticsearch != nil && cfg.Elasticsearch.Enabled {
		m.RegisterExporter(NewElasticsearchExporter(*cfg.Elasticsearch, logger))
	}
	if cfg.InfluxDB != nil && cfg.InfluxDB.Enabled {
		m.RegisterExporter(NewInfluxDBExporter(*cfg.InfluxDB, logger))
	}
	if cfg.Kafka != nil && cfg.Kafka.Enabled {
		m.RegisterExporter(NewKafkaExporter(*cfg.Kafka, logger))
	}
	if cfg.CloudWatch != nil && cfg.CloudWatch.Enabled {
		m.RegisterExporter(NewCloudWatchExporter(*cfg.CloudWatch, logger))
	}
	if cfg.Loki != nil && cfg.Loki.Enabled {
		m.RegisterExporter(NewLokiExporter(*cfg.Loki, logger))
	}
	if cfg.Jaeger != nil && cfg.Jaeger.Enabled {
		m.RegisterExporter(NewJaegerExporter(*cfg.Jaeger, logger))
	}
	if cfg.Zipkin != nil && cfg.Zipkin.Enabled {
		m.RegisterExporter(NewZipkinExporter(*cfg.Zipkin, logger))
	}
	if cfg.Webhook != nil && cfg.Webhook.Enabled {
		m.RegisterExporter(NewWebhookExporter(*cfg.Webhook, logger))
	}
	if cfg.Blackbox != nil && cfg.Blackbox.Enabled {
		m.RegisterExporter(NewBlackboxExporter(*cfg.Blackbox, logger))
	}
	if cfg.Percona != nil && cfg.Percona.Enabled {
		m.RegisterExporter(NewPerconaExporter(*cfg.Percona, logger))
	}
	if cfg.Telegraf != nil && cfg.Telegraf.Enabled {
		m.RegisterExporter(NewTelegrafExporter(*cfg.Telegraf, logger))
	}
	if cfg.Alloy != nil && cfg.Alloy.Enabled {
		m.RegisterExporter(NewAlloyExporter(*cfg.Alloy, logger))
	}
	if cfg.GCP != nil && cfg.GCP.Enabled {
		m.RegisterExporter(NewGCPExporter(*cfg.GCP, logger))
	}
	if cfg.Azure != nil && cfg.Azure.Enabled {
		m.RegisterExporter(NewAzureExporter(*cfg.Azure, logger))
	}
	if cfg.Alibaba != nil && cfg.Alibaba.Enabled {
		m.RegisterExporter(NewAlibabaExporter(*cfg.Alibaba, logger))
	}
	if cfg.Proxmox != nil && cfg.Proxmox.Enabled {
		m.RegisterExporter(NewProxmoxExporter(*cfg.Proxmox, logger))
	}
	if cfg.VMware != nil && cfg.VMware.Enabled {
		m.RegisterExporter(NewVMwareExporter(*cfg.VMware, logger))
	}
	if cfg.AzureArc != nil && cfg.AzureArc.Enabled {
		m.RegisterExporter(NewAzureArcExporter(*cfg.AzureArc, logger))
	}
	if cfg.Cisco != nil && cfg.Cisco.Enabled {
		m.RegisterExporter(NewCiscoExporter(*cfg.Cisco, logger))
	}
	if cfg.SNMP != nil && cfg.SNMP.Enabled {
		m.RegisterExporter(NewSNMPExporter(*cfg.SNMP, logger))
	}
	if cfg.EBPF != nil && cfg.EBPF.Enabled {
		m.RegisterExporter(NewEBPFExporter(*cfg.EBPF, logger))
	}
	if cfg.Nutanix != nil && cfg.Nutanix.Enabled {
		m.RegisterExporter(NewNutanixExporter(*cfg.Nutanix, logger))
	}
	if cfg.MQTT != nil && cfg.MQTT.Enabled {
		m.RegisterExporter(NewMQTTExporter(*cfg.MQTT, logger))
	}

	return m
}

// RegisterExporter registers an exporter with the manager
func (m *Manager) RegisterExporter(exporter Exporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exporters[exporter.Name()] = exporter
	m.logger.Info("Registered exporter",
		zap.String("name", exporter.Name()),
		zap.String("type", exporter.Type()),
	)
}

// UnregisterExporter removes an exporter from the manager
func (m *Manager) UnregisterExporter(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.exporters, name)
	m.logger.Info("Unregistered exporter", zap.String("name", name))
}

// GetExporter returns an exporter by name
func (m *Manager) GetExporter(name string) (Exporter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	exporter, ok := m.exporters[name]
	return exporter, ok
}

// ListExporters returns a list of all registered exporters
func (m *Manager) ListExporters() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.exporters))
	for name := range m.exporters {
		names = append(names, name)
	}
	return names
}

// Init initializes all registered exporters
func (m *Manager) Init(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errors []error
	for name, exporter := range m.exporters {
		if err := exporter.Init(ctx); err != nil {
			m.logger.Error("Failed to initialize exporter",
				zap.String("name", name),
				zap.Error(err),
			)
			errors = append(errors, fmt.Errorf("%s: %w", name, err))
		} else {
			m.logger.Info("Initialized exporter", zap.String("name", name))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to initialize %d exporters", len(errors))
	}

	return nil
}

// ValidateAll validates all registered exporters
func (m *Manager) ValidateAll() []error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errors []error
	for name, exporter := range m.exporters {
		if err := exporter.Validate(); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors
}

// Export exports telemetry data to all enabled exporters
func (m *Manager) Export(ctx context.Context, data *TelemetryData) *BatchExportResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &BatchExportResult{
		StartTime: time.Now(),
		Results:   make(map[string]*ExportResult),
	}

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for name, exporter := range m.exporters {
		if !exporter.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(name string, exp Exporter) {
			defer wg.Done()

			exportResult, err := exp.Export(ctx, data)
			if exportResult == nil {
				exportResult = &ExportResult{}
			}
			if err != nil {
				exportResult.Error = err
				exportResult.Success = false
			}

			resultMu.Lock()
			result.Results[name] = exportResult
			resultMu.Unlock()
		}(name, exporter)
	}

	wg.Wait()

	result.Duration = time.Since(result.StartTime)
	result.calculateTotals()

	return result
}

// ExportMetrics exports metrics to all enabled exporters that support metrics
func (m *Manager) ExportMetrics(ctx context.Context, metrics []Metric) *BatchExportResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &BatchExportResult{
		StartTime: time.Now(),
		Results:   make(map[string]*ExportResult),
	}

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for name, exporter := range m.exporters {
		if !exporter.IsEnabled() {
			continue
		}

		// Check if exporter supports metrics
		supportsMetrics := false
		for _, dt := range exporter.SupportedDataTypes() {
			if dt == DataTypeMetrics {
				supportsMetrics = true
				break
			}
		}
		if !supportsMetrics {
			continue
		}

		wg.Add(1)
		go func(name string, exp Exporter) {
			defer wg.Done()

			exportResult, err := exp.ExportMetrics(ctx, metrics)
			if exportResult == nil {
				exportResult = &ExportResult{}
			}
			if err != nil {
				exportResult.Error = err
				exportResult.Success = false
			}

			resultMu.Lock()
			result.Results[name] = exportResult
			resultMu.Unlock()
		}(name, exporter)
	}

	wg.Wait()

	result.Duration = time.Since(result.StartTime)
	result.calculateTotals()

	return result
}

// ExportTraces exports traces to all enabled exporters that support traces
func (m *Manager) ExportTraces(ctx context.Context, traces []Trace) *BatchExportResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &BatchExportResult{
		StartTime: time.Now(),
		Results:   make(map[string]*ExportResult),
	}

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for name, exporter := range m.exporters {
		if !exporter.IsEnabled() {
			continue
		}

		// Check if exporter supports traces
		supportsTraces := false
		for _, dt := range exporter.SupportedDataTypes() {
			if dt == DataTypeTraces {
				supportsTraces = true
				break
			}
		}
		if !supportsTraces {
			continue
		}

		wg.Add(1)
		go func(name string, exp Exporter) {
			defer wg.Done()

			exportResult, err := exp.ExportTraces(ctx, traces)
			if exportResult == nil {
				exportResult = &ExportResult{}
			}
			if err != nil {
				exportResult.Error = err
				exportResult.Success = false
			}

			resultMu.Lock()
			result.Results[name] = exportResult
			resultMu.Unlock()
		}(name, exporter)
	}

	wg.Wait()

	result.Duration = time.Since(result.StartTime)
	result.calculateTotals()

	return result
}

// ExportLogs exports logs to all enabled exporters that support logs
func (m *Manager) ExportLogs(ctx context.Context, logs []LogEntry) *BatchExportResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &BatchExportResult{
		StartTime: time.Now(),
		Results:   make(map[string]*ExportResult),
	}

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for name, exporter := range m.exporters {
		if !exporter.IsEnabled() {
			continue
		}

		// Check if exporter supports logs
		supportsLogs := false
		for _, dt := range exporter.SupportedDataTypes() {
			if dt == DataTypeLogs {
				supportsLogs = true
				break
			}
		}
		if !supportsLogs {
			continue
		}

		wg.Add(1)
		go func(name string, exp Exporter) {
			defer wg.Done()

			exportResult, err := exp.ExportLogs(ctx, logs)
			if exportResult == nil {
				exportResult = &ExportResult{}
			}
			if err != nil {
				exportResult.Error = err
				exportResult.Success = false
			}

			resultMu.Lock()
			result.Results[name] = exportResult
			resultMu.Unlock()
		}(name, exporter)
	}

	wg.Wait()

	result.Duration = time.Since(result.StartTime)
	result.calculateTotals()

	return result
}

// HealthCheck performs health checks on all enabled exporters
func (m *Manager) HealthCheck(ctx context.Context) map[string]*HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]*HealthStatus)
	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for name, exporter := range m.exporters {
		if !exporter.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(name string, exp Exporter) {
			defer wg.Done()

			status, err := exp.Health(ctx)
			if status == nil {
				status = &HealthStatus{LastCheck: time.Now()}
			}
			if err != nil {
				status.Healthy = false
				status.LastError = err
			}

			resultMu.Lock()
			results[name] = status
			resultMu.Unlock()
		}(name, exporter)
	}

	wg.Wait()
	return results
}

// StatsProvider is an optional interface for exporters that provide statistics
type StatsProvider interface {
	Stats() ExporterStats
}

// Stats returns statistics for all exporters
func (m *Manager) Stats() map[string]ExporterStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]ExporterStats)
	for name, exporter := range m.exporters {
		if provider, ok := exporter.(StatsProvider); ok {
			stats[name] = provider.Stats()
		} else {
			// Fallback for exporters that don't implement StatsProvider
			stats[name] = ExporterStats{
				Name:    name,
				Type:    exporter.Type(),
				Enabled: exporter.IsEnabled(),
			}
		}
	}
	return stats
}

// Close gracefully shuts down all exporters
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
	}

	var errors []error
	for name, exporter := range m.exporters {
		if err := exporter.Close(ctx); err != nil {
			m.logger.Error("Failed to close exporter",
				zap.String("name", name),
				zap.Error(err),
			)
			errors = append(errors, fmt.Errorf("%s: %w", name, err))
		} else {
			m.logger.Info("Closed exporter", zap.String("name", name))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to close %d exporters", len(errors))
	}

	return nil
}

// EnabledCount returns the number of enabled exporters
func (m *Manager) EnabledCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, exporter := range m.exporters {
		if exporter.IsEnabled() {
			count++
		}
	}
	return count
}

// BatchExportResult contains results from exporting to multiple exporters
type BatchExportResult struct {
	StartTime    time.Time                `json:"startTime"`
	Duration     time.Duration            `json:"duration"`
	Results      map[string]*ExportResult `json:"results"`
	TotalSuccess int                      `json:"totalSuccess"`
	TotalFailed  int                      `json:"totalFailed"`
	TotalItems   int                      `json:"totalItems"`
	TotalBytes   int64                    `json:"totalBytes"`
}

// calculateTotals calculates total statistics
func (r *BatchExportResult) calculateTotals() {
	for _, result := range r.Results {
		if result.Success {
			r.TotalSuccess++
		} else {
			r.TotalFailed++
		}
		r.TotalItems += result.ItemsExported
		r.TotalBytes += result.BytesSent
	}
}

// IsSuccess returns true if all exports succeeded
func (r *BatchExportResult) IsSuccess() bool {
	return r.TotalFailed == 0
}

// Errors returns all export errors
func (r *BatchExportResult) Errors() map[string]error {
	errors := make(map[string]error)
	for name, result := range r.Results {
		if result.Error != nil {
			errors[name] = result.Error
		}
	}
	return errors
}
