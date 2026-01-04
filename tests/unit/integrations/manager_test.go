// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// MockExporter implements the Exporter interface for testing
type MockExporter struct {
	name            string
	exporterType    string
	enabled         bool
	initialized     bool
	supportedTypes  []integrations.DataType
	initError       error
	validateError   error
	exportError     error
	healthError     error
	closeError      error
	healthy         bool
	exportCount     int64
	exportCallCount int64
	closeCalled     bool
	initCalled      bool
	mu              sync.RWMutex
}

// NewMockExporter creates a new mock exporter for testing
func NewMockExporter(name, exporterType string, enabled bool, supportedTypes []integrations.DataType) *MockExporter {
	return &MockExporter{
		name:           name,
		exporterType:   exporterType,
		enabled:        enabled,
		supportedTypes: supportedTypes,
		healthy:        true,
	}
}

func (m *MockExporter) Name() string {
	return m.name
}

func (m *MockExporter) Type() string {
	return m.exporterType
}

func (m *MockExporter) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initCalled = true
	if m.initError != nil {
		return m.initError
	}
	m.initialized = true
	return nil
}

func (m *MockExporter) Validate() error {
	return m.validateError
}

func (m *MockExporter) Export(ctx context.Context, data *integrations.TelemetryData) (*integrations.ExportResult, error) {
	atomic.AddInt64(&m.exportCallCount, 1)
	if m.exportError != nil {
		return &integrations.ExportResult{Success: false, Error: m.exportError}, m.exportError
	}

	itemCount := 0
	if data != nil {
		itemCount = len(data.Metrics) + len(data.Traces) + len(data.Logs)
	}
	atomic.AddInt64(&m.exportCount, int64(itemCount))

	return &integrations.ExportResult{
		Success:       true,
		ItemsExported: itemCount,
		BytesSent:     int64(itemCount * 100),
		Duration:      10 * time.Millisecond,
	}, nil
}

func (m *MockExporter) ExportMetrics(ctx context.Context, metrics []integrations.Metric) (*integrations.ExportResult, error) {
	atomic.AddInt64(&m.exportCallCount, 1)
	if m.exportError != nil {
		return &integrations.ExportResult{Success: false, Error: m.exportError}, m.exportError
	}

	atomic.AddInt64(&m.exportCount, int64(len(metrics)))
	return &integrations.ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
		BytesSent:     int64(len(metrics) * 100),
		Duration:      10 * time.Millisecond,
	}, nil
}

func (m *MockExporter) ExportTraces(ctx context.Context, traces []integrations.Trace) (*integrations.ExportResult, error) {
	atomic.AddInt64(&m.exportCallCount, 1)
	if m.exportError != nil {
		return &integrations.ExportResult{Success: false, Error: m.exportError}, m.exportError
	}

	atomic.AddInt64(&m.exportCount, int64(len(traces)))
	return &integrations.ExportResult{
		Success:       true,
		ItemsExported: len(traces),
		BytesSent:     int64(len(traces) * 100),
		Duration:      10 * time.Millisecond,
	}, nil
}

func (m *MockExporter) ExportLogs(ctx context.Context, logs []integrations.LogEntry) (*integrations.ExportResult, error) {
	atomic.AddInt64(&m.exportCallCount, 1)
	if m.exportError != nil {
		return &integrations.ExportResult{Success: false, Error: m.exportError}, m.exportError
	}

	atomic.AddInt64(&m.exportCount, int64(len(logs)))
	return &integrations.ExportResult{
		Success:       true,
		ItemsExported: len(logs),
		BytesSent:     int64(len(logs) * 100),
		Duration:      10 * time.Millisecond,
	}, nil
}

func (m *MockExporter) Health(ctx context.Context) (*integrations.HealthStatus, error) {
	if m.healthError != nil {
		return &integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
			LastError: m.healthError,
		}, m.healthError
	}

	return &integrations.HealthStatus{
		Healthy:   m.healthy,
		Message:   "mock exporter healthy",
		LastCheck: time.Now(),
		Latency:   5 * time.Millisecond,
	}, nil
}

func (m *MockExporter) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return m.closeError
}

func (m *MockExporter) IsEnabled() bool {
	return m.enabled
}

func (m *MockExporter) SupportedDataTypes() []integrations.DataType {
	return m.supportedTypes
}

func (m *MockExporter) Stats() integrations.ExporterStats {
	return integrations.ExporterStats{
		Name:          m.name,
		Type:          m.exporterType,
		Enabled:       m.enabled,
		Initialized:   m.initialized,
		ExportCount:   atomic.LoadInt64(&m.exportCount),
		ErrorCount:    0,
		BytesExported: atomic.LoadInt64(&m.exportCount) * 100,
	}
}

func (m *MockExporter) SetInitError(err error) {
	m.initError = err
}

func (m *MockExporter) SetValidateError(err error) {
	m.validateError = err
}

func (m *MockExporter) SetExportError(err error) {
	m.exportError = err
}

func (m *MockExporter) SetHealthError(err error) {
	m.healthError = err
}

func (m *MockExporter) SetCloseError(err error) {
	m.closeError = err
}

func (m *MockExporter) SetHealthy(healthy bool) {
	m.healthy = healthy
}

func (m *MockExporter) GetExportCallCount() int64 {
	return atomic.LoadInt64(&m.exportCallCount)
}

func (m *MockExporter) IsCloseCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closeCalled
}

func (m *MockExporter) IsInitCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initCalled
}

// =============================================================================
// NewManager Tests
// =============================================================================

func TestNewManager(t *testing.T) {
	logger := zap.NewNop()

	t.Run("empty config", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		assert.Empty(t, manager.ListExporters())
	})

	t.Run("with nil logger", func(t *testing.T) {
		config := integrations.ManagerConfig{}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		assert.Empty(t, manager.ListExporters())
	})

	t.Run("with gcp enabled", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
		}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		exporters := manager.ListExporters()
		assert.NotEmpty(t, exporters)
		assert.Contains(t, exporters, "gcp")
	})

	t.Run("with disabled integration", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled:   false,
				ProjectID: "test-project",
			},
		}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		exporters := manager.ListExporters()
		assert.Empty(t, exporters)
	})

	t.Run("with multiple integrations", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			MQTT: &integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
			Prometheus: &integrations.PrometheusConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9090",
			},
		}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		exporters := manager.ListExporters()
		assert.GreaterOrEqual(t, len(exporters), 3)
	})

	t.Run("with all integrations enabled", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			Azure: &integrations.AzureConfig{
				Enabled:        true,
				SubscriptionID: "test-sub",
				ResourceGroup:  "test-rg",
			},
			Alibaba: &integrations.AlibabaConfig{
				Enabled:         true,
				RegionID:        "cn-hangzhou",
				AccessKeyID:     "test-key",
				AccessKeySecret: "test-secret",
			},
			Proxmox: &integrations.ProxmoxConfig{
				Enabled:  true,
				APIUrl:   "https://proxmox.local:8006",
				Username: "root@pam",
				Password: "password",
			},
			VMware: &integrations.VMwareConfig{
				Enabled:    true,
				VCenterURL: "https://vcenter.local",
				Username:   "admin",
				Password:   "password",
			},
			Nutanix: &integrations.NutanixConfig{
				Enabled:         true,
				PrismCentralURL: "https://nutanix.local:9440",
				Username:        "admin",
				Password:        "password",
			},
			AzureArc: &integrations.AzureArcConfig{
				Enabled:        true,
				SubscriptionID: "test-sub",
				ResourceGroup:  "test-rg",
			},
			MQTT: &integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
		}
		manager := integrations.NewManager(config)

		require.NotNil(t, manager)
		exporters := manager.ListExporters()
		assert.GreaterOrEqual(t, len(exporters), 8)
	})
}

// =============================================================================
// RegisterExporter Tests
// =============================================================================

func TestManagerRegisterExporter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("register single exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test-exporter", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 1)
		assert.Contains(t, exporters, "test-exporter")
	})

	t.Run("register multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock1 := NewMockExporter("exporter-1", "type-a", true, []integrations.DataType{integrations.DataTypeMetrics})
		mock2 := NewMockExporter("exporter-2", "type-b", true, []integrations.DataType{integrations.DataTypeTraces})
		mock3 := NewMockExporter("exporter-3", "type-c", true, []integrations.DataType{integrations.DataTypeLogs})

		manager.RegisterExporter(mock1)
		manager.RegisterExporter(mock2)
		manager.RegisterExporter(mock3)

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 3)
		assert.Contains(t, exporters, "exporter-1")
		assert.Contains(t, exporters, "exporter-2")
		assert.Contains(t, exporters, "exporter-3")
	})

	t.Run("register exporter with same name overwrites", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock1 := NewMockExporter("same-name", "type-a", true, []integrations.DataType{integrations.DataTypeMetrics})
		mock2 := NewMockExporter("same-name", "type-b", true, []integrations.DataType{integrations.DataTypeTraces})

		manager.RegisterExporter(mock1)
		manager.RegisterExporter(mock2)

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 1)

		exporter, ok := manager.GetExporter("same-name")
		assert.True(t, ok)
		assert.Equal(t, "type-b", exporter.Type())
	})

	t.Run("register disabled exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("disabled-exporter", "test", false, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 1)

		exporter, ok := manager.GetExporter("disabled-exporter")
		assert.True(t, ok)
		assert.False(t, exporter.IsEnabled())
	})
}

// =============================================================================
// UnregisterExporter Tests
// =============================================================================

func TestManagerUnregisterExporter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("unregister existing exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test-exporter", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		assert.Len(t, manager.ListExporters(), 1)

		manager.UnregisterExporter("test-exporter")

		assert.Empty(t, manager.ListExporters())
	})

	t.Run("unregister non-existing exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		// Should not panic
		manager.UnregisterExporter("non-existing")

		assert.Empty(t, manager.ListExporters())
	})

	t.Run("unregister one of multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock1 := NewMockExporter("exporter-1", "type-a", true, []integrations.DataType{integrations.DataTypeMetrics})
		mock2 := NewMockExporter("exporter-2", "type-b", true, []integrations.DataType{integrations.DataTypeTraces})

		manager.RegisterExporter(mock1)
		manager.RegisterExporter(mock2)

		manager.UnregisterExporter("exporter-1")

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 1)
		assert.Contains(t, exporters, "exporter-2")
	})
}

// =============================================================================
// GetExporter Tests
// =============================================================================

func TestManagerGetExporter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("get existing exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test-exporter", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		exporter, ok := manager.GetExporter("test-exporter")
		assert.True(t, ok)
		assert.NotNil(t, exporter)
		assert.Equal(t, "test-exporter", exporter.Name())
	})

	t.Run("get non-existing exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		exporter, ok := manager.GetExporter("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, exporter)
	})

	t.Run("get exporter from built-in integration", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
		}
		manager := integrations.NewManager(config)

		exporter, ok := manager.GetExporter("gcp")
		assert.True(t, ok)
		assert.NotNil(t, exporter)
	})
}

// =============================================================================
// ListExporters Tests
// =============================================================================

func TestManagerListExporters(t *testing.T) {
	logger := zap.NewNop()

	t.Run("no exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		exporters := manager.ListExporters()
		assert.Empty(t, exporters)
	})

	t.Run("with multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 5; i++ {
			mock := NewMockExporter(
				"exporter-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 5)
	})

	t.Run("list includes disabled exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		enabledMock := NewMockExporter("enabled", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		disabledMock := NewMockExporter("disabled", "test", false, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(enabledMock)
		manager.RegisterExporter(disabledMock)

		exporters := manager.ListExporters()
		assert.Len(t, exporters, 2)
		assert.Contains(t, exporters, "enabled")
		assert.Contains(t, exporters, "disabled")
	})
}

// =============================================================================
// Init Tests
// =============================================================================

func TestManagerInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		err := manager.Init(ctx)
		assert.NoError(t, err)
	})

	t.Run("init single exporter success", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		err := manager.Init(ctx)
		assert.NoError(t, err)
		assert.True(t, mock.IsInitCalled())
	})

	t.Run("init multiple exporters success", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mocks := make([]*MockExporter, 3)
		for i := 0; i < 3; i++ {
			mocks[i] = NewMockExporter(
				"exporter-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mocks[i])
		}

		err := manager.Init(ctx)
		assert.NoError(t, err)

		for _, mock := range mocks {
			assert.True(t, mock.IsInitCalled())
		}
	})

	t.Run("init with one exporter failure", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		successMock := NewMockExporter("success", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock := NewMockExporter("fail", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock.SetInitError(errors.New("init failed"))

		manager.RegisterExporter(successMock)
		manager.RegisterExporter(failMock)

		err := manager.Init(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize 1 exporters")
	})

	t.Run("init with multiple exporter failures", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter("fail-"+string(rune('a'+i)), "test", true, []integrations.DataType{integrations.DataTypeMetrics})
			mock.SetInitError(errors.New("init failed"))
			manager.RegisterExporter(mock)
		}

		err := manager.Init(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize 3 exporters")
	})

	t.Run("init with disabled integration", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			GCP: &integrations.GCPConfig{
				Enabled: false,
			},
		}
		manager := integrations.NewManager(config)

		err := manager.Init(ctx)
		assert.NoError(t, err)
	})
}

// =============================================================================
// ValidateAll Tests
// =============================================================================

func TestManagerValidateAll(t *testing.T) {
	logger := zap.NewNop()

	t.Run("empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		errs := manager.ValidateAll()
		assert.Empty(t, errs)
	})

	t.Run("all exporters valid", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock1 := NewMockExporter("valid-1", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		mock2 := NewMockExporter("valid-2", "test", true, []integrations.DataType{integrations.DataTypeTraces})

		manager.RegisterExporter(mock1)
		manager.RegisterExporter(mock2)

		errs := manager.ValidateAll()
		assert.Empty(t, errs)
	})

	t.Run("some exporters invalid", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		validMock := NewMockExporter("valid", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		invalidMock := NewMockExporter("invalid", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		invalidMock.SetValidateError(errors.New("validation failed"))

		manager.RegisterExporter(validMock)
		manager.RegisterExporter(invalidMock)

		errs := manager.ValidateAll()
		assert.Len(t, errs, 1)
	})

	t.Run("all exporters invalid", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter("invalid-"+string(rune('a'+i)), "test", true, []integrations.DataType{integrations.DataTypeMetrics})
			mock.SetValidateError(errors.New("validation failed"))
			manager.RegisterExporter(mock)
		}

		errs := manager.ValidateAll()
		assert.Len(t, errs, 3)
	})
}

// =============================================================================
// Export Tests
// =============================================================================

func TestManagerExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export to single exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
			},
		}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 1, result.TotalSuccess)
		assert.Equal(t, 0, result.TotalFailed)
	})

	t.Run("export to multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter(
				"exporter-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
			},
		}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 3, result.TotalSuccess)
	})

	t.Run("export with disabled exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		enabledMock := NewMockExporter("enabled", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		disabledMock := NewMockExporter("disabled", "test", false, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(enabledMock)
		manager.RegisterExporter(disabledMock)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
			},
		}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.Equal(t, 1, result.TotalSuccess)
		assert.Equal(t, int64(1), enabledMock.GetExportCallCount())
		assert.Equal(t, int64(0), disabledMock.GetExportCallCount())
	})

	t.Run("export with exporter failure", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		successMock := NewMockExporter("success", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock := NewMockExporter("fail", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock.SetExportError(errors.New("export failed"))

		manager.RegisterExporter(successMock)
		manager.RegisterExporter(failMock)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
			},
		}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.False(t, result.IsSuccess())
		assert.Equal(t, 1, result.TotalSuccess)
		assert.Equal(t, 1, result.TotalFailed)
	})

	t.Run("export empty data", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		data := &integrations.TelemetryData{}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
	})

	t.Run("export with all data types", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{
			integrations.DataTypeMetrics,
			integrations.DataTypeTraces,
			integrations.DataTypeLogs,
		})
		manager.RegisterExporter(mock)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
				{Name: "test.metric2", Value: 2.0, Type: integrations.MetricTypeCounter},
			},
			Traces: []integrations.Trace{
				{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
			},
			Logs: []integrations.LogEntry{
				{Level: integrations.LogLevelInfo, Message: "test log"},
			},
		}

		result := manager.Export(ctx, data)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 4, result.TotalItems)
	})
}

// =============================================================================
// ExportMetrics Tests
// =============================================================================

func TestManagerExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics to metrics-supporting exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("metrics-exporter", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		metrics := []integrations.Metric{
			{Name: "test.metric.1", Value: 42.0, Type: integrations.MetricTypeGauge},
			{Name: "test.metric.2", Value: 100.5, Type: integrations.MetricTypeCounter},
		}

		result := manager.ExportMetrics(ctx, metrics)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 2, result.TotalItems)
	})

	t.Run("export metrics skips non-metrics exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		metricsMock := NewMockExporter("metrics", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		tracesMock := NewMockExporter("traces", "test", true, []integrations.DataType{integrations.DataTypeTraces})

		manager.RegisterExporter(metricsMock)
		manager.RegisterExporter(tracesMock)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		}

		result := manager.ExportMetrics(ctx, metrics)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result.Results))
		assert.Equal(t, int64(1), metricsMock.GetExportCallCount())
		assert.Equal(t, int64(0), tracesMock.GetExportCallCount())
	})

	t.Run("export metrics to multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter(
				"metrics-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		}

		result := manager.ExportMetrics(ctx, metrics)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 3, result.TotalSuccess)
	})
}

// =============================================================================
// ExportTraces Tests
// =============================================================================

func TestManagerExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export traces to traces-supporting exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("traces-exporter", "test", true, []integrations.DataType{integrations.DataTypeTraces})
		manager.RegisterExporter(mock)

		traces := []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test-op"},
			{TraceID: "trace-2", SpanID: "span-2", OperationName: "test-op-2"},
		}

		result := manager.ExportTraces(ctx, traces)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 2, result.TotalItems)
	})

	t.Run("export traces skips non-traces exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		tracesMock := NewMockExporter("traces", "test", true, []integrations.DataType{integrations.DataTypeTraces})
		metricsMock := NewMockExporter("metrics", "test", true, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(tracesMock)
		manager.RegisterExporter(metricsMock)

		traces := []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
		}

		result := manager.ExportTraces(ctx, traces)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result.Results))
		assert.Equal(t, int64(1), tracesMock.GetExportCallCount())
		assert.Equal(t, int64(0), metricsMock.GetExportCallCount())
	})
}

// =============================================================================
// ExportLogs Tests
// =============================================================================

func TestManagerExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs to logs-supporting exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("logs-exporter", "test", true, []integrations.DataType{integrations.DataTypeLogs})
		manager.RegisterExporter(mock)

		logs := []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test log 1"},
			{Level: integrations.LogLevelError, Message: "test log 2"},
		}

		result := manager.ExportLogs(ctx, logs)
		assert.NotNil(t, result)
		assert.True(t, result.IsSuccess())
		assert.Equal(t, 2, result.TotalItems)
	})

	t.Run("export logs skips non-logs exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		logsMock := NewMockExporter("logs", "test", true, []integrations.DataType{integrations.DataTypeLogs})
		metricsMock := NewMockExporter("metrics", "test", true, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(logsMock)
		manager.RegisterExporter(metricsMock)

		logs := []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test log"},
		}

		result := manager.ExportLogs(ctx, logs)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result.Results))
		assert.Equal(t, int64(1), logsMock.GetExportCallCount())
		assert.Equal(t, int64(0), metricsMock.GetExportCallCount())
	})
}

// =============================================================================
// HealthCheck Tests
// =============================================================================

func TestManagerHealthCheck(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		health := manager.HealthCheck(ctx)
		assert.NotNil(t, health)
		assert.Empty(t, health)
	})

	t.Run("all exporters healthy", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock1 := NewMockExporter("healthy-1", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		mock2 := NewMockExporter("healthy-2", "test", true, []integrations.DataType{integrations.DataTypeTraces})

		manager.RegisterExporter(mock1)
		manager.RegisterExporter(mock2)

		health := manager.HealthCheck(ctx)
		assert.NotNil(t, health)
		assert.Len(t, health, 2)

		for name, status := range health {
			assert.True(t, status.Healthy, "exporter %s should be healthy", name)
		}
	})

	t.Run("some exporters unhealthy", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		healthyMock := NewMockExporter("healthy", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		unhealthyMock := NewMockExporter("unhealthy", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		unhealthyMock.SetHealthy(false)

		manager.RegisterExporter(healthyMock)
		manager.RegisterExporter(unhealthyMock)

		health := manager.HealthCheck(ctx)
		assert.NotNil(t, health)
		assert.Len(t, health, 2)

		assert.True(t, health["healthy"].Healthy)
		assert.False(t, health["unhealthy"].Healthy)
	})

	t.Run("exporter health check with error", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		errorMock := NewMockExporter("error", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		errorMock.SetHealthError(errors.New("health check failed"))

		manager.RegisterExporter(errorMock)

		health := manager.HealthCheck(ctx)
		assert.NotNil(t, health)
		assert.Len(t, health, 1)
		assert.False(t, health["error"].Healthy)
		assert.NotNil(t, health["error"].LastError)
	})

	t.Run("disabled exporters excluded from health check", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		enabledMock := NewMockExporter("enabled", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		disabledMock := NewMockExporter("disabled", "test", false, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(enabledMock)
		manager.RegisterExporter(disabledMock)

		health := manager.HealthCheck(ctx)
		assert.NotNil(t, health)
		assert.Len(t, health, 1)
		assert.Contains(t, health, "enabled")
		assert.NotContains(t, health, "disabled")
	})
}

// =============================================================================
// Stats Tests
// =============================================================================

func TestManagerStats(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		stats := manager.Stats()
		assert.NotNil(t, stats)
		assert.Empty(t, stats)
	})

	t.Run("stats from mock exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test-type", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		// Perform some exports to generate stats
		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
			},
		}
		manager.Export(ctx, data)

		stats := manager.Stats()
		assert.NotNil(t, stats)
		assert.Len(t, stats, 1)
		assert.Contains(t, stats, "test")
		assert.Equal(t, "test", stats["test"].Name)
		assert.Equal(t, "test-type", stats["test"].Type)
		assert.True(t, stats["test"].Enabled)
	})

	t.Run("stats from real integrations", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			MQTT: &integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
		}
		manager := integrations.NewManager(config)
		_ = manager.Init(ctx)

		stats := manager.Stats()
		assert.NotNil(t, stats)
	})
}

// =============================================================================
// Close Tests
// =============================================================================

func TestManagerClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		err := manager.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close with single exporter", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		err := manager.Close(ctx)
		assert.NoError(t, err)
		assert.True(t, mock.IsCloseCalled())
	})

	t.Run("close with multiple exporters", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mocks := make([]*MockExporter, 3)
		for i := 0; i < 3; i++ {
			mocks[i] = NewMockExporter(
				"exporter-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mocks[i])
		}

		err := manager.Close(ctx)
		assert.NoError(t, err)

		for _, mock := range mocks {
			assert.True(t, mock.IsCloseCalled())
		}
	})

	t.Run("close with exporter error", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		successMock := NewMockExporter("success", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock := NewMockExporter("fail", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		failMock.SetCloseError(errors.New("close failed"))

		manager.RegisterExporter(successMock)
		manager.RegisterExporter(failMock)

		err := manager.Close(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to close 1 exporters")
	})

	t.Run("close is idempotent", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		err1 := manager.Close(ctx)
		assert.NoError(t, err1)

		err2 := manager.Close(ctx)
		assert.NoError(t, err2)
	})

	t.Run("close real integration", func(t *testing.T) {
		config := integrations.ManagerConfig{
			Logger: logger,
			MQTT: &integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
		}
		manager := integrations.NewManager(config)
		_ = manager.Init(ctx)

		err := manager.Close(ctx)
		assert.NoError(t, err)
	})
}

// =============================================================================
// EnabledCount Tests
// =============================================================================

func TestManagerEnabledCount(t *testing.T) {
	logger := zap.NewNop()

	t.Run("empty manager", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		assert.Equal(t, 0, manager.EnabledCount())
	})

	t.Run("all exporters enabled", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter(
				"enabled-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		assert.Equal(t, 3, manager.EnabledCount())
	})

	t.Run("some exporters disabled", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		enabled1 := NewMockExporter("enabled-1", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		enabled2 := NewMockExporter("enabled-2", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		disabled := NewMockExporter("disabled", "test", false, []integrations.DataType{integrations.DataTypeMetrics})

		manager.RegisterExporter(enabled1)
		manager.RegisterExporter(enabled2)
		manager.RegisterExporter(disabled)

		assert.Equal(t, 2, manager.EnabledCount())
	})

	t.Run("all exporters disabled", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 3; i++ {
			mock := NewMockExporter(
				"disabled-"+string(rune('a'+i)),
				"test",
				false,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		assert.Equal(t, 0, manager.EnabledCount())
	})
}

// =============================================================================
// BatchExportResult Tests
// =============================================================================

func TestBatchExportResult(t *testing.T) {
	t.Run("IsSuccess with all successful exports", func(t *testing.T) {
		result := &integrations.BatchExportResult{
			Results: map[string]*integrations.ExportResult{
				"exporter-1": {Success: true, ItemsExported: 10},
				"exporter-2": {Success: true, ItemsExported: 5},
			},
			TotalSuccess: 2,
			TotalFailed:  0,
		}

		assert.True(t, result.IsSuccess())
	})

	t.Run("IsSuccess with some failed exports", func(t *testing.T) {
		result := &integrations.BatchExportResult{
			Results: map[string]*integrations.ExportResult{
				"exporter-1": {Success: true, ItemsExported: 10},
				"exporter-2": {Success: false, Error: errors.New("failed")},
			},
			TotalSuccess: 1,
			TotalFailed:  1,
		}

		assert.False(t, result.IsSuccess())
	})

	t.Run("IsSuccess with all failed exports", func(t *testing.T) {
		result := &integrations.BatchExportResult{
			Results: map[string]*integrations.ExportResult{
				"exporter-1": {Success: false, Error: errors.New("failed 1")},
				"exporter-2": {Success: false, Error: errors.New("failed 2")},
			},
			TotalSuccess: 0,
			TotalFailed:  2,
		}

		assert.False(t, result.IsSuccess())
	})

	t.Run("Errors returns all export errors", func(t *testing.T) {
		err1 := errors.New("error 1")
		err2 := errors.New("error 2")

		result := &integrations.BatchExportResult{
			Results: map[string]*integrations.ExportResult{
				"success":  {Success: true, ItemsExported: 10},
				"failure1": {Success: false, Error: err1},
				"failure2": {Success: false, Error: err2},
			},
		}

		errs := result.Errors()
		assert.Len(t, errs, 2)
		assert.Contains(t, errs, "failure1")
		assert.Contains(t, errs, "failure2")
		assert.Equal(t, err1, errs["failure1"])
		assert.Equal(t, err2, errs["failure2"])
	})

	t.Run("Errors returns empty map when no errors", func(t *testing.T) {
		result := &integrations.BatchExportResult{
			Results: map[string]*integrations.ExportResult{
				"success1": {Success: true, ItemsExported: 10},
				"success2": {Success: true, ItemsExported: 5},
			},
		}

		errs := result.Errors()
		assert.Empty(t, errs)
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestManagerConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("concurrent register and list", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		var wg sync.WaitGroup
		numGoroutines := 10

		// Register exporters concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				mock := NewMockExporter(
					"exporter-"+string(rune('a'+i)),
					"test",
					true,
					[]integrations.DataType{integrations.DataTypeMetrics},
				)
				manager.RegisterExporter(mock)
			}(i)
		}

		// List exporters concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = manager.ListExporters()
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent export", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)

		var wg sync.WaitGroup
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				data := &integrations.TelemetryData{
					Metrics: []integrations.Metric{
						{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
					},
				}
				_ = manager.Export(ctx, data)
			}()
		}

		wg.Wait()
		assert.Equal(t, int64(numGoroutines), mock.GetExportCallCount())
	})

	t.Run("concurrent health check", func(t *testing.T) {
		config := integrations.ManagerConfig{Logger: logger}
		manager := integrations.NewManager(config)

		for i := 0; i < 5; i++ {
			mock := NewMockExporter(
				"exporter-"+string(rune('a'+i)),
				"test",
				true,
				[]integrations.DataType{integrations.DataTypeMetrics},
			)
			manager.RegisterExporter(mock)
		}

		var wg sync.WaitGroup
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = manager.HealthCheck(ctx)
			}()
		}

		wg.Wait()
	})
}

// =============================================================================
// Manager Config Tests
// =============================================================================

func TestManagerConfigDefaults(t *testing.T) {
	config := integrations.ManagerConfig{}

	assert.Nil(t, config.Logger)
	assert.Nil(t, config.Prometheus)
	assert.Nil(t, config.Datadog)
	assert.Nil(t, config.NewRelic)
	assert.Nil(t, config.Splunk)
	assert.Nil(t, config.Elasticsearch)
	assert.Nil(t, config.InfluxDB)
	assert.Nil(t, config.Kafka)
	assert.Nil(t, config.CloudWatch)
	assert.Nil(t, config.Loki)
	assert.Nil(t, config.Jaeger)
	assert.Nil(t, config.Zipkin)
	assert.Nil(t, config.Webhook)
	assert.Nil(t, config.Blackbox)
	assert.Nil(t, config.Percona)
	assert.Nil(t, config.Telegraf)
	assert.Nil(t, config.Alloy)
	assert.Nil(t, config.GCP)
	assert.Nil(t, config.Azure)
	assert.Nil(t, config.Alibaba)
	assert.Nil(t, config.Proxmox)
	assert.Nil(t, config.VMware)
	assert.Nil(t, config.AzureArc)
	assert.Nil(t, config.Cisco)
	assert.Nil(t, config.SNMP)
	assert.Nil(t, config.EBPF)
	assert.Nil(t, config.Nutanix)
	assert.Nil(t, config.MQTT)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkNewManager(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ManagerConfig{
		Logger: logger,
		GCP: &integrations.GCPConfig{
			Enabled:   true,
			ProjectID: "test-project",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewManager(config)
	}
}

func BenchmarkManagerRegisterExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
		manager.RegisterExporter(mock)
	}
}

func BenchmarkManagerListExporters(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	for i := 0; i < 10; i++ {
		mock := NewMockExporter(
			"exporter-"+string(rune('a'+i)),
			"test",
			true,
			[]integrations.DataType{integrations.DataTypeMetrics},
		)
		manager.RegisterExporter(mock)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ListExporters()
	}
}

func BenchmarkManagerExport(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	mock := NewMockExporter("test", "test", true, []integrations.DataType{integrations.DataTypeMetrics})
	manager.RegisterExporter(mock)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Export(ctx, data)
	}
}

func BenchmarkManagerExportMultipleExporters(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	for i := 0; i < 5; i++ {
		mock := NewMockExporter(
			"exporter-"+string(rune('a'+i)),
			"test",
			true,
			[]integrations.DataType{integrations.DataTypeMetrics},
		)
		manager.RegisterExporter(mock)
	}

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Export(ctx, data)
	}
}

func BenchmarkManagerHealthCheck(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	for i := 0; i < 5; i++ {
		mock := NewMockExporter(
			"exporter-"+string(rune('a'+i)),
			"test",
			true,
			[]integrations.DataType{integrations.DataTypeMetrics},
		)
		manager.RegisterExporter(mock)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.HealthCheck(ctx)
	}
}

func BenchmarkManagerGetExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ManagerConfig{Logger: logger}
	manager := integrations.NewManager(config)

	for i := 0; i < 10; i++ {
		mock := NewMockExporter(
			"exporter-"+string(rune('a'+i)),
			"test",
			true,
			[]integrations.DataType{integrations.DataTypeMetrics},
		)
		manager.RegisterExporter(mock)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GetExporter("exporter-e")
	}
}
