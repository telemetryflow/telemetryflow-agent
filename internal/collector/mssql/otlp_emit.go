package mssql

import (
	"context"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

type OTLPEmitter struct {
	bridge *exporter.OTLPMetricBridge
	logger *zap.Logger
}

func NewOTLPEmitter(bridge *exporter.OTLPMetricBridge, logger *zap.Logger) *OTLPEmitter {
	return &OTLPEmitter{
		bridge: bridge,
		logger: logger.Named("mssql.otlp"),
	}
}

func (e *OTLPEmitter) EmitMetrics(ctx context.Context, metrics []collector.Metric) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	resourceAttrs := resourceAttrsFromMetric(metrics[0])

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("mssql otlp emit: %w", err)
	}

	e.logger.Debug("Emitted metrics via OTLP",
		zap.Int("count", len(metrics)),
	)
	return nil
}

func (e *OTLPEmitter) EmitMetricsForInstance(ctx context.Context, metrics []collector.Metric, inst *mssqlInstance) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	resourceAttrs := resourceAttrsFromInstance(inst)

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("mssql otlp emit %s: %w", inst.config.Name, err)
	}

	e.logger.Debug("Emitted metrics via OTLP",
		zap.String("instance", inst.config.Name),
		zap.Int("count", len(metrics)),
	)
	return nil
}

func (e *OTLPEmitter) Shutdown(ctx context.Context) error {
	if e.bridge != nil {
		return e.bridge.Shutdown(ctx)
	}
	return nil
}

func resourceAttrsFromMetric(m collector.Metric) map[string]string {
	attrs := map[string]string{
		"service.name":   "mssql",
		"db.system":      "mssql",
		"db.instance.id": m.Labels["mssql_instance"],
		"net.host.name":  m.Labels["mssql_host"],
	}
	if v, ok := m.Labels["mssql_version"]; ok {
		attrs["db.mssql.version"] = v
	}
	return attrs
}

func resourceAttrsFromInstance(inst *mssqlInstance) map[string]string {
	attrs := map[string]string{
		"service.name":   "mssql",
		"db.system":      "mssql",
		"db.instance.id": inst.config.Name,
		"net.host.name":  inst.config.Host,
		"net.host.port":  strconv.Itoa(inst.config.Port),
	}
	if inst.version != "" {
		attrs["db.mssql.version"] = inst.version
	}
	if inst.config.Database != "" {
		attrs["db.name"] = inst.config.Database
	}
	if inst.config.InstanceName != "" {
		attrs["db.mssql.instance_name"] = inst.config.InstanceName
	}
	if inst.engineEdition > 0 {
		attrs["db.mssql.engine_edition"] = strconv.Itoa(inst.engineEdition)
	}
	return attrs
}
