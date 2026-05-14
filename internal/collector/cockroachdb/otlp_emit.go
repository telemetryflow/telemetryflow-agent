package cockroachdb

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
		logger: logger.Named("cockroachdb.otlp"),
	}
}

func (e *OTLPEmitter) EmitMetrics(ctx context.Context, metrics []collector.Metric) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	resourceAttrs := resourceAttrsFromMetric(metrics[0])

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("cockroachdb otlp emit: %w", err)
	}

	e.logger.Debug("Emitted metrics via OTLP",
		zap.Int("count", len(metrics)),
	)
	return nil
}

func (e *OTLPEmitter) EmitMetricsForInstance(ctx context.Context, metrics []collector.Metric, inst *crdbInstance) error {
	if len(metrics) == 0 || e.bridge == nil {
		return nil
	}

	resourceAttrs := resourceAttrsFromInstance(inst)

	if err := e.bridge.Export(ctx, metrics, resourceAttrs); err != nil {
		return fmt.Errorf("cockroachdb otlp emit %s: %w", inst.config.Name, err)
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
		"service.name":   "cockroachdb",
		"db.system":      "cockroachdb",
		"db.instance.id": m.Labels["cockroachdb_instance"],
		"net.host.name":  m.Labels["cockroachdb_host"],
	}
	if v, ok := m.Labels["cockroachdb_version"]; ok {
		attrs["db.cockroachdb.version"] = v
	}
	if v, ok := m.Labels["cockroachdb_cluster_id"]; ok {
		attrs["db.cockroachdb.cluster_id"] = v
	}
	return attrs
}

func resourceAttrsFromInstance(inst *crdbInstance) map[string]string {
	attrs := map[string]string{
		"service.name":   "cockroachdb",
		"db.system":      "cockroachdb",
		"db.instance.id": inst.config.Name,
		"net.host.name":  inst.config.Host,
		"net.host.port":  strconv.Itoa(inst.config.SQLPort),
	}
	if inst.version != "" {
		attrs["db.cockroachdb.version"] = inst.version
	}
	if inst.clusterID != "" {
		attrs["db.cockroachdb.cluster_id"] = inst.clusterID
	}
	if inst.config.Database != "" {
		attrs["db.name"] = inst.config.Database
	}
	return attrs
}
