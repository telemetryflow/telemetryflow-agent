// IF-MIB interface-metrics collector: on each cycle it polls every configured
// device's IF-MIB counters, computes per-interface utilization from the delta
// against the previous cycle, and pushes samples to the platform endpoint.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "snmp_interface"

// prevSample records the last raw counters seen for one interface so the next
// cycle can compute a delta over the true elapsed interval.
type prevSample struct {
	inOctets  uint64
	outOctets uint64
	is64bit   bool
	at        time.Time
}

// Collector implements collector.Collector for IF-MIB interface metrics.
type Collector struct {
	cfg      config.SNMPInterfaceCollectorConfig
	logger   *zap.Logger
	exporter *exporter

	// pollerFactory builds a Poller per device; overridable in tests.
	pollerFactory func(config.SNMPInterfaceDevice) Poller

	mu      sync.Mutex
	running bool
	prev    map[string]prevSample // key: deviceID|ifIndex
}

// NewCollector constructs an IF-MIB collector, applying config defaults.
func NewCollector(cfg config.SNMPInterfaceCollectorConfig, logger *zap.Logger) *Collector {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetryAttempts <= 0 {
		cfg.MaxRetryAttempts = 3
	}
	named := logger.Named(collectorName)
	return &Collector{
		cfg:           cfg,
		logger:        named,
		exporter:      newExporter(cfg, named),
		pollerFactory: NewGoSNMPPoller,
		prev:          make(map[string]prevSample),
	}
}

// SetPollerFactory injects a poller factory (used by tests to avoid a live device).
func (c *Collector) SetPollerFactory(fn func(config.SNMPInterfaceDevice) Poller) {
	c.pollerFactory = fn
}

func (c *Collector) Name() string { return collectorName }

func (c *Collector) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("snmp interface collector already running")
	}
	c.running = true
	c.logger.Info("SNMP interface (IF-MIB) collector starting",
		zap.Int("devices", len(c.cfg.Devices)),
		zap.Duration("interval", c.cfg.Interval),
	)
	return nil
}

func (c *Collector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	return nil
}

// Collect polls every device, computes utilization, and pushes samples to the
// ingestion endpoint. Per-device poll failures are logged and skipped; the
// cycle continues with the next device. It returns no collector.Metric values
// because the ingestion endpoint is the sink for this collector.
func (c *Collector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Devices) == 0 {
		return nil, nil
	}

	now := time.Now()
	timestamp := now.UTC().Format("2006-01-02T15:04:05.000Z")
	var samples []InterfaceSample

	for _, device := range c.cfg.Devices {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		samples = append(samples, c.collectDevice(ctx, device, now, timestamp)...)
	}

	if err := c.exporter.Push(ctx, samples); err != nil {
		c.logger.Warn("failed to push interface samples", zap.Error(err))
		return nil, err
	}
	c.logger.Debug("pushed interface samples", zap.Int("samples", len(samples)))
	return nil, nil
}

// collectDevice polls one device and builds its samples, updating the previous
// snapshot cache for the next cycle.
func (c *Collector) collectDevice(ctx context.Context, device config.SNMPInterfaceDevice, now time.Time, timestamp string) []InterfaceSample {
	poller := c.pollerFactory(device)
	readings, err := poller.Poll(ctx)
	if err != nil {
		c.logger.Warn("SNMP IF-MIB poll failed",
			zap.String("device", device.DeviceName),
			zap.String("host", device.Host),
			zap.Error(err),
		)
		return nil
	}

	out := make([]InterfaceSample, 0, len(readings))
	for _, r := range readings {
		out = append(out, c.buildSample(device, r, now, timestamp))
	}
	return out
}

// buildSample computes utilization against the cached previous counters and
// stores the new counters for the next cycle.
func (c *Collector) buildSample(device config.SNMPInterfaceDevice, r InterfaceReading, now time.Time, timestamp string) InterfaceSample {
	key := device.DeviceID + "|" + strconv.Itoa(r.IfIndex)

	c.mu.Lock()
	prev, hasPrev := c.prev[key]
	c.prev[key] = prevSample{
		inOctets:  r.InOctets,
		outOctets: r.OutOctets,
		is64bit:   r.Is64Bit,
		at:        now,
	}
	c.mu.Unlock()

	var inPct, outPct float64
	if hasPrev {
		intervalSeconds := now.Sub(prev.at).Seconds()
		inPct = Utilization(prev.inOctets, r.InOctets, r.Is64Bit, true, intervalSeconds, r.IfSpeedBps)
		outPct = Utilization(prev.outOctets, r.OutOctets, r.Is64Bit, true, intervalSeconds, r.IfSpeedBps)
	}

	return InterfaceSample{
		DeviceID:          device.DeviceID,
		DeviceName:        device.DeviceName,
		IfIndex:           r.IfIndex,
		IfName:            r.IfName,
		IfSpeedBps:        r.IfSpeedBps,
		InOctets:          r.InOctets,
		OutOctets:         r.OutOctets,
		InErrors:          r.InErrors,
		OutErrors:         r.OutErrors,
		InDiscards:        r.InDiscards,
		OutDiscards:       r.OutDiscards,
		InUtilizationPct:  inPct,
		OutUtilizationPct: outPct,
		OperStatus:        r.OperStatus,
		Timestamp:         timestamp,
	}
}

// Compile-time guard: *Collector satisfies collector.Collector.
var _ collector.Collector = (*Collector)(nil)
