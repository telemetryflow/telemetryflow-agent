// Package ping exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ping

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// PingStatsExported mirrors the internal pingStats struct so external test
// packages can construct probe results without touching unexported fields.
type PingStatsExported struct {
	Host            string
	ResolvedIP      string
	PacketsSent     int
	PacketsReceived int
	Rtts            []time.Duration
	TTL             int
	State           int
}

func (s PingStatsExported) internal() pingStats {
	return pingStats{
		host:            s.Host,
		resolvedIP:      s.ResolvedIP,
		packetsSent:     s.PacketsSent,
		packetsReceived: s.PacketsReceived,
		rtts:            s.Rtts,
		ttl:             s.TTL,
		state:           s.State,
	}
}

// PingerExported is the external-facing pinger interface. Fakes in external
// _test packages implement this; an adapter installs them into the collector.
type PingerExported interface {
	Ping(host string, count int, timeout time.Duration) (PingStatsExported, error)
}

type pingerExportedAdapter struct {
	ext PingerExported
}

func (a *pingerExportedAdapter) ping(host string, count int, timeout time.Duration) (pingStats, error) {
	stats, err := a.ext.Ping(host, count, timeout)
	return stats.internal(), err
}

// SetPingerExported injects a test fake pinger. Production code uses the
// default pinger created by NewPingCollector.
func (c *PingCollector) SetPingerExported(p PingerExported) {
	c.pinger = &pingerExportedAdapter{ext: p}
}

// CfgCountExported returns the effective Count value applied by the constructor.
func (c *PingCollector) CfgCountExported() int { return c.cfg.Count }

// CfgTimeoutExported returns the effective Timeout value applied by the constructor.
func (c *PingCollector) CfgTimeoutExported() time.Duration { return c.cfg.Timeout }

// CfgIntervalBetweenExported returns the effective IntervalBetween value
// applied by the constructor.
func (c *PingCollector) CfgIntervalBetweenExported() time.Duration { return c.cfg.IntervalBetween }

// DefaultPingerInstalledExported reports whether the production defaultPinger
// is still in use (i.e. no fake has been injected).
func (c *PingCollector) DefaultPingerInstalledExported() bool {
	_, ok := c.pinger.(*defaultPinger)
	return ok
}

// BuildPingMetricsExported wraps buildPingMetrics so external tests can drive
// the metric schema checks directly.
func BuildPingMetricsExported(s PingStatsExported, target config.PingTarget, now time.Time) []collector.Metric {
	return buildPingMetrics(s.internal(), target, now)
}
