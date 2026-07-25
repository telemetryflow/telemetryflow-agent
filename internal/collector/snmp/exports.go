// Package snmp exposes unexported symbols for external test packages.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package snmp

import (
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// SnmpClientExported is the external-facing snmpClient interface. Fakes in
// external _test packages implement this; an adapter installs them into the
// collector via SetClientFactoryExported.
type SnmpClientExported interface {
	Connect() error
	Close() error
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	Walk(oid string, walkFn gosnmp.WalkFunc) error
}

// ClientFactoryExported builds a client for a given agent. Each agent gets its
// own client because hosts and credentials differ per device.
type ClientFactoryExported func(agent config.SNMPAgent) SnmpClientExported

// SetClientFactoryExported injects a test client factory. Production code uses
// the default gosnmp-backed factory installed by NewSNMPCollector.
func (c *SNMPCollector) SetClientFactoryExported(fn ClientFactoryExported) {
	c.clientFactory = func(agent config.SNMPAgent) snmpClient {
		return fn(agent)
	}
	c.defaultFactory = false
}

// DefaultFactoryInstalledExported reports whether the production default
// gosnmp factory is still in use (i.e. no fake has been injected).
func (c *SNMPCollector) DefaultFactoryInstalledExported() bool {
	return c.defaultFactory
}

// CfgIntervalExported returns the effective Interval applied by the constructor.
func (c *SNMPCollector) CfgIntervalExported() time.Duration { return c.cfg.Interval }

// ApplyAgentDefaultsExported wraps applyAgentDefaults for external tests.
func ApplyAgentDefaultsExported(a *config.SNMPAgent) { applyAgentDefaults(a) }

// BuildGoSNMPExported wraps buildGoSNMP so tests can assert v1/v2c/v3 wiring
// without opening a socket.
func BuildGoSNMPExported(agent config.SNMPAgent) *gosnmp.GoSNMP { return buildGoSNMP(agent) }

// BuildV3SecurityExported wraps buildV3Security for external tests.
func BuildV3SecurityExported(auth config.SNMPv3Auth) (gosnmp.SnmpV3MsgFlags, gosnmp.SnmpV3SecurityParameters) {
	return buildV3Security(auth)
}

// ConvertPDUExported wraps convertPDU for external tests.
func ConvertPDUExported(pdu gosnmp.SnmpPDU, baseName string) (string, float64, collector.MetricType, bool) {
	return convertPDU(pdu, baseName)
}

// AgentLabelsExported wraps agentLabels for external tests.
func AgentLabelsExported(a config.SNMPAgent) map[string]string { return agentLabels(a) }

// ExtractIndexExported wraps extractIndex for external tests.
func ExtractIndexExported(fullOID, tableOID string) string { return extractIndex(fullOID, tableOID) }
