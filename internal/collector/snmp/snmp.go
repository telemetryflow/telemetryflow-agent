// Package snmp implements a TelemetryFlow Agent network collector that polls
// SNMP-managed devices (v1/v2c/v3) for scalar OID values and table subtrees
// and emits per-agent metrics under the network.snmp.* namespace.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package snmp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "snmp"

// SNMPCollector polls one or more SNMP agents on every Collect cycle.
type SNMPCollector struct {
	cfg            config.SNMPCollectorConfig
	logger         *zap.Logger
	mu             sync.RWMutex
	running        bool
	stopChan       chan struct{}
	clientFactory  func(agent config.SNMPAgent) snmpClient
	defaultFactory bool
}

// snmpClient abstracts the gosnmp GoSNMP API for testability.
// The production default is *defaultClient; tests inject fakes via
// SetClientFactoryExported.
type snmpClient interface {
	Connect() error
	Close() error
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	Walk(oid string, walkFn gosnmp.WalkFunc) error
}

// NewSNMPCollector constructs an SNMPCollector with sensible defaults applied
// to Interval (60s) and each agent (Port 161, Timeout 10s, Retries 3,
// Version "2c", SecurityLevel "authPriv") when they are zero.
func NewSNMPCollector(cfg config.SNMPCollectorConfig, logger *zap.Logger) *SNMPCollector {
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	for i := range cfg.Agents {
		applyAgentDefaults(&cfg.Agents[i])
	}
	c := &SNMPCollector{
		cfg:            cfg,
		logger:         logger.Named(collectorName),
		stopChan:       make(chan struct{}),
		defaultFactory: true,
	}
	c.clientFactory = func(agent config.SNMPAgent) snmpClient {
		return &defaultClient{agent: agent}
	}
	return c
}

// applyAgentDefaults fills in zero-value fields on an SNMPAgent.
func applyAgentDefaults(a *config.SNMPAgent) {
	if a.Port == 0 {
		a.Port = 161
	}
	if a.Timeout <= 0 {
		a.Timeout = 10 * time.Second
	}
	if a.Retries == 0 {
		a.Retries = 3
	}
	if a.Version == "" {
		a.Version = "2c"
	}
	if a.Version == "3" && a.Auth.SecurityLevel == "" {
		a.Auth.SecurityLevel = "authPriv"
	}
}

func (c *SNMPCollector) Name() string { return collectorName }

func (c *SNMPCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *SNMPCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("snmp collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("SNMP collector starting", zap.Int("agents", len(c.cfg.Agents)))
	return nil
}

func (c *SNMPCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect polls every configured agent once and emits metrics. Per-agent
// connection failures emit a network.snmp.state{agent=...}=0 metric and the
// collector continues with the next agent. Cancellation between agents is
// honored.
func (c *SNMPCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Agents) == 0 {
		return nil, nil
	}
	now := time.Now()
	var all []collector.Metric
	for _, agent := range c.cfg.Agents {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		all = append(all, c.collectAgent(agent, now)...)
	}
	return all, nil
}

// collectAgent performs one collection cycle against a single agent.
// A Connect failure yields a single state=0 metric; a successful connect
// yields field metrics, table metrics, and a trailing state=1 metric.
func (c *SNMPCollector) collectAgent(agent config.SNMPAgent, now time.Time) []collector.Metric {
	labels := agentLabels(agent)
	client := c.clientFactory(agent)
	if err := client.Connect(); err != nil {
		c.logger.Warn("SNMP connect failed",
			zap.String("agent", agent.Name),
			zap.String("host", agent.Host),
			zap.Error(err),
		)
		return []collector.Metric{stateMetric(labels, 0, now)}
	}
	defer func() { _ = client.Close() }()

	out := make([]collector.Metric, 0, len(c.cfg.Fields)+len(c.cfg.Tables)+1)

	// Scalar fields via Get.
	if len(c.cfg.Fields) > 0 {
		oids := make([]string, 0, len(c.cfg.Fields))
		for _, f := range c.cfg.Fields {
			oids = append(oids, f.OID)
		}
		pkt, err := client.Get(oids)
		if err != nil {
			c.logger.Warn("SNMP Get failed",
				zap.String("agent", agent.Name),
				zap.String("host", agent.Host),
				zap.Error(err),
			)
		} else {
			for i, f := range c.cfg.Fields {
				var pdu gosnmp.SnmpPDU
				if pkt != nil && i < len(pkt.Variables) {
					pdu = pkt.Variables[i]
				}
				out = append(out, buildFieldMetric(pdu, f, labels, now)...)
			}
		}
	}

	// Tables via Walk.
	for _, t := range c.cfg.Tables {
		walkErr := client.Walk(t.OID, func(pdu gosnmp.SnmpPDU) error {
			out = append(out, buildTableMetric(pdu, t, labels, now)...)
			return nil
		})
		if walkErr != nil {
			c.logger.Warn("SNMP Walk failed",
				zap.String("agent", agent.Name),
				zap.String("table", t.Name),
				zap.Error(walkErr),
			)
		}
	}

	// Agent responded to at least the connect phase: considered up.
	out = append(out, stateMetric(labels, 1, now))
	return out
}

// agentLabels builds the base label set for an agent. The agent label falls
// back to Host when Name is empty.
func agentLabels(a config.SNMPAgent) map[string]string {
	agent := a.Name
	if agent == "" {
		agent = a.Host
	}
	return map[string]string{
		"agent":      agent,
		"agent_name": a.Name,
		"host":       a.Host,
	}
}

func stateMetric(labels map[string]string, state int, now time.Time) collector.Metric {
	return collector.Metric{
		Name:        "network.snmp.state",
		Type:        collector.MetricTypeGauge,
		Value:       float64(state),
		Timestamp:   now,
		Description: "SNMP agent state: 1 = up, 0 = down",
		Labels:      copyLabels(labels),
	}
}

func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// buildFieldMetric converts a scalar SnmpPDU into zero or one metrics under
// network.snmp.<field_name>.
func buildFieldMetric(pdu gosnmp.SnmpPDU, field config.SNMPField, labels map[string]string, now time.Time) []collector.Metric {
	name, value, mtype, ok := convertPDU(pdu, "network.snmp."+field.Name)
	if !ok {
		return nil
	}
	return []collector.Metric{{
		Name:      name,
		Type:      mtype,
		Value:     value,
		Timestamp: now,
		Unit:      field.Unit,
		Labels:    copyLabels(labels),
	}}
}

// buildTableMetric converts a walked SnmpPDU into zero or one metrics under
// network.snmp.<table_name>. When IndexAsTag is set, the trailing OID index is
// added as the "index" label.
func buildTableMetric(pdu gosnmp.SnmpPDU, table config.SNMPTable, labels map[string]string, now time.Time) []collector.Metric {
	name, value, mtype, ok := convertPDU(pdu, "network.snmp."+table.Name)
	if !ok {
		return nil
	}
	m := collector.Metric{
		Name:      name,
		Type:      mtype,
		Value:     value,
		Timestamp: now,
		Labels:    copyLabels(labels),
	}
	if table.IndexAsTag {
		m.Labels["index"] = extractIndex(pdu.Name, table.OID)
	}
	return []collector.Metric{m}
}

// convertPDU maps a gosnmp.SnmpPDU value to a metric name, float64 value, and
// metric type. Returns ok=false for Null / NoSuchObject / NoSuchInstance /
// EndOfMibView / UnknownType and nil values. OctetStrings that are not numeric
// are emitted as a <base>_len gauge holding the byte length, mirroring upstream
// SNMP agent behaviour for non-numeric strings.
func convertPDU(pdu gosnmp.SnmpPDU, baseName string) (name string, value float64, mtype collector.MetricType, ok bool) {
	if pdu.Value == nil {
		return "", 0, "", false
	}
	switch pdu.Type {
	case gosnmp.Null, gosnmp.UnknownType, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return "", 0, "", false
	case gosnmp.OctetString, gosnmp.IPAddress:
		s := octetToString(pdu.Value)
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return baseName, f, collector.MetricTypeGauge, true
		}
		return baseName + "_len", float64(len(s)), collector.MetricTypeGauge, true
	case gosnmp.Counter32, gosnmp.Counter64, gosnmp.TimeTicks:
		return baseName, bigToFloat(pdu.Value), collector.MetricTypeCounter, true
	case gosnmp.Integer, gosnmp.Gauge32, gosnmp.Uinteger32:
		return baseName, bigToFloat(pdu.Value), collector.MetricTypeGauge, true
	default:
		return baseName, bigToFloat(pdu.Value), collector.MetricTypeGauge, true
	}
}

// octetToString coerces an OctetString / IPAddress value to a string.
func octetToString(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// bigToFloat converts any gosnmp numeric value to float64 via gosnmp.ToBigInt.
func bigToFloat(v any) float64 {
	bi := gosnmp.ToBigInt(v)
	if bi == nil {
		return 0
	}
	f, _ := bi.Float64()
	return f
}

// extractIndex returns the trailing OID components that form the row index,
// stripping the table OID prefix and any leading dot.
func extractIndex(fullOID, tableOID string) string {
	normalized := fullOID
	if !strings.HasPrefix(normalized, ".") {
		normalized = "." + normalized
	}
	prefix := tableOID
	if !strings.HasPrefix(prefix, ".") {
		prefix = "." + prefix
	}
	idx := strings.TrimPrefix(normalized, prefix)
	return strings.TrimPrefix(idx, ".")
}

// --- default gosnmp-backed client ---

// buildGoSNMP constructs a *gosnmp.GoSNMP from an agent config without
// connecting. Split out so tests can assert v1/v2c/v3 wiring.
func buildGoSNMP(agent config.SNMPAgent) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{
		Target:    agent.Host,
		Port:      uint16(agent.Port),
		Timeout:   agent.Timeout,
		Retries:   agent.Retries,
		Transport: "udp",
	}
	switch strings.ToLower(agent.Version) {
	case "1":
		g.Version = gosnmp.Version1
		g.Community = agent.Community
	case "3":
		g.Version = gosnmp.Version3
		msgFlags, sp := buildV3Security(agent.Auth)
		g.MsgFlags = msgFlags
		g.SecurityModel = gosnmp.UserSecurityModel
		g.SecurityParameters = sp
	default: // "2c" and any unset value
		g.Version = gosnmp.Version2c
		g.Community = agent.Community
	}
	return g
}

// defaultClient wraps gosnmp.GoSNMP to satisfy snmpClient.
type defaultClient struct {
	agent  config.SNMPAgent
	client *gosnmp.GoSNMP
}

func (d *defaultClient) Connect() error {
	d.client = buildGoSNMP(d.agent)
	return d.client.Connect()
}

func (d *defaultClient) Close() error {
	if d.client == nil {
		return nil
	}
	return d.client.Close()
}

func (d *defaultClient) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return d.client.Get(oids)
}

func (d *defaultClient) Walk(oid string, walkFn gosnmp.WalkFunc) error {
	return d.client.Walk(oid, walkFn)
}

// buildV3Security maps config.SNMPv3Auth into gosnmp message flags and USM
// security parameters.
func buildV3Security(auth config.SNMPv3Auth) (gosnmp.SnmpV3MsgFlags, gosnmp.SnmpV3SecurityParameters) {
	level := strings.ToLower(auth.SecurityLevel)
	if level == "" {
		level = "authpriv"
	}
	var msgFlags gosnmp.SnmpV3MsgFlags
	switch level {
	case "noauthnopriv":
		msgFlags = gosnmp.NoAuthNoPriv
	case "authnopriv":
		msgFlags = gosnmp.AuthNoPriv
	default:
		msgFlags = gosnmp.AuthPriv
	}
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 auth.Username,
		AuthenticationPassphrase: auth.AuthPassword,
		PrivacyPassphrase:        auth.PrivPassword,
		AuthenticationProtocol:   authProtocol(auth.AuthProtocol, level),
		PrivacyProtocol:          privProtocol(auth.PrivProtocol, level),
	}
	return msgFlags, sp
}

func authProtocol(name, level string) gosnmp.SnmpV3AuthProtocol {
	if level == "noauthnopriv" {
		return gosnmp.NoAuth
	}
	switch strings.ToUpper(name) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func privProtocol(name, level string) gosnmp.SnmpV3PrivProtocol {
	if level == "noauthnopriv" || level == "authnopriv" {
		return gosnmp.NoPriv
	}
	switch strings.ToUpper(name) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.AES
	}
}

// Compile-time guard: SNMPCollector satisfies collector.Collector.
var _ collector.Collector = (*SNMPCollector)(nil)
