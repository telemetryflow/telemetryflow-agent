// Package integrations provides fan-out exporters for 30+ third-party
// observability and monitoring platforms (Prometheus Remote Write, Datadog,
// New Relic, Splunk, Elasticsearch, InfluxDB, Kafka, Loki, Jaeger, Zipkin,
// CloudWatch, GCP, Azure, and more), all managed by a single Manager.
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
package integrations

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

const (
	// maxConcurrentTargets bounds how many SNMP targets are polled in parallel
	// per collection cycle, keeping socket/goroutine usage predictable.
	maxConcurrentTargets = 8

	// defaultMaxOIDsPerGet is the fallback batch size for SNMP GET when the
	// client does not report its own MaxOids limit.
	defaultMaxOIDsPerGet = 50

	// healthCheckOID (sysUpTime.0) is a universally implemented scalar used to
	// confirm a target actually answers SNMP, not just that a UDP socket opens.
	healthCheckOID = "1.3.6.1.2.1.1.3.0"
)

// SNMPConfig contains SNMP integration configuration
type SNMPConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	Version        string            `mapstructure:"version"` // v1, v2c, v3
	Community      string            `mapstructure:"community"`
	Targets        []SNMPTarget      `mapstructure:"targets"`
	Port           int               `mapstructure:"port"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	Retries        int               `mapstructure:"retries"`
	ScrapeInterval time.Duration     `mapstructure:"scrape_interval"`
	MaxRepetitions uint32            `mapstructure:"max_repetitions"`
	SecurityLevel  string            `mapstructure:"security_level"` // noAuthNoPriv, authNoPriv, authPriv
	AuthProtocol   string            `mapstructure:"auth_protocol"`  // MD5, SHA
	AuthPassword   string            `mapstructure:"auth_password"`
	PrivProtocol   string            `mapstructure:"priv_protocol"` // DES, AES
	PrivPassword   string            `mapstructure:"priv_password"`
	Username       string            `mapstructure:"username"`
	ContextName    string            `mapstructure:"context_name"`
	MIBs           []string          `mapstructure:"mibs"`
	WalkOIDs       []string          `mapstructure:"walk_oids"`
	GetOIDs        []SNMPOIDConfig   `mapstructure:"get_oids"`
	Labels         map[string]string `mapstructure:"labels"`
}

// SNMPTarget represents an SNMP target device
type SNMPTarget struct {
	Address   string            `mapstructure:"address"`
	Port      int               `mapstructure:"port"`
	Community string            `mapstructure:"community"` // Override global community
	Name      string            `mapstructure:"name"`
	Labels    map[string]string `mapstructure:"labels"`
}

// SNMPOIDConfig represents an OID to collect
type SNMPOIDConfig struct {
	OID         string  `mapstructure:"oid"`
	Name        string  `mapstructure:"name"`
	Type        string  `mapstructure:"type"` // gauge, counter, string
	Unit        string  `mapstructure:"unit"`
	Scale       float64 `mapstructure:"scale"` // Multiplier for value
	Description string  `mapstructure:"description"`
}

// SNMPExporter exports telemetry data via SNMP polling
type SNMPExporter struct {
	*BaseExporter
	config SNMPConfig
}

// defaultSNMPOIDs are the scalar (GET) OIDs polled when no get_oids are
// configured. Only true scalars ending in ".0" belong here — per-interface
// counters live in the IF-MIB tables walked via defaultWalkOIDs. OID names
// follow the standard SNMPv2-MIB / UCD-SNMP-MIB object identifiers so the
// resulting metrics map cleanly onto industry-standard network dashboards.
var defaultSNMPOIDs = []SNMPOIDConfig{
	// SNMPv2-MIB::system group
	{OID: "1.3.6.1.2.1.1.1.0", Name: "sysDescr", Type: "string"},
	{OID: "1.3.6.1.2.1.1.3.0", Name: "sysUpTime", Type: "counter", Unit: "ticks"},
	{OID: "1.3.6.1.2.1.1.5.0", Name: "sysName", Type: "string"},

	// UCD-SNMP-MIB: CPU and Memory (common enterprise scalars)
	{OID: "1.3.6.1.4.1.2021.11.9.0", Name: "ssCpuUser", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.11.10.0", Name: "ssCpuSystem", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.11.11.0", Name: "ssCpuIdle", Type: "gauge", Unit: "percent"},
	{OID: "1.3.6.1.4.1.2021.4.5.0", Name: "memTotalReal", Type: "gauge", Unit: "kilobytes"},
	{OID: "1.3.6.1.4.1.2021.4.6.0", Name: "memAvailReal", Type: "gauge", Unit: "kilobytes"},
	{OID: "1.3.6.1.4.1.2021.4.11.0", Name: "memTotalFree", Type: "gauge", Unit: "kilobytes"},
}

// defaultWalkOIDs are the IF-MIB tables walked when no walk_oids are
// configured. Together ifTable (RFC 1213) and ifXTable (RFC 2233) provide the
// full industry-standard interface dataset — 64-bit HC octet counters, oper
// status, high-speed capacity, errors and discards, and human-readable
// ifName — which back the per-interface utilization view (in/out, capacity,
// errors, discards, status) shown on the platform network dashboard.
var defaultWalkOIDs = []string{
	"1.3.6.1.2.1.2.2",      // IF-MIB::ifTable (ifSpeed, ifOperStatus, ifIn/OutOctets, errors, discards)
	"1.3.6.1.2.1.31.1.1.1", // IF-MIB::ifXTable (ifName, ifHCIn/OutOctets, ifHighSpeed)
}

// NewSNMPExporter creates a new SNMP exporter
func NewSNMPExporter(config SNMPConfig, logger *zap.Logger) *SNMPExporter {
	return &SNMPExporter{
		BaseExporter: NewBaseExporter(
			"snmp",
			"network",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the SNMP exporter
func (s *SNMPExporter) Init(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	if err := s.Validate(); err != nil {
		return err
	}

	// Set defaults
	if s.config.Version == "" {
		s.config.Version = "v2c"
	}
	if s.config.Community == "" {
		s.Logger().Warn("SNMP community string not set; defaulting to 'public' — set an explicit community for v1/v2c targets")
		s.config.Community = "public"
	}
	if s.config.Port == 0 {
		s.config.Port = 161
	}
	if s.config.Timeout == 0 {
		s.config.Timeout = 10 * time.Second
	}
	if s.config.Retries == 0 {
		s.config.Retries = 3
	}
	if s.config.ScrapeInterval == 0 {
		s.config.ScrapeInterval = 60 * time.Second
	}
	if s.config.MaxRepetitions == 0 {
		s.config.MaxRepetitions = 10
	}

	// Add default OIDs if none specified. Scalars are polled via GET; the
	// standard IF-MIB interface tables are walked so per-interface metrics are
	// collected out of the box.
	if len(s.config.GetOIDs) == 0 {
		s.config.GetOIDs = defaultSNMPOIDs
	}
	if len(s.config.WalkOIDs) == 0 {
		s.config.WalkOIDs = defaultWalkOIDs
	}

	s.SetInitialized(true)
	s.Logger().Info("SNMP exporter initialized",
		zap.String("version", s.config.Version),
		zap.Int("targets", len(s.config.Targets)),
	)

	return nil
}

// Validate validates the SNMP configuration
func (s *SNMPExporter) Validate() error {
	if !s.config.Enabled {
		return nil
	}

	if len(s.config.Targets) == 0 {
		return NewValidationError("snmp", "targets", "at least one target is required")
	}

	for i, target := range s.config.Targets {
		if target.Address == "" {
			return NewValidationError("snmp", fmt.Sprintf("targets[%d].address", i), "address is required")
		}
	}

	// Validate SNMPv3 settings
	if s.config.Version == "v3" {
		if s.config.Username == "" {
			return NewValidationError("snmp", "username", "username is required for SNMPv3")
		}
		if s.config.SecurityLevel == "authNoPriv" || s.config.SecurityLevel == "authPriv" {
			if s.config.AuthPassword == "" {
				return NewValidationError("snmp", "auth_password", "auth_password is required for authNoPriv/authPriv")
			}
		}
		if s.config.SecurityLevel == "authPriv" {
			if s.config.PrivPassword == "" {
				return NewValidationError("snmp", "priv_password", "priv_password is required for authPriv")
			}
		}
	}

	return nil
}

// Export exports telemetry data via SNMP
func (s *SNMPExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	metrics, err := s.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for SNMP (it's a data source)
func (s *SNMPExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp is a data source, not a metrics destination")
}

// ExportTraces is not supported by SNMP
func (s *SNMPExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp does not support traces")
}

// ExportLogs is not supported by SNMP
func (s *SNMPExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("snmp does not support log ingestion")
}

// CollectMetrics collects metrics via SNMP polling
func (s *SNMPExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !s.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !s.IsInitialized() {
		return nil, ErrNotInitialized
	}

	now := time.Now()

	// Poll targets concurrently so a slow or timing-out device does not block
	// the rest. Results are collected per-target (indexed) to avoid a shared
	// mutex; the final slice is flattened in target order for stable output.
	results := make([][]Metric, len(s.config.Targets))
	sem := make(chan struct{}, maxConcurrentTargets)
	var wg sync.WaitGroup

	for i, target := range s.config.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target SNMPTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			tags := s.buildTargetTags(target)
			metrics, err := s.pollTarget(ctx, target, now)
			if err != nil {
				s.Logger().Warn("Failed to poll SNMP target",
					zap.String("target", target.Address),
					zap.Error(err),
				)
				results[i] = []Metric{{
					Name:      "snmp_target_up",
					Value:     0,
					Type:      MetricTypeGauge,
					Timestamp: now,
					Tags:      tags,
				}}
				return
			}

			results[i] = append(metrics, Metric{
				Name:      "snmp_target_up",
				Value:     1,
				Type:      MetricTypeGauge,
				Timestamp: now,
				Tags:      tags,
			})
		}(i, target)
	}
	wg.Wait()

	var allMetrics []Metric
	for _, r := range results {
		allMetrics = append(allMetrics, r...)
	}

	return allMetrics, nil
}

// pollTarget polls a single SNMP target using the gosnmp client. It performs
// SNMP GET requests for the configured scalar OIDs and SNMP WALK requests for
// the configured subtree OIDs, converting each returned PDU into a Metric.
func (s *SNMPExporter) pollTarget(ctx context.Context, target SNMPTarget, now time.Time) ([]Metric, error) {
	client, err := s.buildClient(target)
	if err != nil {
		return nil, err
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target.Address, err)
	}
	defer func() {
		if client.Conn != nil {
			_ = client.Conn.Close()
		}
	}()

	// gosnmp v1.44 has no context-aware request API, so bound in-flight I/O to
	// the client Timeout and unblock a blocked Get/Walk on cancellation by
	// closing the underlying conn when ctx is done.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if client.Conn != nil {
				_ = client.Conn.Close()
			}
		case <-done:
		}
	}()

	baseTags := s.buildTargetTags(target)
	var metrics []Metric

	// --- SNMP GET for scalar OIDs ---
	getMetrics, err := s.pollGetOIDs(ctx, client, baseTags, now)
	if err != nil {
		return nil, err
	}
	metrics = append(metrics, getMetrics...)

	// --- SNMP WALK for subtree OIDs ---
	walkMetrics := s.pollWalkOIDs(ctx, client, baseTags, now)
	metrics = append(metrics, walkMetrics...)

	return metrics, nil
}

// pollGetOIDs issues SNMP GET requests (batched) for the configured scalar OIDs.
func (s *SNMPExporter) pollGetOIDs(ctx context.Context, client *gosnmp.GoSNMP, baseTags map[string]string, now time.Time) ([]Metric, error) {
	if len(s.config.GetOIDs) == 0 {
		return nil, nil
	}

	// Index OID config by its dotted OID (without leading dot) for fast lookup.
	oidIndex := make(map[string]SNMPOIDConfig, len(s.config.GetOIDs))
	oids := make([]string, 0, len(s.config.GetOIDs))
	for _, oc := range s.config.GetOIDs {
		key := strings.TrimPrefix(oc.OID, ".")
		oidIndex[key] = oc
		oids = append(oids, oc.OID)
	}

	var metrics []Metric
	// gosnmp allows a bounded number of OIDs per GET PDU; honour the client's
	// own MaxOids limit and fall back to a conservative default.
	maxOIDsPerGet := client.MaxOids
	if maxOIDsPerGet <= 0 {
		maxOIDsPerGet = defaultMaxOIDsPerGet
	}
	for start := 0; start < len(oids); start += maxOIDsPerGet {
		select {
		case <-ctx.Done():
			return metrics, ctx.Err()
		default:
		}

		end := start + maxOIDsPerGet
		if end > len(oids) {
			end = len(oids)
		}

		result, err := client.Get(oids[start:end])
		if err != nil {
			return nil, fmt.Errorf("snmp get: %w", err)
		}

		for _, pdu := range result.Variables {
			key := strings.TrimPrefix(pdu.Name, ".")
			oc, ok := oidIndex[key]
			if !ok {
				continue
			}
			if m, ok := s.pduToMetric(pdu, oc, baseTags, now, ""); ok {
				metrics = append(metrics, m)
			}
		}
	}

	return metrics, nil
}

// pollWalkOIDs issues SNMP WALK requests for the configured subtree OIDs. Walk
// errors are logged per-OID and do not abort the whole poll, so a single bad
// subtree does not lose the scalar metrics already collected.
func (s *SNMPExporter) pollWalkOIDs(ctx context.Context, client *gosnmp.GoSNMP, baseTags map[string]string, now time.Time) []Metric {
	if len(s.config.WalkOIDs) == 0 {
		return nil
	}

	var metrics []Metric
	for _, root := range s.config.WalkOIDs {
		select {
		case <-ctx.Done():
			return metrics
		default:
		}

		rootKey := strings.TrimPrefix(root, ".")
		walkFn := func(pdu gosnmp.SnmpPDU) error {
			// Derive the table index (the suffix after the walked root) so
			// per-row metrics stay distinguishable (e.g. per-interface stats).
			index := strings.TrimPrefix(strings.TrimPrefix(pdu.Name, "."), rootKey)
			index = strings.TrimPrefix(index, ".")

			oc := SNMPOIDConfig{
				OID:  strings.TrimPrefix(pdu.Name, "."),
				Name: s.walkMetricName(root, index),
				Type: "gauge",
			}
			if m, ok := s.pduToMetric(pdu, oc, baseTags, now, index); ok {
				metrics = append(metrics, m)
			}
			return nil
		}

		var err error
		if client.Version == gosnmp.Version1 {
			err = client.Walk(root, walkFn)
		} else {
			err = client.BulkWalk(root, walkFn)
		}
		if err != nil {
			s.Logger().Warn("SNMP walk failed",
				zap.String("oid", root),
				zap.Error(err),
			)
		}
	}

	return metrics
}

// pduToMetric converts a single SNMP PDU into a Metric using the OID config.
// String/opaque values are skipped (returns ok=false) since they have no
// meaningful numeric representation. When index is non-empty it is attached as
// a tag to distinguish table rows.
func (s *SNMPExporter) pduToMetric(pdu gosnmp.SnmpPDU, oc SNMPOIDConfig, baseTags map[string]string, now time.Time, index string) (Metric, bool) {
	if oc.Type == "string" {
		return Metric{}, false
	}

	value, ok := parseOIDValue(pduValue(pdu), oc)
	if !ok {
		return Metric{}, false
	}

	tags := make(map[string]string, len(baseTags)+3)
	for k, v := range baseTags {
		tags[k] = v
	}
	tags["oid"] = oc.OID
	if oc.Description != "" {
		tags["description"] = oc.Description
	}
	if index != "" {
		tags["index"] = index
	}

	metricType := MetricTypeGauge
	if oc.Type == "counter" {
		metricType = MetricTypeCounter
	}

	return Metric{
		Name:      fmt.Sprintf("snmp_%s", s.sanitizeName(oc.Name)),
		Value:     value,
		Type:      metricType,
		Timestamp: now,
		Tags:      tags,
		Unit:      oc.Unit,
	}, true
}

// walkMetricName builds a metric name for a walked OID. Callers that configure
// a friendly root name can rely on sanitizeName; here we fall back to the raw
// OID root so metrics remain queryable even without a MIB name.
func (s *SNMPExporter) walkMetricName(root, index string) string {
	_ = index // index is carried as a tag, not part of the metric name
	return "walk_" + strings.TrimPrefix(root, ".")
}

// buildClient constructs and configures a gosnmp client for the given target,
// applying per-target overrides (port, community) over the global config.
func (s *SNMPExporter) buildClient(target SNMPTarget) (*gosnmp.GoSNMP, error) {
	port := target.Port
	if port == 0 {
		port = s.config.Port
	}
	if port == 0 {
		port = 161
	}

	community := target.Community
	if community == "" {
		community = s.config.Community
	}

	timeout := s.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := &gosnmp.GoSNMP{
		Target:         target.Address,
		Port:           uint16(port),
		Community:      community,
		Version:        snmpVersion(s.config.Version),
		Timeout:        timeout,
		Retries:        s.config.Retries,
		MaxRepetitions: s.config.MaxRepetitions,
	}

	if client.Version == gosnmp.Version3 {
		if err := s.applyV3Security(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// applyV3Security configures SNMPv3 USM (User-based Security Model) parameters.
func (s *SNMPExporter) applyV3Security(client *gosnmp.GoSNMP) error {
	msgFlags, err := v3MsgFlags(s.config.SecurityLevel)
	if err != nil {
		return err
	}

	usm := &gosnmp.UsmSecurityParameters{
		UserName: s.config.Username,
	}

	if msgFlags&gosnmp.AuthNoPriv != 0 {
		usm.AuthenticationProtocol = v3AuthProtocol(s.config.AuthProtocol)
		usm.AuthenticationPassphrase = s.config.AuthPassword
	}
	if msgFlags&gosnmp.AuthPriv == gosnmp.AuthPriv {
		usm.PrivacyProtocol = v3PrivProtocol(s.config.PrivProtocol)
		usm.PrivacyPassphrase = s.config.PrivPassword
	}

	client.SecurityModel = gosnmp.UserSecurityModel
	client.MsgFlags = msgFlags
	client.SecurityParameters = usm
	if s.config.ContextName != "" {
		client.ContextName = s.config.ContextName
	}

	return nil
}

// snmpVersion maps a configured version string ("1", "v1", "2c", "v2c", "3",
// "v3") to the gosnmp version constant, defaulting to v2c.
func snmpVersion(v string) gosnmp.SnmpVersion {
	switch strings.TrimPrefix(strings.ToLower(v), "v") {
	case "1":
		return gosnmp.Version1
	case "3":
		return gosnmp.Version3
	default:
		return gosnmp.Version2c
	}
}

// v3MsgFlags maps a SNMPv3 security level string to gosnmp message flags.
func v3MsgFlags(level string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(level) {
	case "", "noauthnopriv":
		return gosnmp.NoAuthNoPriv, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv, nil
	case "authpriv":
		return gosnmp.AuthPriv, nil
	default:
		return 0, fmt.Errorf("invalid snmp v3 security_level %q", level)
	}
}

// v3AuthProtocol maps an auth protocol string to a gosnmp constant.
func v3AuthProtocol(p string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(p) {
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
		return gosnmp.MD5
	}
}

// v3PrivProtocol maps a privacy protocol string to a gosnmp constant.
func v3PrivProtocol(p string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(p) {
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.DES
	}
}

// pduValue extracts a Go-native value from an SNMP PDU. OctetString and
// ObjectIdentifier come back as []byte/string; numeric types come back as their
// integer forms. gosnmp exposes counters/gauges as uint and Counter64 via a
// big.Int-free uint64, all of which parseOIDValue understands.
func pduValue(pdu gosnmp.SnmpPDU) interface{} {
	switch pdu.Type {
	case gosnmp.OctetString:
		if b, ok := pdu.Value.([]byte); ok {
			return b
		}
	case gosnmp.Counter64:
		return gosnmp.ToBigInt(pdu.Value).Uint64()
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Uinteger32, gosnmp.TimeTicks, gosnmp.Integer:
		return gosnmp.ToBigInt(pdu.Value).Int64()
	}
	return pdu.Value
}

// buildTargetTags builds tags for a target
func (s *SNMPExporter) buildTargetTags(target SNMPTarget) map[string]string {
	tags := make(map[string]string)

	// Add global labels
	for k, v := range s.config.Labels {
		tags[k] = v
	}

	// Add target-specific labels
	for k, v := range target.Labels {
		tags[k] = v
	}

	tags["target"] = target.Address
	if target.Name != "" {
		tags["target_name"] = target.Name
	}
	tags["snmp_version"] = s.config.Version

	return tags
}

// sanitizeName converts an OID name to a valid metric name
func (s *SNMPExporter) sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

// parseOIDValue parses an SNMP value into a float64
func parseOIDValue(value interface{}, oidConfig SNMPOIDConfig) (float64, bool) {
	var result float64

	switch v := value.(type) {
	case int:
		result = float64(v)
	case int64:
		result = float64(v)
	case uint:
		result = float64(v)
	case uint64:
		result = float64(v)
	case float64:
		result = v
	case float32:
		result = float64(v)
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		result = f
	case []byte:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return 0, false
		}
		result = f
	default:
		return 0, false
	}

	// Apply scale if configured
	if oidConfig.Scale != 0 {
		result *= oidConfig.Scale
	}

	return result, true
}

// probeTarget confirms a target answers SNMP by connecting and issuing a GET
// for sysUpTime.0. It returns true only on a successful, error-free response.
func (s *SNMPExporter) probeTarget(target SNMPTarget) bool {
	client, err := s.buildClient(target)
	if err != nil {
		return false
	}
	if err := client.Connect(); err != nil {
		return false
	}
	defer func() {
		if client.Conn != nil {
			_ = client.Conn.Close()
		}
	}()

	result, err := client.Get([]string{healthCheckOID})
	if err != nil || result == nil || len(result.Variables) == 0 {
		return false
	}
	return result.Variables[0].Type != gosnmp.NoSuchObject &&
		result.Variables[0].Type != gosnmp.NoSuchInstance
}

// Health checks the health of SNMP targets
func (s *SNMPExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !s.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()
	reachable := 0
	total := len(s.config.Targets)

	// UDP is connectionless, so a DialTimeout always "succeeds" — it proves
	// nothing about the device. Issue a real SNMP GET for sysUpTime.0 instead
	// so health reflects whether the target actually answers SNMP.
	for _, target := range s.config.Targets {
		if s.probeTarget(target) {
			reachable++
		}
	}

	healthy := reachable > 0
	message := fmt.Sprintf("%d/%d targets reachable", reachable, total)

	return &HealthStatus{
		Healthy:   healthy,
		Message:   message,
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"version":           s.config.Version,
			"total_targets":     total,
			"reachable_targets": reachable,
		},
	}, nil
}

// Close closes the SNMP exporter
func (s *SNMPExporter) Close(ctx context.Context) error {
	s.SetInitialized(false)
	s.Logger().Info("SNMP exporter closed")
	return nil
}
