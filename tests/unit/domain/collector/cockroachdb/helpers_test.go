// Package cockroachdb_test contains unit tests for the CockroachDB collector.
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
package cockroachdb_test

import (
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		name   string
		num    float64
		denom  float64
		expect float64
	}{
		{"normal", 10, 2, 5},
		{"zero_denom", 10, 0, 0},
		{"zero_num", 0, 5, 0},
		{"fractional", 1, 3, 1.0 / 3.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cockroachdb.SafeDivExported(tc.num, tc.denom)
			assert.InDelta(t, tc.expect, got, 1e-9)
		})
	}
}

func TestMakeMetric(t *testing.T) {
	labels := map[string]string{"a": "b"}
	m := cockroachdb.MakeMetricExported("db.test", 42, collector.MetricTypeGauge, labels)

	assert.Equal(t, "db.test", m.Name)
	assert.Equal(t, collector.MetricTypeGauge, m.Type)
	assert.Equal(t, 42.0, m.Value)
	assert.Equal(t, "b", m.Labels["a"])
	assert.False(t, m.Timestamp.IsZero())

	// Verify labels are copied, not aliased.
	labels["a"] = "changed"
	assert.Equal(t, "b", m.Labels["a"])
}

func TestEmitCounterRate(t *testing.T) {
	tests := []struct {
		name   string
		rate   float64
		expect float64
	}{
		{"normal", 12.5, 12.5},
		{"nan", math.NaN(), 0},
		{"posinf", math.Inf(1), 0},
		{"neginf", math.Inf(-1), 0},
		{"zero", 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := cockroachdb.EmitCounterRateExported("db.rate", tc.rate, nil)
			assert.Equal(t, collector.MetricTypeGauge, m.Type)
			assert.Equal(t, tc.expect, m.Value)
		})
	}
}

func TestCopyLabels(t *testing.T) {
	src := map[string]string{"x": "1", "y": "2"}
	dst := cockroachdb.CopyLabelsExported(src)

	assert.Equal(t, src, dst)

	dst["x"] = "changed"
	assert.Equal(t, "1", src["x"], "source must not be mutated")

	// Empty and nil maps.
	assert.Empty(t, cockroachdb.CopyLabelsExported(nil))
	assert.Empty(t, cockroachdb.CopyLabelsExported(map[string]string{}))
}

func TestInstanceLabels(t *testing.T) {
	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{
		Name: "crdb-1",
		Host: "db.example.com",
		Tags: map[string]string{"env": "prod"},
	})
	inst.Version = "23.1"
	inst.ClusterID = "abc-123"
	inst.NodeID = 7

	labels := cockroachdb.InstanceLabelsExported(inst)

	assert.Equal(t, "crdb-1", labels["cockroachdb_instance"])
	assert.Equal(t, "db.example.com", labels["cockroachdb_host"])
	assert.Equal(t, "23.1", labels["cockroachdb_version"])
	assert.Equal(t, "abc-123", labels["cockroachdb_cluster_id"])
	assert.Equal(t, "7", labels["cockroachdb_node_id"])
	assert.Equal(t, "prod", labels["env"])
}

func TestInstanceLabels_Minimal(t *testing.T) {
	// No version/clusterID/nodeID => those labels omitted.
	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{
		Name: "crdb-min",
		Host: "localhost",
	})

	labels := cockroachdb.InstanceLabelsExported(inst)

	assert.Equal(t, "crdb-min", labels["cockroachdb_instance"])
	assert.NotContains(t, labels, "cockroachdb_version")
	assert.NotContains(t, labels, "cockroachdb_cluster_id")
	assert.NotContains(t, labels, "cockroachdb_node_id")
}

func TestNewCRDBTestInstance_Defaults(t *testing.T) {
	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "t"})
	require.NotNil(t, inst)
	assert.NotNil(t, inst.PrevCounters)
	assert.Equal(t, "t", inst.Config.Name)
}

// --- Config defaults ---

func TestNewConfig_AppliesDefaults(t *testing.T) {
	cfg := cockroachdb.NewConfigExported(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{{Name: "n1"}},
	})

	assert.Equal(t, 15*time.Second, cfg.InstanceInterval)
	assert.Equal(t, 60*time.Second, cfg.QueryInterval)
	assert.Equal(t, 30*time.Second, cfg.RangeInterval)
	assert.Equal(t, 3, cfg.MaxConnections)
	assert.Equal(t, 200, cfg.TopStatementsLimit)

	inst := cfg.Instances[0]
	assert.Equal(t, 26257, inst.SQLPort)
	assert.Equal(t, 8080, inst.AdminPort)
	assert.Equal(t, "localhost", inst.Host)
	assert.Equal(t, "root", inst.User)
	assert.Equal(t, "system", inst.Database)
	assert.Equal(t, "disable", inst.SSLMode)
}

func TestNewConfig_PreservesProvidedValues(t *testing.T) {
	cfg := cockroachdb.NewConfigExported(config.CockroachDBCollectorConfig{
		InstanceInterval:   5 * time.Second,
		QueryInterval:      10 * time.Second,
		RangeInterval:      20 * time.Second,
		MaxConnections:     9,
		TopStatementsLimit: 50,
		Instances: []config.CockroachDBInstanceConfig{{
			Name:      "custom",
			Host:      "remote",
			SQLPort:   1234,
			AdminPort: 5678,
			User:      "admin",
			Database:  "app",
			SSLMode:   "require",
		}},
	})

	assert.Equal(t, 5*time.Second, cfg.InstanceInterval)
	assert.Equal(t, 10*time.Second, cfg.QueryInterval)
	assert.Equal(t, 20*time.Second, cfg.RangeInterval)
	assert.Equal(t, 9, cfg.MaxConnections)
	assert.Equal(t, 50, cfg.TopStatementsLimit)

	inst := cfg.Instances[0]
	assert.Equal(t, 1234, inst.SQLPort)
	assert.Equal(t, 5678, inst.AdminPort)
	assert.Equal(t, "remote", inst.Host)
	assert.Equal(t, "admin", inst.User)
	assert.Equal(t, "app", inst.Database)
	assert.Equal(t, "require", inst.SSLMode)
}

// --- Connection string building ---

func TestBuildConnString_Basic(t *testing.T) {
	dsn := cockroachdb.BuildConnStringExported(config.CockroachDBInstanceConfig{
		User:     "root",
		Password: "secret",
		Host:     "localhost",
		SQLPort:  26257,
		Database: "system",
		SSLMode:  "disable",
	})
	assert.Equal(t, "postgres://root:secret@localhost:26257/system?sslmode=disable", dsn)
}

func TestBuildConnString_WithSSLFiles(t *testing.T) {
	dsn := cockroachdb.BuildConnStringExported(config.CockroachDBInstanceConfig{
		User:        "root",
		Host:        "localhost",
		SQLPort:     26257,
		Database:    "system",
		SSLMode:     "verify-full",
		SSLRootCert: "/ca.crt",
		SSLCert:     "/client.crt",
		SSLKey:      "/client.key",
	})
	assert.Contains(t, dsn, "sslmode=verify-full")
	assert.Contains(t, dsn, "sslrootcert=/ca.crt")
	assert.Contains(t, dsn, "sslcert=/client.crt")
	assert.Contains(t, dsn, "sslkey=/client.key")
}

// --- Env var resolution ---

func TestResolveEnvVars(t *testing.T) {
	_ = os.Setenv("CRDB_TEST_ENVVAR", "resolved-value")
	defer func() { _ = os.Unsetenv("CRDB_TEST_ENVVAR") }()

	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"plain", "no-vars-here", "no-vars-here"},
		{"resolved", "${CRDB_TEST_ENVVAR}", "resolved-value"},
		{"embedded", "pre-${CRDB_TEST_ENVVAR}-post", "pre-resolved-value-post"},
		{"missing_no_default", "${CRDB_MISSING_VAR}", ""},
		{"missing_with_default", "${CRDB_MISSING_VAR:-fallback}", "fallback"},
		{"present_ignores_default", "${CRDB_TEST_ENVVAR:-fallback}", "resolved-value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, cockroachdb.ResolveEnvVarsExported(tc.input))
		})
	}
}
