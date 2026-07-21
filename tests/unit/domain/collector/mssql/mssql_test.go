// Package mssql_test contains external (black-box) unit tests for the MSSQL collector.
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
//
// These tests exercise the exported test surface (exports.go) following the
// same convention as the postgresql and mysql collector test suites. The bulk
// of the query-collector coverage lives in the in-package white-box suite.

package mssql_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mssql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mssql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestSafeDivExported(t *testing.T) {
	tests := []struct {
		name       string
		num, denom float64
		expect     float64
	}{
		{"normal", 10, 2, 5},
		{"zero_denom", 10, 0, 0},
		{"zero_num", 0, 5, 0},
		{"both_zero", 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.expect, mssql.SafeDivExported(tc.num, tc.denom), 1e-9)
		})
	}
}

func TestMakeMetricExported(t *testing.T) {
	m := mssql.MakeMetricExported("mssql.x", 1.5, collector.MetricTypeGauge, map[string]string{"a": "b"})
	assert.Equal(t, "mssql.x", m.Name)
	assert.Equal(t, 1.5, m.Value)
	assert.Equal(t, "b", m.Labels["a"])
}

func TestEmitCounterRateExported(t *testing.T) {
	assert.Equal(t, 0.0, mssql.EmitCounterRateExported("r", math.NaN(), nil).Value)
	assert.Equal(t, 0.0, mssql.EmitCounterRateExported("r", math.Inf(1), nil).Value)
	assert.Equal(t, 12.0, mssql.EmitCounterRateExported("r", 12, nil).Value)
}

func TestResolveEnvVarsExported(t *testing.T) {
	t.Setenv("TFO_MSSQL_TEST_PW", "s3cr3t")
	assert.Equal(t, "s3cr3t", mssql.ResolveEnvVarsExported("${TFO_MSSQL_TEST_PW}"))
	assert.Equal(t, "def", mssql.ResolveEnvVarsExported("${TFO_MSSQL_TEST_MISSING:-def}"))
	assert.Equal(t, "plain", mssql.ResolveEnvVarsExported("plain"))
}

func TestCopyLabelsExported(t *testing.T) {
	src := map[string]string{"k": "v"}
	dst := mssql.CopyLabelsExported(src)
	dst["k"] = "mutated"
	assert.Equal(t, "v", src["k"])
}

func TestCategorizeWaitExported(t *testing.T) {
	tests := []struct {
		wait, want string
	}{
		{"SOS_SCHEDULER_YIELD", "CPU"},
		{"LCK_M_X", "Lock"},
		{"PAGELATCH_EX", "Latches"},
		{"WRITELOG", "Transaction Log"},
		{"UNKNOWN_WAIT", "Other"},
	}
	for _, tc := range tests {
		t.Run(tc.wait, func(t *testing.T) {
			assert.Equal(t, tc.want, mssql.CategorizeWaitExported(tc.wait))
		})
	}
}

func TestHHMMSSToSecondsExported(t *testing.T) {
	assert.Equal(t, 3661.0, mssql.HHMMSSToSecondsExported(10101))
	assert.Equal(t, 0.0, mssql.HHMMSSToSecondsExported(0))
	assert.Equal(t, 7200.0, mssql.HHMMSSToSecondsExported(20000))
}

func TestNewConfigExportedDefaults(t *testing.T) {
	c := mssql.NewConfigExported(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "primary"}},
	})
	assert.Equal(t, 15*time.Second, c.MetricsInterval)
	assert.Equal(t, 3, c.MaxConnections)
	assert.Equal(t, 50, c.TopQueriesLimit)
	assert.Equal(t, "localhost", c.Instances[0].Host)
	assert.Equal(t, 1433, c.Instances[0].Port)
}

func TestBuildConnStringExported(t *testing.T) {
	dsn := mssql.BuildConnStringExported(config.MSSQLInstanceConfig{
		Username: "sa", Password: "pw", Host: "h", Port: 1433,
		Database: "master", Encrypt: "true", TrustServerCertificate: true,
	})
	assert.True(t, strings.HasPrefix(dsn, "sqlserver://"))
	assert.Contains(t, dsn, "database=master")
}

func TestInstanceLabelsExported(t *testing.T) {
	ti := mssql.NewMSSQLTestInstance(config.MSSQLInstanceConfig{
		Name: "i1", Host: "h1", Tags: map[string]string{"env": "prod"},
	})
	labels := mssql.InstanceLabelsExported(ti)
	assert.Equal(t, "i1", labels["mssql_instance"])
	assert.Equal(t, "h1", labels["mssql_host"])
	assert.Equal(t, "prod", labels["env"])
}

func TestNewMSSQLCollectorLifecycle(t *testing.T) {
	c := mssql.NewMSSQLCollector(config.MSSQLCollectorConfig{}, zap.NewNop())
	assert.Equal(t, "mssql", c.Name())
	assert.False(t, c.IsRunning())

	// No instances configured -> Collect returns nil without any network I/O.
	m, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestOTLPEmitterExportedNilBridge(t *testing.T) {
	e := mssql.NewOTLPEmitter(nil, zap.NewNop())
	ti := mssql.NewMSSQLTestInstance(config.MSSQLInstanceConfig{Name: "i"})
	require.NoError(t, e.EmitMetricsForInstanceExported(context.TODO(), nil, ti))
	require.NoError(t, e.EmitMetrics(context.Background(), nil))
	require.NoError(t, e.Shutdown(context.Background()))
}

func TestNewQANMSSQLCollectorExported(t *testing.T) {
	c := mssql.NewQANMSSQLCollector(mssql.QANMSSQLConfig{}, zap.NewNop())
	assert.Equal(t, "qan-mssql-querystats", c.Name())
	assert.False(t, c.IsRunning())

	// No instances configured -> CollectQAN returns nil without any network I/O.
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Nil(t, buckets)
}
