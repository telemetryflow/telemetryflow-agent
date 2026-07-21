// Package aurora_test contains unit tests for the Aurora collector module.
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

package aurora_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

func TestNewConfig_AppliesDefaults(t *testing.T) {
	// Arrange
	in := config.AuroraCollectorConfig{
		Clusters: []config.AuroraClusterConfig{{ClusterID: "c1"}},
	}

	// Act
	cfg := aurora.NewConfig(in)

	// Assert
	assert.Equal(t, 60*time.Second, cfg.CollectionInterval)
	assert.Equal(t, 300*time.Second, cfg.TopologyInterval)
	assert.Equal(t, 60*time.Second, cfg.PIInterval)
	assert.Equal(t, 200, cfg.TopQueriesLimit)
	assert.Equal(t, 500, cfg.CloudWatchBatchSize)
	assert.Equal(t, 40, cfg.CloudWatchRateLimit)
	assert.Equal(t, 1000, cfg.PushBatchSize)
	assert.Equal(t, 10*time.Second, cfg.PushFlushInterval)
	assert.Equal(t, "us-east-1", cfg.Clusters[0].Region)
}

func TestNewConfig_PreservesProvidedValues(t *testing.T) {
	in := config.AuroraCollectorConfig{
		CollectionInterval:  30 * time.Second,
		TopologyInterval:    120 * time.Second,
		PIInterval:          15 * time.Second,
		TopQueriesLimit:     50,
		CloudWatchBatchSize: 100,
		CloudWatchRateLimit: 10,
		PushBatchSize:       200,
		PushFlushInterval:   5 * time.Second,
		Clusters:            []config.AuroraClusterConfig{{ClusterID: "c1", Region: "eu-west-1"}},
	}

	cfg := aurora.NewConfig(in)

	assert.Equal(t, 30*time.Second, cfg.CollectionInterval)
	assert.Equal(t, 120*time.Second, cfg.TopologyInterval)
	assert.Equal(t, 15*time.Second, cfg.PIInterval)
	assert.Equal(t, 50, cfg.TopQueriesLimit)
	assert.Equal(t, 100, cfg.CloudWatchBatchSize)
	assert.Equal(t, 10, cfg.CloudWatchRateLimit)
	assert.Equal(t, 200, cfg.PushBatchSize)
	assert.Equal(t, 5*time.Second, cfg.PushFlushInterval)
	assert.Equal(t, "eu-west-1", cfg.Clusters[0].Region)
}

func TestApplyClusterDefaults(t *testing.T) {
	c := &config.AuroraClusterConfig{}
	aurora.ApplyClusterDefaultsExported(c)
	assert.Equal(t, "us-east-1", c.Region)

	c2 := &config.AuroraClusterConfig{Region: "ap-southeast-1"}
	aurora.ApplyClusterDefaultsExported(c2)
	assert.Equal(t, "ap-southeast-1", c2.Region)
}

func TestNewAuroraCollector_BasicProperties(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NotNil(t, c)
	assert.Equal(t, "aurora", c.Name())
	assert.False(t, c.IsRunning())
	assert.Equal(t, 1, c.NumStates())
	assert.Equal(t, qan.AgentTypeAuroraPI, c.AgentType())
}

func TestMapCloudWatchUnit(t *testing.T) {
	cases := map[string]string{
		"Percent":       "percent",
		"Bytes":         "bytes",
		"Bytes/Second":  "bytes_per_second",
		"Seconds":       "seconds",
		"Milliseconds":  "milliseconds",
		"Count":         "count",
		"Count/Second":  "count_per_second",
		"Megabytes":     "megabytes",
		"SomethingElse": "SomethingElse",
	}
	for in, want := range cases {
		assert.Equal(t, want, aurora.MapCloudWatchUnitExported(in), in)
	}
}

func TestIsThrottlingError(t *testing.T) {
	assert.False(t, aurora.IsThrottlingErrorExported(nil))
	assert.True(t, aurora.IsThrottlingErrorExported(errors.New("Throttling: slow down")))
	assert.True(t, aurora.IsThrottlingErrorExported(errors.New("Rate exceeded")))
	assert.True(t, aurora.IsThrottlingErrorExported(errors.New("RequestLimitExceeded")))
	assert.True(t, aurora.IsThrottlingErrorExported(errors.New("throttling in lower")))
	assert.True(t, aurora.IsThrottlingErrorExported(errors.New("hit rate limit")))
	assert.False(t, aurora.IsThrottlingErrorExported(errors.New("access denied")))
}

func TestContains(t *testing.T) {
	assert.True(t, aurora.ContainsExported("hello world", "world"))
	assert.True(t, aurora.ContainsExported("exact", "exact"))
	assert.False(t, aurora.ContainsExported("short", "longer string"))
	assert.False(t, aurora.ContainsExported("abc", "xyz"))
	assert.True(t, aurora.ContainsSubstrExported("abcdef", "cd"))
	assert.False(t, aurora.ContainsSubstrExported("abcdef", "zz"))
}

func TestSanitizeMetricName(t *testing.T) {
	assert.Equal(t, "db_load_avg", aurora.SanitizeMetricNameExported("db.load.avg"))
	assert.Equal(t, "plain", aurora.SanitizeMetricNameExported("plain"))
}

func TestSanitizeLabelName(t *testing.T) {
	assert.Equal(t, "a_b_c_d_e", aurora.SanitizeLabelNameExported("a.b c/d-e"))
	assert.Equal(t, "clean", aurora.SanitizeLabelNameExported("clean"))
}

func TestInstanceLabels(t *testing.T) {
	// Writer with AZ and custom tags.
	labels := aurora.InstanceLabelsExported(
		"cluster-1", "us-east-1",
		map[string]string{"env": "prod"},
		"inst-1", "db.r6g.large", "aurora-postgresql", "us-east-1a",
		true,
	)
	assert.Equal(t, "cluster-1", labels["aurora_cluster"])
	assert.Equal(t, "us-east-1", labels["aurora_region"])
	assert.Equal(t, "inst-1", labels["aurora_instance_id"])
	assert.Equal(t, "db.r6g.large", labels["aurora_instance_class"])
	assert.Equal(t, "aurora-postgresql", labels["aurora_engine"])
	assert.Equal(t, "writer", labels["aurora_role"])
	assert.Equal(t, "us-east-1a", labels["aurora_az"])
	assert.Equal(t, "prod", labels["env"])

	// Reader without AZ or tags.
	reader := aurora.InstanceLabelsExported(
		"cluster-1", "us-east-1", nil,
		"inst-2", "db.r6g.large", "aurora-postgresql", "",
		false,
	)
	assert.Equal(t, "reader", reader["aurora_role"])
	_, hasAZ := reader["aurora_az"]
	assert.False(t, hasAZ)
}

func TestPiStatementFromKey(t *testing.T) {
	assert.Equal(t, "", aurora.PiStatementFromKeyExported(nil))
	assert.Equal(t, "", aurora.PiStatementFromKeyExported(map[string]string{"other": "x"}))
	assert.Equal(t, "SELECT 1",
		aurora.PiStatementFromKeyExported(map[string]string{"db.sql.statement": "SELECT 1"}))
}

func TestFingerprintAurora(t *testing.T) {
	fp1 := aurora.FingerprintAurora("SELECT 1")
	fp2 := aurora.FingerprintAurora("SELECT 1")
	fp3 := aurora.FingerprintAurora("SELECT 2")
	assert.Equal(t, fp1, fp2)
	assert.NotEqual(t, fp1, fp3)
	assert.Len(t, fp1, 32) // 16 bytes hex
}

func TestSortAuroraBuckets(t *testing.T) {
	buckets := []qan.QANMetricsBucket{
		{Fingerprint: "a", QueryTimeSum: 1.0},
		{Fingerprint: "b", QueryTimeSum: 5.0},
		{Fingerprint: "c", QueryTimeSum: 3.0},
	}
	aurora.SortAuroraBuckets(buckets)
	assert.Equal(t, "b", buckets[0].Fingerprint)
	assert.Equal(t, "c", buckets[1].Fingerprint)
	assert.Equal(t, "a", buckets[2].Fingerprint)

	// Empty and single slices must not panic.
	aurora.SortAuroraBuckets(nil)
	aurora.SortAuroraBuckets([]qan.QANMetricsBucket{{Fingerprint: "only"}})
}

func TestMetricNameFromQuery(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	id := "m_0"
	assert.Equal(t, "CPUUtilization", c.MetricNameFromQueryExported(&id, []string{"CPUUtilization"}))
	assert.Equal(t, "", c.MetricNameFromQueryExported(nil, []string{"CPUUtilization"}))
	missing := "m_missing"
	assert.Equal(t, "", c.MetricNameFromQueryExported(&missing, []string{"CPUUtilization"}))
}

func TestClusterInfoChanged(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	assert.False(t, c.ClusterInfoChangedExported("c1", "c1", "e1", "e1"))
	assert.True(t, c.ClusterInfoChangedExported("c1", "c2", "e1", "e1"))
	assert.True(t, c.ClusterInfoChangedExported("c1", "c1", "e1", "e2"))
}

func TestQanTopLimit(t *testing.T) {
	withLimit := aurora.NewAuroraCollector(config.AuroraCollectorConfig{
		TopQueriesLimit: 42,
		Clusters:        []config.AuroraClusterConfig{{ClusterID: "c1"}},
	}, zap.NewNop())
	assert.Equal(t, 42, withLimit.QanTopLimitExported())
}
