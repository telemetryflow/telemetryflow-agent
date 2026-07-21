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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
)

func TestAllMetricGroups(t *testing.T) {
	groups := aurora.AllMetricGroups()
	require.NotEmpty(t, groups)

	// Every group must have a name and at least one metric with a name+unit.
	for _, g := range groups {
		assert.NotEmpty(t, g.Name, "group name")
		assert.NotEmpty(t, g.Metrics, "group %s metrics", g.Name)
		for _, m := range g.Metrics {
			assert.NotEmpty(t, m.Name, "metric name in %s", g.Name)
			assert.NotEmpty(t, m.Unit, "metric unit for %s", m.Name)
			assert.NotEmpty(t, m.Description, "metric description for %s", m.Name)
		}
	}
}

func TestAllCloudWatchMetricNames(t *testing.T) {
	names := aurora.AllCloudWatchMetricNames()
	require.NotEmpty(t, names)

	// Names must be unique and include some well-known metrics.
	seen := make(map[string]bool)
	for _, n := range names {
		assert.False(t, seen[n], "duplicate metric name %s", n)
		seen[n] = true
	}
	assert.True(t, seen["CPUUtilization"])
	assert.True(t, seen["FreeStorageSpace"])
	assert.True(t, seen["AuroraReplicaLag"])
}

func TestMetricDescription(t *testing.T) {
	assert.Equal(t, "CPU utilization as a percentage", aurora.MetricDescription("CPUUtilization"))
	assert.Equal(t, "", aurora.MetricDescription("DoesNotExist"))
}

func TestMetricUnit(t *testing.T) {
	assert.Equal(t, "Percent", aurora.MetricUnit("CPUUtilization"))
	assert.Equal(t, "Bytes", aurora.MetricUnit("FreeStorageSpace"))
	assert.Equal(t, "", aurora.MetricUnit("DoesNotExist"))
}

func TestPerformanceInsightsMetricGroups(t *testing.T) {
	groups := aurora.PerformanceInsightsMetricGroups()
	require.NotEmpty(t, groups)
	for _, g := range groups {
		assert.NotEmpty(t, g.Name)
		assert.NotEmpty(t, g.Metrics)
		for _, m := range g.Metrics {
			assert.NotEmpty(t, m.Name)
			assert.NotEmpty(t, m.Unit)
		}
	}
}

func TestPiMetricGroupsInternal(t *testing.T) {
	assert.Equal(t, 5, aurora.PiMetricGroupsCount())
	assert.Greater(t, aurora.PiMetricGroupsTotalMetrics(), 10)
}
