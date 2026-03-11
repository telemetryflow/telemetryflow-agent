// Package remotewrite property-based tests for the TimeSeries converter.
//
// Validates: Requirements 3.4, 3.12
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package remotewrite

import (
	"testing"
	"testing/quick"

	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertTimeSeriesLabelPreservation verifies that all labels in a
// TimeSeries (except __name__) are preserved in the resulting collector.Metric.
//
// **Validates: Requirements 3.4, 3.12**
func TestConvertTimeSeriesLabelPreservation(t *testing.T) {
	property := func(labelKeys []string, labelValues []string) bool {
		if len(labelKeys) == 0 {
			return true
		}
		n := len(labelKeys)
		if len(labelValues) < n {
			n = len(labelValues)
		}
		if n > 20 {
			n = 20
		}

		// Build a valid TimeSeries with __name__ + random labels
		labels := []prompb.Label{
			{Name: "__name__", Value: "test_metric"},
		}
		expected := make(map[string]string)
		for i := 0; i < n; i++ {
			key := sanitizeLabelName(labelKeys[i])
			if key == "" || key == "__name__" {
				continue
			}
			val := labelValues[i]
			labels = append(labels, prompb.Label{Name: key, Value: val})
			expected[key] = val
		}

		ts := prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: 1.0, Timestamp: 0}},
		}

		metrics, err := convertTimeSeries(ts)
		if err != nil {
			return false
		}
		if len(metrics) == 0 {
			return false
		}

		// All expected labels must be present in every resulting metric
		for _, m := range metrics {
			for k, v := range expected {
				if m.Labels[k] != v {
					return false
				}
			}
			// __name__ must NOT be in Labels
			if _, ok := m.Labels["__name__"]; ok {
				return false
			}
		}
		return true
	}

	err := quick.Check(property, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

// TestConvertTimeSeriesNameExtraction verifies __name__ becomes the metric Name.
func TestConvertTimeSeriesNameExtraction(t *testing.T) {
	ts := prompb.TimeSeries{
		Labels: []prompb.Label{
			{Name: "__name__", Value: "my_metric"},
			{Name: "env", Value: "prod"},
		},
		Samples: []prompb.Sample{{Value: 42.0, Timestamp: 1000}},
	}
	metrics, err := convertTimeSeries(ts)
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	assert.Equal(t, "my_metric", metrics[0].Name)
	assert.Equal(t, "prod", metrics[0].Labels["env"])
	assert.NotContains(t, metrics[0].Labels, "__name__")
}

// TestConvertTimeSeriesMissingName verifies error on missing __name__.
func TestConvertTimeSeriesMissingName(t *testing.T) {
	ts := prompb.TimeSeries{
		Labels:  []prompb.Label{{Name: "env", Value: "prod"}},
		Samples: []prompb.Sample{{Value: 1.0}},
	}
	_, err := convertTimeSeries(ts)
	assert.Error(t, err)
}

// sanitizeLabelName returns a valid Prometheus label name or empty string.
func sanitizeLabelName(s string) string {
	if s == "" {
		return ""
	}
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			result = append(result, c)
		} else if i > 0 && c >= '0' && c <= '9' {
			result = append(result, c)
		}
	}
	return string(result)
}
