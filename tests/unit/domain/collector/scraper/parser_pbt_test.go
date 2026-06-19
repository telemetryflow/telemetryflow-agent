// Package scraper property-based tests for the Prometheus text parser.
//
// Validates: Requirements 1.13
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
package scraper_test

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

// TestParsePrometheusTextRoundtrip verifies that for any set of counter/gauge
// metrics serialized to Prometheus text format, ParsePrometheusTextExported returns
// metrics with matching names and finite values.
//
// **Validates: Requirements 1.13**
func TestParsePrometheusTextRoundtrip(t *testing.T) {
	property := func(names []string, values []float64) bool {
		if len(names) == 0 || len(values) == 0 {
			return true
		}
		// Clamp to min length and sanitize
		n := len(names)
		if len(values) < n {
			n = len(values)
		}
		if n > 10 {
			n = 10
		}

		var buf bytes.Buffer
		expected := make(map[string]float64)
		for i := 0; i < n; i++ {
			// Sanitize metric name: must match [a-zA-Z_:][a-zA-Z0-9_:]*
			name := sanitizeMetricName(names[i])
			if name == "" {
				continue
			}
			// Skip NaN/Inf as they serialize differently
			if math.IsNaN(values[i]) || math.IsInf(values[i], 0) {
				continue
			}
			fmt.Fprintf(&buf, "# TYPE %s gauge\n%s %g\n", name, name, values[i])
			expected[name] = values[i]
		}

		if len(expected) == 0 {
			return true
		}

		metrics, err := scraper.ParsePrometheusTextExported(&buf)
		if err != nil {
			return false
		}

		got := make(map[string]float64)
		for _, m := range metrics {
			got[m.Name] = m.Value
		}

		for name, val := range expected {
			gotVal, ok := got[name]
			if !ok {
				return false
			}
			if math.Abs(gotVal-val) > 1e-9 {
				return false
			}
		}
		return true
	}

	err := quick.Check(property, &quick.Config{MaxCount: 100})
	require.NoError(t, err)
}

// TestParsePrometheusTextCounterNames verifies that counter metric names are
// preserved through the parse cycle.
func TestParsePrometheusTextCounterNames(t *testing.T) {
	input := `# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 42
http_requests_total{method="POST",status="500"} 7
`
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader(input))
	require.NoError(t, err)
	assert.Len(t, metrics, 2)
	for _, m := range metrics {
		assert.Equal(t, "http_requests_total", m.Name)
	}
}

// sanitizeMetricName returns a valid Prometheus metric name or empty string.
func sanitizeMetricName(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			b.WriteRune(c)
		} else if b.Len() > 0 && c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	result := b.String()
	if len(result) == 0 {
		return ""
	}
	// Avoid reserved prefixes
	if strings.HasPrefix(result, "__") {
		return "metric_" + result
	}
	return result
}
