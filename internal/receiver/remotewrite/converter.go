// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
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
	"fmt"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// convertTimeSeries converts a single prompb.TimeSeries into a slice of
// collector.Metric — one per sample. The __name__ label is used as the metric
// name and is excluded from the Labels map. Returns an error (and increments
// InvalidSeriesTotal) if __name__ is absent or empty.
func convertTimeSeries(ts prompb.TimeSeries) ([]collector.Metric, error) {
	// Extract __name__ and build the labels map in one pass.
	var name string
	labels := make(map[string]string, len(ts.Labels))

	for _, lp := range ts.Labels {
		if lp.Name == "__name__" {
			name = lp.Value
		} else {
			labels[lp.Name] = lp.Value
		}
	}

	if name == "" {
		InvalidSeriesTotal.Inc()
		return nil, fmt.Errorf("time series missing or empty __name__ label")
	}

	metrics := make([]collector.Metric, 0, len(ts.Samples))
	for _, s := range ts.Samples {
		m := collector.Metric{
			Name:      name,
			Type:      collector.MetricTypeGauge,
			Value:     s.Value,
			Timestamp: time.UnixMilli(s.Timestamp),
			Labels:    labels,
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}
