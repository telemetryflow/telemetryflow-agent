// Package exporter exposes unexported symbols for external test packages.
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

package exporter

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// Exported wrappers for unexported symbols, exposed for external test packages.

func LabelsToAttributeSetExported(labels map[string]string) attribute.Set {
	return labelsToAttributeSet(labels)
}

func GroupMetricsByNameExported(metrics []collector.Metric) map[string][]MetricPointExported {
	groups := groupMetricsByName(metrics)
	out := make(map[string][]MetricPointExported, len(groups))
	for name, points := range groups {
		exported := make([]MetricPointExported, len(points))
		for i, p := range points {
			exported[i] = MetricPointExported{M: p.m, Attrs: p.attrs}
		}
		out[name] = exported
	}
	return out
}

func BuildAggregationExported(points []MetricPointExported) metricdata.Aggregation {
	internal := make([]metricPoint, len(points))
	for i, p := range points {
		internal[i] = metricPoint{m: p.M, attrs: p.Attrs}
	}
	return buildAggregation(internal)
}

func BaseResourceAttrsExported() []attribute.KeyValue {
	return baseResourceAttrs()
}

// MetricPointExported is the exported equivalent of metricPoint.
type MetricPointExported struct {
	M     collector.Metric
	Attrs attribute.Set
}
