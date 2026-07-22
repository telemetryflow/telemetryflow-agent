// Package kafka exposes unexported symbols for external test packages.
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

package kafka

import (
	"context"
	"io"

	dto "github.com/prometheus/client_model/go"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ScrapeExported forwards to the unexported scrape helper so external test
// packages can exercise the HTTP scrape path against an httptest server.
func ScrapeExported(ctx context.Context, inst config.KafkaInstanceConfig) (io.Reader, error) {
	return scrape(ctx, inst)
}

// ParseTextExported forwards to the unexported parseText helper.
func ParseTextExported(r io.Reader) (map[string]*dto.MetricFamily, error) {
	return parseText(r)
}

// NormalizeNameExported forwards to the unexported normalizeName helper.
func NormalizeNameExported(family string) string {
	return normalizeName(family)
}

// InstanceLabelsExported forwards to the unexported instanceLabels method.
func (c *KafkaCollector) InstanceLabelsExported(inst config.KafkaInstanceConfig) map[string]string {
	return c.instanceLabels(inst)
}
