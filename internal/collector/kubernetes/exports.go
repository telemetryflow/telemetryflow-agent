// Package kubernetes exports internal functions for testing.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
package kubernetes

import "go.uber.org/zap"

// ParseApiServerMetricsExported exposes parseApiServerMetrics for testing.
func ParseApiServerMetricsExported(body string, logger *zap.Logger) *ApiServerMetrics {
	return parseApiServerMetrics(body, logger)
}

// ParseCoreDNSMetricsExported exposes parseCoreDNSMetrics for testing.
func ParseCoreDNSMetricsExported(body string, podCount int, logger *zap.Logger) *CoreDNSMetrics {
	return parseCoreDNSMetrics(body, podCount, logger)
}

// ParsePromLineExported exposes parsePromLine for testing.
func ParsePromLineExported(line string) (map[string]string, float64) {
	return parsePromLine(line)
}
