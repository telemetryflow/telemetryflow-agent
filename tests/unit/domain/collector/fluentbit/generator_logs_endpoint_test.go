// Package fluentbit_test contains unit tests for the corresponding collector module.
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

package fluentbit_test

import (
	"strings"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// The [OUTPUT] target follows exporter.otlp.logs.endpoint when set, so logs reach
// the same host and API version as metrics and traces. Without it, logs silently
// fall back to the unauthenticated /v1/logs path on the platform endpoint.
func TestGenerateConfig_LogsEndpointRouting(t *testing.T) {
	tests := []struct {
		name         string
		logsEndpoint string
		tfEndpoint   string
		wantHost     string
		wantPort     string
		wantLogsURI  string
		wantTLS      string
	}{
		{
			name:         "logs endpoint overrides host, port and path",
			logsEndpoint: "https://api.platform-staging.example.com/v2/logs",
			tfEndpoint:   "https://platform-staging.example.com:443",
			wantHost:     "api.platform-staging.example.com",
			wantPort:     "443",
			wantLogsURI:  "/v2/logs",
			wantTLS:      "    tls               on\n",
		},
		{
			name:         "empty logs endpoint falls back to prior behaviour",
			logsEndpoint: "",
			tfEndpoint:   "https://platform-staging.example.com:443",
			wantHost:     "platform-staging.example.com",
			wantPort:     "443",
			wantLogsURI:  "/v1/logs",
			wantTLS:      "    tls               on\n",
		},
		{
			name:         "plain http logs endpoint disables tls and keeps its port",
			logsEndpoint: "http://collector.internal:4318/v2/logs",
			tfEndpoint:   "https://platform-staging.example.com:443",
			wantHost:     "collector.internal",
			wantPort:     "4318",
			wantLogsURI:  "/v2/logs",
			wantTLS:      "    tls               off\n",
		},
		{
			name:         "logs endpoint without a path keeps the OTEL default",
			logsEndpoint: "https://api.platform-staging.example.com",
			tfEndpoint:   "https://platform-staging.example.com:443",
			wantHost:     "api.platform-staging.example.com",
			wantPort:     "443",
			wantLogsURI:  "/v1/logs",
			wantTLS:      "    tls               on\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.FluentBitCollectorConfig{
				ConfigDir:    "/tmp/fb",
				LogsEndpoint: tt.logsEndpoint,
				Tail: config.FluentBitTailConfig{
					Enabled: true,
					Paths:   []string{"/var/log/syslog"},
				},
			}
			tfCfg := config.TelemetryFlowConfig{Endpoint: tt.tfEndpoint}

			conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
			if err != nil {
				t.Fatalf("GenerateConfig: %v", err)
			}

			wants := []string{
				"    host              " + tt.wantHost + "\n",
				"    port              " + tt.wantPort + "\n",
				"    logs_uri          " + tt.wantLogsURI + "\n",
				tt.wantTLS,
			}
			for _, want := range wants {
				if !strings.Contains(conf, want) {
					t.Errorf("config missing %q\n--- got ---\n%s", want, conf)
				}
			}
		})
	}
}
