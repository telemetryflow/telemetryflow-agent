// Package fluentbit_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		host     string
		port     string
		tls      bool
	}{
		{"empty", "", "localhost", "4318", false},
		{"host_port", "localhost:4318", "localhost", "4318", false},
		{"https_with_port", "https://otel.example.com:443", "otel.example.com", "443", true},
		{"http_with_port", "http://localhost:4318", "localhost", "4318", false},
		{"grpc_scheme", "grpc://collector:4317", "collector", "4317", false},
		{"https_no_port", "https://example.com", "example.com", "443", true},
		{"http_no_port", "http://example.com", "example.com", "4318", false},
		{"host_no_scheme_no_port", "myhost", "myhost", "4318", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, tls, err := fluentbit.ParseEndpointExported(tc.endpoint)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.host {
				t.Errorf("host = %q, want %q", host, tc.host)
			}
			if port != tc.port {
				t.Errorf("port = %q, want %q", port, tc.port)
			}
			if tls != tc.tls {
				t.Errorf("tls = %v, want %v", tls, tc.tls)
			}
		})
	}
}

func TestGenerateConfig_Minimal(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir: "/tmp/fb",
	}
	tfCfg := config.TelemetryFlowConfig{
		Endpoint: "http://localhost:4318",
	}

	conf, parsers, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig failed: %v", err)
	}
	if !strings.Contains(conf, "[SERVICE]") {
		t.Error("config should contain [SERVICE]")
	}
	if !strings.Contains(conf, "[OUTPUT]") {
		t.Error("config should contain [OUTPUT]")
	}
	if strings.Contains(conf, "[INPUT]") {
		t.Error("minimal config should not contain [INPUT]")
	}
	if parsers == "" {
		t.Error("parsers should not be empty")
	}
}

func TestGenerateConfig_WithTail(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir: "/tmp/fb",
		Tail: config.FluentBitTailConfig{
			Enabled: true,
			Paths:   []string{"/var/log/app/*.log"},
		},
	}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "http://localhost:4318"}

	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig failed: %v", err)
	}
	if !strings.Contains(conf, "name              tail") {
		t.Error("should contain tail input")
	}
	if !strings.Contains(conf, "/var/log/app/*.log") {
		t.Error("should contain tail path")
	}
}

func TestGenerateConfig_WithTLS(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{ConfigDir: "/tmp/fb"}
	tfCfg := config.TelemetryFlowConfig{
		Endpoint: "https://otel.example.com:443",
		TLS:      config.TLSConfig{SkipVerify: true},
		APIKeyID: "key-123",
	}

	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig failed: %v", err)
	}
	if !strings.Contains(conf, "tls               on") {
		t.Error("should enable TLS")
	}
	if !strings.Contains(conf, "tls.verify        off") {
		t.Error("should skip TLS verify")
	}
	if !strings.Contains(conf, "X-TelemetryFlow-Key-ID key-123") {
		t.Error("should include API key header")
	}
}

func TestBuiltinParsers(t *testing.T) {
	parsers := []string{"docker", "cri", "syslog-rfc5424", "json"}
	for _, name := range parsers {
		if !strings.Contains(fluentbit.BuiltinParsersConf, name) {
			t.Errorf("BuiltinParsersConf missing parser %q", name)
		}
	}
}

func TestBuiltinMultilineParsers(t *testing.T) {
	parsers := []string{"java-stacktrace", "python-traceback", "go-panic"}
	for _, name := range parsers {
		if !strings.Contains(fluentbit.BuiltinMultilineParsersConf, name) {
			t.Errorf("BuiltinMultilineParsersConf missing parser %q", name)
		}
	}
}

func TestGenerateConfig_WithHealthCheck(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir:   "/tmp/fb",
		HealthCheck: true,
		HealthPort:  9090,
	}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "http://localhost:4318"}

	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig failed: %v", err)
	}
	if !strings.Contains(conf, "health_check      on") {
		t.Error("should enable health check")
	}
	if !strings.Contains(conf, "http_port         9090") {
		t.Error("should set health port to 9090")
	}
}
