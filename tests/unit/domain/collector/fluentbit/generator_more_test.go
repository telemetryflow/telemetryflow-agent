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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestGenerateConfig_FullFeatured(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir:      "/tmp/fb",
		FlushInterval:  0, // triggers default
		LogLevel:       "",
		StorageEnabled: true,
		StoragePath:    "", // triggers default
		HealthCheck:    true,
		HealthPort:     0, // triggers default 2020
		Tail: config.FluentBitTailConfig{
			Enabled:         true,
			Paths:           []string{"/var/log/a/*.log", "/var/log/b/*.log"},
			ExcludePaths:    []string{"/var/log/a/skip.log"},
			MultilineParser: "docker",
			ReadFromHead:    true,
			RefreshInterval: 15,
			RotateWait:      7,
		},
		Systemd: config.FluentBitSystemdConfig{
			Enabled:          true,
			Units:            []string{"nginx", "sshd"},
			StripUnderscores: true,
		},
		Kubernetes: config.FluentBitKubernetesConfig{
			Enabled:          true,
			LogPath:          "", // triggers default
			MergeLog:         true,
			KeepLog:          false,
			K8sLoggingParser: true,
		},
		CustomInputs: []config.FluentBitCustomSection{
			{Properties: map[string]string{"name": "dummy"}},
		},
		CustomFilters: []config.FluentBitCustomSection{
			{Properties: map[string]string{"name": "grep"}},
		},
	}
	tfCfg := config.TelemetryFlowConfig{
		Endpoint:     "https://otel.example.com:443",
		TLS:          config.TLSConfig{SkipVerify: false},
		APIKeyID:     "kid",
		APIKeySecret: "ksecret",
	}

	conf, parsers, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	wants := []string{
		"flush             5",
		"log_level         info",
		"storage.path",
		"storage.sync      normal",
		"health_check      on",
		"http_port         2020",
		"exclude_path      /var/log/a/skip.log",
		"multiline.parser  docker",
		"read_from_head    on",
		"refresh_interval  15",
		"rotate_wait       7",
		"storage.type      filesystem",
		"name              systemd",
		"_SYSTEMD_UNIT=nginx.service",
		"strip_underscores on",
		"name              kubernetes",
		"/var/log/containers/*.log",
		"merge_log         on",
		"keep_log          off",
		"k8s-logging.parser on",
		"tls               on",
		"tls.verify        on",
		"X-TelemetryFlow-Key-ID kid",
		"X-TelemetryFlow-Key-Secret ksecret",
	}
	for _, w := range wants {
		if !strings.Contains(conf, w) {
			t.Errorf("config missing %q", w)
		}
	}
	if parsers == "" {
		t.Error("parsers empty")
	}
}

func TestGenerateConfig_TailWithExplicitDBAndNoStorage(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir: "/tmp/fb",
		Tail: config.FluentBitTailConfig{
			Enabled: true,
			Paths:   []string{"/var/log/x.log"},
			DBPath:  "/custom/tail.db",
		},
	}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "localhost:4318"}
	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if !strings.Contains(conf, "db                /custom/tail.db") {
		t.Error("should use explicit db path")
	}
	if strings.Contains(conf, "storage.type      filesystem") {
		t.Error("storage not enabled; should not appear")
	}
}

func TestGenerateConfig_KubernetesKeepLog(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{
		ConfigDir: "/tmp/fb",
		Kubernetes: config.FluentBitKubernetesConfig{
			Enabled: true,
			KeepLog: true,
		},
	}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "localhost:4318"}
	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if strings.Contains(conf, "keep_log          off") {
		t.Error("keep_log should not be off when KeepLog=true")
	}
}

func TestGenerateConfig_NoTLSPlainEndpoint(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{ConfigDir: "/tmp/fb"}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "collector:4318"}
	conf, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if !strings.Contains(conf, "tls               off") {
		t.Error("expected tls off for plain endpoint")
	}
}

func TestGenerateConfig_EndpointParseError(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{ConfigDir: "/tmp/fb"}
	tfCfg := config.TelemetryFlowConfig{Endpoint: "ht tp://bad host"}
	_, _, err := fluentbit.GenerateConfig(cfg, tfCfg)
	if err == nil {
		t.Fatal("expected error for malformed endpoint")
	}
}

func TestWriteConfigs_Success(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gen")
	if err := fluentbit.WriteConfigs(dir, "conf-body", "parsers-body"); err != nil {
		t.Fatalf("WriteConfigs: %v", err)
	}
	for _, name := range []string{"fluent-bit.conf", "parsers.conf", "multiline-parsers.conf"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "storage")); err != nil {
		t.Errorf("expected storage dir: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "fluent-bit.conf"))
	if string(body) != "conf-body" {
		t.Errorf("unexpected conf body %q", string(body))
	}
}

func TestWriteConfigs_MkdirError(t *testing.T) {
	// Create a regular file, then try to use a path beneath it as a directory.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(f, "sub")
	if err := fluentbit.WriteConfigs(badDir, "c", "p"); err == nil {
		t.Fatal("expected mkdir error when parent is a file")
	}
}
