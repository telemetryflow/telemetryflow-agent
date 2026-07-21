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

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// writeFakeBinary creates an executable file so exec.LookPath / os.Stat succeed.
func writeFakeBinary(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return p
}

func TestNewFluentBitCollector_ExplicitBinaryDefaults(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")

	// Ensure K8s auto-detect does not trigger.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	cfg := config.FluentBitCollectorConfig{BinaryPath: bin}
	c, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "agent-1", zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name() != "fluent-bit" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("collector should not be running before Start")
	}
}

func TestNewFluentBitCollector_BinaryNotFoundAtPath(t *testing.T) {
	cfg := config.FluentBitCollectorConfig{BinaryPath: "/does/not/exist/fluent-bit"}
	_, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err == nil {
		t.Fatal("expected error for missing binary at explicit path")
	}
	if !strings.Contains(err.Error(), "not found at") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewFluentBitCollector_LookPathSuccess(t *testing.T) {
	dir := t.TempDir()
	writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("PATH", dir)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	cfg := config.FluentBitCollectorConfig{}
	c, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected collector")
	}
}

func TestNewFluentBitCollector_LookPathFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir, no fluent-bit
	cfg := config.FluentBitCollectorConfig{}
	_, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err == nil {
		t.Fatal("expected error when fluent-bit not in PATH")
	}
	if !strings.Contains(err.Error(), "not found in PATH") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewFluentBitCollector_KubernetesAutoDetect(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	cfg := config.FluentBitCollectorConfig{BinaryPath: bin}
	c, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected collector")
	}
}

func TestCollect_NoProcess(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{BinaryPath: bin},
		config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	metrics, err := c.Collect(nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Without a started process, only the running gauge is emitted.
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Name != "tfo.fluentbit.running" {
		t.Errorf("unexpected metric %q", metrics[0].Name)
	}
	if metrics[0].Value != 0.0 {
		t.Errorf("expected running=0, got %v", metrics[0].Value)
	}
}

func TestStop_NoProcess(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	cfgDir := filepath.Join(t.TempDir(), "confdir")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{BinaryPath: bin, ConfigDir: cfgDir},
		config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// ConfigDir should have been removed.
	if _, statErr := os.Stat(cfgDir); !os.IsNotExist(statErr) {
		t.Error("expected config dir to be cleaned up")
	}
}

func TestNewFluentBitCollector_ExternalConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	cfg := config.FluentBitCollectorConfig{
		BinaryPath:     bin,
		ExternalConfig: true, // config_file not set
	}
	_, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err == nil {
		t.Fatal("expected error when external_config enabled without config_file")
	}
	if !strings.Contains(err.Error(), "config_file is not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewFluentBitCollector_ExternalConfigFileNotFound(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	cfg := config.FluentBitCollectorConfig{
		BinaryPath:     bin,
		ExternalConfig: true,
		ConfigFile:     filepath.Join(dir, "does-not-exist.conf"),
	}
	_, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err == nil {
		t.Fatal("expected error when external config_file does not exist")
	}
	if !strings.Contains(err.Error(), "external config_file not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewFluentBitCollector_ExternalConfigValid(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	confPath := filepath.Join(dir, "fluent-bit.conf")
	if err := os.WriteFile(confPath, []byte("[SERVICE]\n    flush 5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.FluentBitCollectorConfig{
		BinaryPath:     bin,
		ExternalConfig: true,
		ConfigFile:     confPath,
	}
	c, err := fluentbit.NewFluentBitCollector(cfg, config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected collector")
	}
}

func TestStop_ExternalConfigPreservesUserFiles(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "fluent-bit")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	// User-owned config lives in its own directory that the agent must not touch.
	userDir := filepath.Join(t.TempDir(), "user-flb")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(userDir, "fluent-bit.conf")
	if err := os.WriteFile(confPath, []byte("[SERVICE]\n    flush 5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := fluentbit.NewFluentBitCollector(
		config.FluentBitCollectorConfig{
			BinaryPath:     bin,
			ExternalConfig: true,
			ConfigFile:     confPath,
			ConfigDir:      userDir, // even if ConfigDir points at user files, external mode must not delete
		},
		config.TelemetryFlowConfig{}, "a", zap.NewNop())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// External config file and directory must survive Stop().
	if _, statErr := os.Stat(confPath); statErr != nil {
		t.Errorf("external config file was removed: %v", statErr)
	}
}
