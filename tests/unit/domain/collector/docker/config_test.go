// Package docker_test contains unit tests for the corresponding collector module.
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

package docker_test

import (
	"regexp"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func newTestCollectorConfig(include, exclude []string) *docker.CollectorConfigExport {
	cfg := config.DockerCollectorConfig{
		IncludeContainers: include,
		ExcludeContainers: exclude,
	}
	return docker.NewCollectorConfigExported(cfg, zap.NewNop())
}

func TestShouldIncludeContainer(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		target  string
		expect  bool
	}{
		{"no_filters", nil, nil, "web-app", true},
		{"include_match", []string{"web-.*"}, nil, "web-app", true},
		{"include_no_match", []string{"db-.*"}, nil, "web-app", false},
		{"exclude_match", nil, []string{"pause-.*"}, "pause-container", false},
		{"exclude_no_match", nil, []string{"pause-.*"}, "web-app", true},
		{"exclude_takes_precedence", []string{".*"}, []string{"pause-.*"}, "pause-container", false},
		{"include_and_exclude_pass", []string{"web-.*"}, []string{"web-test"}, "web-prod", true},
		{"include_and_exclude_blocked", []string{"web-.*"}, []string{"web-test"}, "web-test", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := newTestCollectorConfig(tc.include, tc.exclude)
			got := cc.ShouldIncludeContainer(tc.target)
			if got != tc.expect {
				t.Errorf("ShouldIncludeContainer(%q) = %v, want %v", tc.target, got, tc.expect)
			}
		})
	}
}

func TestNewCollectorConfig_InvalidRegex(t *testing.T) {
	cc := docker.NewCollectorConfigExported(config.DockerCollectorConfig{
		IncludeContainers: []string{"[invalid", "valid-.*"},
		ExcludeContainers: []string{"[also-invalid"},
	}, zap.NewNop())

	if cc.IncludeCount() != 1 {
		t.Errorf("expected 1 valid include pattern, got %d", cc.IncludeCount())
	}
	if cc.ExcludeCount() != 0 {
		t.Errorf("expected 0 valid exclude patterns, got %d", cc.ExcludeCount())
	}
}

func TestContainerLabels(t *testing.T) {
	labels := docker.ContainerLabelsExported("abc123def", "web-app", "nginx:latest", "running")

	if labels["container_id"] != "abc123def" {
		t.Error("container_id wrong")
	}
	if labels["container_name"] != "web-app" {
		t.Error("container_name wrong")
	}
	if labels["image"] != "nginx:latest" {
		t.Error("image wrong")
	}
	if labels["status"] != "running" {
		t.Error("status wrong")
	}
}

func TestCleanContainerName(t *testing.T) {
	tests := []struct {
		name   string
		names  []string
		expect string
	}{
		{"slash_prefix", []string{"/web-app"}, "web-app"},
		{"no_slash", []string{"web-app"}, "web-app"},
		{"empty", nil, "unknown"},
		{"multiple_takes_first", []string{"/first", "/second"}, "first"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := docker.CleanContainerNameExported(tc.names)
			if got != tc.expect {
				t.Errorf("CleanContainerNameExported(%v) = %q, want %q", tc.names, got, tc.expect)
			}
		})
	}
}

func TestNewCollectorConfig_CompiledRegex(t *testing.T) {
	cc := docker.NewCollectorConfigExported(config.DockerCollectorConfig{
		IncludeContainers: []string{"app-.*", "web-.*"},
		ExcludeContainers: []string{"test-.*"},
	}, zap.NewNop())

	if cc.IncludeCount() != 2 {
		t.Fatalf("expected 2 include patterns, got %d", cc.IncludeCount())
	}
	if !cc.IncludeRe()[0].MatchString("app-server") {
		t.Error("first include pattern should match app-server")
	}
	if !cc.IncludeRe()[1].MatchString("web-frontend") {
		t.Error("second include pattern should match web-frontend")
	}
	_ = regexp.MustCompile // ensure import used
}
