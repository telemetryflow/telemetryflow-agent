// Package log_test contains unit tests for the corresponding collector module.
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

package log_test

import (
	"regexp"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
)

func TestCompilePatterns(t *testing.T) {
	t.Run("valid_patterns", func(t *testing.T) {
		patterns := log.CompilePatternsExported([]string{"error.*", "warn.*"})
		if len(patterns) != 2 {
			t.Errorf("expected 2, got %d", len(patterns))
		}
	})

	t.Run("skips_invalid", func(t *testing.T) {
		patterns := log.CompilePatternsExported([]string{"valid.*", "[invalid", "also-valid"})
		if len(patterns) != 2 {
			t.Errorf("expected 2 (invalid skipped), got %d", len(patterns))
		}
	})

	t.Run("empty", func(t *testing.T) {
		patterns := log.CompilePatternsExported(nil)
		if len(patterns) != 0 {
			t.Errorf("expected 0, got %d", len(patterns))
		}
	})
}

func TestMatchesFilter(t *testing.T) {
	include := log.CompilePatternsExported([]string{"ERROR.*", "WARN.*"})
	exclude := log.CompilePatternsExported([]string{".*debug.*"})

	tests := []struct {
		name    string
		line    string
		include []*regexp.Regexp
		exclude []*regexp.Regexp
		expect  bool
	}{
		{"no_filters_pass", "anything", nil, nil, true},
		{"include_match", "ERROR: disk full", include, nil, true},
		{"include_no_match", "INFO: ok", include, nil, false},
		{"exclude_match", "ERROR: debug info", include, exclude, false},
		{"exclude_no_match", "ERROR: disk full", include, exclude, true},
		{"exclude_only_match", "debug output", nil, exclude, false},
		{"exclude_only_pass", "normal output", nil, exclude, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := log.MatchesFilterExported(tc.line, tc.include, tc.exclude)
			if got != tc.expect {
				t.Errorf("MatchesFilter(%q) = %v, want %v", tc.line, got, tc.expect)
			}
		})
	}
}
