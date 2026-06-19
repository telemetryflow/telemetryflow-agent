// Package system_test contains unit tests for the corresponding collector module.
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

package system_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

func TestParseUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect uint64
	}{
		{"simple", "12345", 12345},
		{"zero", "0", 0},
		{"empty", "", 0},
		{"with_spaces", " 42 ", 42},
		{"with_letters", "12abc34", 1234},
		{"only_letters", "abc", 0},
		{"large", "18446744073709551615", 18446744073709551615},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := system.ParseUint64Exported(tc.input)
			if got != tc.expect {
				t.Errorf("ParseUint64(%q) = %d, want %d", tc.input, got, tc.expect)
			}
		})
	}
}

func TestNewHostCollector(t *testing.T) {
	cfg := system.HostCollectorConfig{
		CollectCPU:  true,
		CollectMem:  true,
		CollectDisk: true,
		CollectNet:  true,
	}
	c := system.NewHostCollector(cfg)
	if c == nil {
		t.Fatal("NewHostCollector returned nil")
	}
	if c.Name() != "system.host" {
		t.Errorf("Name() = %q, want system.host", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running before Start()")
	}
}
