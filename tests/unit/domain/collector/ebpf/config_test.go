// Package ebpf_test contains unit tests for the eBPF collector domain logic
// including configuration, network event handling, and syscall tracking.
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
package ebpf_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	ebpfcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ebpf"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestConfigValidation_InvalidSampleRate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name       string
		sampleRate int
		wantErr    bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"too_high", 101, true},
		{"valid_min", 1, false},
		{"valid_max", 100, false},
		{"valid_mid", 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.EBPFCollectorConfig{
				Enabled:    true,
				Interval:   1 * time.Second,
				SampleRate: tt.sampleRate,
			}
			_, err := ebpfcollector.NewEBPFCollector(cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "sample_rate")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidation_InvalidBufferSizes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("negative_ring_buffer", func(t *testing.T) {
		cfg := config.EBPFCollectorConfig{
			Enabled:        true,
			Interval:       1 * time.Second,
			SampleRate:     100,
			RingBufferSize: -1,
		}
		_, err := ebpfcollector.NewEBPFCollector(cfg, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ring_buffer_size")
	})

	t.Run("negative_perf_buffer", func(t *testing.T) {
		cfg := config.EBPFCollectorConfig{
			Enabled:        true,
			Interval:       1 * time.Second,
			SampleRate:     100,
			PerfBufferSize: -1,
		}
		_, err := ebpfcollector.NewEBPFCollector(cfg, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "perf_buffer_size")
	})

	t.Run("valid_zero_buffers", func(t *testing.T) {
		cfg := config.EBPFCollectorConfig{
			Enabled:        true,
			Interval:       1 * time.Second,
			SampleRate:     100,
			RingBufferSize: 0,
			PerfBufferSize: 0,
		}
		_, err := ebpfcollector.NewEBPFCollector(cfg, logger)
		assert.NoError(t, err)
	})
}

func TestConfigValidation_ProcessFilter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("valid_patterns", func(t *testing.T) {
		cfg := config.EBPFCollectorConfig{
			Enabled:          true,
			Interval:         1 * time.Second,
			SampleRate:       100,
			ProcessFilter:    []string{"nginx", "postgres.*"},
			ExcludeProcesses: []string{"tfo-agent"},
		}
		c, err := ebpfcollector.NewEBPFCollector(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("invalid_regex_skipped", func(t *testing.T) {
		cfg := config.EBPFCollectorConfig{
			Enabled:       true,
			Interval:      1 * time.Second,
			SampleRate:    100,
			ProcessFilter: []string{"valid", "[invalid"},
		}
		// Invalid patterns are skipped with a warning, not an error
		c, err := ebpfcollector.NewEBPFCollector(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestConfigValidation_CiliumConfig(t *testing.T) {
	logger := zap.NewNop()

	cfg := config.EBPFCollectorConfig{
		Enabled:    true,
		Interval:   1 * time.Second,
		SampleRate: 100,
		Cilium: config.CiliumCollectorConfig{
			Enabled:         true,
			HubbleAddress:   "localhost:4245",
			CollectFlows:    true,
			CollectDrops:    true,
			CollectPolicies: true,
			CollectL7Flows:  false,
		},
	}
	c, err := ebpfcollector.NewEBPFCollector(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "ebpf", c.Name())
}
