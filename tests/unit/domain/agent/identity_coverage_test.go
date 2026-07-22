// Package agent_test contains additional unit tests for agent identity
// resolution (ResolveAgentID / host fingerprinting).
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
package agent_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/agent"
)

func TestResolveAgentID(t *testing.T) {
	logger := zap.NewNop()

	t.Run("explicit id wins", func(t *testing.T) {
		id := agent.ResolveAgentID("explicit-123", "host", logger)
		assert.Equal(t, "explicit-123", id)
	})

	t.Run("derives stable id from hostname fingerprint", func(t *testing.T) {
		id1 := agent.ResolveAgentID("", "stable-host", logger)
		id2 := agent.ResolveAgentID("", "stable-host", logger)
		assert.NotEmpty(t, id1)
		// Deterministic: same fingerprint yields same UUIDv5.
		assert.Equal(t, id1, id2)
	})

	t.Run("uses NODE_NAME fingerprint component", func(t *testing.T) {
		t.Setenv("NODE_NAME", "k8s-node-1")
		id := agent.ResolveAgentID("", "", logger)
		assert.NotEmpty(t, id)
	})

	t.Run("different hostnames yield different ids", func(t *testing.T) {
		a := agent.ResolveAgentID("", "host-a", logger)
		b := agent.ResolveAgentID("", "host-b", logger)
		assert.NotEqual(t, a, b)
	})
}
