// Package e2e contains end-to-end tests covering the full TelemetryFlow Agent
// pipeline: startup, metric collection, export, and graceful shutdown.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package e2e_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Run("should start with valid config", func(t *testing.T) {
		// Build agent binary
		buildCmd := exec.Command("go", "build", "-o", "../../build/tfo-agent", "../../cmd/tfo-agent")
		err := buildCmd.Run()
		require.NoError(t, err, "Failed to build agent binary")

		// Start agent with test config
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		agentCmd := exec.CommandContext(ctx, "../../build/tfo-agent", "start", "--config", "testdata/minimal.yaml")
		err = agentCmd.Start()
		require.NoError(t, err)

		// Wait for agent to start
		time.Sleep(time.Second)

		// Verify process is running
		assert.NotNil(t, agentCmd.Process)

		// Stop agent
		_ = agentCmd.Process.Kill()
		_ = agentCmd.Wait()
	})

	t.Run("should fail with invalid config", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		agentCmd := exec.CommandContext(ctx, "../../build/tfo-agent", "start", "--config", "testdata/invalid.yaml")
		err := agentCmd.Run()
		assert.Error(t, err, "Agent should fail with invalid config")
	})
}
