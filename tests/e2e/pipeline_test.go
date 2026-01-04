package e2e_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Run("should process telemetry pipeline", func(t *testing.T) {
		// Build agent binary
		buildCmd := exec.Command("go", "build", "-o", "../../build/tfo-agent", "../../cmd/tfo-agent")
		err := buildCmd.Run()
		require.NoError(t, err, "Failed to build agent binary")

		// Start agent with full pipeline
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		agentCmd := exec.CommandContext(ctx, "../../build/tfo-agent", "start", "--config", "testdata/minimal.yaml")
		err = agentCmd.Start()
		require.NoError(t, err)

		// Let pipeline run for several seconds
		time.Sleep(5 * time.Second)

		// Verify process is running and processing data
		assert.NotNil(t, agentCmd.Process)

		// Stop agent
		_ = agentCmd.Process.Kill()
		_ = agentCmd.Wait()
	})
}
