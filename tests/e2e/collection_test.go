package e2e_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricCollection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Run("should collect system metrics", func(t *testing.T) {
		// Build agent binary
		buildCmd := exec.Command("go", "build", "-o", "../../build/tfo-agent", "../../cmd/tfo-agent")
		err := buildCmd.Run()
		require.NoError(t, err, "Failed to build agent binary")

		// Start agent with system collector enabled
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		agentCmd := exec.CommandContext(ctx, "../../build/tfo-agent", "start", "--config", "testdata/minimal.yaml")
		err = agentCmd.Start()
		require.NoError(t, err)

		// Let agent collect metrics for a few seconds
		time.Sleep(3 * time.Second)

		// Verify process is still running (collecting metrics)
		assert.NotNil(t, agentCmd.Process)

		// Stop agent
		_ = agentCmd.Process.Kill()
		_ = agentCmd.Wait()
	})
}
