package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGracefulShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Run("should handle SIGTERM gracefully", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Build agent binary
		buildCmd := exec.CommandContext(ctx, "go", "build", "-o", "../../build/tfo-agent", "../../cmd/tfo-agent")
		err := buildCmd.Run()
		require.NoError(t, err, "Failed to build agent binary")

		// Start agent
		agentCmd := exec.Command("../../build/tfo-agent", "start", "--config", "testdata/minimal.yaml")
		err = agentCmd.Start()
		require.NoError(t, err)

		// Wait for startup
		time.Sleep(time.Second)

		// Send SIGTERM
		err = agentCmd.Process.Signal(syscall.SIGTERM)
		require.NoError(t, err)

		// Wait for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- agentCmd.Wait()
		}()

		select {
		case err := <-done:
			assert.NoError(t, err, "Agent should shutdown gracefully")
		case <-time.After(5 * time.Second):
			t.Fatal("Agent did not shutdown within timeout")
			_ = agentCmd.Process.Kill()
		}
	})

	t.Run("should handle SIGINT gracefully", func(t *testing.T) {
		// Start agent
		agentCmd := exec.Command("../../build/tfo-agent", "start", "--config", "testdata/minimal.yaml")
		err := agentCmd.Start()
		require.NoError(t, err)

		// Wait for startup
		time.Sleep(time.Second)

		// Send SIGINT (Ctrl+C)
		err = agentCmd.Process.Signal(os.Interrupt)
		require.NoError(t, err)

		// Wait for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- agentCmd.Wait()
		}()

		select {
		case err := <-done:
			assert.NoError(t, err, "Agent should shutdown gracefully")
		case <-time.After(5 * time.Second):
			t.Fatal("Agent did not shutdown within timeout")
			_ = agentCmd.Process.Kill()
		}
	})
}
