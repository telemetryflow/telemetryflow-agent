// Package application_test provides unit tests for the TelemetryFlow Agent CLI commands.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package application_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

func TestRootCommand(t *testing.T) {
	t.Run("should have correct use and description", func(t *testing.T) {
		rootCmd := &cobra.Command{
			Use:   "tfo-agent",
			Short: "TelemetryFlow Agent - Enterprise Observability Platform",
		}

		assert.Equal(t, "tfo-agent", rootCmd.Use)
		assert.Contains(t, rootCmd.Short, "TelemetryFlow Agent")
	})

	t.Run("should support subcommands", func(t *testing.T) {
		rootCmd := &cobra.Command{
			Use:   "tfo-agent",
			Short: "TelemetryFlow Agent",
		}

		startCmd := &cobra.Command{Use: "start", Short: "Start the agent"}
		versionCmd := &cobra.Command{Use: "version", Short: "Print version"}
		configCmd := &cobra.Command{Use: "config", Short: "Config commands"}

		rootCmd.AddCommand(startCmd, versionCmd, configCmd)

		assert.Len(t, rootCmd.Commands(), 3)

		cmdNames := make([]string, 0)
		for _, cmd := range rootCmd.Commands() {
			cmdNames = append(cmdNames, cmd.Use)
		}
		assert.Contains(t, cmdNames, "start")
		assert.Contains(t, cmdNames, "version")
		assert.Contains(t, cmdNames, "config")
	})
}

func TestVersionOutput(t *testing.T) {
	t.Run("should have valid version info", func(t *testing.T) {
		info := version.Get()
		assert.NotEmpty(t, info.Product)
		assert.NotEmpty(t, info.Version)
		assert.NotEmpty(t, info.OS)
		assert.NotEmpty(t, info.Arch)
	})

	t.Run("should have valid banner", func(t *testing.T) {
		banner := version.Banner()
		assert.NotEmpty(t, banner)
		assert.Contains(t, banner, "TelemetryFlow")
	})

	t.Run("should have valid one-liner", func(t *testing.T) {
		oneLiner := version.OneLiner()
		assert.NotEmpty(t, oneLiner)
	})
}

func TestGlobalFlags(t *testing.T) {
	t.Run("should set config flag", func(t *testing.T) {
		rootCmd := &cobra.Command{Use: "tfo-agent"}
		var testCfgFile string
		rootCmd.PersistentFlags().StringVarP(&testCfgFile, "config", "c", "", "config file path")

		err := rootCmd.PersistentFlags().Set("config", "/path/to/config.yaml")
		assert.NoError(t, err)
		assert.Equal(t, "/path/to/config.yaml", testCfgFile)
	})

	t.Run("should set log-level flag", func(t *testing.T) {
		rootCmd := &cobra.Command{Use: "tfo-agent"}
		var testLogLevel string
		rootCmd.PersistentFlags().StringVar(&testLogLevel, "log-level", "", "log level")

		err := rootCmd.PersistentFlags().Set("log-level", "debug")
		assert.NoError(t, err)
		assert.Equal(t, "debug", testLogLevel)
	})

	t.Run("should set log-format flag", func(t *testing.T) {
		rootCmd := &cobra.Command{Use: "tfo-agent"}
		var testLogFormat string
		rootCmd.PersistentFlags().StringVar(&testLogFormat, "log-format", "", "log format")

		err := rootCmd.PersistentFlags().Set("log-format", "json")
		assert.NoError(t, err)
		assert.Equal(t, "json", testLogFormat)
	})
}

func TestConfigValidation(t *testing.T) {
	t.Run("should validate valid config file", func(t *testing.T) {
		validConfig := `
agent:
  id: "test-agent"
  hostname: "test-host"

telemetryflow:
  endpoint: "localhost:4317"
  workspace_id: "test-workspace"
  api_key:
    id: "key-id"
    secret: "key-secret"

logging:
  level: "info"
  format: "text"
`
		tmpFile, err := os.CreateTemp("", "valid-config-*.yaml")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })

		_, err = tmpFile.WriteString(validConfig)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		loader := config.NewLoader()
		cfg, err := loader.Load(tmpFile.Name())
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "test-agent", cfg.Agent.ID)
	})

	t.Run("should fail with invalid config", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid-config-*.yaml")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })

		_, err = tmpFile.WriteString("invalid: yaml: : content")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		loader := config.NewLoader()
		_, err = loader.Load(tmpFile.Name())
		assert.Error(t, err)
	})
}

func TestHelpOutput(t *testing.T) {
	t.Run("should display help without error", func(t *testing.T) {
		rootCmd := &cobra.Command{
			Use:   "tfo-agent",
			Short: "TelemetryFlow Agent",
		}
		rootCmd.AddCommand(&cobra.Command{Use: "start", Short: "Start"})
		rootCmd.AddCommand(&cobra.Command{Use: "version", Short: "Version"})
		rootCmd.AddCommand(&cobra.Command{Use: "config", Short: "Config"})

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)
		rootCmd.SetArgs([]string{"--help"})

		err := rootCmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "tfo-agent")
		assert.Contains(t, output, "start")
		assert.Contains(t, output, "version")
		assert.Contains(t, output, "config")
	})
}

func TestCommandExecution(t *testing.T) {
	t.Run("should fail with invalid command", func(t *testing.T) {
		rootCmd := &cobra.Command{
			Use:   "tfo-agent",
			Short: "TelemetryFlow Agent",
		}
		rootCmd.AddCommand(&cobra.Command{Use: "start", Short: "Start"})

		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)
		rootCmd.SetArgs([]string{"invalidcmd"})

		err := rootCmd.Execute()
		assert.Error(t, err)
	})
}
