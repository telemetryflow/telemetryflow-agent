// Package config provides configuration loading tests for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	t.Run("should create loader with defaults", func(t *testing.T) {
		loader := NewLoader()

		require.NotNil(t, loader)
		assert.Equal(t, "TELEMETRYFLOW_", loader.envPrefix)
		assert.Contains(t, loader.sources, SourceFile)
		assert.Contains(t, loader.sources, SourceEnv)
	})

	t.Run("should apply options", func(t *testing.T) {
		loader := NewLoader(
			WithEnvPrefix("CUSTOM_"),
			WithConfigPaths("/custom/path"),
			WithSources(SourceEnv),
		)

		assert.Equal(t, "CUSTOM_", loader.envPrefix)
		assert.Contains(t, loader.configPaths, "/custom/path")
		assert.Contains(t, loader.sources, SourceEnv)
	})
}

func TestWithEnvPrefix(t *testing.T) {
	t.Run("should set custom prefix", func(t *testing.T) {
		loader := NewLoader(WithEnvPrefix("TEST_"))

		assert.Equal(t, "TEST_", loader.envPrefix)
	})
}

func TestWithConfigPaths(t *testing.T) {
	t.Run("should set config paths", func(t *testing.T) {
		loader := NewLoader(WithConfigPaths("/path1", "/path2"))

		assert.Contains(t, loader.configPaths, "/path1")
		assert.Contains(t, loader.configPaths, "/path2")
	})
}

func TestWithSources(t *testing.T) {
	t.Run("should set sources", func(t *testing.T) {
		loader := NewLoader(WithSources(SourceFile))

		assert.Contains(t, loader.sources, SourceFile)
		assert.NotContains(t, loader.sources, SourceEnv)
	})
}

func TestLoaderLoad(t *testing.T) {
	t.Run("should load config from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
name: test-config
value: 123
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := NewLoader()

		var target struct {
			Name  string `yaml:"name"`
			Value int    `yaml:"value"`
		}

		err = loader.Load(configPath, &target)
		require.NoError(t, err)
		assert.Equal(t, "test-config", target.Name)
		assert.Equal(t, 123, target.Value)
	})

	t.Run("should return error for invalid file", func(t *testing.T) {
		loader := NewLoader()

		var target map[string]interface{}
		err := loader.Load("/nonexistent/path/config.yaml", &target)
		require.Error(t, err)
	})

	t.Run("should expand environment variables in config", func(t *testing.T) {
		t.Setenv("TEST_VALUE", "expanded-value")

		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
name: ${TEST_VALUE}
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := NewLoader()

		var target struct {
			Name string `yaml:"name"`
		}

		err = loader.Load(configPath, &target)
		require.NoError(t, err)
		assert.Equal(t, "expanded-value", target.Name)
	})
}

func TestLoaderGetEnv(t *testing.T) {
	t.Run("should get env with prefix", func(t *testing.T) {
		// Prefix is "TELEMETRYFLOW_" + "_" + key = "TELEMETRYFLOW__TEST_KEY"
		t.Setenv("TELEMETRYFLOW__TEST_KEY", "test-value")

		loader := NewLoader()
		value := loader.GetEnv("TEST_KEY")

		assert.Equal(t, "test-value", value)
	})

	t.Run("should return empty for missing env", func(t *testing.T) {
		loader := NewLoader()
		value := loader.GetEnv("NONEXISTENT_KEY")

		assert.Empty(t, value)
	})
}

func TestLoaderGetEnvOrDefault(t *testing.T) {
	t.Run("should return env value when set", func(t *testing.T) {
		// Prefix is "TELEMETRYFLOW_" + "_" + key = "TELEMETRYFLOW__EXISTING"
		t.Setenv("TELEMETRYFLOW__EXISTING", "env-value")

		loader := NewLoader()
		value := loader.GetEnvOrDefault("EXISTING", "default")

		assert.Equal(t, "env-value", value)
	})

	t.Run("should return default when env not set", func(t *testing.T) {
		loader := NewLoader()
		value := loader.GetEnvOrDefault("NONEXISTENT", "default-value")

		assert.Equal(t, "default-value", value)
	})
}

func TestLoaderMustLoad(t *testing.T) {
	t.Run("should panic on error", func(t *testing.T) {
		loader := NewLoader()

		assert.Panics(t, func() {
			var target map[string]interface{}
			loader.MustLoad("/nonexistent/path/config.yaml", &target)
		})
	})
}

func TestValidate(t *testing.T) {
	t.Run("should return nil for valid config", func(t *testing.T) {
		config := map[string]string{"key": "value"}
		err := Validate(config)
		assert.NoError(t, err)
	})
}

func TestDefaultLoader(t *testing.T) {
	t.Run("Load should use default loader", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		err := os.WriteFile(configPath, []byte("key: value"), 0644)
		require.NoError(t, err)

		var target struct {
			Key string `yaml:"key"`
		}

		err = Load(configPath, &target)
		require.NoError(t, err)
		assert.Equal(t, "value", target.Key)
	})

	t.Run("MustLoad should panic on error", func(t *testing.T) {
		assert.Panics(t, func() {
			var target map[string]interface{}
			MustLoad("/nonexistent/file.yaml", &target)
		})
	})
}

func TestSourceConstants(t *testing.T) {
	t.Run("should have correct source values", func(t *testing.T) {
		assert.Equal(t, Source("file"), SourceFile)
		assert.Equal(t, Source("env"), SourceEnv)
		assert.Equal(t, Source("remote"), SourceRemote)
	})
}
