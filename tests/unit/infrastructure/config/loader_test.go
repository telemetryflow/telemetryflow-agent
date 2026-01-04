// Package config_test provides unit tests for the pkg/config loader.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/telemetryflow/telemetryflow-agent/pkg/config"
)

func TestNewLoader(t *testing.T) {
	t.Run("should create loader with defaults", func(t *testing.T) {
		loader := pkgconfig.NewLoader()
		require.NotNil(t, loader)
	})

	t.Run("should create loader with options", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("TEST_PREFIX"),
			pkgconfig.WithConfigPaths("/custom/path", "/another/path"),
		)
		require.NotNil(t, loader)
	})

	t.Run("should create loader with sources", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithSources(pkgconfig.SourceFile, pkgconfig.SourceEnv),
		)
		require.NotNil(t, loader)
	})
}

func TestLoaderWithEnvPrefix(t *testing.T) {
	t.Run("should set env prefix", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("CUSTOM_PREFIX"),
		)
		require.NotNil(t, loader)
	})

	t.Run("should handle empty prefix", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix(""),
		)
		require.NotNil(t, loader)
	})
}

func TestLoaderWithConfigPaths(t *testing.T) {
	t.Run("should set config paths", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths("/path/one", "/path/two", "/path/three"),
		)
		require.NotNil(t, loader)
	})

	t.Run("should handle empty paths", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(),
		)
		require.NotNil(t, loader)
	})

	t.Run("should handle single path", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths("/single/path"),
		)
		require.NotNil(t, loader)
	})
}

func TestLoaderWithSources(t *testing.T) {
	t.Run("should set source to file only", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithSources(pkgconfig.SourceFile),
		)
		require.NotNil(t, loader)
	})

	t.Run("should set source to env only", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithSources(pkgconfig.SourceEnv),
		)
		require.NotNil(t, loader)
	})

	t.Run("should set multiple sources", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithSources(pkgconfig.SourceFile, pkgconfig.SourceEnv, pkgconfig.SourceRemote),
		)
		require.NotNil(t, loader)
	})
}

func TestLoaderLoad(t *testing.T) {
	t.Run("should load from explicit file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
name: test-app
endpoint: localhost:8080
debug: true
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name     string `yaml:"name"`
			Endpoint string `yaml:"endpoint"`
			Debug    bool   `yaml:"debug"`
		}

		loader := pkgconfig.NewLoader()
		var cfg TestConfig
		err = loader.Load(configPath, &cfg)
		require.NoError(t, err)

		assert.Equal(t, "test-app", cfg.Name)
		assert.Equal(t, "localhost:8080", cfg.Endpoint)
		assert.True(t, cfg.Debug)
	})

	t.Run("should fail with non-existent file", func(t *testing.T) {
		loader := pkgconfig.NewLoader()
		var cfg struct{}
		err := loader.Load("/non/existent/file.yaml", &cfg)
		assert.Error(t, err)
	})

	t.Run("should search for config in paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
name: discovered-app
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "discovered-app", cfg.Name)
	})

	t.Run("should handle invalid YAML", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		err := os.WriteFile(configPath, []byte("invalid: yaml: : content"), 0644)
		require.NoError(t, err)

		loader := pkgconfig.NewLoader()
		var cfg struct{}
		err = loader.Load(configPath, &cfg)
		assert.Error(t, err)
	})

	t.Run("should expand environment variables in config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		t.Setenv("TEST_VALUE", "expanded-value")

		configContent := `
name: $TEST_VALUE
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader()
		var cfg TestConfig
		err = loader.Load(configPath, &cfg)
		require.NoError(t, err)
		assert.Equal(t, "expanded-value", cfg.Name)
	})
}

func TestLoaderLoadFromEnv(t *testing.T) {
	t.Run("should handle empty config path with env fallback", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths("/non/existent/path"),
		)
		var cfg struct {
			Name string `yaml:"name"`
		}
		// Should not error, just load nothing
		err := loader.Load("", &cfg)
		assert.NoError(t, err)
	})
}

func TestLoaderGetEnv(t *testing.T) {
	t.Run("should get env with prefix", func(t *testing.T) {
		t.Setenv("TELEMETRYFLOW__TEST_KEY", "test-value")

		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("TELEMETRYFLOW_"),
		)

		value := loader.GetEnv("TEST_KEY")
		assert.Equal(t, "test-value", value)
	})

	t.Run("should return empty for non-existent env", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("TELEMETRYFLOW_"),
		)

		value := loader.GetEnv("NON_EXISTENT_KEY")
		assert.Empty(t, value)
	})
}

func TestLoaderGetEnvOrDefault(t *testing.T) {
	t.Run("should return env value when set", func(t *testing.T) {
		t.Setenv("TELEMETRYFLOW__EXISTING_KEY", "existing-value")

		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("TELEMETRYFLOW_"),
		)

		value := loader.GetEnvOrDefault("EXISTING_KEY", "default-value")
		assert.Equal(t, "existing-value", value)
	})

	t.Run("should return default when env not set", func(t *testing.T) {
		loader := pkgconfig.NewLoader(
			pkgconfig.WithEnvPrefix("TELEMETRYFLOW_"),
		)

		value := loader.GetEnvOrDefault("NOT_SET_KEY", "default-value")
		assert.Equal(t, "default-value", value)
	})
}

func TestLoaderMustLoad(t *testing.T) {
	t.Run("should load successfully", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `name: must-load-app`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader()
		var cfg TestConfig

		// Should not panic
		assert.NotPanics(t, func() {
			loader.MustLoad(configPath, &cfg)
		})
		assert.Equal(t, "must-load-app", cfg.Name)
	})

	t.Run("should panic on error", func(t *testing.T) {
		loader := pkgconfig.NewLoader()
		var cfg struct{}

		assert.Panics(t, func() {
			loader.MustLoad("/non/existent/file.yaml", &cfg)
		})
	})
}

func TestValidate(t *testing.T) {
	t.Run("should validate config", func(t *testing.T) {
		cfg := struct {
			Name string
		}{
			Name: "test",
		}

		err := pkgconfig.Validate(cfg)
		assert.NoError(t, err)
	})

	t.Run("should validate nil config", func(t *testing.T) {
		err := pkgconfig.Validate(nil)
		assert.NoError(t, err)
	})
}

func TestDefaultLoaderFunctions(t *testing.T) {
	t.Run("Load should use default loader", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `name: default-loader-app`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		var cfg TestConfig
		err = pkgconfig.Load(configPath, &cfg)
		require.NoError(t, err)
		assert.Equal(t, "default-loader-app", cfg.Name)
	})

	t.Run("MustLoad should use default loader", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `name: must-default-app`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		var cfg TestConfig
		assert.NotPanics(t, func() {
			pkgconfig.MustLoad(configPath, &cfg)
		})
		assert.Equal(t, "must-default-app", cfg.Name)
	})

	t.Run("MustLoad should panic on error", func(t *testing.T) {
		var cfg struct{}
		assert.Panics(t, func() {
			pkgconfig.MustLoad("/invalid/path.yaml", &cfg)
		})
	})
}

func TestSourceConstants(t *testing.T) {
	t.Run("should have correct source values", func(t *testing.T) {
		assert.Equal(t, pkgconfig.Source("file"), pkgconfig.SourceFile)
		assert.Equal(t, pkgconfig.Source("env"), pkgconfig.SourceEnv)
		assert.Equal(t, pkgconfig.Source("remote"), pkgconfig.SourceRemote)
	})
}

func TestLoaderConfigFileDiscovery(t *testing.T) {
	t.Run("should discover tfo-agent.yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `name: tfo-agent-config`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "tfo-agent-config", cfg.Name)
	})

	t.Run("should discover tfo-agent.yml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yml")

		configContent := `name: tfo-agent-yml-config`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "tfo-agent-yml-config", cfg.Name)
	})

	t.Run("should discover config.yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `name: config-yaml-discovered`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "config-yaml-discovered", cfg.Name)
	})

	t.Run("should discover config.yml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")

		configContent := `name: config-yml-discovered`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "config-yml-discovered", cfg.Name)
	})

	t.Run("should prioritize tfo-agent.yaml over config.yaml", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create both files
		err := os.WriteFile(filepath.Join(tmpDir, "tfo-agent.yaml"), []byte(`name: tfo-agent`), 0644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(`name: config`), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths(tmpDir),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "tfo-agent", cfg.Name) // tfo-agent.yaml should be prioritized
	})
}

func TestLoaderEnvVarExpansion(t *testing.T) {
	t.Run("should expand HOME env var in path", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("HOME", tmpDir)

		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")
		configContent := `name: home-expanded`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type TestConfig struct {
			Name string `yaml:"name"`
		}

		loader := pkgconfig.NewLoader(
			pkgconfig.WithConfigPaths("$HOME"),
		)
		var cfg TestConfig
		err = loader.Load("", &cfg)
		require.NoError(t, err)
		assert.Equal(t, "home-expanded", cfg.Name)
	})
}

func TestLoaderComplexConfig(t *testing.T) {
	t.Run("should load complex nested config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
server:
  host: localhost
  port: 8080
database:
  host: db.example.com
  port: 5432
  name: mydb
features:
  - feature1
  - feature2
  - feature3
settings:
  timeout: 30
  retries: 3
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		type ServerConfig struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
		}
		type DatabaseConfig struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
			Name string `yaml:"name"`
		}
		type Settings struct {
			Timeout int `yaml:"timeout"`
			Retries int `yaml:"retries"`
		}
		type TestConfig struct {
			Server   ServerConfig   `yaml:"server"`
			Database DatabaseConfig `yaml:"database"`
			Features []string       `yaml:"features"`
			Settings Settings       `yaml:"settings"`
		}

		loader := pkgconfig.NewLoader()
		var cfg TestConfig
		err = loader.Load(configPath, &cfg)
		require.NoError(t, err)

		assert.Equal(t, "localhost", cfg.Server.Host)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, "db.example.com", cfg.Database.Host)
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "mydb", cfg.Database.Name)
		assert.Len(t, cfg.Features, 3)
		assert.Contains(t, cfg.Features, "feature1")
		assert.Equal(t, 30, cfg.Settings.Timeout)
		assert.Equal(t, 3, cfg.Settings.Retries)
	})
}
