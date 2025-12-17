// Package config provides configuration loading for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
//
// LEGO Building Block - Flexible config loading from multiple sources.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source represents a configuration source type
type Source string

const (
	// SourceFile loads config from a file
	SourceFile Source = "file"

	// SourceEnv loads config from environment variables
	SourceEnv Source = "env"

	// SourceRemote loads config from a remote source (future)
	SourceRemote Source = "remote"
)

// Loader loads configuration from various sources
type Loader struct {
	sources     []Source
	envPrefix   string
	configPaths []string
}

// Option configures the loader
type Option func(*Loader)

// WithEnvPrefix sets the environment variable prefix
func WithEnvPrefix(prefix string) Option {
	return func(l *Loader) {
		l.envPrefix = prefix
	}
}

// WithConfigPaths sets config file search paths
func WithConfigPaths(paths ...string) Option {
	return func(l *Loader) {
		l.configPaths = paths
	}
}

// WithSources sets the configuration sources
func WithSources(sources ...Source) Option {
	return func(l *Loader) {
		l.sources = sources
	}
}

// NewLoader creates a new configuration loader
func NewLoader(opts ...Option) *Loader {
	l := &Loader{
		sources:   []Source{SourceFile, SourceEnv},
		envPrefix: "TELEMETRYFLOW_",
		configPaths: []string{
			".",
			"./configs",
			"/etc/tfo-agent",
			"$HOME/.tfo-agent",
		},
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Load loads configuration into the target struct
func (l *Loader) Load(configFile string, target interface{}) error {
	// Try to load from file first
	if configFile != "" {
		if err := l.loadFromFile(configFile, target); err != nil {
			return fmt.Errorf("failed to load config file %s: %w", configFile, err)
		}
	} else {
		// Search for config file in paths
		found := false
		for _, name := range []string{"tfo-agent.yaml", "tfo-agent.yml", "config.yaml", "config.yml"} {
			for _, path := range l.configPaths {
				path = os.ExpandEnv(path)
				fullPath := filepath.Join(path, name)
				if _, err := os.Stat(fullPath); err == nil {
					if err := l.loadFromFile(fullPath, target); err != nil {
						return fmt.Errorf("failed to load config file %s: %w", fullPath, err)
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}

	// Override with environment variables
	if err := l.loadFromEnv(target); err != nil {
		return fmt.Errorf("failed to load env config: %w", err)
	}

	return nil
}

// loadFromFile loads configuration from a YAML file
func (l *Loader) loadFromFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Expand environment variables in the config
	expanded := os.ExpandEnv(string(data))

	return yaml.Unmarshal([]byte(expanded), target)
}

// loadFromEnv loads configuration from environment variables
func (l *Loader) loadFromEnv(target interface{}) error {
	// This is a simplified implementation
	// In production, you'd use reflection to map env vars to struct fields
	_ = target
	return nil
}

// GetEnv gets an environment variable with prefix
func (l *Loader) GetEnv(key string) string {
	fullKey := fmt.Sprintf("%s_%s", l.envPrefix, strings.ToUpper(key))
	return os.Getenv(fullKey)
}

// GetEnvOrDefault gets an environment variable or returns default
func (l *Loader) GetEnvOrDefault(key, defaultValue string) string {
	if value := l.GetEnv(key); value != "" {
		return value
	}
	return defaultValue
}

// MustLoad loads configuration and panics on error
func (l *Loader) MustLoad(configFile string, target interface{}) {
	if err := l.Load(configFile, target); err != nil {
		panic(fmt.Sprintf("failed to load configuration: %v", err))
	}
}

// Validate validates the loaded configuration
func Validate(config interface{}) error {
	// Add validation logic here
	// Could use struct tags or validation library
	return nil
}

// Default loader instance
var defaultLoader = NewLoader()

// Load loads config using the default loader
func Load(configFile string, target interface{}) error {
	return defaultLoader.Load(configFile, target)
}

// MustLoad loads config using the default loader, panics on error
func MustLoad(configFile string, target interface{}) {
	defaultLoader.MustLoad(configFile, target)
}
