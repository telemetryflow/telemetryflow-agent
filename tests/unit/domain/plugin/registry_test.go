// Package plugin_test provides unit tests for the TelemetryFlow plugin domain.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package plugin_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/pkg/plugin"
)

// mockPlugin implements plugin.Plugin interface for testing
type mockPlugin struct {
	info    plugin.Info
	started bool
	stopped bool
}

func (m *mockPlugin) Info() plugin.Info {
	return m.info
}

func (m *mockPlugin) Init(config map[string]interface{}) error {
	return nil
}

func (m *mockPlugin) Start() error {
	m.started = true
	return nil
}

func (m *mockPlugin) Stop() error {
	m.stopped = true
	return nil
}

func newMockPlugin(name string, t plugin.Type) plugin.Factory {
	return func() plugin.Plugin {
		return &mockPlugin{
			info: plugin.Info{
				Name:        name,
				Type:        t,
				Version:     "1.0.0",
				Description: "Mock plugin for testing",
			},
		}
	}
}

func TestNewRegistry(t *testing.T) {
	t.Run("should create empty registry", func(t *testing.T) {
		registry := plugin.NewRegistry()

		require.NotNil(t, registry)
		assert.Empty(t, registry.List())
	})
}

func TestRegistryRegister(t *testing.T) {
	t.Run("should register plugin factory", func(t *testing.T) {
		registry := plugin.NewRegistry()

		err := registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))
		require.NoError(t, err)
		assert.True(t, registry.Has("test-plugin"))
	})

	t.Run("should return error for duplicate registration", func(t *testing.T) {
		registry := plugin.NewRegistry()

		err := registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))
		require.NoError(t, err)

		err = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})
}

func TestRegistryUnregister(t *testing.T) {
	t.Run("should unregister plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()

		_ = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))
		assert.True(t, registry.Has("test-plugin"))

		registry.Unregister("test-plugin")
		assert.False(t, registry.Has("test-plugin"))
	})

	t.Run("should not panic on unregistering non-existent plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()

		assert.NotPanics(t, func() {
			registry.Unregister("non-existent")
		})
	})
}

func TestRegistryGet(t *testing.T) {
	t.Run("should get and create plugin instance", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))

		p, err := registry.Get("test-plugin")
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, "test-plugin", p.Info().Name)
	})

	t.Run("should return same instance on multiple gets", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))

		plugin1, _ := registry.Get("test-plugin")
		plugin2, _ := registry.Get("test-plugin")

		assert.Same(t, plugin1, plugin2)
	})

	t.Run("should return error for non-existent plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()

		_, err := registry.Get("non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRegistryCreate(t *testing.T) {
	t.Run("should create new plugin instance each time", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))

		plugin1, err := registry.Create("test-plugin")
		require.NoError(t, err)

		plugin2, err := registry.Create("test-plugin")
		require.NoError(t, err)

		assert.NotSame(t, plugin1, plugin2)
	})

	t.Run("should return error for non-existent plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()

		_, err := registry.Create("non-existent")
		require.Error(t, err)
	})
}

func TestRegistryList(t *testing.T) {
	t.Run("should list all registered plugins", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("plugin-a", newMockPlugin("plugin-a", plugin.TypeCollector))
		_ = registry.Register("plugin-b", newMockPlugin("plugin-b", plugin.TypeExporter))
		_ = registry.Register("plugin-c", newMockPlugin("plugin-c", plugin.TypeProcessor))

		names := registry.List()

		assert.Len(t, names, 3)
		assert.Contains(t, names, "plugin-a")
		assert.Contains(t, names, "plugin-b")
		assert.Contains(t, names, "plugin-c")
	})
}

func TestRegistryListByType(t *testing.T) {
	t.Run("should list plugins by type", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("collector-1", newMockPlugin("collector-1", plugin.TypeCollector))
		_ = registry.Register("collector-2", newMockPlugin("collector-2", plugin.TypeCollector))
		_ = registry.Register("exporter-1", newMockPlugin("exporter-1", plugin.TypeExporter))

		collectors := registry.ListByType(plugin.TypeCollector)
		assert.Len(t, collectors, 2)

		exporters := registry.ListByType(plugin.TypeExporter)
		assert.Len(t, exporters, 1)

		processors := registry.ListByType(plugin.TypeProcessor)
		assert.Empty(t, processors)
	})
}

func TestRegistryHas(t *testing.T) {
	t.Run("should return true for registered plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("test-plugin", newMockPlugin("test-plugin", plugin.TypeCollector))

		assert.True(t, registry.Has("test-plugin"))
	})

	t.Run("should return false for non-existent plugin", func(t *testing.T) {
		registry := plugin.NewRegistry()

		assert.False(t, registry.Has("non-existent"))
	})
}

func TestRegistryStopAll(t *testing.T) {
	t.Run("should stop all running instances", func(t *testing.T) {
		registry := plugin.NewRegistry()
		_ = registry.Register("plugin-1", newMockPlugin("plugin-1", plugin.TypeCollector))
		_ = registry.Register("plugin-2", newMockPlugin("plugin-2", plugin.TypeExporter))

		// Get instances to create them
		p1, _ := registry.Get("plugin-1")
		p2, _ := registry.Get("plugin-2")

		err := registry.StopAll()
		require.NoError(t, err)

		// Verify plugins were stopped
		assert.True(t, p1.(*mockPlugin).stopped)
		assert.True(t, p2.(*mockPlugin).stopped)
	})
}

func TestTypeConstants(t *testing.T) {
	t.Run("should have correct type values", func(t *testing.T) {
		assert.Equal(t, plugin.Type("collector"), plugin.TypeCollector)
		assert.Equal(t, plugin.Type("exporter"), plugin.TypeExporter)
		assert.Equal(t, plugin.Type("processor"), plugin.TypeProcessor)
		assert.Equal(t, plugin.Type("extension"), plugin.TypeExtension)
	})
}
