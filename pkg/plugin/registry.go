// Package plugin provides a plugin registry system for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
//
// LEGO Building Block - Flexible plugin system for adding components.
package plugin

import (
	"fmt"
	"sync"
)

// Type represents the type of plugin
type Type string

const (
	// TypeCollector is a metrics/logs/traces collector plugin
	TypeCollector Type = "collector"

	// TypeExporter is a data exporter plugin
	TypeExporter Type = "exporter"

	// TypeProcessor is a data processor plugin
	TypeProcessor Type = "processor"

	// TypeExtension is an extension plugin
	TypeExtension Type = "extension"
)

// Info contains plugin metadata
type Info struct {
	Name        string
	Type        Type
	Version     string
	Description string
	Author      string
}

// Plugin is the interface all plugins must implement
type Plugin interface {
	// Info returns plugin metadata
	Info() Info

	// Init initializes the plugin with configuration
	Init(config map[string]interface{}) error

	// Start starts the plugin
	Start() error

	// Stop stops the plugin gracefully
	Stop() error
}

// Factory creates a new plugin instance
type Factory func() Plugin

// Registry holds registered plugins
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
	instances map[string]Plugin
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
		instances: make(map[string]Plugin),
	}
}

// Register adds a plugin factory to the registry
func (r *Registry) Register(name string, factory Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	r.factories[name] = factory
	return nil
}

// Unregister removes a plugin factory from the registry
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.factories, name)
}

// Get retrieves a plugin instance by name, creating if needed
func (r *Registry) Get(name string) (Plugin, error) {
	r.mu.RLock()
	if instance, exists := r.instances[name]; exists {
		r.mu.RUnlock()
		return instance, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if instance, exists := r.instances[name]; exists {
		return instance, nil
	}

	factory, exists := r.factories[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	instance := factory()
	r.instances[name] = instance
	return instance, nil
}

// Create creates a new plugin instance without caching
func (r *Registry) Create(name string) (Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return factory(), nil
}

// List returns all registered plugin names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// ListByType returns plugin names filtered by type
func (r *Registry) ListByType(t Type) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, factory := range r.factories {
		plugin := factory()
		if plugin.Info().Type == t {
			names = append(names, name)
		}
	}
	return names
}

// Has checks if a plugin is registered
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.factories[name]
	return exists
}

// StopAll stops all running plugin instances
func (r *Registry) StopAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for name, instance := range r.instances {
		if err := instance.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop %s: %w", name, err))
		}
	}

	r.instances = make(map[string]Plugin)

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping plugins: %v", errs)
	}
	return nil
}

// Global default registry
var defaultRegistry = NewRegistry()

// Register adds a plugin to the default registry
func Register(name string, factory Factory) error {
	return defaultRegistry.Register(name, factory)
}

// Get retrieves a plugin from the default registry
func Get(name string) (Plugin, error) {
	return defaultRegistry.Get(name)
}

// List returns all plugins from the default registry
func List() []string {
	return defaultRegistry.List()
}

// ListByType returns plugins by type from the default registry
func ListByType(t Type) []string {
	return defaultRegistry.ListByType(t)
}
