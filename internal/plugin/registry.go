// Registry: typed plugin registries with self-registration via init().
// Mirrors the Telegraf pattern where each plugin registers itself in its
// package init() function, and a top-level `all` package blank-imports every
// plugin to assemble the build.

package plugin

import (
	"fmt"
	"sort"
	"sync"
)

// Creator is a factory function that returns a fresh plugin instance.
type (
	CollectorCreator   func() Collector
	ServiceCollCreator func() ServiceCollector
	OutputCreator      func() Output
	ProcessorCreator   func() StreamingProcessor
	SyncProcCreator    func() SyncProcessor
	AggregatorCreator  func() Aggregator
	ParserCreator      func() Parser
	SerializerCreator  func() Serializer
	SecretStoreCreator func() SecretStore
)

// registryEntry stores the creator plus a deprecation notice (empty if none).
type registryEntry[C any] struct {
	creator    C
	deprecated string
}

type typedRegistry[C any] struct {
	mu      sync.RWMutex
	entries map[string]registryEntry[C]
}

func newTypedRegistry[C any]() *typedRegistry[C] {
	return &typedRegistry[C]{entries: make(map[string]registryEntry[C])}
}

func (r *typedRegistry[C]) add(name, deprecation string, creator C) error {
	if name == "" {
		return fmt.Errorf("plugin name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}
	r.entries[name] = registryEntry[C]{creator: creator, deprecated: deprecation}
	return nil
}

func (r *typedRegistry[C]) get(name string) (C, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	if !ok {
		var zero C
		return zero, "", false
	}
	return e.creator, e.deprecated, true
}

func (r *typedRegistry[C]) names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for n := range r.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Global registries — one per plugin type. Sub-systems (collectors, outputs,
// processors, aggregators, parsers, serializers, secret stores) register
// themselves at init() time.
var (
	collectorsReg     = newTypedRegistry[CollectorCreator]()
	serviceCollsReg   = newTypedRegistry[ServiceCollCreator]()
	outputsReg        = newTypedRegistry[OutputCreator]()
	processorsReg     = newTypedRegistry[ProcessorCreator]()
	syncProcessorsReg = newTypedRegistry[SyncProcCreator]()
	aggregatorsReg    = newTypedRegistry[AggregatorCreator]()
	parsersReg        = newTypedRegistry[ParserCreator]()
	serializersReg    = newTypedRegistry[SerializerCreator]()
	secretStoresReg   = newTypedRegistry[SecretStoreCreator]()
)

// --- Collectors --------------------------------------------------------------

// AddCollector registers a Collector under the given name. Intended to be
// called from a plugin package init().
func AddCollector(name string, c CollectorCreator) error {
	return collectorsReg.add(name, "", c)
}

// MustAddCollector is like AddCollector but panics on error. Use in init() to
// fail fast on duplicate registrations (programming error).
func MustAddCollector(name string, c CollectorCreator) {
	if err := AddCollector(name, c); err != nil {
		panic(err)
	}
}

// GetCollector returns a fresh Collector instance by name and its deprecation
// notice (empty if none). ok=false if the name is unknown.
func GetCollector(name string) (Collector, string, bool) {
	creator, dep, ok := collectorsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}

// CollectorNames returns the sorted list of registered Collector names.
func CollectorNames() []string { return collectorsReg.names() }

// --- Service Collectors ------------------------------------------------------

func AddServiceCollector(name string, c ServiceCollCreator) error {
	return serviceCollsReg.add(name, "", c)
}
func MustAddServiceCollector(name string, c ServiceCollCreator) {
	if err := AddServiceCollector(name, c); err != nil {
		panic(err)
	}
}
func GetServiceCollector(name string) (ServiceCollector, string, bool) {
	creator, dep, ok := serviceCollsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func ServiceCollectorNames() []string { return serviceCollsReg.names() }

// --- Outputs -----------------------------------------------------------------

func AddOutput(name string, c OutputCreator) error { return outputsReg.add(name, "", c) }
func MustAddOutput(name string, c OutputCreator) {
	if err := AddOutput(name, c); err != nil {
		panic(err)
	}
}
func GetOutput(name string) (Output, string, bool) {
	creator, dep, ok := outputsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func OutputNames() []string { return outputsReg.names() }

// --- Streaming Processors ----------------------------------------------------

func AddProcessor(name string, c ProcessorCreator) error { return processorsReg.add(name, "", c) }
func MustAddProcessor(name string, c ProcessorCreator) {
	if err := AddProcessor(name, c); err != nil {
		panic(err)
	}
}
func GetProcessor(name string) (StreamingProcessor, string, bool) {
	creator, dep, ok := processorsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func ProcessorNames() []string { return processorsReg.names() }

// --- Sync Processors (legacy) ------------------------------------------------

func AddSyncProcessor(name string, c SyncProcCreator) error {
	return syncProcessorsReg.add(name, "", c)
}
func MustAddSyncProcessor(name string, c SyncProcCreator) {
	if err := AddSyncProcessor(name, c); err != nil {
		panic(err)
	}
}
func GetSyncProcessor(name string) (SyncProcessor, string, bool) {
	creator, dep, ok := syncProcessorsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}

// --- Aggregators -------------------------------------------------------------

func AddAggregator(name string, c AggregatorCreator) error { return aggregatorsReg.add(name, "", c) }
func MustAddAggregator(name string, c AggregatorCreator) {
	if err := AddAggregator(name, c); err != nil {
		panic(err)
	}
}
func GetAggregator(name string) (Aggregator, string, bool) {
	creator, dep, ok := aggregatorsReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func AggregatorNames() []string { return aggregatorsReg.names() }

// --- Parsers -----------------------------------------------------------------

func AddParser(name string, c ParserCreator) error { return parsersReg.add(name, "", c) }
func MustAddParser(name string, c ParserCreator) {
	if err := AddParser(name, c); err != nil {
		panic(err)
	}
}
func GetParser(name string) (Parser, string, bool) {
	creator, dep, ok := parsersReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func ParserNames() []string { return parsersReg.names() }

// --- Serializers -------------------------------------------------------------

func AddSerializer(name string, c SerializerCreator) error { return serializersReg.add(name, "", c) }
func MustAddSerializer(name string, c SerializerCreator) {
	if err := AddSerializer(name, c); err != nil {
		panic(err)
	}
}
func GetSerializer(name string) (Serializer, string, bool) {
	creator, dep, ok := serializersReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func SerializerNames() []string { return serializersReg.names() }

// --- Secret Stores -----------------------------------------------------------

func AddSecretStore(name string, c SecretStoreCreator) error { return secretStoresReg.add(name, "", c) }
func MustAddSecretStore(name string, c SecretStoreCreator) {
	if err := AddSecretStore(name, c); err != nil {
		panic(err)
	}
}
func GetSecretStore(name string) (SecretStore, string, bool) {
	creator, dep, ok := secretStoresReg.get(name)
	if !ok {
		return nil, "", false
	}
	return creator(), dep, true
}
func SecretStoreNames() []string { return secretStoresReg.names() }

// AllNames returns a sorted list of all registered plugin names across all
// types. Used by the `tfo-agent plugins list` CLI command (M3).
func AllNames() []string {
	out := append([]string(nil), CollectorNames()...)
	out = append(out, ServiceCollectorNames()...)
	out = append(out, OutputNames()...)
	out = append(out, ProcessorNames()...)
	out = append(out, AggregatorNames()...)
	out = append(out, ParserNames()...)
	out = append(out, SerializerNames()...)
	out = append(out, SecretStoreNames()...)
	sort.Strings(out)
	return out
}
