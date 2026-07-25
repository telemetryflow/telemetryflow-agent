// Package secret provides the @{store:key} config resolver and the typed
// StoreConfig used to declaratively instantiate SecretStore backends.
//
// The resolver is the single entry point used by internal/config (and any
// other caller) to expand secret references embedded in arbitrary strings.
// Resolution order is:
//
//  1. ${VAR} references are expanded via os.ExpandEnv first. This lets ops
//     inject SecretStore configuration (e.g. a Vault token) directly from the
//     process environment.
//  2. @{store:key} references are then expanded by looking up the named
//     SecretStore and invoking its GetResolver.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package secret

import (
	"fmt"
	"os"
	"regexp"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// secretRefPattern captures the store name and the lookup key from a
// @{storeName:key} reference. Store names are restricted to identifier-like
// runes; keys may additionally include '.', '/', and '-'.
var secretRefPattern = regexp.MustCompile(`@\{([a-zA-Z0-9_-]+):([a-zA-Z0-9_./-]+)\}`)

// StoreConfig declares one named SecretStore instance to be instantiated by
// NewResolver.
type StoreConfig struct {
	// Name is the identifier used inside @{Name:key} references. Must be
	// unique across all StoreConfig entries passed to a single Resolver.
	Name string

	// Type selects the SecretStore implementation. Must match a name
	// registered via plugin.AddSecretStore (e.g. "env", "file", "vault").
	Type string

	// Config is the implementation-specific configuration passed through to
	// SecretStore.Init.
	Config map[string]interface{}
}

// Resolver expands @{store:key} references in configuration strings using a
// fixed set of named SecretStore backends.
type Resolver struct {
	stores  map[string]plugin.SecretStore
	logger  *zap.Logger
	pattern *regexp.Regexp
}

// NewResolver instantiates and initialises every SecretStore declared in
// storeConfigs. Stores are addressed by their StoreConfig.Name from that
// point on; the underlying Type is no longer queried at Resolve time.
//
// A nil logger is replaced with a no-op logger so callers never need to
// branch on logging availability.
func NewResolver(storeConfigs []StoreConfig, logger *zap.Logger) (*Resolver, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &Resolver{
		stores:  make(map[string]plugin.SecretStore, len(storeConfigs)),
		logger:  logger,
		pattern: secretRefPattern,
	}
	for _, sc := range storeConfigs {
		store, dep, ok := plugin.GetSecretStore(sc.Type)
		if !ok {
			return nil, fmt.Errorf("secret resolver: unknown store type %q for store %q; registered types: %v",
				sc.Type, sc.Name, plugin.SecretStoreNames())
		}
		if dep != "" {
			logger.Warn("secret store uses deprecated type",
				zap.String("name", sc.Name),
				zap.String("type", sc.Type),
				zap.String("deprecation", dep))
		}
		if err := store.Init(sc.Config); err != nil {
			return nil, fmt.Errorf("secret resolver: init store %q (%s): %w", sc.Name, sc.Type, err)
		}
		if _, dup := r.stores[sc.Name]; dup {
			return nil, fmt.Errorf("secret resolver: duplicate store name %q", sc.Name)
		}
		r.stores[sc.Name] = store
		logger.Info("secret store initialized",
			zap.String("name", sc.Name),
			zap.String("type", sc.Type))
	}
	return r, nil
}

// Resolve expands ${VAR} and @{store:key} references in input. An empty input
// is returned unchanged. Unknown stores and missing keys produce an error and
// short-circuit further resolution.
func (r *Resolver) Resolve(input string) (string, error) {
	if input == "" {
		return input, nil
	}
	// Step 1: expand ${VAR} env references so SecretStore configuration can
	// be bootstrapped from the environment (e.g. a Vault token).
	expanded := os.ExpandEnv(input)

	// Step 2: expand @{store:key} references against the registered stores.
	var resolveErr error
	out := r.pattern.ReplaceAllStringFunc(expanded, func(match string) string {
		if resolveErr != nil {
			return match
		}
		sub := r.pattern.FindStringSubmatch(match)
		// sub[0] is the whole match; sub[1] is the store name; sub[2] is the key.
		// FindStringSubmatch on a string that ReplaceAllStringFunc just matched
		// cannot return nil, but we defend against regexp edge cases regardless.
		if len(sub) < 3 {
			resolveErr = fmt.Errorf("secret resolver: malformed reference %q", match)
			return match
		}
		storeName, key := sub[1], sub[2]
		store, ok := r.stores[storeName]
		if !ok {
			resolveErr = fmt.Errorf("secret resolver: unknown store %q in %q", storeName, match)
			return match
		}
		resolveFn, err := store.GetResolver(key)
		if err != nil {
			resolveErr = fmt.Errorf("secret resolver: bind %q: %w", match, err)
			return match
		}
		value, _, err := resolveFn()
		if err != nil {
			resolveErr = fmt.Errorf("secret resolver: resolve %q: %w", match, err)
			return match
		}
		return value
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	return out, nil
}

// ResolveBytes is a []byte convenience wrapper around Resolve.
func (r *Resolver) ResolveBytes(input []byte) ([]byte, error) {
	out, err := r.Resolve(string(input))
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}
