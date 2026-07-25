// Package env implements an environment-variable-backed SecretStore.
//
// The env store maps each configured key directly to an OS environment
// variable. An optional prefix may be configured to namespace the variables
// (e.g. prefix "TFO_" makes key "API_TOKEN" resolve to ${TFO_API_TOKEN}).
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
package env

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// init registers the env SecretStore with the global plugin registry. The
// store is keyed under the name "env".
func init() {
	plugin.MustAddSecretStore("env", func() plugin.SecretStore { return &EnvStore{} })
}

// EnvStore resolves secrets from process environment variables.
//
// It is the simplest backend and is well-suited for container runtimes
// (Docker, Kubernetes) and systemd unit files that inject secrets via env.
type EnvStore struct {
	// prefix is prepended to every lookup key. Empty by default.
	prefix string
}

// Name returns the registry name of this store: "env".
func (s *EnvStore) Name() string { return "env" }

// Init configures the store. The following config keys are recognised:
//
//   - prefix (string, optional): prepended to every key before env lookup.
//
// nil/empty config is valid and yields a prefixless store.
func (s *EnvStore) Init(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if v, ok := config["prefix"]; ok {
		p, ok := v.(string)
		if !ok {
			return fmt.Errorf("env store: \"prefix\" must be a string, got %T", v)
		}
		s.prefix = p
	}
	return nil
}

// Get returns the value of the environment variable named prefix+key.
// It returns an error if the variable is unset or empty.
func (s *EnvStore) Get(key string) (string, error) {
	name := s.prefix + key
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("env store: environment variable %q not set or empty", name)
	}
	return v, nil
}

// List returns the names of all environment variables matching the configured
// prefix, sorted lexicographically. With an empty prefix every exported
// environment variable is returned.
func (s *EnvStore) List() ([]string, error) {
	out := make([]string, 0, 16)
	for _, kv := range os.Environ() {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		name := kv[:idx]
		if strings.HasPrefix(name, s.prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// GetResolver returns a resolver closure for the given key. The returned
// resolver is static (dynamic=false): environment variables do not rotate at
// runtime within a single process.
func (s *EnvStore) GetResolver(key string) (plugin.ResolveFunc, error) {
	store := s
	return func() (string, bool, error) {
		v, err := store.Get(key)
		return v, false, err
	}, nil
}
