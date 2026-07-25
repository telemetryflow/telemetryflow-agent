// Package migration provides a versioned config schema migration framework.
//
// Each migration is registered as a small, independently testable unit that
// rewrites raw config bytes from one schema version to the next. Migration
// packages register themselves against DefaultRegistry from their init()
// functions; callers that want every available migration linked in import the
// internal/migration/all aggregator package.
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
package migration

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// LegacyVersion is the version returned by DetectVersion for configs that do
// not declare an explicit schema version. It corresponds to the 1.2.0 release
// line, the last version shipped before the migration framework was
// introduced.
const LegacyVersion = "1.2.0"

// Migration represents a single config schema transformation between two
// versions. Apply receives the raw config bytes at FromVersion and must return
// the bytes rewritten for ToVersion.
type Migration struct {
	// FromVersion is the schema version the input bytes are expected to be on
	// when this migration runs.
	FromVersion string
	// ToVersion is the schema version the returned bytes will conform to.
	ToVersion string
	// Name is a short, unique-within-FromVersion identifier for the migration.
	Name string
	// Description is a human-readable summary shown in help output and logs.
	Description string
	// Apply performs the actual rewrite of the config bytes.
	Apply func(input []byte) ([]byte, error)
}

// Registry holds a collection of migrations keyed by (FromVersion, Name).
// Migrations are kept sorted by FromVersion (then ToVersion) so that ordered
// application is deterministic.
type Registry struct {
	mu         sync.RWMutex
	migrations []Migration
	byKey      map[string]struct{}
}

// NewRegistry returns an empty Registry safe for concurrent use.
func NewRegistry() *Registry {
	return &Registry{byKey: make(map[string]struct{})}
}

// DefaultRegistry is the package-level Registry used by the package-level
// Register, MustRegister, ApplyAll, ApplyLatest, and List helpers. Versioned
// migration packages register themselves against this instance from their
// init() functions.
var DefaultRegistry = NewRegistry()

// Register adds a migration to the target Registry. It returns an error if a
// migration with the same (FromVersion, Name) pair has already been registered
// or if required fields are missing.
func (r *Registry) Register(m Migration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m.Name == "" {
		return fmt.Errorf("migration registration: Name must not be empty")
	}
	if m.FromVersion == "" || m.ToVersion == "" {
		return fmt.Errorf("migration %q: FromVersion and ToVersion must be set", m.Name)
	}
	if m.Apply == nil {
		return fmt.Errorf("migration %q: Apply function must not be nil", m.Name)
	}

	key := m.FromVersion + "::" + m.Name
	if _, exists := r.byKey[key]; exists {
		return fmt.Errorf("migration already registered for fromVersion=%s name=%s", m.FromVersion, m.Name)
	}
	r.byKey[key] = struct{}{}
	r.migrations = append(r.migrations, m)

	sort.SliceStable(r.migrations, func(i, j int) bool {
		if c := compareVersion(r.migrations[i].FromVersion, r.migrations[j].FromVersion); c != 0 {
			return c < 0
		}
		return compareVersion(r.migrations[i].ToVersion, r.migrations[j].ToVersion) < 0
	})
	return nil
}

// MustRegister wraps Register and panics on error. It is intended for use from
// migration packages' init() functions where a registration failure indicates
// a programmer error.
func (r *Registry) MustRegister(m Migration) {
	if err := r.Register(m); err != nil {
		panic(fmt.Sprintf("migration: %v", err))
	}
}

// List returns a copy of all registered migrations sorted by FromVersion (then
// ToVersion). The returned slice is safe to mutate and does not alias the
// registry's internal storage.
func (r *Registry) List() []Migration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Migration, len(r.migrations))
	copy(out, r.migrations)
	return out
}

// ApplyAll applies every registered migration whose FromVersion is greater than
// or equal to fromVersion AND whose ToVersion is less than or equal to
// toVersion, in sorted order. When fromVersion == toVersion no migrations match
// and the input is returned unchanged. A migration returning an error aborts
// the chain.
func (r *Registry) ApplyAll(input []byte, fromVersion, toVersion string) ([]byte, error) {
	current := input
	for _, m := range r.List() {
		if compareVersion(m.FromVersion, fromVersion) < 0 {
			continue
		}
		if compareVersion(m.ToVersion, toVersion) > 0 {
			continue
		}
		out, err := m.Apply(current)
		if err != nil {
			return nil, fmt.Errorf("migration %q (%s -> %s): %w", m.Name, m.FromVersion, m.ToVersion, err)
		}
		current = out
	}
	return current, nil
}

// ApplyLatest applies every registered migration in sorted order and returns
// the migrated bytes together with the resulting schema version. The resulting
// version is the ToVersion of the last applied migration, or the version
// detected from the input when no migrations ran.
func (r *Registry) ApplyLatest(input []byte) ([]byte, string, error) {
	current := input
	lastVersion := DetectVersion(input)
	for _, m := range r.List() {
		out, err := m.Apply(current)
		if err != nil {
			return nil, lastVersion, fmt.Errorf("migration %q (%s -> %s): %w", m.Name, m.FromVersion, m.ToVersion, err)
		}
		current = out
		lastVersion = m.ToVersion
	}
	return current, lastVersion, nil
}

// Register adds a migration to DefaultRegistry.
func Register(m Migration) error { return DefaultRegistry.Register(m) }

// MustRegister adds a migration to DefaultRegistry, panicking on error.
func MustRegister(m Migration) { DefaultRegistry.MustRegister(m) }

// List returns the migrations registered against DefaultRegistry, sorted.
func List() []Migration { return DefaultRegistry.List() }

// ApplyAll applies the matching migrations from DefaultRegistry. See
// Registry.ApplyAll for the selection rules.
func ApplyAll(input []byte, fromVersion, toVersion string) ([]byte, error) {
	return DefaultRegistry.ApplyAll(input, fromVersion, toVersion)
}

// ApplyLatest applies all DefaultRegistry migrations and returns the migrated
// bytes plus the resulting version.
func ApplyLatest(input []byte) ([]byte, string, error) {
	return DefaultRegistry.ApplyLatest(input)
}

// DetectVersion performs a best-effort lookup of the config schema version by
// reading the top-level "agent.version" YAML field. When the field is absent or
// the bytes cannot be parsed as YAML it returns LegacyVersion ("1.2.0"),
// matching the last pre-migration release.
func DetectVersion(input []byte) string {
	var root struct {
		Agent struct {
			Version string `yaml:"version"`
		} `yaml:"agent"`
	}
	if err := yaml.Unmarshal(input, &root); err != nil {
		return LegacyVersion
	}
	if v := strings.TrimSpace(root.Agent.Version); v != "" {
		return v
	}
	return LegacyVersion
}

// compareVersion compares two dotted numeric versions (e.g. "1.2.0"). It
// returns -1, 0, or +1. Missing trailing segments are treated as zero so
// "1.2" compares equal to "1.2.0". Segments that are not pure integers (for
// example pre-release suffixes like "0-dev") fall back to lexicographic
// comparison.
func compareVersion(a, b string) int {
	ta := strings.Split(a, ".")
	tb := strings.Split(b, ".")
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		sa := "0"
		sb := "0"
		if i < len(ta) {
			sa = strings.TrimSpace(ta[i])
			if sa == "" {
				sa = "0"
			}
		}
		if i < len(tb) {
			sb = strings.TrimSpace(tb[i])
			if sb == "" {
				sb = "0"
			}
		}
		ia, ea := strconv.Atoi(sa)
		ib, eb := strconv.Atoi(sb)
		if ea == nil && eb == nil {
			if ia < ib {
				return -1
			}
			if ia > ib {
				return 1
			}
			continue
		}
		if sa < sb {
			return -1
		}
		if sa > sb {
			return 1
		}
	}
	return 0
}
