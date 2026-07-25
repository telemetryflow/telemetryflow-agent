// Package file implements a JSON-file-backed SecretStore.
//
// The file store reads a flat JSON object mapping secret names to string
// values (e.g. {"mysql_password": "secret123", "api_key": "abcdef"}) into
// memory once at Init time. The parsed map is guarded by an RWMutex so the
// store can be safely reloaded at runtime in a future revision.
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
package file

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// init registers the file SecretStore under the name "file".
func init() {
	plugin.MustAddSecretStore("file", func() plugin.SecretStore { return &FileStore{} })
}

// FileStore resolves secrets from a JSON file on disk.
//
// The file content must be a JSON object with string values, for example:
//
//	{"mysql_password": "secret123", "api_key": "abcdef"}
//
// The file is parsed once during Init and cached in memory; all lookups are
// in-process and never touch the filesystem.
type FileStore struct {
	mu      sync.RWMutex
	path    string
	secrets map[string]string
}

// Name returns the registry name of this store: "file".
func (s *FileStore) Name() string { return "file" }

// Init reads and parses the configured JSON file. Required config keys:
//
//   - path (string): absolute or relative path to a readable JSON file whose
//     top-level object maps secret names to string values.
//
// nil config is rejected; "path" is mandatory.
func (s *FileStore) Init(config map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("file store: config is nil")
	}
	rawPath, ok := config["path"]
	if !ok {
		return fmt.Errorf("file store: \"path\" is required")
	}
	path, ok := rawPath.(string)
	if !ok || path == "" {
		return fmt.Errorf("file store: \"path\" must be a non-empty string")
	}
	s.path = path
	return s.reload()
}

// reload re-reads and parses the JSON file. Caller is responsible for any
// lock coordination around s.path; s.secrets is updated under s.mu.
func (s *FileStore) reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("file store: read %q: %w", s.path, err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("file store: parse %q: %w", s.path, err)
	}
	s.mu.Lock()
	s.secrets = parsed
	s.mu.Unlock()
	return nil
}

// Get returns the value associated with key in the parsed file. It returns
// an error if the key is absent or the store has not been initialised.
func (s *FileStore) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.secrets == nil {
		return "", fmt.Errorf("file store: not initialized")
	}
	v, ok := s.secrets[key]
	if !ok {
		return "", fmt.Errorf("file store: key %q not found in %s", key, s.path)
	}
	return v, nil
}

// List returns the sorted names of all secrets in the file.
func (s *FileStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.secrets == nil {
		return nil, fmt.Errorf("file store: not initialized")
	}
	out := make([]string, 0, len(s.secrets))
	for k := range s.secrets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// GetResolver returns a resolver closure for the given key. The returned
// resolver is static (dynamic=false): the on-disk file does not auto-reload
// within the lifetime of a GetResolver binding.
func (s *FileStore) GetResolver(key string) (plugin.ResolveFunc, error) {
	store := s
	return func() (string, bool, error) {
		v, err := store.Get(key)
		return v, false, err
	}, nil
}
