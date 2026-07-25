// Package persister provides disk-backed state persistence for plugins that
// implement the plugin.StatefulPlugin mixin. Plugin state is periodically
// snapshotted to a JSON file atomically (temp file + rename) and restored on
// the next agent startup, mirroring the Telegraf persister pattern.
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
package persister

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// Persister periodically snapshots the state of registered StatefulPlugin
// instances to a JSON file on disk and restores that state on the next
// startup. It is safe for concurrent use.
type Persister struct {
	path string
	mu   sync.RWMutex
	// plugins is the set of registered (id, StatefulPlugin) pairs that
	// participate in state save/restore.
	plugins map[string]plugin.StatefulPlugin
	// cache holds the last decoded state per id so callers can inspect what
	// was restored without re-reading the file.
	cache map[string]interface{}
	// log receives save/restore lifecycle events.
	log *zap.Logger
}

// New returns a Persister that persists state to the given file path. The
// path's parent directory is created on the first Store. By default the
// persister uses a no-op logger; call WithLogger to inject one.
func New(path string) *Persister {
	return &Persister{
		path:    path,
		plugins: make(map[string]plugin.StatefulPlugin),
		cache:   make(map[string]interface{}),
		log:     zap.NewNop(),
	}
}

// WithLogger injects a zap.Logger for save/restore lifecycle events and
// returns the receiver for chaining. A nil logger is ignored so the no-op
// default is preserved.
func (p *Persister) WithLogger(l *zap.Logger) *Persister {
	if l != nil {
		p.log = l
	}
	return p
}

// Register adds a plugin to the persister under the given id. The id is used
// as the JSON key and should be stable across restarts (prefer the plugin's
// PluginWithID value when available). Register returns an error if id is
// empty, the plugin is nil, or id is already registered.
func (p *Persister) Register(id string, plg plugin.StatefulPlugin) error {
	if id == "" {
		return fmt.Errorf("persister: plugin id must not be empty")
	}
	if plg == nil {
		return fmt.Errorf("persister: plugin %q must not be nil", id)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.plugins[id]; exists {
		return fmt.Errorf("persister: plugin %q already registered", id)
	}
	p.plugins[id] = plg
	return nil
}

// Load reads the state file at path and dispatches each entry to the matching
// registered plugin via SetState. A missing file is treated as a first run
// and is not an error. Entries whose id has no registered plugin are skipped
// silently. An individual entry that fails to decode is skipped with a
// warning. A syntactically corrupt file is moved aside to
// "<path>.corrupt-<timestamp>" and Load returns nil so the agent can start
// fresh rather than crash.
func (p *Persister) Load() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			p.log.Info("persister: no existing state file, starting fresh",
				zap.String("path", p.path))
			return nil
		}
		return fmt.Errorf("persister: failed to read state file %q: %w", p.path, err)
	}

	// Decode the top-level object as raw messages so we can validate overall
	// JSON syntax and then decode each entry independently.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return p.quarantineCorrupt(data, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for id, b := range raw {
		plg, ok := p.plugins[id]
		if !ok {
			// State on disk for a plugin that is not registered this run.
			p.log.Debug("persister: skipping state for unregistered plugin",
				zap.String("id", id))
			continue
		}
		// We do not know the concrete state type here, so decode into
		// interface{} and let the plugin type-assert inside SetState.
		var decoded interface{}
		if err := json.Unmarshal(b, &decoded); err != nil {
			p.log.Warn("persister: failed to decode state for plugin; skipping",
				zap.String("id", id), zap.Error(err))
			continue
		}
		plg.SetState(decoded)
		if p.cache != nil {
			p.cache[id] = decoded
		}
	}
	return nil
}

// quarantineCorrupt moves the unreadable state file aside to
// "<path>.corrupt-<timestamp>" so the next Store starts from a clean slate.
// It always returns nil so Load callers can recover automatically.
func (p *Persister) quarantineCorrupt(original []byte, parseErr error) error {
	ts := time.Now().UTC().Format("20060102-150405.000000000")
	quarantine := p.path + ".corrupt-" + ts
	if renameErr := os.Rename(p.path, quarantine); renameErr != nil {
		// Cross-device or permission issue: fall back to copying the bytes
		// out and truncating the original.
		if writeErr := os.WriteFile(quarantine, original, 0600); writeErr != nil {
			p.log.Error("persister: failed to quarantine corrupt state file",
				zap.String("path", p.path),
				zap.String("quarantine", quarantine),
				zap.Error(writeErr))
		}
		_ = os.Remove(p.path)
	}
	p.log.Warn("persister: state file was corrupt; quarantined and starting fresh",
		zap.String("path", p.path),
		zap.String("quarantine", quarantine),
		zap.Error(parseErr))
	return nil
}

// Store snapshots every registered plugin's state via GetState and writes it
// atomically to path. Atomicity is achieved by writing to a ".tmp" sibling
// file and renaming it over the final path. The file is created with mode
// 0600. Concurrent Store calls are serialised so they cannot corrupt each
// other or the temp file.
func (p *Persister) Store() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.plugins) == 0 {
		return nil
	}

	// Snapshot every registered plugin's state under the lock.
	snapshot := make(map[string]interface{}, len(p.plugins))
	for id, plg := range p.plugins {
		snapshot[id] = plg.GetState()
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("persister: failed to marshal state: %w", err)
	}

	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("persister: failed to create state directory %q: %w", dir, err)
	}

	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("persister: failed to write temp state file %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("persister: failed to commit state file %q: %w", p.path, err)
	}

	if p.cache != nil {
		for id, st := range snapshot {
			p.cache[id] = st
		}
	}
	return nil
}

// StartSaveLoop blocks and periodically calls Store at the given interval
// until ctx is cancelled, at which point it returns. Each successful save is
// logged at Info level and each failure at Error level. Callers should run
// this in its own goroutine. A non-positive interval returns immediately.
func (p *Persister) StartSaveLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.log.Info("persister: save loop stopped")
			return
		case <-ticker.C:
			if err := p.Store(); err != nil {
				p.log.Error("persister: periodic save failed", zap.Error(err))
				continue
			}
			p.log.Info("persister: periodic save completed",
				zap.Duration("interval", interval),
				zap.Int("plugins", len(p.snapshotIDs())))
		}
	}
}

// snapshotIDs returns a copy of the currently registered plugin ids. Caller
// must not be holding p.mu (this method takes the read lock itself).
func (p *Persister) snapshotIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.plugins))
	for id := range p.plugins {
		ids = append(ids, id)
	}
	return ids
}

// RegisteredIDs returns a copy of the currently registered plugin ids.
// Intended for tests and diagnostics that need to inspect registration state
// without holding the persister's internal lock.
func (p *Persister) RegisteredIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.plugins))
	for id := range p.plugins {
		ids = append(ids, id)
	}
	return ids
}

// CacheSnapshot returns a shallow copy of the last decoded/loaded state per
// plugin id. It returns nil after Close has nilled the cache, allowing tests
// and callers to verify the post-close lifecycle state.
func (p *Persister) CacheSnapshot() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cache == nil {
		return nil
	}
	out := make(map[string]interface{}, len(p.cache))
	for id, st := range p.cache {
		out[id] = st
	}
	return out
}

// Close performs a final Store to flush the latest state to disk and then
// nils out the in-memory state cache. After Close returns the persister
// should not be reused.
func (p *Persister) Close() error {
	if err := p.Store(); err != nil {
		return err
	}
	p.mu.Lock()
	p.cache = nil
	p.mu.Unlock()
	return nil
}
