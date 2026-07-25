// Package persister contains unit tests for the disk-backed plugin state
// persister, covering first-run, roundtrip, corrupt-file recovery, concurrent
// atomic writes, and the periodic save loop.
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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// fakeStatefulPlugin is a thread-safe plugin.StatefulPlugin test double. It
// records how many times GetState was invoked so tests can assert on save
// counts, and it restores whatever was passed to SetState.
type fakeStatefulPlugin struct {
	mu            sync.Mutex
	state         interface{}
	getStateCount int64
	setStateCount int64
}

// Compile-time guard: fakeStatefulPlugin satisfies plugin.StatefulPlugin.
var _ plugin.StatefulPlugin = (*fakeStatefulPlugin)(nil)

func (f *fakeStatefulPlugin) GetState() interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getStateCount++
	return f.state
}

func (f *fakeStatefulPlugin) SetState(state interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setStateCount++
	f.state = state
}

func (f *fakeStatefulPlugin) counts() (gets, sets int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getStateCount, f.setStateCount
}

func TestPersister_LoadFirstRun_NoExistingFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "plain missing file", path: "state.json"},
		{name: "nested missing path", path: filepath.Join("nested", "dir", "state.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := New(filepath.Join(dir, tt.path))
			fp := &fakeStatefulPlugin{state: map[string]interface{}{"counter": 42}}
			require.NoError(t, p.Register("cpu", fp))

			err := p.Load()
			require.NoError(t, err, "missing state file must not be an error")
			assert.False(t, tt.wantErr)

			// On first run nothing should have been restored.
			_, sets := fp.counts()
			assert.Equal(t, int64(0), sets, "SetState must not be called when no file exists")
		})
	}
}

func TestPersister_RegisterStoreLoad_Roundtrip(t *testing.T) {
	tests := []struct {
		name  string
		state interface{}
	}{
		{name: "map state", state: map[string]interface{}{"counter": float64(7), "name": "cpu"}},
		{name: "numeric state", state: float64(12345)},
		{name: "nested state", state: map[string]interface{}{
			"offsets": []interface{}{float64(1), float64(2), float64(3)},
			"meta":    map[string]interface{}{"host": "node-1"},
		}},
		{name: "string state", state: "last-seen-offset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")

			// Phase 1: register, set state, store.
			pOut := New(path)
			fpOut := &fakeStatefulPlugin{state: tt.state}
			require.NoError(t, pOut.Register("counter-plugin", fpOut))

			require.NoError(t, pOut.Store())

			// File must exist with 0600 perms and be valid JSON.
			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

			// Phase 2: brand-new persister + plugin instance, load, verify.
			pIn := New(path)
			fpIn := &fakeStatefulPlugin{}
			require.NoError(t, pIn.Register("counter-plugin", fpIn))

			require.NoError(t, pIn.Load())

			_, sets := fpIn.counts()
			require.Equal(t, int64(1), sets, "SetState must be called exactly once on Load")
			assert.Equal(t, tt.state, fpIn.state)
		})
	}
}

func TestPersister_LoadCorruptFile_Recovery(t *testing.T) {
	// Define byte payloads outside the table so the struct literal contains
	// only plain identifier references (avoids any composite-literal parsing
	// ambiguity from inline conversions with braces).
	var (
		garbage    = []byte("not json at all {{{{{")
		truncated  = []byte(`{"cpu": {"counter":`)
		leadingArr = []byte(`["not", "an", "object"]`)
		emptyFile  = []byte{}
	)
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "garbage bytes", content: garbage},
		{name: "truncated json", content: truncated},
		{name: "leading array", content: leadingArr},
		{name: "empty file", content: emptyFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			require.NoError(t, os.WriteFile(path, tt.content, 0600))

			p := New(path)
			fp := &fakeStatefulPlugin{state: map[string]interface{}{"counter": 0}}
			require.NoError(t, p.Register("cpu", fp))

			// Load must succeed (nil error) even though the file is corrupt.
			err := p.Load()
			require.NoError(t, err, "corrupt file must not error; it should be quarantined")

			// Original path must be gone.
			_, statErr := os.Stat(path)
			assert.True(t, os.IsNotExist(statErr), "original corrupt file must be moved aside")

			// A .corrupt-* sibling must exist holding the original bytes.
			matches, err := filepath.Glob(path + ".corrupt-*")
			require.NoError(t, err)
			require.Len(t, matches, 1, "exactly one quarantine file expected")
			archived, err := os.ReadFile(matches[0])
			require.NoError(t, err)
			assert.Equal(t, tt.content, archived)

			// Plugin must NOT have been restored (Load recovered cleanly).
			_, sets := fp.counts()
			assert.Equal(t, int64(0), sets, "no SetState on corrupt recovery")

			// A subsequent Store must succeed, proving recovery is real.
			require.NoError(t, p.Store())
			_, err = os.Stat(path)
			assert.NoError(t, err, "state file must be writable after recovery")
		})
	}
}

func TestPersister_Store_ConcurrentAtomicWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	p := New(path)
	// Register several plugins so the snapshot is non-trivial.
	for i := 0; i < 5; i++ {
		fp := &fakeStatefulPlugin{state: map[string]interface{}{
			"counter": float64(i),
		}}
		require.NoError(t, p.Register(pluginID(i), fp))
	}

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			errs <- p.Store()
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "concurrent Store must not error")
	}

	// The final file must be valid JSON that decodes into a map and contains
	// all registered ids.
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var restored map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &restored), "concurrent writes must not corrupt the file")

	require.Len(t, restored, 5, "all plugin ids must be present after concurrent stores")
	for i := 0; i < 5; i++ {
		_, ok := restored[pluginID(i)]
		assert.True(t, ok, "id %q missing", pluginID(i))
	}

	// No leftover temp file.
	_, err = os.Stat(path + ".tmp")
	assert.True(t, os.IsNotExist(err), "temp file must be cleaned up after rename")
}

func TestPersister_StartSaveLoop_PeriodicSaves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	p := New(path)
	fp := &fakeStatefulPlugin{state: map[string]interface{}{"counter": float64(0)}}
	require.NoError(t, p.Register("counter", fp))

	// Short interval so multiple ticks land within the test window.
	interval := 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.StartSaveLoop(ctx, interval)
		close(done)
	}()

	// Wait long enough for several saves to occur.
	require.Eventually(t, func() bool {
		gets, _ := fp.counts()
		return gets >= 3
	}, 500*time.Millisecond, 5*time.Millisecond, "expected at least 3 periodic saves")

	// Cancel and confirm the loop returns promptly.
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StartSaveLoop did not return after ctx cancellation")
	}

	// The file must exist and contain valid persisted state.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var restored map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &restored))
	_, ok := restored["counter"]
	assert.True(t, ok)
}

func TestPersister_Register_Errors(t *testing.T) {
	t.Run("empty id", func(t *testing.T) {
		p := New(filepath.Join(t.TempDir(), "state.json"))
		err := p.Register("", &fakeStatefulPlugin{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("nil plugin", func(t *testing.T) {
		p := New(filepath.Join(t.TempDir(), "state.json"))
		err := p.Register("cpu", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("duplicate id", func(t *testing.T) {
		p := New(filepath.Join(t.TempDir(), "state.json"))
		require.NoError(t, p.Register("cpu", &fakeStatefulPlugin{}))
		err := p.Register("cpu", &fakeStatefulPlugin{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})
}

func TestPersister_Close_FlushesAndNilsCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	p := New(path)
	fp := &fakeStatefulPlugin{state: map[string]interface{}{"counter": float64(99)}}
	require.NoError(t, p.Register("cpu", fp))

	require.NoError(t, p.Close())

	// Final flush wrote the file.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var restored map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Contains(t, restored, "cpu")

	// Cache is nil after close.
	p.mu.RLock()
	assert.Nil(t, p.cache)
	p.mu.RUnlock()
}

func TestPersister_Load_SkipsUnregisteredEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Persisted state contains entries for plugins that are NOT registered in
	// this run ("orphan-a", "orphan-b") alongside one that is ("registered").
	// Load must restore only the registered plugin and silently ignore the
	// orphaned entries without erroring.
	doc := map[string]json.RawMessage{
		"registered": json.RawMessage(`{"counter":5}`),
		"orphan-a":   json.RawMessage(`{"counter":1}`),
		"orphan-b":   json.RawMessage(`{"last":"2024-01-01T00:00:00Z"}`),
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))

	p := New(path)
	registered := &fakeStatefulPlugin{}
	require.NoError(t, p.Register("registered", registered))

	require.NoError(t, p.Load(), "orphaned entries must not fail Load")

	// Only the registered plugin was touched.
	_, sets := registered.counts()
	assert.Equal(t, int64(1), sets, "only the registered plugin should be restored")
	assert.Equal(t, map[string]interface{}{"counter": float64(5)}, registered.state)

	// The orphan state must not have leaked into the registered plugin.
	p.mu.RLock()
	assert.Len(t, p.plugins, 1)
	p.mu.RUnlock()
}

// pluginID returns a deterministic id for index i.
func pluginID(i int) string { return "plugin-" + string(rune('a'+i)) }
