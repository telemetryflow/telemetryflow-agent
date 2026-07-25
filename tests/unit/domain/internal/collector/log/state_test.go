// Package log_test contains black-box unit tests for the file log collector's
// StatefulPlugin implementation: tail offset persistence across restarts via
// the persister framework.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package log_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	logcol "github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// readOneLine drains at most one line out of the collector over a bounded
// timeout. It installs a log callback, runs Start in a goroutine, and returns
// once a line arrives or the timeout elapses. Start/Stop are handled
// internally so each test stays linear.
func readOneLine(t *testing.T, c *logcol.LogCollector, timeout time.Duration) (string, bool) {
	t.Helper()
	got := make(chan string, 1)
	c.SetLogCallback(func(_ time.Time, _, body, _ string, _ map[string]string) {
		select {
		case got <- body:
		default:
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()
	select {
	case line := <-got:
		_ = c.Stop()
		<-errCh
		return line, true
	case <-ctx.Done():
		_ = c.Stop()
		<-errCh
		return "", false
	}
}

// inodeOf returns the current inode of the open file at path. Used to seed
// persisted state with the exact same inode the tailer will see on restart.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open for inode: %v", err)
	}
	defer f.Close()
	return logcol.FileInodeExported(f)
}

// --- Tests ------------------------------------------------------------------

// TestTailerState_JSONRoundTrip ensures all TailerState fields survive a JSON
// marshal/unmarshal cycle so the persister can persist them faithfully.
func TestTailerState_JSONRoundTrip(t *testing.T) {
	original := logcol.TailerState{
		Path:        "/var/log/app.log",
		Inode:       12345,
		Offset:      6789,
		Fingerprint: "abc",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded logcol.TailerState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != original {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", decoded, original)
	}
}

// TestCollectorState_GetStateReturnsAllTailers wires up three tailers with
// distinct offsets and verifies GetState() snapshots every one of them.
func TestCollectorState_GetStateReturnsAllTailers(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.log", "b.log", "c.log"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("seed\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		paths = append(paths, p)
	}
	cfg := config.LogCollectorConfig{Enabled: true, Paths: paths, Interval: 50 * time.Millisecond}
	c := logcol.NewLogCollector(cfg, "agent-x", zap.NewNop())

	// Kick Start in a goroutine long enough for the tailers to open the files
	// and register themselves on the collector, then Stop. GetState iterates
	// the collector's tailer slice so it must see all three.
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()
	time.Sleep(400 * time.Millisecond)
	cancel()
	_ = c.Stop()
	<-errCh

	state := c.GetState()
	cs, ok := state.(*logcol.CollectorState)
	if !ok {
		t.Fatalf("GetState returned %T, want *logcol.CollectorState", state)
	}
	if len(cs.Tailers) != 3 {
		t.Fatalf("expected 3 tailers in state, got %d", len(cs.Tailers))
	}
	for _, p := range paths {
		ts, exists := cs.Tailers[p]
		if !exists {
			t.Errorf("missing tailer state for %s", p)
			continue
		}
		if ts.Path != p {
			t.Errorf("tailer state path mismatch: got %q want %q", ts.Path, p)
		}
	}
}

// TestSetState_NilIsSafe ensures SetState(nil) does not panic.
func TestSetState_NilIsSafe(t *testing.T) {
	c := logcol.NewLogCollector(config.LogCollectorConfig{}, "a", zap.NewNop())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetState(nil) panicked: %v", r)
		}
	}()
	c.SetState(nil)
}

// TestSetState_WrongTypeIsSafe ensures SetState with an unexpected concrete
// type is ignored rather than panicking. The persister's contract is that
// SetState must tolerate anything.
func TestSetState_WrongTypeIsSafe(t *testing.T) {
	c := logcol.NewLogCollector(config.LogCollectorConfig{}, "a", zap.NewNop())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetState(unexpected) panicked: %v", r)
		}
	}()
	// Pass a variety of unexpected shapes.
	c.SetState("not a state")
	c.SetState(42)
	c.SetState([]string{"nope"})
	c.SetState((*logcol.CollectorState)(nil))
	c.SetState(map[string]interface{}{"unrelated": "field"})
}

// TestSetState_DecodesGenericMap verifies that the map[string]interface{}
// shape produced by encoding/json (i.e. what the persister's Load() delivers)
// is decoded back into a usable restored offset.
func TestSetState_DecodesGenericMap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	if err := os.WriteFile(p, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	inode := inodeOf(t, p)

	c := logcol.NewLogCollector(
		config.LogCollectorConfig{Enabled: true, Paths: []string{p}, Interval: 50 * time.Millisecond},
		"a", zap.NewNop(),
	)
	generic := map[string]interface{}{
		"tailers": map[string]interface{}{
			p: map[string]interface{}{
				"path":   p,
				"inode":  float64(inode),
				"offset": float64(3), // resume at 'd' of "seed\n" (s=0,e=1,e=2,d=3)
			},
		},
	}
	c.SetState(generic)

	line, ok := readOneLine(t, c, 800*time.Millisecond)
	if !ok {
		t.Fatalf("no line collected; restored offset not honoured")
	}
	// The seed was "seed\n" (5 bytes). Restored offset 3 means we resume at
	// "d\n", which the scanner yields as the single non-empty line "d".
	if line != "d" {
		t.Errorf("expected first post-restore line %q, got %q", "d", line)
	}
}

// TestRestoredOffset_AppliedOnStart verifies the end-to-end restart story:
// 1. write seed bytes, 2. pretend we persisted an offset mid-file, 3. start
// the collector, 4. confirm it resumes from the persisted offset rather than
// skipping to EOF.
func TestRestoredOffset_AppliedOnStart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	// 12 bytes: "hello world\n"
	seed := []byte("hello world\n")
	if err := os.WriteFile(p, seed, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	inode := inodeOf(t, p)

	// Persisted offset of 6 means the tailer resumes at "world\n".
	state := &logcol.CollectorState{
		Tailers: map[string]logcol.TailerState{
			p: {Path: p, Inode: inode, Offset: 6},
		},
	}
	c := logcol.NewLogCollector(
		config.LogCollectorConfig{Enabled: true, Paths: []string{p}, Interval: 50 * time.Millisecond},
		"a", zap.NewNop(),
	)
	c.SetState(state)

	line, ok := readOneLine(t, c, 800*time.Millisecond)
	if !ok {
		t.Fatalf("no line collected; restored offset not honoured")
	}
	if line != "world" {
		t.Errorf("expected first post-restore line %q, got %q", "world", line)
	}
}

// TestInodeMismatch_FallsBackToEOF verifies that when the persisted inode does
// not match the current file inode, the tailer falls back to EOF behaviour
// (only newly-appended content is read) rather than resuming at a stale
// offset that may point into a completely different file's bytes.
func TestInodeMismatch_FallsBackToEOF(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rotated.log")
	// Pre-existing content that we should NOT see because we'll claim a stale
	// inode (so the tailer must skip to EOF).
	if err := os.WriteFile(p, []byte("OLD_CONTENT_LINE\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	// Persisted inode is bogus (will never match a real file) so the tailer
	// must detect the mismatch and start from EOF.
	state := &logcol.CollectorState{
		Tailers: map[string]logcol.TailerState{
			p: {Path: p, Inode: 9999999999, Offset: 1},
		},
	}
	c := logcol.NewLogCollector(
		config.LogCollectorConfig{Enabled: true, Paths: []string{p}, Interval: 50 * time.Millisecond},
		"a", zap.NewNop(),
	)
	c.SetState(state)

	done := make(chan string, 1)
	c.SetLogCallback(func(_ time.Time, _, body, _ string, _ map[string]string) {
		select {
		case done <- body:
		default:
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	// Wait briefly so the tailer has opened the file at EOF, then append.
	time.Sleep(200 * time.Millisecond)
	appendLine := "APPENDED_AFTER_START"
	if err := appendToFile(p, appendLine+"\n"); err != nil {
		t.Fatalf("append: %v", err)
	}

	select {
	case got := <-done:
		if got != appendLine {
			t.Errorf("expected %q, got %q (tailer did not fall back to EOF on inode mismatch)", appendLine, got)
		}
	case <-ctx.Done():
		t.Fatal("no line collected; tailer neither resumed nor tailed new content")
	}
	_ = c.Stop()
	<-errCh
}

// TestStatefulPluginInterface asserts LogCollector satisfies the
// plugin.StatefulPlugin mixin at compile time.
func TestStatefulPluginInterface(t *testing.T) {
	var _ plugin.StatefulPlugin = (*logcol.LogCollector)(nil)
}

// appendToFile appends a string to path, creating it if necessary.
func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, content)
	return err
}
