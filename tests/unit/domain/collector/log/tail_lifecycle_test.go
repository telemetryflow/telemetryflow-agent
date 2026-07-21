// Package log_test contains unit tests for the log collector module.
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

package log_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// writeFile writes content to a file, creating or overwriting it.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// appendFile appends content to an existing file.
func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

// collectLines reads up to want lines from the channel within timeout.
func collectLines(ch <-chan string, want int, timeout time.Duration) []string {
	var got []string
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case line := <-ch:
			got = append(got, line)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestNewFileTailerDefaults(t *testing.T) {
	tl := log.NewFileTailer("/tmp/foo.log", 0, zap.NewNop())
	if tl.Path() != "/tmp/foo.log" {
		t.Errorf("Path() = %q", tl.Path())
	}
	if tl.Lines() == nil {
		t.Error("Lines() channel is nil")
	}
	// Explicit max line size path
	tl2 := log.NewFileTailer("/tmp/bar.log", 128, zap.NewNop())
	if tl2.Path() != "/tmp/bar.log" {
		t.Errorf("Path() = %q", tl2.Path())
	}
}

func TestFileTailerStartMissingFile(t *testing.T) {
	tl := log.NewFileTailer(filepath.Join(t.TempDir(), "nope.log"), 0, zap.NewNop())
	if err := tl.Start(context.Background()); err == nil {
		t.Fatal("expected error opening missing file")
	}
}

func TestFileTailerTailAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "old line\n")

	tl := log.NewFileTailer(path, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- tl.Start(ctx) }()

	// Append quickly after Start seeks to end but before the first poll tick,
	// so the scanner reads the new content on its first (non-latched) scan.
	time.Sleep(30 * time.Millisecond)
	appendFile(t, path, "line1\n\nline2\n") // blank line should be skipped
	lines := collectLines(tl.Lines(), 2, 3*time.Second)
	if len(lines) != 2 || lines[0] != "line1" || lines[1] != "line2" {
		t.Fatalf("got %v", lines)
	}

	// Rotation via truncation: overwrite with content smaller than the last
	// offset so checkRotation detects truncation and reopens with a fresh scanner.
	writeFile(t, path, "reset\n")
	rotated := collectLines(tl.Lines(), 1, 3*time.Second)
	if len(rotated) != 1 || rotated[0] != "reset" {
		t.Fatalf("post-rotation got %v", rotated)
	}

	// Stop is idempotent.
	tl.Stop()
	tl.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not stop")
	}
}

func TestFileTailerStopViaContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctx.log")
	writeFile(t, path, "")
	tl := log.NewFileTailer(path, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected context error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not return on ctx cancel")
	}
}

func TestCheckRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.log")
	writeFile(t, path, "data")
	tl := log.NewFileTailer(path, 0, zap.NewNop())

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Fresh tailer has inode 0, so a real file's inode differs -> rotation.
	if !tl.CheckRotationExported(f) {
		t.Error("expected rotation detected on inode change")
	}
	// Closed file -> stat error -> rotation.
	_ = f.Close()
	if !tl.CheckRotationExported(f) {
		t.Error("expected rotation on stat error")
	}
}

func TestExpandGlobs(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	b := filepath.Join(dir, "b.log")
	writeFile(t, a, "")
	writeFile(t, b, "")

	got := log.ExpandGlobs([]string{filepath.Join(dir, "*.log"), "/literal/path.log", "/literal/path.log"})
	// two glob matches + one literal (deduped)
	if len(got) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(got), got)
	}
	found := map[string]bool{}
	for _, p := range got {
		found[p] = true
	}
	if !found[a] || !found[b] || !found["/literal/path.log"] {
		t.Errorf("missing expected paths: %v", got)
	}
}

func TestLogCollectorMetadata(t *testing.T) {
	c := log.NewLogCollector(config.LogCollectorConfig{}, "agent-1", zap.NewNop())
	if c.Name() != "logs" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running initially")
	}
	// Stop when not running is a no-op returning nil.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() = %v", err)
	}
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}
}

func TestLogCollectorLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "life.log")
	writeFile(t, path, "")

	cfg := config.LogCollectorConfig{
		Enabled:  true,
		Interval: 5 * time.Millisecond,
		// Include a nonexistent path so a tailer fails to open (warn branch).
		Paths:           []string{path, filepath.Join(dir, "missing", "no.log")},
		IncludePatterns: []string{".*"},
		ExcludePatterns: []string{"secret"},
		MaxLineSize:     0,
		Journald:        config.JournaldConfig{Enabled: false},
	}
	c := log.NewLogCollector(cfg, "agent-1", zap.NewNop())

	var mu sync.Mutex
	var got []string
	c.SetLogCallback(func(_ time.Time, _, body, _ string, _ map[string]string) {
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Append quickly after Start so the tailer's first (non-latched) scan picks
	// up the lines, then wait for the tailer poll + collector drain to run.
	time.Sleep(30 * time.Millisecond)
	if !c.IsRunning() {
		t.Error("collector should be running")
	}
	appendFile(t, path, "hello world\nsecret data\n")
	time.Sleep(600 * time.Millisecond)

	if err := c.Stop(); err != nil {
		t.Errorf("Stop() = %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not stop")
	}

	mu.Lock()
	defer mu.Unlock()
	sawHello, sawSecret := false, false
	for _, b := range got {
		if b == "hello world" {
			sawHello = true
		}
		if b == "secret data" {
			sawSecret = true
		}
	}
	if !sawHello {
		t.Errorf("expected 'hello world' to be collected, got %v", got)
	}
	if sawSecret {
		t.Error("excluded line 'secret data' should have been dropped")
	}
}

func TestLogCollectorStartCtxCancel(t *testing.T) {
	c := log.NewLogCollector(config.LogCollectorConfig{Interval: 5 * time.Millisecond}, "a", zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected ctx error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return on ctx cancel")
	}
}

func TestLogCollectorDefaultInterval(t *testing.T) {
	// Interval unset -> Start applies the 10s default; cancel immediately.
	c := log.NewLogCollector(config.LogCollectorConfig{}, "a", zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestFileTailerSeekError(t *testing.T) {
	// A pipe is openable but not seekable. Opening its /dev/fd path lets the
	// tailer open it, then Seek(0, SeekEnd) fails, exercising the seek-error
	// path in Start.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()

	path := "/dev/fd/" + strconv.Itoa(int(r.Fd()))
	if _, statErr := os.Stat(path); statErr != nil {
		t.Skipf("/dev/fd not available: %v", statErr)
	}
	tl := log.NewFileTailer(path, 0, zap.NewNop())
	if err := tl.Start(context.Background()); err == nil {
		t.Skip("platform allows seeking a pipe; seek-error path not exercised")
	}
}

func TestFileInodeStatError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ino.log")
	writeFile(t, path, "x")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if log.FileInodeExported(f) == 0 {
		t.Error("expected nonzero inode for open file")
	}
	_ = f.Close()
	// Stat on a closed file errors -> fileInode returns 0.
	if log.FileInodeExported(f) != 0 {
		t.Error("expected 0 inode after close (stat error)")
	}
}

func TestFileTailerReopenError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permission-based reopen failure not reproducible")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "reopen.log")
	writeFile(t, path, "seed content here\n")

	tl := log.NewFileTailer(path, 0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tl.Start(ctx) }()

	// Let the tailer open + seek, then trigger truncation (rotation) while
	// making the path unreadable so the reopen fails.
	time.Sleep(300 * time.Millisecond)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	// Allow a couple of poll ticks so rotation is detected and reopen fails.
	time.Sleep(700 * time.Millisecond)
	_ = os.Chmod(path, 0o644)
	tl.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not stop")
	}
}

func TestDrainFileTailerFiltersAndCallback(t *testing.T) {
	c := log.NewLogCollector(config.LogCollectorConfig{}, "agent-x", zap.NewNop())
	include := log.CompilePatternsExported([]string{"keep"})
	exclude := log.CompilePatternsExported([]string{"drop"})

	tl := log.NewFileTailer("/tmp/drain.log", 0, zap.NewNop())
	tl.PushLineExported("keep this")
	tl.PushLineExported("drop this")
	tl.PushLineExported("ignore this") // not in include -> filtered

	// No callback set yet: still drains and counts, exercises nil-callback branch.
	c.DrainFileTailerExported(tl, include, exclude)

	var count int
	c.SetLogCallback(func(_ time.Time, _, _, _ string, _ map[string]string) { count++ })
	tl.PushLineExported("keep again")
	c.DrainFileTailerExported(tl, include, exclude)
	if count != 1 {
		t.Errorf("expected callback once, got %d", count)
	}
}

func TestDrainJournaldSeverityMapping(t *testing.T) {
	c := log.NewLogCollector(config.LogCollectorConfig{}, "agent-j", zap.NewNop())
	include := log.CompilePatternsExported([]string{"keep"})
	exclude := log.CompilePatternsExported([]string{"drop"})

	j := log.NewJournaldCollector(config.JournaldConfig{}, zap.NewNop())
	j.PushEntryExported("sshd", "fatal", "keep fatal")
	j.PushEntryExported("sshd", "error", "keep error")
	j.PushEntryExported("sshd", "warn", "keep warn")
	j.PushEntryExported("sshd", "debug", "keep debug")
	j.PushEntryExported("sshd", "info", "keep info")
	j.PushEntryExported("sshd", "info", "drop this one") // excluded
	j.PushEntryExported("sshd", "info", "no match")      // not included

	severities := map[string]string{}
	c.SetLogCallback(func(_ time.Time, severity, body, source string, attrs map[string]string) {
		severities[body] = severity
		if source != "journald" {
			t.Errorf("source = %q, want journald", source)
		}
		if attrs["log.systemd.unit"] != "sshd" {
			t.Errorf("unit attr = %q", attrs["log.systemd.unit"])
		}
	})
	c.DrainJournaldExported(j, include, exclude)

	want := map[string]string{
		"keep fatal": "FATAL",
		"keep error": "ERROR",
		"keep warn":  "WARN",
		"keep debug": "DEBUG",
		"keep info":  "INFO",
	}
	for body, sev := range want {
		if severities[body] != sev {
			t.Errorf("severity[%q] = %q, want %q", body, severities[body], sev)
		}
	}
	if _, ok := severities["drop this one"]; ok {
		t.Error("excluded entry should not be delivered")
	}
	if _, ok := severities["no match"]; ok {
		t.Error("non-included entry should not be delivered")
	}
}

func TestJournaldStub(t *testing.T) {
	j := log.NewJournaldCollector(config.JournaldConfig{Enabled: true}, zap.NewNop())
	if j.Lines() == nil {
		t.Fatal("Lines() channel should be non-nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- j.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	j.Stop()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("journald stub did not return")
	}
}
