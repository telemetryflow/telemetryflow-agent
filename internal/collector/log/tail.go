// Package log implements file-based and journald log collection for TFO-Agent.
//
// FileTailer tails log files, handles rotation (truncation/inode change),
// and supports glob path expansion for collecting from multiple files.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
package log

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FileTailer tails a single log file, emitting new lines as they appear.
// Handles log rotation (truncation or inode change) by reopening the file.
type FileTailer struct {
	path      string
	logger    *zap.Logger
	lines     chan string
	offset    int64
	inode     uint64
	mu        sync.Mutex
	stopCh    chan struct{}
	stopped   bool
	maxLine   int
	pollDelay time.Duration
}

// NewFileTailer creates a tailer for the given file path.
// maxLineSize limits the scanner buffer (default 64KB).
func NewFileTailer(path string, maxLineSize int, logger *zap.Logger) *FileTailer {
	if maxLineSize <= 0 {
		maxLineSize = 64 * 1024
	}
	return &FileTailer{
		path:      path,
		logger:    logger,
		lines:     make(chan string, 1024),
		maxLine:   maxLineSize,
		pollDelay: 250 * time.Millisecond,
		stopCh:    make(chan struct{}),
	}
}

// Lines returns the channel of new log lines.
func (t *FileTailer) Lines() <-chan string { return t.lines }

// Path returns the file path being tailed.
func (t *FileTailer) Path() string { return t.path }

// Start begins tailing the file from the current end. Blocks until ctx is cancelled or Stop is called.
func (t *FileTailer) Start(ctx context.Context) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}

	// Seek to end — only collect new lines
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return err
	}
	t.offset = offset
	t.inode = fileInode(f)

	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, t.maxLine), t.maxLine*2)

	ticker := time.NewTicker(t.pollDelay)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.stopCh:
			return nil
		case <-ticker.C:
			// Check for rotation (truncation or new inode)
			if t.checkRotation(f) {
				_ = f.Close()
				f, err = os.Open(t.path)
				if err != nil {
					t.logger.Debug("File disappeared during rotation, waiting", zap.String("path", t.path))
					continue
				}
				t.offset = 0
				t.inode = fileInode(f)
				scanner = bufio.NewScanner(f)
				scanner.Buffer(make([]byte, 0, t.maxLine), t.maxLine*2)
			}

			// Read new lines
			for scanner.Scan() {
				line := scanner.Text()
				if strings.TrimSpace(line) == "" {
					continue
				}
				select {
				case t.lines <- line:
				default:
					// Channel full — drop oldest to prevent backpressure
				}
			}

			// Update offset
			pos, _ := f.Seek(0, io.SeekCurrent)
			t.offset = pos
		}
	}
}

// Stop signals the tailer to stop.
func (t *FileTailer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopped {
		t.stopped = true
		close(t.stopCh)
	}
}

// checkRotation detects if the file was truncated or replaced.
func (t *FileTailer) checkRotation(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return true // Can't stat — assume rotated
	}
	// Truncation: current size < last known offset
	if info.Size() < t.offset {
		t.logger.Debug("File truncated, resetting", zap.String("path", t.path))
		return true
	}
	// Inode change: file was replaced (rename + create)
	newInode := fileInode(f)
	if newInode != 0 && newInode != t.inode {
		t.logger.Debug("File inode changed, reopening", zap.String("path", t.path))
		return true
	}
	return false
}

// ExpandGlobs expands a list of paths/globs into concrete file paths.
func ExpandGlobs(patterns []string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			// Treat as literal path if glob fails
			if !seen[pattern] {
				result = append(result, pattern)
				seen[pattern] = true
			}
			continue
		}
		for _, m := range matches {
			if !seen[m] {
				result = append(result, m)
				seen[m] = true
			}
		}
	}
	return result
}
