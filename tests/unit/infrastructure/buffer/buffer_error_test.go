// Package buffer_test contains additional unit tests exercising the error and
// edge-case branches of the disk-backed telemetry buffer (directory creation
// failures, disk I/O errors, corrupt persistence, and size-limit enforcement).
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
package buffer_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/buffer"
)

// TestBufferNewMkdirError verifies New returns an error when the buffer
// directory cannot be created (path collides with an existing regular file).
func TestBufferNewMkdirError(t *testing.T) {
	t.Run("should error when buffer directory cannot be created", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a regular file, then use a path *under* it so MkdirAll fails
		// because a parent component is not a directory.
		filePath := filepath.Join(tmpDir, "not-a-dir")
		require.NoError(t, os.WriteFile(filePath, []byte("x"), 0600))

		cfg := buffer.Config{
			Enabled:       true,
			Path:          filepath.Join(filePath, "buffer"),
			MaxSizeMB:     10,
			FlushInterval: time.Second,
		}

		b, err := buffer.New(cfg)
		require.Error(t, err)
		assert.Nil(t, b)
	})
}

// TestBufferNewLoadCorrupt verifies New tolerates a corrupt buffer.json by
// logging a warning and continuing (exercising load's Unmarshal error branch).
func TestBufferNewLoadCorrupt(t *testing.T) {
	t.Run("should continue when existing buffer file is corrupt", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, "buffer.json"),
			[]byte("{ this is not valid json ]"),
			0600,
		))

		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		require.NotNil(t, b)
		defer func() { _ = b.Close() }()

		// Corrupt data must not be loaded as entries.
		assert.Equal(t, 0, b.Len())
	})
}

// TestBufferNewLoadReadError verifies New tolerates a read error on the buffer
// file (exercising load's non-IsNotExist error branch). buffer.json is created
// as a directory so os.ReadFile fails with a non-"not exist" error.
func TestBufferNewLoadReadError(t *testing.T) {
	t.Run("should continue when existing buffer file is unreadable", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "buffer.json"), 0750))

		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		require.NotNil(t, b)
		defer func() { _ = b.Close() }()

		assert.Equal(t, 0, b.Len())
	})
}

// TestBufferFlushWriteError verifies flush surfaces a write error when the
// buffer file cannot be written (file made read-only), returned via Close.
func TestBufferFlushWriteError(t *testing.T) {
	t.Run("should return error when buffer file is not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root bypasses file permission checks")
		}

		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        time.Hour,
			FlushInterval: 50 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)

		require.NoError(t, b.Push("metrics", map[string]interface{}{"k": "v"}))

		// Let the ticker move the entry into the buffer and flush it once,
		// creating buffer.json.
		time.Sleep(150 * time.Millisecond)

		bufFile := filepath.Join(tmpDir, "buffer.json")
		require.NoError(t, os.Chmod(bufFile, 0400))
		defer func() { _ = os.Chmod(bufFile, 0600) }()

		// Close performs a final flush; writing to the read-only file must fail.
		err = b.Close()
		assert.Error(t, err)
	})
}

// TestBufferCleanupSizeLimit verifies cleanup drops entries when the buffer
// exceeds the configured size limit (MaxSizeMB = 0 forces the eviction loop).
func TestBufferCleanupSizeLimit(t *testing.T) {
	t.Run("should evict entries when over size limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     0, // maxBytes == 0, any buffered data is over-limit
			MaxAge:        time.Hour,
			FlushInterval: 50 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		for i := 0; i < 5; i++ {
			require.NoError(t, b.Push("metrics", map[string]interface{}{"index": i}))
		}

		// Wait for at least one flush (sets size > 0) followed by cleanup,
		// which must evict everything given the zero size budget.
		assert.Eventually(t, func() bool {
			return b.Len() == 0
		}, 2*time.Second, 25*time.Millisecond)
	})
}
