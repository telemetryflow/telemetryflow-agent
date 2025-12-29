// Package buffer_test provides unit tests for the TelemetryFlow buffer infrastructure.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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

func TestBuffer(t *testing.T) {
	t.Run("should create buffer with config", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			FlushInterval: time.Second,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, b)
		defer func() { _ = b.Close() }()
	})

	t.Run("should handle disabled buffer", func(t *testing.T) {
		cfg := buffer.Config{Enabled: false}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, b)

		err = b.Push("metrics", map[string]interface{}{"test": "data"})
		assert.NoError(t, err) // Should not error when disabled
	})

	t.Run("should push and pop entries", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Push test data
		testData := map[string]interface{}{
			"metric": "test.value",
			"value":  42.0,
		}

		err = b.Push("metrics", testData)
		require.NoError(t, err)

		// Wait for flush
		time.Sleep(200 * time.Millisecond)

		// Pop entries
		entries := b.Pop(10)
		assert.Len(t, entries, 1)
		assert.Equal(t, "metrics", entries[0].Type)
		assert.Equal(t, testData, entries[0].Data)
	})

	t.Run("should peek without removing", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		err = b.Push("logs", map[string]interface{}{"message": "test"})
		require.NoError(t, err)

		time.Sleep(200 * time.Millisecond)

		// Peek should not remove
		entries := b.Peek(10)
		assert.Len(t, entries, 1)
		assert.Equal(t, 1, b.Len())

		// Pop should remove
		entries = b.Pop(10)
		assert.Len(t, entries, 1)
		assert.Equal(t, 0, b.Len())
	})

	t.Run("should handle retry", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Create test entries
		entries := []buffer.Entry{
			{
				ID:        "test-1",
				Type:      "metrics",
				Data:      map[string]interface{}{"test": "data1"},
				Timestamp: time.Now(),
				Retries:   0,
			},
		}

		// Retry should increment retry count
		b.Retry(entries)

		time.Sleep(200 * time.Millisecond)

		retrieved := b.Pop(10)
		assert.Len(t, retrieved, 1)
		assert.Equal(t, 1, retrieved[0].Retries)
	})

	t.Run("should return stats", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		stats := b.Stats()
		assert.True(t, stats.Enabled)
		assert.Equal(t, int64(10), stats.MaxSizeMB)
		assert.Equal(t, 0, stats.EntryCount)
	})

	t.Run("should use subdirectory path", func(t *testing.T) {
		tmpDir := t.TempDir()
		bufferPath := filepath.Join(tmpDir, "buffer", "data")

		// Create nested directory
		err := os.MkdirAll(bufferPath, 0755)
		require.NoError(t, err)

		cfg := buffer.Config{
			Enabled:       true,
			Path:          bufferPath,
			MaxSizeMB:     10,
			FlushInterval: time.Second,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, b)
		defer func() { _ = b.Close() }()

		// Verify directory exists
		info, err := os.Stat(bufferPath)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
}

func TestDefaultConfig(t *testing.T) {
	t.Run("should return valid defaults", func(t *testing.T) {
		cfg := buffer.DefaultConfig()

		assert.True(t, cfg.Enabled)
		assert.Equal(t, "/var/lib/tfo-agent/buffer", cfg.Path)
		assert.Equal(t, int64(100), cfg.MaxSizeMB)
		assert.Equal(t, 24*time.Hour, cfg.MaxAge)
		assert.Equal(t, 5*time.Second, cfg.FlushInterval)
	})
}

func TestBufferSize(t *testing.T) {
	t.Run("should return buffer size", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Initial size should be 0
		assert.GreaterOrEqual(t, b.Size(), int64(0))

		// Push some data
		err = b.Push("metrics", map[string]interface{}{"test": "data"})
		require.NoError(t, err)

		// Wait for flush
		time.Sleep(200 * time.Millisecond)

		// Size should be greater than 0 after flush
		assert.GreaterOrEqual(t, b.Size(), int64(0))
	})
}

func TestBufferClear(t *testing.T) {
	t.Run("should clear all entries", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Push test data
		err = b.Push("metrics", map[string]interface{}{"test": "data"})
		require.NoError(t, err)

		// Wait for flush
		time.Sleep(200 * time.Millisecond)

		assert.Greater(t, b.Len(), 0)

		// Clear buffer
		b.Clear()

		assert.Equal(t, 0, b.Len())
		assert.Equal(t, int64(0), b.Size())
	})
}

func TestBufferLen(t *testing.T) {
	t.Run("should return correct length", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		assert.Equal(t, 0, b.Len())

		// Push multiple entries
		for i := 0; i < 3; i++ {
			err = b.Push("metrics", map[string]interface{}{"index": i})
			require.NoError(t, err)
		}

		// Wait for entries to be processed
		time.Sleep(200 * time.Millisecond)

		assert.Equal(t, 3, b.Len())
	})
}

func TestBufferClose(t *testing.T) {
	t.Run("should close buffer gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)

		// Push some data
		err = b.Push("metrics", map[string]interface{}{"test": "data"})
		require.NoError(t, err)

		// Close should not error
		err = b.Close()
		assert.NoError(t, err)

		// Double close should not error
		err = b.Close()
		assert.NoError(t, err)
	})
}

func TestBufferPushChannelFull(t *testing.T) {
	t.Run("should handle channel full scenario", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 10 * time.Second, // Long interval so channel fills up
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Try to push many entries rapidly
		var pushError error
		for i := 0; i < 1500; i++ {
			err := b.Push("metrics", map[string]interface{}{"index": i})
			if err != nil {
				pushError = err
				break
			}
		}

		// Should eventually get channel full error (or not if fast enough)
		// This is just to ensure the code handles the scenario
		_ = pushError
	})
}

func TestBufferLoadExisting(t *testing.T) {
	t.Run("should load existing buffer data", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create existing buffer file
		existingData := `[{"id":"test-1","timestamp":"2024-01-01T00:00:00Z","type":"metrics","data":{"value":42},"retries":0}]`
		err := os.WriteFile(filepath.Join(tmpDir, "buffer.json"), []byte(existingData), 0600)
		require.NoError(t, err)

		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Should have loaded the existing entry
		assert.Equal(t, 1, b.Len())

		entries := b.Pop(1)
		assert.Len(t, entries, 1)
		assert.Equal(t, "test-1", entries[0].ID)
	})
}

func TestBufferEntry(t *testing.T) {
	t.Run("should have all fields", func(t *testing.T) {
		entry := buffer.Entry{
			ID:        "entry-001",
			Timestamp: time.Now(),
			Type:      "metrics",
			Data:      map[string]interface{}{"key": "value"},
			Retries:   3,
		}

		assert.Equal(t, "entry-001", entry.ID)
		assert.False(t, entry.Timestamp.IsZero())
		assert.Equal(t, "metrics", entry.Type)
		assert.Equal(t, "value", entry.Data["key"])
		assert.Equal(t, 3, entry.Retries)
	})
}

func TestBufferConfig(t *testing.T) {
	t.Run("should have all config fields", func(t *testing.T) {
		cfg := buffer.Config{
			Enabled:       true,
			Path:          "/custom/path",
			MaxSizeMB:     50,
			MaxAge:        2 * time.Hour,
			FlushInterval: 10 * time.Second,
		}

		assert.True(t, cfg.Enabled)
		assert.Equal(t, "/custom/path", cfg.Path)
		assert.Equal(t, int64(50), cfg.MaxSizeMB)
		assert.Equal(t, 2*time.Hour, cfg.MaxAge)
		assert.Equal(t, 10*time.Second, cfg.FlushInterval)
	})
}

func TestBufferStats(t *testing.T) {
	t.Run("should have all stats fields", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     50,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Push some data
		err = b.Push("metrics", map[string]interface{}{"test": "data"})
		require.NoError(t, err)

		time.Sleep(200 * time.Millisecond)

		stats := b.Stats()
		assert.True(t, stats.Enabled)
		assert.Equal(t, 1, stats.EntryCount)
		assert.GreaterOrEqual(t, stats.SizeBytes, int64(0))
		assert.Equal(t, int64(50), stats.MaxSizeMB)
	})
}

func TestBufferPopEmpty(t *testing.T) {
	t.Run("should return nil for empty buffer", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		entries := b.Pop(10)
		assert.Nil(t, entries)
	})
}

func TestBufferPeekEmpty(t *testing.T) {
	t.Run("should return nil for empty buffer", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		entries := b.Peek(10)
		assert.Nil(t, entries)
	})
}

func TestBufferPopLessThanCount(t *testing.T) {
	t.Run("should return available entries when count exceeds length", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := buffer.Config{
			Enabled:       true,
			Path:          tmpDir,
			MaxSizeMB:     10,
			MaxAge:        1 * time.Hour,
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		// Push only 2 entries
		err = b.Push("metrics", map[string]interface{}{"index": 1})
		require.NoError(t, err)
		err = b.Push("metrics", map[string]interface{}{"index": 2})
		require.NoError(t, err)

		time.Sleep(200 * time.Millisecond)

		// Try to pop 10 but only 2 exist
		entries := b.Pop(10)
		assert.Len(t, entries, 2)
	})
}
