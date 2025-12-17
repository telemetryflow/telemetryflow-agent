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
		defer b.Close()
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
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer b.Close()

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
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer b.Close()

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
			FlushInterval: 100 * time.Millisecond,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer b.Close()

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
			Enabled:   true,
			Path:      tmpDir,
			MaxSizeMB: 10,
		}

		b, err := buffer.New(cfg)
		require.NoError(t, err)
		defer b.Close()

		stats := b.Stats()
		assert.True(t, stats.Enabled)
		assert.Equal(t, int64(10), stats.MaxSizeMB)
		assert.Equal(t, 0, stats.EntryCount)
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