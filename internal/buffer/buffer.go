// Package buffer provides disk-backed buffering for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
//
// This buffer ensures data isn't lost during network issues or restarts.
package buffer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config holds buffer configuration
type Config struct {
	// Enabled enables disk-backed buffering
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Path is the directory for buffer files
	Path string `yaml:"path" json:"path"`

	// MaxSizeMB is the maximum buffer size in megabytes
	MaxSizeMB int64 `yaml:"max_size_mb" json:"max_size_mb"`

	// MaxAge is the maximum age of buffered data
	MaxAge time.Duration `yaml:"max_age" json:"max_age"`

	// FlushInterval is how often to flush to disk
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`
}

// DefaultConfig returns default buffer configuration
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		Path:          "/var/lib/tfo-agent/buffer",
		MaxSizeMB:     100,
		MaxAge:        24 * time.Hour,
		FlushInterval: 5 * time.Second,
	}
}

// Entry represents a buffered data entry
type Entry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"` // "metrics", "logs", "traces"
	Data      map[string]interface{} `json:"data"`
	Retries   int                    `json:"retries"`
}

// Buffer provides disk-backed data buffering
type Buffer struct {
	config  Config
	mu      sync.RWMutex
	entries []Entry
	size    int64
	closed  bool

	// Channels
	incoming chan Entry
	done     chan struct{}
}

// New creates a new buffer
func New(config Config) (*Buffer, error) {
	if !config.Enabled {
		return &Buffer{config: config, closed: true}, nil
	}

	// Create buffer directory
	if err := os.MkdirAll(config.Path, 0750); err != nil {
		return nil, fmt.Errorf("failed to create buffer directory: %w", err)
	}

	b := &Buffer{
		config:   config,
		entries:  make([]Entry, 0),
		incoming: make(chan Entry, 1000),
		done:     make(chan struct{}),
	}

	// Load existing buffered data
	if err := b.load(); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: failed to load existing buffer: %v\n", err)
	}

	// Start background flush goroutine
	go b.flushLoop()

	return b, nil
}

// Push adds data to the buffer
func (b *Buffer) Push(entryType string, data map[string]interface{}) error {
	if !b.config.Enabled || b.closed {
		return nil
	}

	entry := Entry{
		ID:        fmt.Sprintf("%d-%s", time.Now().UnixNano(), entryType),
		Timestamp: time.Now(),
		Type:      entryType,
		Data:      data,
		Retries:   0,
	}

	select {
	case b.incoming <- entry:
		return nil
	default:
		return fmt.Errorf("buffer channel full")
	}
}

// Pop retrieves and removes entries from the buffer
func (b *Buffer) Pop(count int) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) == 0 {
		return nil
	}

	if count > len(b.entries) {
		count = len(b.entries)
	}

	entries := make([]Entry, count)
	copy(entries, b.entries[:count])
	b.entries = b.entries[count:]

	return entries
}

// Peek returns entries without removing them
func (b *Buffer) Peek(count int) []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.entries) == 0 {
		return nil
	}

	if count > len(b.entries) {
		count = len(b.entries)
	}

	entries := make([]Entry, count)
	copy(entries, b.entries[:count])

	return entries
}

// Retry puts failed entries back into the buffer
func (b *Buffer) Retry(entries []Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range entries {
		entries[i].Retries++
	}

	// Prepend to front of queue for retry
	b.entries = append(entries, b.entries...)
}

// Len returns the number of buffered entries
func (b *Buffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Size returns the approximate size in bytes
func (b *Buffer) Size() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size
}

// Clear removes all buffered entries
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = make([]Entry, 0)
	b.size = 0
}

// Close stops the buffer and flushes remaining data
func (b *Buffer) Close() error {
	if b.closed {
		return nil
	}

	b.closed = true
	close(b.done)

	// Final flush
	return b.flush()
}

// flushLoop periodically flushes the buffer to disk
func (b *Buffer) flushLoop() {
	ticker := time.NewTicker(b.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry := <-b.incoming:
			b.mu.Lock()
			b.entries = append(b.entries, entry)
			b.mu.Unlock()

		case <-ticker.C:
			if err := b.flush(); err != nil {
				fmt.Printf("Warning: buffer flush failed: %v\n", err)
			}
			b.cleanup()

		case <-b.done:
			// Drain remaining incoming
			for {
				select {
				case entry := <-b.incoming:
					b.mu.Lock()
					b.entries = append(b.entries, entry)
					b.mu.Unlock()
				default:
					return
				}
			}
		}
	}
}

// flush writes the buffer to disk
func (b *Buffer) flush() error {
	b.mu.RLock()
	if len(b.entries) == 0 {
		b.mu.RUnlock()
		return nil
	}

	// Copy entries for serialization
	entries := make([]Entry, len(b.entries))
	copy(entries, b.entries)
	b.mu.RUnlock()

	// Write to file
	filename := filepath.Join(b.config.Path, "buffer.json")
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal buffer: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write buffer file: %w", err)
	}

	b.mu.Lock()
	b.size = int64(len(data))
	b.mu.Unlock()

	return nil
}

// load reads buffered data from disk
func (b *Buffer) load() error {
	filename := filepath.Join(b.config.Path, "buffer.json")

	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil // No existing buffer
	}
	if err != nil {
		return err
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	b.mu.Lock()
	b.entries = entries
	b.size = int64(len(data))
	b.mu.Unlock()

	return nil
}

// cleanup removes old entries and enforces size limits
func (b *Buffer) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	maxAge := b.config.MaxAge

	// Remove old entries
	filtered := make([]Entry, 0, len(b.entries))
	for _, entry := range b.entries {
		if now.Sub(entry.Timestamp) < maxAge {
			filtered = append(filtered, entry)
		}
	}
	b.entries = filtered

	// Enforce size limit (remove oldest if over limit)
	maxBytes := b.config.MaxSizeMB * 1024 * 1024
	for b.size > maxBytes && len(b.entries) > 0 {
		b.entries = b.entries[1:]
		// Recalculate size (approximate)
		data, _ := json.Marshal(b.entries)
		b.size = int64(len(data))
	}
}

// Stats returns buffer statistics
type Stats struct {
	Enabled    bool  `json:"enabled"`
	EntryCount int   `json:"entry_count"`
	SizeBytes  int64 `json:"size_bytes"`
	MaxSizeMB  int64 `json:"max_size_mb"`
}

// Stats returns current buffer statistics
func (b *Buffer) Stats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return Stats{
		Enabled:    b.config.Enabled,
		EntryCount: len(b.entries),
		SizeBytes:  b.size,
		MaxSizeMB:  b.config.MaxSizeMB,
	}
}
