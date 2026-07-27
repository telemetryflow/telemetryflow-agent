// Package exporter: file_output.go implements a file output that writes
// metrics to a local file in JSON Lines, InfluxDB line protocol, or
// Prometheus text exposition format, with size-based rotation, backup
// retention, and optional gzip compression. It is intentionally stdlib-only
// apart from zap logging and the typed plugin contracts.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// FileOutputConfig configures a FileOutput.
type FileOutputConfig struct {
	// Path is the file to write to. Required (e.g.
	// "/var/log/tfo-agent/metrics.jsonl").
	Path string

	// Format selects the on-disk encoding: "json" (default, JSON Lines),
	// "influx_lp" (InfluxDB line protocol), or "prometheus_text" (OpenMetrics
	// exposition).
	Format string

	// Rotation tunes the size-based rotation policy.
	Rotation RotationConfig

	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger
}

// RotationConfig configures file rotation and backup retention. Defaults are
// applied by NewFileOutput for MaxBackups and MaxAgeDays; MaxSizeMB and
// Compress are taken literally (the YAML loader is expected to provide
// production defaults).
type RotationConfig struct {
	// MaxSizeMB is the file size in megabytes that triggers rotation. A
	// value of 0 means "rotate after every successful write that produced
	// content" — primarily useful for tests. Production configs should set
	// this explicitly (e.g. 100).
	MaxSizeMB int

	// MaxBackups is the number of rotated files to keep. Default 7.
	MaxBackups int

	// MaxAgeDays is the retention window for rotated files. Default 30.
	MaxAgeDays int

	// Compress gzip-compresses rotated files (.N.gz). Default false.
	Compress bool
}

// FileOutput is a plugin.Output that writes metrics to a local file with
// optional rotation, backup retention, and compression. It is safe for
// concurrent use: Connect, Write, and Close are guarded by a single mutex.
type FileOutput struct {
	cfg FileOutputConfig
	log *zap.Logger

	mu sync.Mutex
	f  *os.File
	sz int64
}

// NewFileOutput validates the configuration and returns a ready output.
// Connect must still be called before Write.
func NewFileOutput(cfg FileOutputConfig) (*FileOutput, error) {
	if cfg.Path == "" {
		return nil, errors.New("file output: path is required")
	}
	cfg.Format = strings.ToLower(strings.TrimSpace(cfg.Format))
	switch cfg.Format {
	case "":
		cfg.Format = "json"
	case "json", "influx_lp", "prometheus_text":
		// ok
	default:
		return nil, fmt.Errorf("file output: unsupported format %q (want json|influx_lp|prometheus_text)", cfg.Format)
	}
	if cfg.Rotation.MaxBackups <= 0 {
		cfg.Rotation.MaxBackups = 7
	}
	if cfg.Rotation.MaxAgeDays <= 0 {
		cfg.Rotation.MaxAgeDays = 30
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("file_output")
	return &FileOutput{cfg: cfg, log: logger}, nil
}

// Name implements plugin.Output.
func (o *FileOutput) Name() string { return "file" }

// Connect opens (or creates) the target file in append mode and records its
// current size so rotation decisions are based on the real on-disk length.
// Calling Connect on an already-connected output is a no-op.
func (o *FileOutput) Connect() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.f != nil {
		return nil
	}
	return o.openFile()
}

// Close flushes and releases the current file. Subsequent Write calls return
// an error until Connect is called again.
func (o *FileOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.f == nil {
		return nil
	}
	err := o.f.Close()
	o.f = nil
	o.sz = 0
	return err
}

// Write serializes the batch in the configured format, appends it to the
// file, and rotates if the resulting size would exceed MaxSizeMB.
func (o *FileOutput) Write(metrics []plugin.Metric) error {
	if len(metrics) == 0 {
		return nil
	}
	payload, err := o.encode(metrics)
	if err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.f == nil {
		return errors.New("file output: not connected")
	}
	if err := o.maybeRotate(int64(len(payload))); err != nil {
		return fmt.Errorf("file output: rotate: %w", err)
	}
	n, err := o.f.Write(payload)
	if err != nil {
		return fmt.Errorf("file output: write: %w", err)
	}
	o.sz += int64(n)
	return nil
}

// openFile opens (or creates) the target file in append mode and stats it to
// record the current size. Caller must hold o.mu.
func (o *FileOutput) openFile() error {
	f, err := os.OpenFile(o.cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("file output: open %q: %w", o.cfg.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("file output: stat %q: %w", o.cfg.Path, err)
	}
	o.f = f
	o.sz = info.Size()
	return nil
}

// maybeRotate rotates the file when appending writeSize more bytes would
// exceed the configured MaxSizeMB threshold. Caller must hold o.mu.
func (o *FileOutput) maybeRotate(writeSize int64) error {
	if o.sz == 0 {
		return nil
	}
	threshold := int64(o.cfg.Rotation.MaxSizeMB) * 1_000_000
	if threshold == 0 || o.sz+writeSize > threshold {
		return o.rotate()
	}
	return nil
}

// rotate performs the backup shift, compresses or renames the current file
// to .1, prunes old backups, and opens a fresh file. Caller must hold o.mu.
func (o *FileOutput) rotate() error {
	if o.f != nil {
		_ = o.f.Close()
		o.f = nil
	}

	maxBackups := o.cfg.Rotation.MaxBackups
	// Shift existing backups .N -> .N+1 (highest first), removing any that
	// would exceed MaxBackups. Both compressed and plain variants are
	// checked so a Compress config change does not strand old files.
	for idx := maxBackups; idx >= 1; idx-- {
		for _, suffix := range []string{".gz", ""} {
			src := fmt.Sprintf("%s.%d%s", o.cfg.Path, idx, suffix)
			if _, err := os.Stat(src); err != nil {
				continue
			}
			if idx+1 > maxBackups {
				if err := os.Remove(src); err != nil {
					o.log.Warn("file output: drop overflowed backup",
						zap.String("path", src), zap.Error(err))
				}
				continue
			}
			dst := fmt.Sprintf("%s.%d%s", o.cfg.Path, idx+1, suffix)
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("file output: shift backup %s: %w", src, err)
			}
		}
	}

	// Move the current file to .1 (compressing if configured).
	if _, err := os.Stat(o.cfg.Path); err == nil {
		if o.cfg.Rotation.Compress {
			dst := o.cfg.Path + ".1.gz"
			if err := gzipFile(o.cfg.Path, dst); err != nil {
				return fmt.Errorf("file output: compress rotated file: %w", err)
			}
			if err := os.Remove(o.cfg.Path); err != nil {
				o.log.Warn("file output: remove pre-rotation source",
					zap.String("path", o.cfg.Path), zap.Error(err))
			}
		} else {
			dst := o.cfg.Path + ".1"
			if err := os.Rename(o.cfg.Path, dst); err != nil {
				return fmt.Errorf("file output: rename rotated file: %w", err)
			}
		}
	}

	o.enforceMaxAge()

	if err := o.openFile(); err != nil {
		return err
	}
	o.log.Debug("file output: rotated",
		zap.String("path", o.cfg.Path),
		zap.Int("max_backups", maxBackups),
		zap.Bool("compress", o.cfg.Rotation.Compress),
	)
	return nil
}

// enforceMaxAge removes any backup files older than MaxAgeDays. Best effort:
// errors are logged but do not fail the rotation. Caller must hold o.mu.
func (o *FileOutput) enforceMaxAge() {
	maxAge := time.Duration(o.cfg.Rotation.MaxAgeDays) * 24 * time.Hour
	if maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	matches, err := filepath.Glob(o.cfg.Path + ".*")
	if err != nil {
		return
	}
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(m); err != nil {
				o.log.Warn("file output: remove aged backup",
					zap.String("path", m), zap.Error(err))
			}
		}
	}
}

// encode renders a batch of metrics in the configured format. It returns a
// single byte slice that is safe to append atomically.
func (o *FileOutput) encode(metrics []plugin.Metric) ([]byte, error) {
	var buf bytes.Buffer
	switch o.cfg.Format {
	case "json":
		for i := range metrics {
			line, err := encodeJSONMetric(metrics[i])
			if err != nil {
				return nil, fmt.Errorf("file output: json encode %q: %w", metrics[i].Name, err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
	case "influx_lp":
		for i := range metrics {
			encodeInfluxLine(&buf, metrics[i])
		}
	case "prometheus_text":
		for i := range metrics {
			encodePrometheusText(&buf, metrics[i])
		}
	default:
		return nil, fmt.Errorf("file output: unsupported format %q", o.cfg.Format)
	}
	return buf.Bytes(), nil
}

// encodeJSONMetric renders one metric as a single JSON object (JSONL line,
// without the trailing newline).
func encodeJSONMetric(m plugin.Metric) ([]byte, error) {
	type jsonMetric struct {
		Name      string            `json:"name"`
		Type      string            `json:"type"`
		Value     float64           `json:"value"`
		Labels    map[string]string `json:"labels"`
		Timestamp string            `json:"timestamp"`
		Unit      string            `json:"unit"`
	}
	obj := jsonMetric{
		Name:      m.Name,
		Type:      string(m.Type),
		Value:     m.Value,
		Labels:    m.Labels,
		Timestamp: m.Timestamp.UTC().Format(time.RFC3339Nano),
		Unit:      m.Unit,
	}
	return json.Marshal(obj)
}

// encodeInfluxLine appends one metric in InfluxDB line protocol:
//
//	measurement,tag1=val1,tag2=val2 value=<float> <unix_nanos>
//
// The measurement is derived from the metric name with dots replaced by
// underscores (dots are not allowed in InfluxDB measurements).
func encodeInfluxLine(buf *bytes.Buffer, m plugin.Metric) {
	measurement := strings.ReplaceAll(m.Name, ".", "_")
	buf.WriteString(measurement)

	keys := make([]string, 0, len(m.Labels))
	for k := range m.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteByte(',')
		buf.WriteString(escapeInfluxToken(k))
		buf.WriteByte('=')
		buf.WriteString(escapeInfluxToken(m.Labels[k]))
	}

	buf.WriteString(" value=")
	buf.WriteString(strconv.FormatFloat(m.Value, 'f', -1, 64))

	buf.WriteByte(' ')
	buf.WriteString(strconv.FormatInt(m.Timestamp.UnixNano(), 10))
	buf.WriteByte('\n')
}

// escapeInfluxToken escapes characters that have special meaning in the
// InfluxDB line protocol tag set (comma, equals, space, backslash).
func escapeInfluxToken(s string) string {
	if !strings.ContainsAny(s, ",= \\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',', '=', ' ', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// encodePrometheusText appends one metric in Prometheus text exposition
// format:
//
//	# HELP <name> <description>
//	# TYPE <name> <type>
//	<name>{labels} <value> <ts_ms>
//
// The HELP line is omitted when the metric has no description.
func encodePrometheusText(buf *bytes.Buffer, m plugin.Metric) {
	if m.Description != "" {
		buf.WriteString("# HELP ")
		buf.WriteString(m.Name)
		buf.WriteByte(' ')
		buf.WriteString(escapePromHelp(m.Description))
		buf.WriteByte('\n')
	}
	buf.WriteString("# TYPE ")
	buf.WriteString(m.Name)
	buf.WriteByte(' ')
	if m.Type == "" {
		buf.WriteString("untyped")
	} else {
		buf.WriteString(string(m.Type))
	}
	buf.WriteByte('\n')

	buf.WriteString(m.Name)
	if len(m.Labels) > 0 {
		buf.WriteByte('{')
		keys := make([]string, 0, len(m.Labels))
		for k := range m.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(k)
			buf.WriteString(`="`)
			buf.WriteString(escapePromLabelValue(m.Labels[k]))
			buf.WriteByte('"')
		}
		buf.WriteByte('}')
	}
	buf.WriteByte(' ')
	buf.WriteString(strconv.FormatFloat(m.Value, 'g', -1, 64))
	buf.WriteByte(' ')
	buf.WriteString(strconv.FormatInt(m.Timestamp.UnixMilli(), 10))
	buf.WriteByte('\n')
}

// escapePromHelp escapes backslash and newline per the Prometheus exposition
// spec for HELP text.
func escapePromHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// escapePromLabelValue escapes backslash, double-quote, and newline per the
// Prometheus exposition spec for label values.
func escapePromLabelValue(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// gzipFile compresses the contents of src into a new file at dst. src is left
// in place; the caller decides whether to remove it.
func gzipFile(src, dst string) (retErr error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() {
		if cerr := out.Close(); retErr == nil {
			retErr = cerr
		}
	}()

	w := bufio.NewWriterSize(out, 64*1024)
	gz := gzip.NewWriter(w)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		return fmt.Errorf("gzip copy: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	return nil
}

// init self-registers the output with the plugin registry so it is reachable
// via the typed registry by name. The instance returned is unconfigured; the
// pipeline builder is expected to call NewFileOutput with the resolved
// configuration before Connect/Write.
func init() {
	plugin.MustAddOutput("file", func() plugin.Output {
		out, err := NewFileOutput(FileOutputConfig{})
		if err != nil {
			// Constructor with empty cfg returns an error (path required);
			// fall back to a zero struct so registration still succeeds. Real
			// wiring always goes through the explicit constructor.
			return &FileOutput{}
		}
		return out
	})
}
