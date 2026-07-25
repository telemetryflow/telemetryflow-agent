// Package redis implements a TelemetryFlow Agent collector for Redis cache
// instances. It connects via the RESP protocol over TCP and collects INFO,
// commandstats, keyspace, optional LATENCY LATEST, and optional CLUSTER INFO
// statistics. No external client library is required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package redis

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// RespClient is a minimal RESP client sufficient for INFO / CLUSTER NODES.
// It is exported so the Valkey collector (which speaks the same RESP wire
// protocol) can reuse it. It is not a general-purpose Redis client.
type RespClient struct {
	addr       string
	password   string
	db         int
	tls        bool
	skipVerify bool
	timeout    time.Duration

	conn   net.Conn
	reader *bufio.Reader
}

// NewRespClient creates an unconnected client.
func NewRespClient(host string, port int, password string, db int, tlsEnabled, skipVerify bool, timeout time.Duration) *RespClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &RespClient{
		addr:       net.JoinHostPort(host, strconv.Itoa(port)),
		password:   password,
		db:         db,
		tls:        tlsEnabled,
		skipVerify: skipVerify,
		timeout:    timeout,
	}
}

// Connect opens a connection and authenticates if needed.
func (c *RespClient) Connect() error {
	dialer := &net.Dialer{Timeout: c.timeout}
	if c.tls {
		tlsCfg := &tls.Config{InsecureSkipVerify: c.skipVerify}
		conn, err := tls.DialWithDialer(dialer, "tcp", c.addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("redis tls dial %s: %w", c.addr, err)
		}
		c.conn = conn
	} else {
		conn, err := dialer.Dial("tcp", c.addr)
		if err != nil {
			return fmt.Errorf("redis dial %s: %w", c.addr, err)
		}
		c.conn = conn
	}
	c.reader = bufio.NewReaderSize(c.conn, 1<<16)

	if c.password != "" {
		if err := c.simpleCmd([]string{"AUTH", c.password}); err != nil {
			c.Close()
			return fmt.Errorf("redis AUTH: %w", err)
		}
	}
	if c.db != 0 {
		if err := c.simpleCmd([]string{"SELECT", strconv.Itoa(c.db)}); err != nil {
			c.Close()
			return fmt.Errorf("redis SELECT: %w", err)
		}
	}
	return nil
}

// Close closes the underlying connection.
func (c *RespClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// simpleCmd sends a command and expects a +OK / simple-string or integer reply.
func (c *RespClient) simpleCmd(args []string) error {
	if err := c.writeCmd(args); err != nil {
		return err
	}
	return c.readSimple()
}

// BulkString sends a command and returns the bulk-string reply as a string.
// Returns empty string for a nil bulk reply.
func (c *RespClient) BulkString(args []string) (string, error) {
	if err := c.writeCmd(args); err != nil {
		return "", err
	}
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read reply header: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", fmt.Errorf("empty reply")
	}
	switch line[0] {
	case '-':
		return "", fmt.Errorf("redis error: %s", line[1:])
	case '+':
		return line[1:], nil // simple string
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("parse bulk length: %w", err)
		}
		if n < 0 {
			return "", nil // nil bulk
		}
		buf := make([]byte, n+2) // +2 for trailing \r\n
		if _, err := readFull(c.reader, buf); err != nil {
			return "", fmt.Errorf("read bulk body: %w", err)
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("unexpected reply: %q", line)
	}
}

// writeCmd encodes args using the RESP array format.
func (c *RespClient) writeCmd(args []string) error {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	_, err := c.conn.Write([]byte(b.String()))
	return err
}

func (c *RespClient) readSimple() error {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return fmt.Errorf("empty reply")
	}
	switch line[0] {
	case '+':
		return nil
	case '-':
		return fmt.Errorf("redis error: %s", line[1:])
	case ':':
		return nil // integer ok
	default:
		return fmt.Errorf("unexpected simple reply: %q", line)
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := r.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// ParseInfo parses an INFO bulk-string response into a flat key→value map.
// Sections are flattened: e.g. "connected_clients" and "db0" keys coexist.
func ParseInfo(info string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		out[line[:idx]] = line[idx+1:]
	}
	return out
}

// ToFloat parses a Redis INFO numeric value, returning 0 on parse failure.
func ToFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// ParseSemver parses a semantic version string like "7.2.5" into its major,
// minor, and patch integer components. Non-numeric components are treated as
// 0. An empty or completely malformed string yields 0,0,0. Trailing
// pre-release suffixes (e.g. "7.2.5-rc1") are ignored for the patch value.
//
// Exported so the Valkey collector (which speaks the same RESP wire protocol
// and reports versions in the same form) and external tests can reuse it.
func ParseSemver(s string) (major, minor, patch int) {
	if s == "" {
		return 0, 0, 0
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(stripPreRelease(parts[0]))
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(stripPreRelease(parts[1]))
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(stripPreRelease(parts[2]))
	}
	return major, minor, patch
}

// stripPreRelease removes any "-" pre-release suffix from a version component
// (e.g. "5-rc1" → "5"). Non-numeric trailing characters after a digit run are
// also stripped so "5rc1" becomes "5".
func stripPreRelease(s string) string {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	var (
		out       strings.Builder
		seenDigit bool
	)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			out.WriteRune(r)
			seenDigit = true
			continue
		}
		if !seenDigit {
			// Leading non-digit (e.g. "rc1"); stop — Atoi will fail and yield 0.
			break
		}
		// Once we've seen a digit, stop at any non-digit trailing char.
		break
	}
	return out.String()
}

// LatencyEvent represents a single entry from a LATENCY LATEST reply. Timestamp
// is the unix time (seconds) of the most recent occurrence.
type LatencyEvent struct {
	Event        string
	Timestamp    int64
	LatencyMs    float64
	MaxLatencyMs float64
}

// ParseLatencyLatest parses the bulk-string form of a LATENCY LATEST reply
// where each line is one event and fields are separated by whitespace:
//
//	event_name timestamp latency_ms max_latency_ms
//
// Malformed lines (fewer than two whitespace-separated fields) are skipped.
// Exported for the Valkey collector and external tests.
func ParseLatencyLatest(s string) map[string]LatencyEvent {
	out := make(map[string]LatencyEvent)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ev := LatencyEvent{Event: fields[0]}
		ts, _ := strconv.ParseInt(fields[1], 10, 64)
		ev.Timestamp = ts
		if len(fields) >= 3 {
			ev.LatencyMs, _ = strconv.ParseFloat(fields[2], 64)
		}
		if len(fields) >= 4 {
			ev.MaxLatencyMs, _ = strconv.ParseFloat(fields[3], 64)
		}
		out[ev.Event] = ev
	}
	return out
}

// ParseClusterInfo parses a CLUSTER INFO bulk-string reply into a flat
// key→value map. The CLUSTER INFO response uses the same line-oriented
// "key:value" format as INFO, so this delegates to ParseInfo. Exported for the
// Valkey collector and external tests.
func ParseClusterInfo(s string) map[string]string {
	return ParseInfo(s)
}
