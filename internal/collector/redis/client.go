// Package redis implements a TelemetryFlow Agent collector for Redis cache
// instances. It connects via the RESP protocol over TCP and collects INFO,
// commandstats, replication, and cluster statistics. No external client
// library is required.
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
