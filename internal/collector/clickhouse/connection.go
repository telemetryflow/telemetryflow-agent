// Package clickhouse — HTTP connection to a ClickHouse instance.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package clickhouse

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// connection is an HTTP client that talks to a single ClickHouse instance.
type connection struct {
	inst    config.ClickHouseInstanceConfig
	client  *http.Client
	baseURL string
}

// newConnection builds an HTTP connection for the given instance.
// It configures TLS when inst.TLS.Enabled is true.
func newConnection(inst config.ClickHouseInstanceConfig) (*connection, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   inst.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   inst.ConnectTimeout,
		ResponseHeaderTimeout: inst.QueryTimeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}

	if inst.TLS.Enabled {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: inst.TLS.SkipVerify, //nolint:gosec
		}
		if inst.TLS.CAFile != "" {
			caPEM, err := os.ReadFile(inst.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("clickhouse connection: read CA file: %w", err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caPEM)
			tlsCfg.RootCAs = pool
		}
		if inst.TLS.CertFile != "" && inst.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(inst.TLS.CertFile, inst.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("clickhouse connection: load client cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		transport.TLSClientConfig = tlsCfg
	}

	scheme := "http"
	if inst.TLS.Enabled {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, inst.Host, inst.HTTPPort)

	return &connection{
		inst:    inst,
		client:  &http.Client{Transport: transport, Timeout: inst.QueryTimeout},
		baseURL: baseURL,
	}, nil
}

// Execute sends SQL to ClickHouse and returns the results as a slice of
// map[string]interface{}.  The query is sent via POST with JSONEachRow format
// so every row is a separate JSON object on its own line.
func (c *connection) Execute(ctx context.Context, query string) ([]map[string]interface{}, error) {
	params := url.Values{}
	params.Set("default_format", "JSONEachRow")
	// Append a FORMAT clause only when there isn't one already.
	if !strings.Contains(strings.ToUpper(query), "FORMAT ") {
		query = strings.TrimRight(strings.TrimSpace(query), ";") + " FORMAT JSONEachRow"
	}
	reqURL := c.baseURL + "/?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("clickhouse execute: build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if c.inst.Username != "" {
		req.Header.Set("X-ClickHouse-User", c.inst.Username)
	}
	if c.inst.Password != "" {
		req.Header.Set("X-ClickHouse-Key", c.inst.Password)
	}
	if c.inst.Database != "" {
		req.Header.Set("X-ClickHouse-Database", c.inst.Database)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse execute: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse execute: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rows []map[string]interface{}
	scanner := bufio.NewScanner(resp.Body)
	// Increase scanner buffer for wide rows (e.g. query text in query_log).
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var row map[string]interface{}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("clickhouse execute: parse row: %w", err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("clickhouse execute: read body: %w", err)
	}
	return rows, nil
}

// Check runs a minimal health query to verify the connection is alive.
func (c *connection) Check(ctx context.Context) error {
	rows, err := c.Execute(ctx, "SELECT 1")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("clickhouse check: empty response")
	}
	return nil
}

// Close releases resources held by the connection.
func (c *connection) Close() {
	c.client.CloseIdleConnections()
}
