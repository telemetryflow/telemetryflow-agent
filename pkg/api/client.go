// Package api provides HTTP client for TelemetryFlow backend communication.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// Client is the HTTP client for TelemetryFlow backend
type Client struct {
	baseURL    string
	httpClient *http.Client
	config     ClientConfig
	logger     *zap.Logger
}

// ClientConfig contains client configuration
type ClientConfig struct {
	// BaseURL is the backend API base URL
	BaseURL string

	// APIKeyID is the API key identifier
	APIKeyID string

	// APIKeySecret is the API key secret
	APIKeySecret string

	// WorkspaceID is the workspace identifier
	WorkspaceID string

	// TenantID is the tenant/organization identifier
	TenantID string

	// Timeout is the request timeout
	Timeout time.Duration

	// RetryAttempts is the number of retry attempts
	RetryAttempts int

	// RetryDelay is the initial delay between retries
	RetryDelay time.Duration

	// TLSConfig contains TLS settings
	TLSConfig TLSConfig

	// Logger is the logger instance
	Logger *zap.Logger
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	Enabled    bool
	SkipVerify bool
	CertFile   string
	KeyFile    string
	CAFile     string
}

// NewClient creates a new API client
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.RetryAttempts == 0 {
		cfg.RetryAttempts = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	// Create transport with TLS config
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if cfg.TLSConfig.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.TLSConfig.SkipVerify, //nolint:gosec // G402: Configurable for dev/testing with self-signed certs
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		config: cfg,
		logger: cfg.Logger,
	}
}

// Request performs an HTTP request with retries
func (c *Client) Request(ctx context.Context, method, path string, body interface{}) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			delay := c.config.RetryDelay * time.Duration(attempt)
			c.logger.Debug("Retrying request",
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := c.doRequest(ctx, method, path, body)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		c.logger.Debug("Request failed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("attempt", attempt),
			zap.Error(err),
		)

		// Don't retry on context errors
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.RetryAttempts, lastErr)
}

// doRequest performs a single HTTP request
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*Response, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("X-Agent-Version", version.Short())
	req.Header.Set("X-Agent-Product", version.ProductName)

	// Set auth headers
	if c.config.APIKeyID != "" && c.config.APIKeySecret != "" {
		req.Header.Set("X-API-Key-ID", c.config.APIKeyID)
		req.Header.Set("X-API-Key-Secret", c.config.APIKeySecret)
	}

	if c.config.WorkspaceID != "" {
		req.Header.Set("X-Workspace-ID", c.config.WorkspaceID)
	}

	if c.config.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.config.TenantID)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := &Response{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		return response, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return response, nil
}

// RequestWithGzip performs a gzip-compressed request
func (c *Client) RequestWithGzip(ctx context.Context, method, path string, body interface{}) (*Response, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}

		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		if _, err := gzipWriter.Write(jsonData); err != nil {
			return nil, fmt.Errorf("failed to gzip compress: %w", err)
		}
		if err := gzipWriter.Close(); err != nil {
			return nil, fmt.Errorf("failed to close gzip writer: %w", err)
		}
		bodyReader = &buf
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("X-Agent-Version", version.Short())
	req.Header.Set("X-Agent-Product", version.ProductName)

	// Set auth headers
	if c.config.APIKeyID != "" && c.config.APIKeySecret != "" {
		req.Header.Set("X-API-Key-ID", c.config.APIKeyID)
		req.Header.Set("X-API-Key-Secret", c.config.APIKeySecret)
	}

	if c.config.WorkspaceID != "" {
		req.Header.Set("X-Workspace-ID", c.config.WorkspaceID)
	}

	if c.config.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.config.TenantID)
	}

	// Execute with retry
	var lastErr error
	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			delay := c.config.RetryDelay * time.Duration(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		response := &Response{
			StatusCode: resp.StatusCode,
			Body:       respBody,
			Headers:    resp.Header,
		}

		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("request failed with status %d", resp.StatusCode)
			continue
		}

		return response, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.RetryAttempts, lastErr)
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
}

// JSON unmarshals the response body into the given interface
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal(r.Body, v)
}

// IsSuccess returns true if the status code is 2xx
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// HeartbeatRequest represents a heartbeat request to the backend
type HeartbeatRequest struct {
	SystemInfo *SystemInfoPayload `json:"systemInfo,omitempty"`
}

// SystemInfoPayload is the system info sent with heartbeat
type SystemInfoPayload struct {
	Hostname        string  `json:"hostname,omitempty"`
	OS              string  `json:"os,omitempty"`
	OSVersion       string  `json:"osVersion,omitempty"`
	KernelVersion   string  `json:"kernelVersion,omitempty"`
	Architecture    string  `json:"architecture,omitempty"`
	Uptime          uint64  `json:"uptime,omitempty"`
	CPUCores        int     `json:"cpuCores,omitempty"`
	CPUModel        string  `json:"cpuModel,omitempty"`
	CPUUsage        float64 `json:"cpuUsage,omitempty"`
	MemoryTotal     uint64  `json:"memoryTotal,omitempty"`
	MemoryUsed      uint64  `json:"memoryUsed,omitempty"`
	MemoryAvailable uint64  `json:"memoryAvailable,omitempty"`
	MemoryUsage     float64 `json:"memoryUsage,omitempty"`
	DiskTotal       uint64  `json:"diskTotal,omitempty"`
	DiskUsed        uint64  `json:"diskUsed,omitempty"`
	DiskAvailable   uint64  `json:"diskAvailable,omitempty"`
	DiskUsage       float64 `json:"diskUsage,omitempty"`
}

// HeartbeatResponse represents the heartbeat response from backend
type HeartbeatResponse struct {
	Success   bool   `json:"success"`
	Timestamp string `json:"timestamp"`
}

// Heartbeat sends a heartbeat to the backend
func (c *Client) Heartbeat(ctx context.Context, agentID string, sysInfo *SystemInfoPayload) error {
	path := fmt.Sprintf("/agents/%s/heartbeat", agentID)

	req := &HeartbeatRequest{
		SystemInfo: sysInfo,
	}

	resp, err := c.Request(ctx, http.MethodPost, path, req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("heartbeat failed with status %d", resp.StatusCode)
	}

	return nil
}

// RegisterAgent registers the agent with the backend
func (c *Client) RegisterAgent(ctx context.Context, req *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	resp, err := c.Request(ctx, http.MethodPost, "/agents", req)
	if err != nil {
		return nil, fmt.Errorf("register agent request failed: %w", err)
	}

	var result RegisterAgentResponse
	if err := resp.JSON(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// RegisterAgentRequest represents an agent registration request
type RegisterAgentRequest struct {
	Hostname        string            `json:"hostname"`
	AgentVersion    string            `json:"agentVersion"`
	OrganizationID  string            `json:"organizationId"`
	OperatingSystem string            `json:"operatingSystem,omitempty"`
	MacAddress      string            `json:"macAddress,omitempty"`
	IPAddress       string            `json:"ipAddress,omitempty"`
	Description     string            `json:"description,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// RegisterAgentResponse represents the agent registration response
type RegisterAgentResponse struct {
	ID string `json:"id"`
}

// SendMetrics sends metrics to the OTLP endpoint
func (c *Client) SendMetrics(ctx context.Context, endpoint string, metrics interface{}) error {
	resp, err := c.RequestWithGzip(ctx, http.MethodPost, endpoint, metrics)
	if err != nil {
		return fmt.Errorf("send metrics failed: %w", err)
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("send metrics failed with status %d", resp.StatusCode)
	}

	return nil
}

// SendLogs sends logs to the OTLP endpoint
func (c *Client) SendLogs(ctx context.Context, endpoint string, logs interface{}) error {
	resp, err := c.RequestWithGzip(ctx, http.MethodPost, endpoint, logs)
	if err != nil {
		return fmt.Errorf("send logs failed: %w", err)
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("send logs failed with status %d", resp.StatusCode)
	}

	return nil
}
