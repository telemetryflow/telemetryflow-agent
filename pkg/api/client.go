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

// SystemInfoPayload is the comprehensive system info sent with heartbeat
type SystemInfoPayload struct {
	// ==========================================================================
	// Host Information
	// ==========================================================================
	Hostname       string `json:"hostname,omitempty"`
	OS             string `json:"os,omitempty"`
	OSVersion      string `json:"osVersion,omitempty"`
	Platform       string `json:"platform,omitempty"`
	PlatformFamily string `json:"platformFamily,omitempty"`
	KernelVersion  string `json:"kernelVersion,omitempty"`
	Architecture   string `json:"architecture,omitempty"`
	Uptime         uint64 `json:"uptime,omitempty"`
	BootTime       uint64 `json:"bootTime,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	HostID         string `json:"hostId,omitempty"`

	// ==========================================================================
	// CPU Information
	// ==========================================================================
	CPUCores          int     `json:"cpuCores,omitempty"`
	CPULogicalCores   int     `json:"cpuLogicalCores,omitempty"`
	CPUPhysicalCores  int     `json:"cpuPhysicalCores,omitempty"`
	CPUModel          string  `json:"cpuModel,omitempty"`
	CPUVendor         string  `json:"cpuVendor,omitempty"`
	CPUFamily         string  `json:"cpuFamily,omitempty"`
	CPUMhz            float64 `json:"cpuMhz,omitempty"`
	CPUCacheSize      int32   `json:"cpuCacheSize,omitempty"`
	CPUUsage          float64 `json:"cpuUsage,omitempty"`
	CPUUserPercent    float64 `json:"cpuUserPercent,omitempty"`
	CPUSystemPercent  float64 `json:"cpuSystemPercent,omitempty"`
	CPUIdlePercent    float64 `json:"cpuIdlePercent,omitempty"`
	CPUIOWaitPercent  float64 `json:"cpuIowaitPercent,omitempty"`
	CPUStealPercent   float64 `json:"cpuStealPercent,omitempty"`
	CPUGuestPercent   float64 `json:"cpuGuestPercent,omitempty"`
	CPUIrqPercent     float64 `json:"cpuIrqPercent,omitempty"`
	CPUSoftIrqPercent float64 `json:"cpuSoftirqPercent,omitempty"`
	CPUNicePercent    float64 `json:"cpuNicePercent,omitempty"`
	LoadAvg1          float64 `json:"loadAvg1,omitempty"`
	LoadAvg5          float64 `json:"loadAvg5,omitempty"`
	LoadAvg15         float64 `json:"loadAvg15,omitempty"`

	// CPU Per-Core (optional detailed breakdown)
	CPUPerCore []CPUCoreInfoPayload `json:"cpuPerCore,omitempty"`

	// ==========================================================================
	// Memory Information
	// ==========================================================================
	MemoryTotal       uint64  `json:"memoryTotal,omitempty"`
	MemoryUsed        uint64  `json:"memoryUsed,omitempty"`
	MemoryAvailable   uint64  `json:"memoryAvailable,omitempty"`
	MemoryFree        uint64  `json:"memoryFree,omitempty"`
	MemoryUsage       float64 `json:"memoryUsage,omitempty"`
	MemoryCached      uint64  `json:"memoryCached,omitempty"`
	MemoryBuffers     uint64  `json:"memoryBuffers,omitempty"`
	MemoryActive      uint64  `json:"memoryActive,omitempty"`
	MemoryInactive    uint64  `json:"memoryInactive,omitempty"`
	MemoryWired       uint64  `json:"memoryWired,omitempty"`
	MemoryShared      uint64  `json:"memoryShared,omitempty"`
	MemorySlab        uint64  `json:"memorySlab,omitempty"`
	MemoryPageTables  uint64  `json:"memoryPageTables,omitempty"`
	MemoryCommitted   uint64  `json:"memoryCommitted,omitempty"`
	MemoryCommitLimit uint64  `json:"memoryCommitLimit,omitempty"`
	MemoryDirty       uint64  `json:"memoryDirty,omitempty"`
	MemoryWriteback   uint64  `json:"memoryWriteback,omitempty"`
	SwapTotal         uint64  `json:"swapTotal,omitempty"`
	SwapUsed          uint64  `json:"swapUsed,omitempty"`
	SwapFree          uint64  `json:"swapFree,omitempty"`
	SwapUsage         float64 `json:"swapUsage,omitempty"`
	SwapIn            uint64  `json:"swapIn,omitempty"`
	SwapOut           uint64  `json:"swapOut,omitempty"`
	PageFaultsMajor   uint64  `json:"pageFaultsMajor,omitempty"`
	PageFaultsMinor   uint64  `json:"pageFaultsMinor,omitempty"`

	// ==========================================================================
	// Disk Information
	// ==========================================================================
	DiskTotal        uint64  `json:"diskTotal,omitempty"`
	DiskUsed         uint64  `json:"diskUsed,omitempty"`
	DiskAvailable    uint64  `json:"diskAvailable,omitempty"`
	DiskUsage        float64 `json:"diskUsage,omitempty"`
	DiskInodes       uint64  `json:"diskInodes,omitempty"`
	DiskInodesFree   uint64  `json:"diskInodesFree,omitempty"`
	DiskInodesUsed   uint64  `json:"diskInodesUsed,omitempty"`
	DiskInodesUsage  float64 `json:"diskInodesUsage,omitempty"`
	DiskReadBytes    uint64  `json:"diskReadBytes,omitempty"`
	DiskWriteBytes   uint64  `json:"diskWriteBytes,omitempty"`
	DiskReadOps      uint64  `json:"diskReadOps,omitempty"`
	DiskWriteOps     uint64  `json:"diskWriteOps,omitempty"`
	DiskReadTime     uint64  `json:"diskReadTime,omitempty"`
	DiskWriteTime    uint64  `json:"diskWriteTime,omitempty"`
	DiskIOTime       uint64  `json:"diskIoTime,omitempty"`
	DiskWeightedIO   uint64  `json:"diskWeightedIo,omitempty"`
	DiskIOInProgress uint64  `json:"diskIoInProgress,omitempty"`
	DiskIOPS         float64 `json:"diskIops,omitempty"`
	DiskLatencyRead  float64 `json:"diskLatencyRead,omitempty"`
	DiskLatencyWrite float64 `json:"diskLatencyWrite,omitempty"`

	// Per-partition metrics
	DiskPartitions []DiskPartitionInfoPayload `json:"diskPartitions,omitempty"`

	// ==========================================================================
	// Network Information
	// ==========================================================================
	NetworkBytesSent     uint64  `json:"networkBytesSent,omitempty"`
	NetworkBytesRecv     uint64  `json:"networkBytesRecv,omitempty"`
	NetworkPacketsSent   uint64  `json:"networkPacketsSent,omitempty"`
	NetworkPacketsRecv   uint64  `json:"networkPacketsRecv,omitempty"`
	NetworkErrorsIn      uint64  `json:"networkErrorsIn,omitempty"`
	NetworkErrorsOut     uint64  `json:"networkErrorsOut,omitempty"`
	NetworkDropsIn       uint64  `json:"networkDropsIn,omitempty"`
	NetworkDropsOut      uint64  `json:"networkDropsOut,omitempty"`
	NetworkFifoIn        uint64  `json:"networkFifoIn,omitempty"`
	NetworkFifoOut       uint64  `json:"networkFifoOut,omitempty"`
	NetworkBytesSentRate float64 `json:"networkBytesSentRate,omitempty"`
	NetworkBytesRecvRate float64 `json:"networkBytesRecvRate,omitempty"`

	// TCP Connection States
	TCPConnectionsEstablished uint32 `json:"tcpConnectionsEstablished,omitempty"`
	TCPConnectionsTimeWait    uint32 `json:"tcpConnectionsTimeWait,omitempty"`
	TCPConnectionsCloseWait   uint32 `json:"tcpConnectionsCloseWait,omitempty"`
	TCPConnectionsListen      uint32 `json:"tcpConnectionsListen,omitempty"`
	TCPConnectionsSynSent     uint32 `json:"tcpConnectionsSynSent,omitempty"`
	TCPConnectionsSynRecv     uint32 `json:"tcpConnectionsSynRecv,omitempty"`
	TCPConnectionsFinWait1    uint32 `json:"tcpConnectionsFinWait1,omitempty"`
	TCPConnectionsFinWait2    uint32 `json:"tcpConnectionsFinWait2,omitempty"`
	TCPConnectionsLastAck     uint32 `json:"tcpConnectionsLastAck,omitempty"`
	TCPConnectionsClosing     uint32 `json:"tcpConnectionsClosing,omitempty"`
	TCPRetransmits            uint64 `json:"tcpRetransmits,omitempty"`

	// Per-interface metrics
	NetworkInterfaces []NetworkInterfaceInfoPayload `json:"networkInterfaces,omitempty"`

	// ==========================================================================
	// Process Information
	// ==========================================================================
	ProcessCount    uint64 `json:"processCount,omitempty"`
	ProcessRunning  uint64 `json:"processRunning,omitempty"`
	ProcessSleeping uint64 `json:"processSleeping,omitempty"`
	ProcessStopped  uint64 `json:"processStopped,omitempty"`
	ProcessZombie   uint64 `json:"processZombie,omitempty"`
	ProcessBlocked  uint64 `json:"processBlocked,omitempty"`
	ThreadCount     uint64 `json:"threadCount,omitempty"`
	ContextSwitches uint64 `json:"contextSwitches,omitempty"`
	Interrupts      uint64 `json:"interrupts,omitempty"`
	SoftInterrupts  uint64 `json:"softInterrupts,omitempty"`
	SystemCalls     uint64 `json:"systemCalls,omitempty"`

	// ==========================================================================
	// System Resources
	// ==========================================================================
	OpenFileDescriptors  uint64  `json:"openFileDescriptors,omitempty"`
	MaxFileDescriptors   uint64  `json:"maxFileDescriptors,omitempty"`
	FileDescriptorsUsage float64 `json:"fileDescriptorsUsage,omitempty"`
	EntropyAvailable     uint64  `json:"entropyAvailable,omitempty"`

	// ==========================================================================
	// Container/Virtualization Detection
	// ==========================================================================
	IsContainer        bool   `json:"isContainer,omitempty"`
	ContainerID        string `json:"containerId,omitempty"`
	ContainerRuntime   string `json:"containerRuntime,omitempty"`
	ContainerName      string `json:"containerName,omitempty"`
	ContainerImage     string `json:"containerImage,omitempty"`
	IsVirtualized      bool   `json:"isVirtualized,omitempty"`
	VirtualizationType string `json:"virtualizationType,omitempty"`
	CloudProvider      string `json:"cloudProvider,omitempty"`
	CloudInstanceID    string `json:"cloudInstanceId,omitempty"`
	CloudInstanceType  string `json:"cloudInstanceType,omitempty"`
	CloudRegion        string `json:"cloudRegion,omitempty"`
	CloudZone          string `json:"cloudZone,omitempty"`

	// ==========================================================================
	// Agent Metadata
	// ==========================================================================
	AgentVersion       string `json:"agentVersion,omitempty"`
	AgentStartTime     uint64 `json:"agentStartTime,omitempty"`
	AgentUptime        uint64 `json:"agentUptime,omitempty"`
	CollectionTime     int64  `json:"collectionTime,omitempty"`
	CollectionDuration int64  `json:"collectionDuration,omitempty"`
}

// CPUCoreInfoPayload contains per-core CPU information for API payload
type CPUCoreInfoPayload struct {
	CoreID        int     `json:"coreId"`
	Usage         float64 `json:"usage"`
	UserPercent   float64 `json:"userPercent,omitempty"`
	SystemPercent float64 `json:"systemPercent,omitempty"`
	IdlePercent   float64 `json:"idlePercent,omitempty"`
}

// DiskPartitionInfoPayload contains per-partition disk information for API payload
type DiskPartitionInfoPayload struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	Usage       float64 `json:"usage"`
	Inodes      uint64  `json:"inodes,omitempty"`
	InodesFree  uint64  `json:"inodesFree,omitempty"`
	InodesUsage float64 `json:"inodesUsage,omitempty"`
}

// NetworkInterfaceInfoPayload contains per-interface network information for API payload
type NetworkInterfaceInfoPayload struct {
	Name        string   `json:"name"`
	MacAddress  string   `json:"macAddress,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	Speed       uint64   `json:"speed,omitempty"`
	IsUp        bool     `json:"isUp"`
	IsLoopback  bool     `json:"isLoopback"`
	BytesSent   uint64   `json:"bytesSent"`
	BytesRecv   uint64   `json:"bytesRecv"`
	PacketsSent uint64   `json:"packetsSent"`
	PacketsRecv uint64   `json:"packetsRecv"`
	ErrorsIn    uint64   `json:"errorsIn"`
	ErrorsOut   uint64   `json:"errorsOut"`
	DropsIn     uint64   `json:"dropsIn"`
	DropsOut    uint64   `json:"dropsOut"`
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
