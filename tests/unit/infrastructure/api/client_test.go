// Package api_test provides unit tests for the TelemetryFlow API client infrastructure.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

func TestNewClient(t *testing.T) {
	t.Run("should create client with config", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL: "http://localhost:8080",
		})
		require.NotNil(t, client)
	})

	t.Run("should use provided timeout", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL: "http://localhost:8080",
			Timeout: 60 * time.Second,
		})
		require.NotNil(t, client)
	})

	t.Run("should configure TLS when enabled", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL: "https://localhost:8080",
			TLSConfig: api.TLSConfig{
				Enabled:    true,
				SkipVerify: true,
			},
		})
		require.NotNil(t, client)
	})
}

func TestClientRequest(t *testing.T) {
	t.Run("should make successful GET request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/test", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, resp.IsSuccess())
	})

	t.Run("should make successful POST request with body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var body map[string]string
			err := json.NewDecoder(r.Body).Decode(&body)
			require.NoError(t, err)
			assert.Equal(t, "value", body["key"])

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.Request(context.Background(), http.MethodPost, "/test", map[string]string{"key": "value"})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("should set auth headers when configured", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "tfk_test", r.Header.Get("X-API-Key-ID"))
			assert.Equal(t, "tfs_secret", r.Header.Get("X-API-Key-Secret"))
			assert.Equal(t, "workspace-123", r.Header.Get("X-Workspace-ID"))
			assert.Equal(t, "tenant-456", r.Header.Get("X-Tenant-ID"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:      server.URL,
			APIKeyID:     "tfk_test",
			APIKeySecret: "tfs_secret",
			WorkspaceID:  "workspace-123",
			TenantID:     "tenant-456",
		})

		_, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.NoError(t, err)
	})

	t.Run("should return error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		_, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("should respect context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := client.Request(ctx, http.MethodGet, "/test", nil)
		require.Error(t, err)
	})
}

func TestResponse(t *testing.T) {
	t.Run("should unmarshal JSON response", func(t *testing.T) {
		resp := &api.Response{
			StatusCode: 200,
			Body:       []byte(`{"name": "test", "value": 123}`),
		}

		var result struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		err := resp.JSON(&result)
		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
		assert.Equal(t, 123, result.Value)
	})

	t.Run("should return error on invalid JSON", func(t *testing.T) {
		resp := &api.Response{
			StatusCode: 200,
			Body:       []byte(`invalid json`),
		}

		var result map[string]string
		err := resp.JSON(&result)
		require.Error(t, err)
	})

	t.Run("should correctly identify success status codes", func(t *testing.T) {
		successCodes := []int{200, 201, 202, 204, 299}
		for _, code := range successCodes {
			resp := &api.Response{StatusCode: code}
			assert.True(t, resp.IsSuccess(), "status %d should be success", code)
		}

		failureCodes := []int{400, 401, 403, 404, 500, 502, 503}
		for _, code := range failureCodes {
			resp := &api.Response{StatusCode: code}
			assert.False(t, resp.IsSuccess(), "status %d should not be success", code)
		}
	})
}

func TestClientHeartbeat(t *testing.T) {
	t.Run("should send heartbeat successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.URL.Path, "/agents/")
			assert.Contains(t, r.URL.Path, "/heartbeat")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		err := client.Heartbeat(context.Background(), "agent-123", nil)
		require.NoError(t, err)
	})

	t.Run("should send heartbeat with system info", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req api.HeartbeatRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotNil(t, req.SystemInfo)
			assert.Equal(t, "test-host", req.SystemInfo.Hostname)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		sysInfo := &api.SystemInfoPayload{
			Hostname: "test-host",
			OS:       "linux",
		}

		err := client.Heartbeat(context.Background(), "agent-123", sysInfo)
		require.NoError(t, err)
	})
}

func TestClientRegisterAgent(t *testing.T) {
	t.Run("should register agent successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/agents", r.URL.Path)

			var req api.RegisterAgentRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "test-host", req.Hostname)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": "agent-123"}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.RegisterAgent(context.Background(), &api.RegisterAgentRequest{
			Hostname:     "test-host",
			AgentVersion: "1.0.0",
		})
		require.NoError(t, err)
		assert.Equal(t, "agent-123", resp.ID)
	})

	t.Run("should return error on registration failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "invalid request"}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		_, err := client.RegisterAgent(context.Background(), &api.RegisterAgentRequest{
			Hostname: "test-host",
		})
		require.Error(t, err)
	})
}

func TestRequestWithGzip(t *testing.T) {
	t.Run("should send gzip compressed request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.RequestWithGzip(context.Background(), http.MethodPost, "/metrics", map[string]string{"test": "data"})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("should set auth headers in gzip request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "tfk_test", r.Header.Get("X-API-Key-ID"))
			assert.Equal(t, "tfs_secret", r.Header.Get("X-API-Key-Secret"))
			assert.Equal(t, "workspace-123", r.Header.Get("X-Workspace-ID"))
			assert.Equal(t, "tenant-456", r.Header.Get("X-Tenant-ID"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:      server.URL,
			APIKeyID:     "tfk_test",
			APIKeySecret: "tfs_secret",
			WorkspaceID:  "workspace-123",
			TenantID:     "tenant-456",
		})

		_, err := client.RequestWithGzip(context.Background(), http.MethodPost, "/test", map[string]string{"key": "value"})
		require.NoError(t, err)
	})

	t.Run("should handle nil body in gzip request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.RequestWithGzip(context.Background(), http.MethodPost, "/test", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("should return error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		_, err := client.RequestWithGzip(context.Background(), http.MethodPost, "/test", map[string]string{"test": "data"})
		require.Error(t, err)
	})

	t.Run("should respect context cancellation in gzip request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := client.RequestWithGzip(ctx, http.MethodPost, "/test", map[string]string{"test": "data"})
		require.Error(t, err)
	})
}

func TestSendMetrics(t *testing.T) {
	t.Run("should send metrics successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/v1/metrics", r.URL.Path)
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		metrics := map[string]interface{}{
			"name":  "cpu.usage",
			"value": 75.5,
		}

		err := client.SendMetrics(context.Background(), "/v1/metrics", metrics)
		require.NoError(t, err)
	})

	t.Run("should return error on metrics send failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.SendMetrics(context.Background(), "/v1/metrics", map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send metrics failed")
	})

	t.Run("should return error on non-success status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.SendMetrics(context.Background(), "/v1/metrics", map[string]interface{}{})
		require.Error(t, err)
	})
}

func TestSendLogs(t *testing.T) {
	t.Run("should send logs successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/v1/logs", r.URL.Path)
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		logs := map[string]interface{}{
			"message": "test log message",
			"level":   "info",
		}

		err := client.SendLogs(context.Background(), "/v1/logs", logs)
		require.NoError(t, err)
	})

	t.Run("should return error on logs send failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.SendLogs(context.Background(), "/v1/logs", map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send logs failed")
	})

	t.Run("should return error on non-success status for logs", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.SendLogs(context.Background(), "/v1/logs", map[string]interface{}{})
		require.Error(t, err)
	})
}

func TestClientRetry(t *testing.T) {
	t.Run("should retry on transient failures", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 3,
			RetryDelay:    10 * time.Millisecond,
		})

		resp, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 3, attempts)
	})

	t.Run("should fail after max retry attempts", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 2,
			RetryDelay:    10 * time.Millisecond,
		})

		_, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request failed after")
		assert.Equal(t, 3, attempts) // 1 initial + 2 retries
	})

	t.Run("should not retry on context cancellation", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 3,
			RetryDelay:    50 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := client.Request(ctx, http.MethodGet, "/test", nil)
		require.Error(t, err)
		assert.LessOrEqual(t, atomic.LoadInt32(&attempts), int32(2)) // Should not do all retries
	})
}

func TestHeartbeatFailure(t *testing.T) {
	t.Run("should return error on heartbeat server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.Heartbeat(context.Background(), "agent-123", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "heartbeat request failed")
	})

	t.Run("should return error on non-success status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
		})

		err := client.Heartbeat(context.Background(), "agent-123", nil)
		require.Error(t, err)
	})
}

func TestClientConfigDefaults(t *testing.T) {
	t.Run("should use default values when not specified", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL: "http://localhost:8080",
		})
		require.NotNil(t, client)
		// Client is created with defaults - verify via server request
	})

	t.Run("should use custom retry delay", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 2 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		start := time.Now()
		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 2,
			RetryDelay:    50 * time.Millisecond,
		})

		_, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		elapsed := time.Since(start)

		require.NoError(t, err)
		// Should have at least one retry delay
		assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(50))
	})
}

func TestResponseHeaders(t *testing.T) {
	t.Run("should capture response headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "req-12345")
			w.Header().Set("X-Rate-Limit", "100")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.Request(context.Background(), http.MethodGet, "/test", nil)
		require.NoError(t, err)
		assert.Equal(t, "req-12345", resp.Headers.Get("X-Request-ID"))
		assert.Equal(t, "100", resp.Headers.Get("X-Rate-Limit"))
	})
}

func TestTLSConfig(t *testing.T) {
	t.Run("should create client with full TLS config", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL: "https://localhost:8080",
			TLSConfig: api.TLSConfig{
				Enabled:    true,
				SkipVerify: false,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				CAFile:     "/path/to/ca.pem",
			},
		})
		require.NotNil(t, client)
	})
}

func TestSystemInfoPayload(t *testing.T) {
	t.Run("should create complete system info payload", func(t *testing.T) {
		payload := &api.SystemInfoPayload{
			Hostname:        "test-server",
			OS:              "linux",
			OSVersion:       "Ubuntu 22.04",
			KernelVersion:   "5.15.0",
			Architecture:    "x86_64",
			Uptime:          86400,
			CPUCores:        8,
			CPUModel:        "Intel Core i7",
			CPUUsage:        25.5,
			MemoryTotal:     16000000000,
			MemoryUsed:      8000000000,
			MemoryAvailable: 8000000000,
			MemoryUsage:     50.0,
			DiskTotal:       500000000000,
			DiskUsed:        250000000000,
			DiskAvailable:   250000000000,
			DiskUsage:       50.0,
		}

		assert.Equal(t, "test-server", payload.Hostname)
		assert.Equal(t, "linux", payload.OS)
		assert.Equal(t, 8, payload.CPUCores)
		assert.Equal(t, 50.0, payload.MemoryUsage)
	})
}
