// Package api provides HTTP client tests for TelemetryFlow backend communication.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Run("should create client with default values", func(t *testing.T) {
		client := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
		})

		require.NotNil(t, client)
		assert.Equal(t, "http://localhost:8080", client.baseURL)
	})

	t.Run("should use provided timeout", func(t *testing.T) {
		client := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
			Timeout: 60 * time.Second,
		})

		require.NotNil(t, client)
		assert.Equal(t, 60*time.Second, client.httpClient.Timeout)
	})

	t.Run("should use default timeout when not provided", func(t *testing.T) {
		client := NewClient(ClientConfig{
			BaseURL: "http://localhost:8080",
		})

		assert.Equal(t, 30*time.Second, client.httpClient.Timeout)
	})

	t.Run("should configure TLS when enabled", func(t *testing.T) {
		client := NewClient(ClientConfig{
			BaseURL: "https://localhost:8080",
			TLSConfig: TLSConfig{
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

		client := NewClient(ClientConfig{
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

		client := NewClient(ClientConfig{
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

		client := NewClient(ClientConfig{
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

		client := NewClient(ClientConfig{
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

		client := NewClient(ClientConfig{
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
		resp := &Response{
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
		resp := &Response{
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
			resp := &Response{StatusCode: code}
			assert.True(t, resp.IsSuccess(), "status %d should be success", code)
		}

		failureCodes := []int{400, 401, 403, 404, 500, 502, 503}
		for _, code := range failureCodes {
			resp := &Response{StatusCode: code}
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

		client := NewClient(ClientConfig{
			BaseURL: server.URL,
		})

		err := client.Heartbeat(context.Background(), "agent-123", nil)
		require.NoError(t, err)
	})

	t.Run("should send heartbeat with system info", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req HeartbeatRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotNil(t, req.SystemInfo)
			assert.Equal(t, "test-host", req.SystemInfo.Hostname)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		client := NewClient(ClientConfig{
			BaseURL: server.URL,
		})

		sysInfo := &SystemInfoPayload{
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

			var req RegisterAgentRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "test-host", req.Hostname)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": "agent-123"}`))
		}))
		defer server.Close()

		client := NewClient(ClientConfig{
			BaseURL: server.URL,
		})

		resp, err := client.RegisterAgent(context.Background(), &RegisterAgentRequest{
			Hostname:     "test-host",
			AgentVersion: "1.0.0",
		})
		require.NoError(t, err)
		assert.Equal(t, "agent-123", resp.ID)
	})
}
