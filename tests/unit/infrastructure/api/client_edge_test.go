// Package api_test contains edge-case unit tests for the TelemetryFlow backend
// HTTP client: marshal failures, request-construction errors, retry-delay
// cancellation, and non-success (3xx) status handling.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package api_test

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

// unmarshalable returns a body that json.Marshal cannot encode (Inf float),
// forcing the marshal-error branch in doRequest / RequestWithGzip.
func unmarshalableBody() interface{} {
	return map[string]interface{}{"bad": math.Inf(1)}
}

func TestRequestMarshalError(t *testing.T) {
	client := api.NewClient(api.ClientConfig{BaseURL: "http://127.0.0.1:0", RetryAttempts: 0})

	t.Run("Request surfaces marshal error", func(t *testing.T) {
		_, err := client.Request(context.Background(), http.MethodPost, "/x", unmarshalableBody())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "marshal request body")
	})

	t.Run("RequestWithGzip surfaces marshal error", func(t *testing.T) {
		_, err := client.RequestWithGzip(context.Background(), http.MethodPost, "/x", unmarshalableBody())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "marshal request body")
	})
}

func TestRequestInvalidMethod(t *testing.T) {
	client := api.NewClient(api.ClientConfig{BaseURL: "http://127.0.0.1:0", RetryAttempts: 0})

	t.Run("Request fails to build with invalid method", func(t *testing.T) {
		_, err := client.Request(context.Background(), "BAD METHOD", "/x", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create request")
	})

	t.Run("RequestWithGzip fails to build with invalid method", func(t *testing.T) {
		_, err := client.RequestWithGzip(context.Background(), "BAD METHOD", "/x", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create request")
	})
}

// TestRetryDelayCancellation cancels the context during the inter-attempt
// delay so the ctx.Done() branch inside the retry loop is exercised.
func TestRetryDelayCancellation(t *testing.T) {
	t.Run("Request aborts during retry delay", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 5,
			RetryDelay:    500 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := client.Request(ctx, http.MethodGet, "/x", nil)
		require.Error(t, err)
	})

	t.Run("RequestWithGzip aborts during retry delay", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 5,
			RetryDelay:    500 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := client.RequestWithGzip(ctx, http.MethodPost, "/x", map[string]string{"a": "b"})
		require.Error(t, err)
	})
}

// TestNonSuccessRedirectBranches uses a 3xx status: Request/RequestWithGzip
// return no error (status < 400) but IsSuccess() is false, exercising the
// explicit non-success guard in the high-level helpers.
func TestNonSuccessRedirectBranches(t *testing.T) {
	newRedirectServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound) // 302, no Location -> client does not follow
			_, _ = w.Write([]byte(`{}`))
		}))
	}

	t.Run("Heartbeat non-success", func(t *testing.T) {
		server := newRedirectServer()
		defer server.Close()
		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.Heartbeat(context.Background(), "agent-1", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "heartbeat failed with status")
	})

	t.Run("SendMetrics non-success", func(t *testing.T) {
		server := newRedirectServer()
		defer server.Close()
		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.SendMetrics(context.Background(), "/v1/metrics", map[string]string{"a": "b"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send metrics failed with status")
	})

	t.Run("SendLogs non-success", func(t *testing.T) {
		server := newRedirectServer()
		defer server.Close()
		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.SendLogs(context.Background(), "/v1/logs", map[string]string{"a": "b"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send logs failed with status")
	})

	t.Run("SyncKubernetesState non-success", func(t *testing.T) {
		server := newRedirectServer()
		defer server.Close()
		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.SyncKubernetesState(context.Background(), "c-1", map[string]string{"a": "b"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync kubernetes state failed with status")
	})
}

// TestRegisterAgentInvalidJSON covers the JSON-parse error branch in
// RegisterAgent when the backend returns a non-success-shaped body.
func TestRegisterAgentInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
	_, err := client.RegisterAgent(context.Background(), &api.RegisterAgentRequest{Hostname: "h"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse response")
}
