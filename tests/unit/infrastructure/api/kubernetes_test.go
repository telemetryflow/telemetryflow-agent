// Package api_test contains unit tests for the TelemetryFlow backend HTTP
// client Kubernetes cluster sync and registration endpoints.
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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

func TestSyncKubernetesState(t *testing.T) {
	t.Run("should sync cluster state successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/monitoring/kubernetes/clusters/cluster-1/sync", r.URL.Path)
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		err := client.SyncKubernetesState(context.Background(), "cluster-1", map[string]string{"state": "ok"})
		require.NoError(t, err)
	})

	t.Run("should return error on transport failure", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{
			BaseURL:       "http://127.0.0.1:0",
			RetryAttempts: 0,
		})
		err := client.SyncKubernetesState(context.Background(), "cluster-1", map[string]string{"a": "b"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sync kubernetes state")
	})

	t.Run("should return error on non-success status", func(t *testing.T) {
		// RequestWithGzip retries on >=400 and finally returns an error, so the
		// non-success branch inside SyncKubernetesState is reached only when the
		// underlying request itself succeeds. Force that using a server that
		// returns 500 but where RequestWithGzip surfaces it as an error path.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{
			BaseURL:       server.URL,
			RetryAttempts: 0,
			RetryDelay:    time.Millisecond,
		})
		err := client.SyncKubernetesState(context.Background(), "cluster-1", map[string]string{"a": "b"})
		require.Error(t, err)
	})
}

func TestRegisterCluster(t *testing.T) {
	t.Run("should register cluster successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/monitoring/kubernetes/clusters", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"c-1","cluster_name":"prod"}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		resp, err := client.RegisterCluster(context.Background(), &api.RegisterClusterRequest{
			ClusterName:     "prod",
			ClusterProvider: "eks",
			AgentID:         "agent-1",
			Version:         "1.29",
		})
		require.NoError(t, err)
		assert.Equal(t, "c-1", resp.ID)
		assert.Equal(t, "prod", resp.ClusterName)
	})

	t.Run("should return error on request failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		_, err := client.RegisterCluster(context.Background(), &api.RegisterClusterRequest{ClusterName: "prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "register cluster")
	})

	t.Run("should return error on invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		_, err := client.RegisterCluster(context.Background(), &api.RegisterClusterRequest{ClusterName: "prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse register cluster response")
	})
}

func TestAgentRegisterCluster(t *testing.T) {
	t.Run("should agent-register cluster successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/monitoring/kubernetes/clusters/agent-register", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"c-9","name":"prod","isNew":true}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		resp, err := client.AgentRegisterCluster(context.Background(), &api.AgentRegisterClusterRequest{
			Name:     "prod",
			Provider: "gke",
			Version:  "1.30",
			Region:   "us-central1",
			Labels:   map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		assert.Equal(t, "c-9", resp.ID)
		assert.True(t, resp.IsNew)
	})

	t.Run("should return error on request failure", func(t *testing.T) {
		client := api.NewClient(api.ClientConfig{BaseURL: "http://127.0.0.1:0", RetryAttempts: 0})
		_, err := client.AgentRegisterCluster(context.Background(), &api.AgentRegisterClusterRequest{Name: "prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "agent register cluster")
	})

	t.Run("should return error on non-success status", func(t *testing.T) {
		// A 3xx status makes Request succeed (no error) but IsSuccess false,
		// exercising the explicit status-check branch.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		_, err := client.AgentRegisterCluster(context.Background(), &api.AgentRegisterClusterRequest{Name: "prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "agent register cluster failed with status")
	})

	t.Run("should return error on invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		_, err := client.AgentRegisterCluster(context.Background(), &api.AgentRegisterClusterRequest{Name: "prod"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse agent register cluster response")
	})
}

func TestDeregisterCluster(t *testing.T) {
	t.Run("should deregister cluster successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/monitoring/kubernetes/clusters/prod", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL})
		err := client.DeregisterCluster(context.Background(), "prod")
		require.NoError(t, err)
	})

	t.Run("should return error on request failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.DeregisterCluster(context.Background(), "prod")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deregister cluster")
	})

	t.Run("should return error on non-success status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound)
		}))
		defer server.Close()

		client := api.NewClient(api.ClientConfig{BaseURL: server.URL, RetryAttempts: 0})
		err := client.DeregisterCluster(context.Background(), "prod")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deregister cluster failed with status")
	})
}
