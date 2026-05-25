// Package api provides the HTTP client used by the TelemetryFlow Agent to
// communicate with the TelemetryFlow backend: agent registration, heartbeat,
// Kubernetes cluster sync, and authenticated API-key requests.
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
package api

import (
	"context"
	"fmt"
	"net/http"
)

// SyncKubernetesStateRequest is the payload for syncing cluster state to the backend.
type SyncKubernetesStateRequest struct {
	ClusterName     string      `json:"cluster_name"`
	ClusterProvider string      `json:"cluster_provider"`
	State           interface{} `json:"state"`
}

// RegisterClusterRequest registers a Kubernetes cluster with the backend.
type RegisterClusterRequest struct {
	ClusterName     string `json:"cluster_name"`
	ClusterProvider string `json:"cluster_provider"`
	AgentID         string `json:"agent_id"`
	Version         string `json:"version,omitempty"`
}

// RegisterClusterResponse contains the backend-assigned cluster ID.
type RegisterClusterResponse struct {
	ID          string `json:"id"`
	ClusterName string `json:"cluster_name"`
}

// AgentRegisterClusterRequest is the payload for agent-driven cluster registration.
// Uses API key auth and is safe to call on every restart (find-or-create semantics).
type AgentRegisterClusterRequest struct {
	Name     string            `json:"name"`
	Provider string            `json:"provider,omitempty"`
	Version  string            `json:"version,omitempty"`
	Region   string            `json:"region,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// AgentRegisterClusterResponse is returned by the agent-register endpoint.
type AgentRegisterClusterResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	IsNew bool   `json:"isNew"`
}

// SyncKubernetesState sends the full cluster state snapshot to the TFO backend.
func (c *Client) SyncKubernetesState(ctx context.Context, clusterID string, payload interface{}) error {
	path := fmt.Sprintf("/monitoring/kubernetes/clusters/%s/sync", clusterID)
	resp, err := c.RequestWithGzip(ctx, http.MethodPost, path, payload)
	if err != nil {
		return fmt.Errorf("sync kubernetes state: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("sync kubernetes state failed with status %d", resp.StatusCode)
	}
	return nil
}

// RegisterCluster registers a Kubernetes cluster with the TFO backend.
func (c *Client) RegisterCluster(ctx context.Context, req *RegisterClusterRequest) (*RegisterClusterResponse, error) {
	resp, err := c.Request(ctx, http.MethodPost, "/monitoring/kubernetes/clusters", req)
	if err != nil {
		return nil, fmt.Errorf("register cluster: %w", err)
	}

	var result RegisterClusterResponse
	if err := resp.JSON(&result); err != nil {
		return nil, fmt.Errorf("parse register cluster response: %w", err)
	}
	return &result, nil
}

// AgentRegisterCluster auto-registers a Kubernetes cluster using API key auth.
// Implements find-or-create — safe to call on every agent restart.
func (c *Client) AgentRegisterCluster(ctx context.Context, req *AgentRegisterClusterRequest) (*AgentRegisterClusterResponse, error) {
	resp, err := c.Request(ctx, http.MethodPost, "/monitoring/kubernetes/clusters/agent-register", req)
	if err != nil {
		return nil, fmt.Errorf("agent register cluster: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("agent register cluster failed with status %d", resp.StatusCode)
	}
	var result AgentRegisterClusterResponse
	if err := resp.JSON(&result); err != nil {
		return nil, fmt.Errorf("parse agent register cluster response: %w", err)
	}
	return &result, nil
}

// DeregisterCluster removes a Kubernetes cluster from the TFO backend.
func (c *Client) DeregisterCluster(ctx context.Context, clusterName string) error {
	path := fmt.Sprintf("/monitoring/kubernetes/clusters/%s", clusterName)
	resp, err := c.Request(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deregister cluster: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("deregister cluster failed with status %d", resp.StatusCode)
	}
	return nil
}
