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

// SyncKubernetesState sends the full cluster state snapshot to the TFO backend.
func (c *Client) SyncKubernetesState(ctx context.Context, state interface{}) error {
	resp, err := c.RequestWithGzip(ctx, http.MethodPost, "/monitoring/kubernetes/sync", state)
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
