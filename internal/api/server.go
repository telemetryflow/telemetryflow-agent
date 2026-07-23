// Package api provides a lightweight HTTP API server for the TFO Agent,
// enabling real-time Kubernetes queries (pod log streaming) from the
// TelemetryFlow Platform backend.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

// Config holds the agent API server configuration.
type Config struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Port    int    `mapstructure:"port" yaml:"port"`
	APIKey  string // Validated against incoming requests
}

// Server is the Agent HTTP API server for real-time K8s queries.
type Server struct {
	config    Config
	clientset kubernetes.Interface
	logger    *zap.Logger
	mu        sync.Mutex // guards server
	server    *http.Server
	agent     AgentProvider
}

// AgentProvider exposes agent methods needed by API handlers.
type AgentProvider interface {
	CollectorStates() []CollectorState
	ReloadConfig() error
	IsRunning() bool
	Stats() AgentStats
}

// CollectorState mirrors collector.CollectorStatus for the API layer.
type CollectorState struct {
	Name         string `json:"name"`
	State        string `json:"state"`
	StartedAt    int64  `json:"started_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	FailureCount int    `json:"failure_count"`
}

// AgentStats mirrors agent.AgentStats for the API layer.
type AgentStats struct {
	ID             string `json:"id"`
	Hostname       string `json:"hostname"`
	Running        bool   `json:"running"`
	Started        int64  `json:"started,omitempty"`
	UptimeMs       int64  `json:"uptime_ms"`
	CollectorCount int    `json:"collector_count"`
}

// NewServer creates a new agent API server.
func NewServer(cfg Config, clientset kubernetes.Interface, logger *zap.Logger, agent AgentProvider) *Server {
	return &Server{
		config:    cfg,
		clientset: clientset,
		logger:    logger.Named("agent-api"),
		agent:     agent,
	}
}

// Start begins listening for HTTP requests. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Supervisor endpoints
	mux.HandleFunc("GET /api/v1/collectors", s.handleCollectors)
	mux.HandleFunc("POST /api/v1/reload", s.handleReload)

	// Pod log streaming (SSE)
	mux.HandleFunc("GET /api/v1/pods/{namespace}/{pod}/logs", s.handlePodLogs)

	addr := fmt.Sprintf("0.0.0.0:%d", s.config.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.authMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // No timeout for SSE streaming
		IdleTimeout:  120 * time.Second,
	}
	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	s.logger.Info("Agent API server starting", zap.String("addr", addr))

	// Start server in goroutine, wait for context cancellation
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	s.mu.Lock()
	srv := s.server
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.logger.Info("Agent API server shutting down")
	return srv.Shutdown(ctx)
}

// Port returns the configured port.
func (s *Server) Port() int {
	return s.config.Port
}

// SetAgent injects the agent provider for supervisor endpoints.
func (s *Server) SetAgent(ap AgentProvider) {
	s.agent = ap
}
