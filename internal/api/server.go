// Package api provides a lightweight HTTP API server for the TFO Agent,
// enabling real-time Kubernetes queries (pod log streaming) from the
// TelemetryFlow Platform backend.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
package api

import (
	"context"
	"fmt"
	"net/http"
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
	server    *http.Server
}

// NewServer creates a new agent API server.
func NewServer(cfg Config, clientset kubernetes.Interface, logger *zap.Logger) *Server {
	return &Server{
		config:    cfg,
		clientset: clientset,
		logger:    logger.Named("agent-api"),
	}
}

// Start begins listening for HTTP requests. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Pod log streaming (SSE)
	mux.HandleFunc("GET /api/v1/pods/{namespace}/{pod}/logs", s.handlePodLogs)

	addr := fmt.Sprintf("0.0.0.0:%d", s.config.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.authMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // No timeout for SSE streaming
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Agent API server starting", zap.String("addr", addr))

	// Start server in goroutine, wait for context cancellation
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.logger.Info("Agent API server shutting down")
	return s.server.Shutdown(ctx)
}

// Port returns the configured port.
func (s *Server) Port() int {
	return s.config.Port
}
