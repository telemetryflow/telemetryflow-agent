package exporter

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// PrometheusServer serves a Prometheus /metrics HTTP endpoint.
type PrometheusServer struct {
	config config.PrometheusServerConfig
	logger *zap.Logger
	server *http.Server
	bridge *MetricsBridge
	self   *SelfMetrics

	mu      sync.RWMutex
	running bool
}

// NewPrometheusServer creates a new Prometheus metrics HTTP server.
func NewPrometheusServer(cfg config.PrometheusServerConfig, logger *zap.Logger) *PrometheusServer {
	registry := prometheus.NewRegistry()

	// Optionally register Go runtime collectors
	if cfg.IncludeGoMetrics {
		registry.MustRegister(collectors.NewGoCollector())
	}
	if cfg.IncludeProcessMetrics {
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	bridge := NewMetricsBridge(cfg.MetricPrefix, registry, logger)
	self := NewSelfMetrics(cfg.MetricPrefix, registry)

	return &PrometheusServer{
		config: cfg,
		logger: logger,
		bridge: bridge,
		self:   self,
	}
}

// Start starts the HTTP server. It blocks until the context is cancelled or
// the server encounters a fatal error.
func (s *PrometheusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("prometheus server is already running")
	}

	mux := http.NewServeMux()

	// Main metrics handler
	mux.Handle(s.config.Path, promhttp.HandlerFor(
		s.bridge.registry,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))

	// Readiness endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Root redirect to metrics
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, s.config.Path, http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%d", s.config.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	s.running = true
	s.mu.Unlock()

	s.logger.Info("Prometheus server starting",
		zap.String("addr", addr),
		zap.String("path", s.config.Path),
	)

	// Run server in a goroutine so we can listen for context cancellation
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return err
	}
}

// Stop gracefully shuts down the HTTP server.
func (s *PrometheusServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}

	s.logger.Info("Prometheus server stopping")
	s.running = false

	ctx, cancel := context.WithTimeout(context.Background(), s.config.WriteTimeout)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// IsRunning returns whether the server is currently running.
func (s *PrometheusServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// UpdateMetrics feeds a batch of collected metrics to the Prometheus bridge.
func (s *PrometheusServer) UpdateMetrics(metrics []collector.Metric) {
	s.bridge.UpdateMetrics(metrics)
}

// SelfMetrics returns the agent self-observability metrics for external updates.
func (s *PrometheusServer) SelfMetrics() *SelfMetrics {
	return s.self
}

// Bridge returns the underlying MetricsBridge.
func (s *PrometheusServer) Bridge() *MetricsBridge {
	return s.bridge
}
