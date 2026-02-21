//go:build linux

package ebpf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// hubbleClient manages the gRPC connection to Cilium Hubble Relay.
// It subscribes to network flow events and converts them to collector metrics.
type hubbleClient struct {
	cfg    config.CiliumCollectorConfig
	logger *zap.Logger

	mu   sync.RWMutex
	conn *grpc.ClientConn

	// Counters accumulated between scrapes
	flows          uint64
	drops          uint64
	policyVerdicts uint64
	httpRequests   uint64
	dnsQueries     uint64
	l7Errors       uint64
}

// newHubbleClient creates a new Hubble gRPC client.
func newHubbleClient(cfg config.CiliumCollectorConfig, logger *zap.Logger) *hubbleClient {
	return &hubbleClient{
		cfg:    cfg,
		logger: logger.With(zap.String("component", "hubble")),
	}
}

// connect establishes a gRPC connection to Hubble Relay.
func (h *hubbleClient) connect(ctx context.Context) error {
	var opts []grpc.DialOption

	if h.cfg.HubbleTLSEnabled {
		tlsCfg, err := h.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("hubble TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(h.cfg.HubbleAddress, opts...)
	if err != nil {
		return fmt.Errorf("hubble dial %s: %w", h.cfg.HubbleAddress, err)
	}

	h.mu.Lock()
	h.conn = conn
	h.mu.Unlock()

	h.logger.Info("Connected to Hubble Relay",
		zap.String("address", h.cfg.HubbleAddress),
		zap.Bool("tls", h.cfg.HubbleTLSEnabled),
	)

	return nil
}

// close disconnects from Hubble Relay.
func (h *hubbleClient) close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
		h.logger.Debug("Hubble connection closed")
	}
}

// buildTLSConfig constructs TLS credentials from configured cert/key/CA paths.
func (h *hubbleClient) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if h.cfg.HubbleTLSCertPath != "" && h.cfg.HubbleTLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(h.cfg.HubbleTLSCertPath, h.cfg.HubbleTLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if h.cfg.HubbleTLSCAPath != "" {
		caCert, err := os.ReadFile(h.cfg.HubbleTLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// collectMetrics returns current counters as collector.Metric slices and resets.
func (h *hubbleClient) collectMetrics() []collector.Metric {
	h.mu.Lock()
	flows := h.flows
	drops := h.drops
	policyVerdicts := h.policyVerdicts
	httpRequests := h.httpRequests
	dnsQueries := h.dnsQueries
	l7Errors := h.l7Errors
	h.flows = 0
	h.drops = 0
	h.policyVerdicts = 0
	h.httpRequests = 0
	h.dnsQueries = 0
	h.l7Errors = 0
	h.mu.Unlock()

	var metrics []collector.Metric

	if h.cfg.CollectFlows {
		metrics = append(metrics,
			collector.NewMetric("hubble.flows", float64(flows), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
		)
	}
	if h.cfg.CollectDrops {
		metrics = append(metrics,
			collector.NewMetric("hubble.drops", float64(drops), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
		)
	}
	if h.cfg.CollectPolicies {
		metrics = append(metrics,
			collector.NewMetric("hubble.policy_verdicts", float64(policyVerdicts), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
		)
	}
	if h.cfg.CollectL7Flows {
		metrics = append(metrics,
			collector.NewMetric("hubble.http_requests", float64(httpRequests), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
			collector.NewMetric("hubble.dns_queries", float64(dnsQueries), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
			collector.NewMetric("hubble.l7_errors", float64(l7Errors), collector.MetricTypeCounter).
				WithLabel("source", "hubble"),
		)
	}

	return metrics
}

// isConnected returns whether the gRPC connection is established.
func (h *hubbleClient) isConnected() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conn != nil
}

// recordFlow increments the appropriate counters based on flow type.
// Called from the Hubble flow observer goroutine (future implementation).
func (h *hubbleClient) recordFlow(isL7 bool, isDrop bool, isPolicyVerdict bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.flows++
	if isDrop {
		h.drops++
	}
	if isPolicyVerdict {
		h.policyVerdicts++
	}
	if isL7 {
		h.httpRequests++
	}
}

// recordDNS increments the DNS query counter.
// Called from the Hubble flow observer goroutine (future implementation).
func (h *hubbleClient) recordDNS() {
	h.mu.Lock()
	h.dnsQueries++
	h.mu.Unlock()
}
