// Package rum implements a local Real User Monitoring (RUM) ingestion edge for
// the TelemetryFlow Agent. Browsers running the @telemetryflow/rum-web SDK
// beacon OTLP/JSON to the agent's /v1/rum/traces and /v1/rum/metrics routes; the
// agent transparently forwards each beacon (body + public-key header + Origin)
// to the platform RUM edge and returns its response. The platform performs the
// authoritative public-key + origin-allowlist auth; the agent adds a local
// origin allowlist (defense-in-depth) and CORS so browsers can reach a nearby
// agent instead of the platform directly. Available since v1.3.6.
//
// TelemetryFlow Agent - Copyright (c) 2024-2026 Telemetri Data Indonesia.
// Licensed under the Apache License, Version 2.0.
package rum

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	tracesPath       = "/v1/rum/traces"
	metricsPath      = "/v1/rum/metrics"
	defaultTimeout   = 15 * time.Second
	maxBeaconBytes   = 2 << 20 // 2 MiB cap per beacon
	corsAllowMethods = "POST, OPTIONS"
	corsMaxAge       = "600"
)

// hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

// Proxy forwards browser RUM beacons to the platform RUM edge.
type Proxy struct {
	upstream *url.URL
	allowAll bool
	allowed  map[string]bool
	client   *http.Client
	logger   *zap.Logger
}

// NewProxy builds a RUM proxy. upstream is the platform RUM edge base
// (e.g. https://ingest.telemetryflow.id); allowOrigins is the browser origin
// allowlist ("*" allows any origin). A nil logger is replaced with a no-op.
func NewProxy(upstream string, allowOrigins []string, timeout time.Duration, logger *zap.Logger) (*Proxy, error) {
	if strings.TrimSpace(upstream) == "" {
		return nil, fmt.Errorf("rum: upstream endpoint is required")
	}
	u, err := url.Parse(strings.TrimRight(upstream, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("rum: invalid upstream endpoint %q", upstream)
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	allowed := make(map[string]bool, len(allowOrigins))
	allowAll := false
	for _, o := range allowOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			allowAll = true
		} else if o != "" {
			allowed[strings.ToLower(o)] = true
		}
	}
	return &Proxy{
		upstream: u,
		allowAll: allowAll,
		allowed:  allowed,
		client:   &http.Client{Timeout: timeout},
		logger:   logger,
	}, nil
}

// Handler mounts the RUM routes on a fresh ServeMux.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(tracesPath, p.handle)
	mux.HandleFunc(metricsPath, p.handle)
	return mux
}

func (p *Proxy) originAllowed(origin string) bool {
	if p.allowAll {
		return true
	}
	return p.allowed[strings.ToLower(origin)]
}

func (p *Proxy) setCORS(w http.ResponseWriter, r *http.Request, origin string) {
	if p.allowAll {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
	reqHeaders := r.Header.Get("Access-Control-Request-Headers")
	if reqHeaders == "" {
		reqHeaders = "Content-Type"
	}
	w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
	w.Header().Set("Access-Control-Max-Age", corsMaxAge)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// CORS preflight.
	if r.Method == http.MethodOptions {
		if origin != "" && p.originAllowed(origin) {
			p.setCORS(w, r, origin)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", corsAllowMethods)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Local origin allowlist (defense-in-depth; the platform re-checks).
	if origin == "" || !p.originAllowed(origin) {
		p.logger.Warn("rum: origin rejected", zap.String("origin", origin))
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBeaconBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	upstreamURL := p.upstream.String() + r.URL.Path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return
	}
	// Forward all request headers (incl. the RUM public key + Origin +
	// User-Agent) except hop-by-hop; the platform guard authenticates them.
	for k, vals := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Warn("rum: upstream forward failed", zap.Error(err))
		p.setCORS(w, r, origin)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Relay upstream response headers (rate-limit, content-type, …) + CORS.
	for k, vals := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	p.setCORS(w, r, origin)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxBeaconBytes))
}
