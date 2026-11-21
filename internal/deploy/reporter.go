// Package deploy reports a software deployment to the TelemetryFlow platform
// (Operations → Deployments). It POSTs a canonical deployment record to
// /api/v2/deployments, authenticated by the agent's ingestion key — the same
// key the agent already uses for telemetry. Tenant/project are resolved
// server-side from that key and are never sent in the body.
//
// TelemetryFlow Agent - Copyright (c) 2024-2026 Telemetri Data Indonesia.
// Licensed under the Apache License, Version 2.0.
package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	deploymentsPath  = "/api/v2/deployments"
	defaultTimeout   = 30 * time.Second
	maxResponseBytes = 1 << 20 // 1 MiB cap on the response we read
	keyIDHeaderName  = "X-TelemetryFlow-Key-ID"
	keySecretHdrName = "X-TelemetryFlow-Key-Secret"
)

// ValidStatuses is the deployment status lifecycle accepted by the platform.
var ValidStatuses = map[string]bool{
	"queued": true, "running": true, "success": true, "failed": true, "rolled_back": true,
}

// ValidProviders is the set of deployment source providers.
var ValidProviders = map[string]bool{
	"github": true, "gitlab": true, "bitbucket": true, "jenkins": true,
	"aws": true, "azure": true, "argocd": true, "cli": true,
}

// Request is the canonical deployment payload. Tenant/workspace/project are
// resolved server-side from the ingestion key and MUST NOT appear here.
type Request struct {
	Service     string         `json:"service"`
	Version     string         `json:"version"`
	Provider    string         `json:"provider,omitempty"`
	ExternalID  string         `json:"externalId,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Status      string         `json:"status,omitempty"`
	CommitSHA   string         `json:"commitSha,omitempty"`
	CommitRef   string         `json:"commitRef,omitempty"`
	Actor       string         `json:"actor,omitempty"`
	URL         string         `json:"url,omitempty"`
	StartedAt   string         `json:"startedAt,omitempty"`
	FinishedAt  string         `json:"finishedAt,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Response is the platform deploy-ingest envelope (`{ data: { … } }`).
type Response struct {
	Data struct {
		DeploymentID  string `json:"deployment_id"`
		Created       bool   `json:"created"`
		Status        string `json:"status"`
		StatusChanged bool   `json:"status_changed"`
	} `json:"data"`
}

// Validate checks required fields and enumerations before sending.
func Validate(req Request) error {
	if strings.TrimSpace(req.Service) == "" {
		return fmt.Errorf("deploy: --service is required")
	}
	if strings.TrimSpace(req.Version) == "" {
		return fmt.Errorf("deploy: --version is required")
	}
	if req.Status != "" && !ValidStatuses[req.Status] {
		return fmt.Errorf("deploy: invalid --status %q (queued|running|success|failed|rolled_back)", req.Status)
	}
	if req.Provider != "" && !ValidProviders[req.Provider] {
		return fmt.Errorf("deploy: invalid --provider %q", req.Provider)
	}
	return nil
}

// Reporter posts deployment records to the platform backend.
type Reporter struct {
	baseURL    string
	keyID      string
	keySecret  string
	httpClient *http.Client
}

// Option configures a Reporter.
type Option func(*Reporter)

// WithHTTPClient overrides the default HTTP client (used in tests).
func WithHTTPClient(c *http.Client) Option {
	return func(r *Reporter) {
		if c != nil {
			r.httpClient = c
		}
	}
}

// WithInsecureTLS opts into skipping TLS verification (self-signed platform
// certs). Off by default; enabled only via an explicit flag.
func WithInsecureTLS(insecure bool) Option {
	return func(r *Reporter) {
		if insecure {
			r.httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via --insecure
			}
		}
	}
}

// NewReporter builds a Reporter. baseURL is the platform backend base
// (e.g. https://tfo.example); keyID/keySecret are the ingestion key.
func NewReporter(baseURL, keyID, keySecret string, timeout time.Duration, opts ...Option) *Reporter {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	r := &Reporter{
		baseURL:    strings.TrimRight(baseURL, "/"),
		keyID:      keyID,
		keySecret:  keySecret,
		httpClient: &http.Client{Timeout: timeout},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Report validates and sends one deployment record to the platform.
func (r *Reporter) Report(ctx context.Context, req Request) (*Response, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	if r.baseURL == "" {
		return nil, fmt.Errorf("deploy: platform endpoint is empty (set telemetryflow.backend_endpoint or --endpoint)")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("deploy: marshal payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+deploymentsPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("deploy: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.keyID != "" {
		httpReq.Header.Set(keyIDHeaderName, r.keyID)
	}
	if r.keySecret != "" {
		httpReq.Header.Set(keySecretHdrName, r.keySecret)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("deploy: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("deploy: platform returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out Response
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &out)
	}
	return &out, nil
}
