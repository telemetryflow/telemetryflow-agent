// Package pubsub implements a TelemetryFlow Agent collector for Google Cloud
// Pub/Sub via the Cloud Monitoring API. It authenticates with a GCP service
// account key (RS256 JWT -> OAuth2 token) and queries subscription-level
// metrics, emitting them under the messaging.pubsub.* namespace. No external
// Google client library is required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package pubsub

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "pubsub"

// pubsubMetric maps a Cloud Monitoring metric type to its emitted suffix.
type pubsubMetric struct {
	metricType string
	suffix     string
	typ        collector.MetricType
	unit       string
	desc       string
}

// standardMetrics is the default Pub/Sub subscription metric set.
var standardMetrics = []pubsubMetric{
	{metricType: "pubsub.googleapis.com/subscription/num_undelivered_messages", suffix: "undelivered_messages", typ: collector.MetricTypeGauge, unit: "", desc: "Undelivered messages"},
	{metricType: "pubsub.googleapis.com/subscription/num_outstanding_messages", suffix: "outstanding_messages", typ: collector.MetricTypeGauge, unit: "", desc: "Outstanding messages"},
	{metricType: "pubsub.googleapis.com/subscription/oldest_unacked_message_age", suffix: "oldest_unacked_message_age", typ: collector.MetricTypeGauge, unit: "s", desc: "Age of oldest unacked message"},
	{metricType: "pubsub.googleapis.com/subscription/sent_message_count", suffix: "sent_messages", typ: collector.MetricTypeCounter, unit: "", desc: "Messages sent to subscribers"},
	{metricType: "pubsub.googleapis.com/subscription/ack_request_count", suffix: "ack_requests", typ: collector.MetricTypeCounter, unit: "", desc: "Ack requests"},
}

// PubSubCollector monitors Google Cloud Pub/Sub subscriptions via Cloud Monitoring.
type PubSubCollector struct {
	cfg    config.PubSubCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewPubSubCollector creates a new PubSubCollector.
func NewPubSubCollector(cfg config.PubSubCollectorConfig, logger *zap.Logger) *PubSubCollector {
	if cfg.StatsInterval == 0 {
		cfg.StatsInterval = 60 * time.Second
	}
	return &PubSubCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *PubSubCollector) Name() string { return collectorName }

func (c *PubSubCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *PubSubCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("pubsub collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("Pub/Sub collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("stats_interval", c.cfg.StatsInterval),
	)
	return nil
}

func (c *PubSubCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances.
func (c *PubSubCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("Pub/Sub collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *PubSubCollector) collectInstance(ctx context.Context, inst config.PubSubInstanceConfig) ([]collector.Metric, error) {
	if inst.ProjectID == "" {
		return nil, fmt.Errorf("pubsub instance %q: project_id is required", inst.Name)
	}
	creds, err := loadCredentials(inst)
	if err != nil {
		return nil, err
	}
	token, err := getAccessToken(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	end := time.Now().UTC()
	start := end.Add(-6 * time.Minute) // Cloud Monitoring aligns on minutes; allow slack.

	series, err := queryMonitoring(ctx, inst.ProjectID, token, standardMetrics, start, end)
	if err != nil {
		return nil, fmt.Errorf("query monitoring: %w", err)
	}

	labels := c.instanceLabels(inst)
	return BuildPubSubMetrics(labels, standardMetrics, series, inst.SubscriptionFilter)
}

func (c *PubSubCollector) instanceLabels(inst config.PubSubInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["pubsub_instance"] = inst.Name
	labels["messaging_system"] = "pubsub"
	labels["gcp_project"] = inst.ProjectID
	return labels
}

// =====================================================================
// Service-account credentials + OAuth2 JWT grant.
// =====================================================================

// serviceAccount holds the fields required to mint an OAuth2 access token.
type serviceAccount struct {
	clientEmail string
	privateKey  *rsa.PrivateKey
}

// loadCredentials builds a serviceAccount from a key file or raw key path.
func loadCredentials(inst config.PubSubInstanceConfig) (*serviceAccount, error) {
	if inst.CredentialsFile != "" {
		return loadCredentialsFromFile(inst.CredentialsFile)
	}
	if inst.ServiceAccountEmail != "" && inst.PrivateKeyFile != "" {
		key, err := loadPrivateKeyFile(inst.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("private_key_file: %w", err)
		}
		return &serviceAccount{clientEmail: inst.ServiceAccountEmail, privateKey: key}, nil
	}
	return nil, fmt.Errorf("pubsub instance %q: credentials_file or (service_account_email + private_key_file) required", inst.Name)
}

// serviceAccountKeyJSON models the relevant fields of a GCP key file.
type serviceAccountKeyJSON struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

func loadCredentialsFromFile(path string) (*serviceAccount, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var k serviceAccountKeyJSON
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("parse credentials JSON: %w", err)
	}
	if k.ClientEmail == "" || k.PrivateKey == "" {
		return nil, fmt.Errorf("credentials missing client_email/private_key")
	}
	key, err := parseRSAPrivateKey([]byte(k.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &serviceAccount{clientEmail: k.ClientEmail, privateKey: key}, nil
}

func loadPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(raw)
}

// parseRSAPrivateKey parses a PEM-encoded PKCS#1 or PKCS#8 RSA private key.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

// getAccessToken mints an OAuth2 access token via a JWT bearer grant (RS256).
func getAccessToken(ctx context.Context, sa *serviceAccount) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":   sa.clientEmail,
		"scope": "https://www.googleapis.com/auth/monitoring.readonly",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	assertion, err := signJWT(claims, sa.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token request: HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return tok.AccessToken, nil
}

// signJWT builds and signs a compact JWT using RS256.
func signJWT(claims map[string]any, key *rsa.PrivateKey) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(enc))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return enc + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// =====================================================================
// Cloud Monitoring API query.
// =====================================================================

type monitoringTimeSeries struct {
	Metric struct {
		Type string `json:"type"`
	} `json:"metric"`
	Resource struct {
		Labels struct {
			SubscriptionID string `json:"subscription_id"`
			ProjectID      string `json:"project_id"`
		} `json:"labels"`
	} `json:"resource"`
	Points []monitoringPoint `json:"points"`
}

type monitoringPoint struct {
	Interval struct {
		EndTime   time.Time `json:"endTime"`
		StartTime time.Time `json:"startTime"`
	} `json:"interval"`
	Value struct {
		Int64Value  *int64   `json:"int64Value,omitempty"`
		DoubleValue *float64 `json:"doubleValue,omitempty"`
	} `json:"value"`
}

type monitoringResponse struct {
	TimeSeries []monitoringTimeSeries `json:"timeSeries"`
}

// queryMonitoring fetches time series for every metric in standardMetrics
// within [start, end]. Each metric is queried separately because Cloud
// Monitoring filters by a single metric.type.
func queryMonitoring(ctx context.Context, projectID, token string, metrics []pubsubMetric, start, end time.Time) ([]monitoringTimeSeries, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	base := fmt.Sprintf("https://monitoring.googleapis.com/v3/projects/%s/timeSeries", projectID)

	var all []monitoringTimeSeries
	for _, m := range metrics {
		filter := fmt.Sprintf(`metric.type="%s"`, m.metricType)
		params := url.Values{}
		params.Set("filter", filter)
		params.Set("interval.startTime", start.Format(time.RFC3339Nano))
		params.Set("interval.endTime", end.Format(time.RFC3339Nano))
		// Coarse aggregation: most recent aligned point per series.
		params.Set("view", "FULL")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+params.Encode(), nil)
		if err != nil {
			return nil, fmt.Errorf("build request for %s: %w", m.metricType, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request %s: %w", m.metricType, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%s: HTTP %d: %s", m.metricType, resp.StatusCode, truncate(string(body), 256))
		}
		var mr monitoringResponse
		if err := json.Unmarshal(body, &mr); err != nil {
			return nil, fmt.Errorf("decode %s: %w", m.metricType, err)
		}
		all = append(all, mr.TimeSeries...)
	}
	return all, nil
}

// =====================================================================
// Metric building.
// =====================================================================

// BuildPubSubMetrics maps Cloud Monitoring time series to collector.Metric
// under the messaging.pubsub.* namespace. The most recent point per series is
// emitted. Exported for external test coverage.
func BuildPubSubMetrics(labels map[string]string, metrics []pubsubMetric, series []monitoringTimeSeries, subscriptionFilter string) ([]collector.Metric, error) {
	suffixByType := make(map[string]pubsubMetric, len(metrics))
	for _, m := range metrics {
		suffixByType[m.metricType] = m
	}
	filterRe, err := compileFilter(subscriptionFilter)
	if err != nil {
		return nil, fmt.Errorf("subscription_filter: %w", err)
	}

	now := time.Now()
	out := make([]collector.Metric, 0, len(series))
	for _, ts := range series {
		def, ok := suffixByType[ts.Metric.Type]
		if !ok {
			continue
		}
		sub := ts.Resource.Labels.SubscriptionID
		if filterRe != nil && !filterRe.MatchString(sub) {
			continue
		}
		p, ok := latestPoint(ts.Points)
		if !ok {
			continue
		}
		value := 0.0
		if p.Value.DoubleValue != nil {
			value = *p.Value.DoubleValue
		} else if p.Value.Int64Value != nil {
			value = float64(*p.Value.Int64Value)
		}
		lbl := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			lbl[k] = v
		}
		if sub != "" {
			lbl["pubsub_subscription"] = sub
		}
		out = append(out, collector.Metric{
			Name: "messaging.pubsub." + def.suffix,
			Type: def.typ, Value: value, Timestamp: now,
			Unit: def.unit, Description: def.desc, Labels: lbl,
		})
	}
	return out, nil
}

// latestPoint returns the most recent point (Cloud Monitoring returns points
// in reverse-chronological order).
func latestPoint(points []monitoringPoint) (monitoringPoint, bool) {
	if len(points) == 0 {
		return monitoringPoint{}, false
	}
	latest := points[0]
	for _, p := range points[1:] {
		if p.Interval.EndTime.After(latest.Interval.EndTime) {
			latest = p
		}
	}
	return latest, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
