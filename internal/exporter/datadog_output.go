// Package exporter: datadog_output.go implements a Datadog output that ships
// plugin.Metric values to the Datadog Metrics v2 API over plain HTTP. No
// vendor SDK dependency is required. The site is configurable so EU/US3/Gov
// customers can target the right intake.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// datadogDefaultSite is the default Datadog site (US1).
const datadogDefaultSite = "datadoghq.com"

// datadogV2SeriesPath is the Datadog Metrics v2 intake path appended to
// "https://api.<site>".
const datadogV2SeriesPath = "/api/v2/series"

// datadogAPIKeyHeader is the header used by the v2 intake to carry the API
// key. Datadog's public docs use the hyphenated form "DD-API-KEY".
const datadogAPIKeyHeader = "DD-API-KEY"

// datadogMaxSeriesPerRequest is the documented v2 intake ceiling.
const datadogMaxSeriesPerRequest = 1000

// DatadogOutputConfig configures a DatadogOutput.
type DatadogOutputConfig struct {
	// APIKey is the Datadog API key (required). Sent as the DD-API-KEY
	// header on every request.
	APIKey string

	// Site selects the Datadog site. Default "datadoghq.com". Alternatives:
	// "datadoghq.eu", "us3.datadoghq.com", "us5.datadoghq.com",
	// "ddog-gov.com".
	Site string

	// Timeout is the per-request HTTP timeout. Default 30s.
	Timeout time.Duration

	// BatchSize is the max number of series per POST. Default 1000 (the
	// documented v2 ceiling).
	BatchSize int

	// FlushInterval is reserved for the async flusher path; the synchronous
	// Write path flushes immediately. Default 5s.
	FlushInterval time.Duration

	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger
}

// DatadogOutput is a plugin.Output that ships metrics to the Datadog
// Metrics v2 intake.
type DatadogOutput struct {
	cfg    DatadogOutputConfig
	log    *zap.Logger
	client *http.Client

	// endpoint is captured separately so tests can override it after
	// construction (e.g. point at an httptest server) without mutating the
	// user-facing cfg.
	endpoint string
}

// datadogSeriesPayload is the v2 intake request body.
//
// Reference: https://docs.datadoghq.com/api/latest/metrics/#submit-metrics
type datadogSeriesPayload struct {
	Series []datadogSeries `json:"series"`
}

// datadogSeries is a single series entry in the v2 payload. Type is the
// metric type: 0 = unspecified (server infers), 1 = count, 2 = rate, 3 =
// gauge. TelemetryFlow metrics are emitted as gauges (3) by default;
// counters use count (1).
type datadogSeries struct {
	Metric string         `json:"metric"`
	Points []datadogPoint `json:"points"`
	Tags   []string       `json:"tags,omitempty"`
	Type   int32          `json:"type"`
	Unit   *string        `json:"unit,omitempty"`
	Source *datadogSource `json:"source,omitempty"`
}

// datadogPoint is a single (timestamp, value) sample. The v2 schema wraps
// the value in an object; the timestamp is in seconds (epoch).
type datadogPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// datadogSource is the optional source-type metadata block (unused today
// but kept so future provenance work can populate it without a schema
// break in this file).
type datadogSource struct {
	Name string `json:"name"`
}

// NewDatadogOutput validates the configuration and returns a ready output.
// Connect must still be called before Write.
func NewDatadogOutput(cfg DatadogOutputConfig) (*DatadogOutput, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("datadog: api_key is required")
	}
	if cfg.Site == "" {
		cfg.Site = datadogDefaultSite
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = datadogMaxSeriesPerRequest
	}
	if cfg.BatchSize > datadogMaxSeriesPerRequest {
		cfg.BatchSize = datadogMaxSeriesPerRequest
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("datadog_output")

	client := &http.Client{Timeout: cfg.Timeout}

	return &DatadogOutput{
		cfg:      cfg,
		log:      logger,
		client:   client,
		endpoint: "https://api." + cfg.Site + datadogV2SeriesPath,
	}, nil
}

// Name implements plugin.Output.
func (o *DatadogOutput) Name() string { return "datadog" }

// SetEndpointForTest overrides the intake URL so tests can point at an
// httptest server. Production code goes through the constructor + Connect.
func (o *DatadogOutput) SetEndpointForTest(endpoint string) {
	o.endpoint = endpoint
}

// EndpointForTest returns the intake URL the output will POST to. Intended
// for assertions in tests.
func (o *DatadogOutput) EndpointForTest() string { return o.endpoint }

// Connect verifies the output is wired up. The Datadog intake does not
// expose a cheap authentication probe endpoint, so Connect only ensures
// the client and endpoint are populated; the first real Write is what
// surfaces auth failures.
func (o *DatadogOutput) Connect() error {
	if o.client == nil {
		return errors.New("datadog: http client not initialised")
	}
	if o.endpoint == "" {
		return errors.New("datadog: endpoint not initialised")
	}
	o.log.Info("datadog output connected",
		zap.String("site", o.cfg.Site),
		zap.String("endpoint", o.endpoint),
	)
	return nil
}

// Close releases the HTTP client's idle connections.
func (o *DatadogOutput) Close() error {
	if o.client != nil {
		o.client.CloseIdleConnections()
	}
	return nil
}

// Write implements plugin.Output. It converts each plugin.Metric to one or
// more Datadog series, batches to BatchSize, and POSTs each batch to the v2
// intake.
func (o *DatadogOutput) Write(metrics []plugin.Metric) error {
	if o.client == nil {
		return errors.New("datadog: not connected")
	}
	if len(metrics) == 0 {
		return nil
	}

	series := make([]datadogSeries, 0, len(metrics))
	for _, m := range metrics {
		series = append(series, metricToDatadogSeries(m))
	}

	batchSize := o.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = datadogMaxSeriesPerRequest
	}

	ctx := context.Background()
	for start := 0; start < len(series); start += batchSize {
		end := start + batchSize
		if end > len(series) {
			end = len(series)
		}
		if err := o.post(ctx, series[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// post encodes a batch and sends a single POST to the v2 intake.
func (o *DatadogOutput) post(ctx context.Context, batch []datadogSeries) error {
	body, err := json.Marshal(datadogSeriesPayload{Series: batch})
	if err != nil {
		return fmt.Errorf("datadog: marshal series: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("datadog: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(datadogAPIKeyHeader, o.cfg.APIKey)
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: post series: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("datadog: intake returned %s: %s",
			resp.Status, strings.TrimSpace(string(snippet)))
	}

	o.log.Debug("datadog push ok",
		zap.Int("series", len(batch)),
		zap.Int("status", resp.StatusCode),
	)
	return nil
}

// metricToDatadogSeries converts a plugin.Metric to a single Datadog series.
// Counters are typed as count(1); everything else is typed as gauge(3) per
// the v2 schema. Tags are emitted as "<key>:<value>" to match Datadog's
// expected tag format.
func metricToDatadogSeries(m plugin.Metric) datadogSeries {
	var seriesType int32 = 3 // gauge
	if m.Type == plugin.MetricTypeCounter {
		seriesType = 1 // count
	}
	return datadogSeries{
		Metric: m.Name,
		Points: []datadogPoint{{
			Timestamp: m.Timestamp.Unix(),
			Value:     m.Value,
		}},
		Tags: labelsToDatadogTags(m.Labels),
		Type: seriesType,
	}
}

// labelsToDatadogTags converts a metric's labels to Datadog tag strings
// ("key:value"). Tags are sorted for deterministic test output.
func labelsToDatadogTags(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	// Deterministic order so tests can compare tag slices verbatim.
	sort.Strings(names)

	tags := make([]string, 0, len(labels))
	for _, name := range names {
		val := labels[name]
		if name == "" || val == "" {
			continue
		}
		tags = append(tags, name+":"+val)
	}
	return tags
}

// init self-registers the output with the plugin registry so it is
// reachable by name. The instance returned is unconfigured; the pipeline
// builder is expected to call NewDatadogOutput with the resolved
// configuration before Connect/Write.
func init() {
	plugin.MustAddOutput("datadog", func() plugin.Output {
		out, err := NewDatadogOutput(DatadogOutputConfig{})
		if err != nil {
			return &DatadogOutput{}
		}
		return out
	})
}
