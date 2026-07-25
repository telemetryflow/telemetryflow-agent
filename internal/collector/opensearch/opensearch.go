// Package opensearch implements a TelemetryFlow Agent collector that scrapes
// OpenSearch /_cluster/health and /_nodes/stats endpoints and emits metrics
// under the db.opensearch.* namespace. It uses the Go standard library only.
// OpenSearch is the AWS-backed fork of Elasticsearch and exposes the same
// REST API, so this collector mirrors the elasticsearch collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package opensearch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "opensearch"

// defaultTimeout is applied when an instance does not set one.
const defaultTimeout = 10 * time.Second

// OpenSearchCollector monitors one or more OpenSearch clusters via the
// REST API. It implements the collector.Collector interface.
type OpenSearchCollector struct {
	cfg      config.OpenSearchCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewOpenSearchCollector constructs a new OpenSearch collector.
func NewOpenSearchCollector(cfg config.OpenSearchCollectorConfig, logger *zap.Logger) *OpenSearchCollector {
	return &OpenSearchCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *OpenSearchCollector) Name() string { return collectorName }

func (c *OpenSearchCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *OpenSearchCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("opensearch collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("OpenSearch collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *OpenSearchCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances,
// honoring context cancellation between instances.
func (c *OpenSearchCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		all = append(all, c.collectInstance(ctx, inst)...)
	}
	return all, nil
}

// collectInstance scrapes a single OpenSearch endpoint and returns metrics.
// Cluster-health failures (auth, transport, non-200, malformed JSON) yield a
// state=0 metric set. Nodes-stats failures are logged and skipped so the
// cluster-level metrics survive.
func (c *OpenSearchCollector) collectInstance(ctx context.Context, inst config.OpenSearchInstance) []collector.Metric {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	baseLabels := instanceLabels(inst)
	now := time.Now()
	// mk assembles a metric with the shared base labels plus any per-metric
	// extras (used for node-level os_node labels). baseLabels is copied at
	// call time, so later mutations (e.g. promoting cluster_name) propagate
	// only to subsequent calls.
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        typ,
			Value:       v,
			Timestamp:   now,
			Unit:        unit,
			Description: desc,
			Labels:      make(map[string]string, len(baseLabels)+len(extra)),
		}
		for k, val := range baseLabels {
			m.Labels[k] = val
		}
		for k, val := range extra {
			m.Labels[k] = val
		}
		return m
	}

	client := newHTTPClient(inst, timeout)

	// /_cluster/health — required. Failure here aborts the instance.
	body, ok := c.fetchJSON(ctx, client, inst, "/_cluster/health")
	if !ok {
		return failureMetrics(mk)
	}
	var health ClusterHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		c.logger.Debug("OpenSearch /_cluster/health malformed JSON",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(mk)
	}
	// Promote the cluster-reported cluster_name over the configured name.
	if health.ClusterName != "" {
		baseLabels["os_cluster"] = health.ClusterName
	}

	out := BuildOpenSearchClusterMetrics(health, mk)

	if inst.ClusterHealthOnly {
		return out
	}

	// /_nodes/stats — optional. Failure here does not affect cluster metrics.
	nodesBody, ok := c.fetchJSON(ctx, client, inst, "/_nodes/stats")
	if !ok {
		return out
	}
	var nodes NodesStatsResponse
	if err := json.Unmarshal(nodesBody, &nodes); err != nil {
		c.logger.Debug("OpenSearch /_nodes/stats malformed JSON",
			zap.String("instance", inst.Name), zap.Error(err))
		return out
	}
	out = append(out, BuildOpenSearchNodeMetrics(nodes, mk)...)
	return out
}

// fetchJSON performs an HTTP GET and returns the body bytes. The boolean is
// false when the request fails or the response status is not 200.
func (c *OpenSearchCollector) fetchJSON(ctx context.Context, client *http.Client, inst config.OpenSearchInstance, path string) ([]byte, bool) {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	url := strings.TrimRight(inst.URL, "/") + path
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		c.logger.Debug("OpenSearch request build failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("OpenSearch scrape request failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("OpenSearch scrape non-200",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Int("status", resp.StatusCode))
		return nil, false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug("OpenSearch scrape read failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	return body, true
}

// newHTTPClient builds an *http.Client honoring TLSEnabled / TLSSkipVerify.
func newHTTPClient(inst config.OpenSearchInstance, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: inst.TLSSkipVerify,
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// instanceLabels builds the standard label set for an instance. The os_cluster
// label is the configured instance name by default and is later replaced with
// the cluster_name reported by /_cluster/health when present.
func instanceLabels(inst config.OpenSearchInstance) map[string]string {
	name := inst.Name
	if name == "" {
		name = inst.URL
	}
	return map[string]string{
		"os_cluster": name,
		"db_system":  "opensearch",
	}
}

// metricBuilder is the closure signature used to assemble metrics with shared
// labels and timestamp.
type metricBuilder func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric

// failureMetrics is the state=0 metric set emitted when the cluster-health
// scrape did not produce a usable body.
func failureMetrics(mk metricBuilder) []collector.Metric {
	return []collector.Metric{
		mk("db.opensearch.state", 0, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil),
	}
}

// statusToGauge maps an OpenSearch health status string to a numeric gauge.
// red=0, yellow=1, green=2; unknown statuses default to 0.
func statusToGauge(s string) float64 {
	switch strings.ToLower(s) {
	case "green":
		return 2
	case "yellow":
		return 1
	default:
		return 0
	}
}

// BuildOpenSearchClusterMetrics emits the state=1 marker plus all cluster
// health metrics. Exported for external test coverage.
func BuildOpenSearchClusterMetrics(health ClusterHealthResponse, mk metricBuilder) []collector.Metric {
	return []collector.Metric{
		mk("db.opensearch.state", 1, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil),
		mk("db.opensearch.cluster_status", statusToGauge(health.Status), collector.MetricTypeGauge, "", "Cluster health: 0=red, 1=yellow, 2=green", nil),
		mk("db.opensearch.nodes_total", float64(health.NumberOfNodes), collector.MetricTypeGauge, "", "Total nodes in cluster", nil),
		mk("db.opensearch.nodes_data", float64(health.NumberOfDataNodes), collector.MetricTypeGauge, "", "Data nodes in cluster", nil),
		mk("db.opensearch.shards_active_primary", float64(health.ActivePrimaryShards), collector.MetricTypeGauge, "", "Active primary shards", nil),
		mk("db.opensearch.shards_active", float64(health.ActiveShards), collector.MetricTypeGauge, "", "Active shards", nil),
		mk("db.opensearch.shards_relocating", float64(health.RelocatingShards), collector.MetricTypeGauge, "", "Relocating shards", nil),
		mk("db.opensearch.shards_initializing", float64(health.InitializingShards), collector.MetricTypeGauge, "", "Initializing shards", nil),
		mk("db.opensearch.shards_unassigned", float64(health.UnassignedShards), collector.MetricTypeGauge, "", "Unassigned shards", nil),
		mk("db.opensearch.pending_tasks", float64(health.NumberOfPendingTasks), collector.MetricTypeGauge, "", "Pending cluster tasks", nil),
	}
}

// BuildOpenSearchNodeMetrics emits per-node metrics from /_nodes/stats.
// Exported for external test coverage.
func BuildOpenSearchNodeMetrics(resp NodesStatsResponse, mk metricBuilder) []collector.Metric {
	out := make([]collector.Metric, 0, len(resp.Nodes)*5)
	for id, node := range resp.Nodes {
		name := node.Name
		if name == "" {
			name = id
		}
		labels := map[string]string{"os_node": name}
		out = append(out,
			mk("db.opensearch.node.heap_used_percent", float64(node.JVM.Mem.HeapUsedPercent), collector.MetricTypeGauge, "%", "JVM heap used percent", labels),
			mk("db.opensearch.node.docs_count", float64(node.Indices.Docs.Count), collector.MetricTypeGauge, "", "Indexed document count", labels),
			mk("db.opensearch.node.store_size_bytes", float64(node.Indices.Store.SizeInBytes), collector.MetricTypeGauge, "bytes", "Store size in bytes", labels),
			mk("db.opensearch.node.search_query_total", float64(node.Indices.Search.QueryTotal), collector.MetricTypeCounter, "", "Total search queries", labels),
			mk("db.opensearch.node.indexing_total", float64(node.Indices.Indexing.IndexTotal), collector.MetricTypeCounter, "", "Total indexing operations", labels),
		)
	}
	return out
}

// =====================================================================
// API response types (only fields we expose as metrics).
// OpenSearch returns the same document shape as Elasticsearch.
// =====================================================================

// ClusterHealthResponse models the /_cluster/health document.
type ClusterHealthResponse struct {
	ClusterName          string `json:"cluster_name"`
	Status               string `json:"status"`
	TimedOut             bool   `json:"timed_out"`
	NumberOfNodes        int    `json:"number_of_nodes"`
	NumberOfDataNodes    int    `json:"number_of_data_nodes"`
	ActivePrimaryShards  int    `json:"active_primary_shards"`
	ActiveShards         int    `json:"active_shards"`
	RelocatingShards     int    `json:"relocating_shards"`
	InitializingShards   int    `json:"initializing_shards"`
	UnassignedShards     int    `json:"unassigned_shards"`
	NumberOfPendingTasks int    `json:"number_of_pending_tasks"`
}

// NodesStatsResponse models the /_nodes/stats document.
type NodesStatsResponse struct {
	ClusterName string              `json:"cluster_name"`
	Nodes       map[string]NodeStat `json:"nodes"`
}

// NodeStat is a single node entry within /_nodes/stats.
type NodeStat struct {
	Name    string     `json:"name"`
	JVM     JVMStats   `json:"jvm"`
	Indices IndexStats `json:"indices"`
}

// JVMStats carries the JVM memory section.
type JVMStats struct {
	Mem JVMMem `json:"mem"`
}

// JVMMem carries heap usage.
type JVMMem struct {
	HeapUsedPercent int `json:"heap_used_percent"`
}

// IndexStats carries per-node index totals.
type IndexStats struct {
	Docs     DocsStats     `json:"docs"`
	Store    StoreStats    `json:"store"`
	Search   SearchStats   `json:"search"`
	Indexing IndexingStats `json:"indexing"`
}

// DocsStats is the documents section.
type DocsStats struct {
	Count int `json:"count"`
}

// StoreStats is the storage section.
type StoreStats struct {
	SizeInBytes int64 `json:"size_in_bytes"`
}

// SearchStats is the search section.
type SearchStats struct {
	QueryTotal int64 `json:"query_total"`
}

// IndexingStats is the indexing section.
type IndexingStats struct {
	IndexTotal int64 `json:"index_total"`
}
