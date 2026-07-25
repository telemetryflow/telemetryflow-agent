// Package couchbase implements a TelemetryFlow Agent collector that scrapes
// Couchbase /pools/default and /pools/default/buckets/{bucket} endpoints and
// emits metrics under the db.couchbase.* namespace. It uses the Go standard
// library only.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package couchbase

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

const collectorName = "couchbase"

// defaultTimeout is applied when an instance does not set one.
const defaultTimeout = 10 * time.Second

// CouchbaseCollector monitors one or more Couchbase clusters via the REST API.
// It implements the collector.Collector interface.
type CouchbaseCollector struct {
	cfg      config.CouchbaseCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewCouchbaseCollector constructs a new Couchbase collector.
func NewCouchbaseCollector(cfg config.CouchbaseCollectorConfig, logger *zap.Logger) *CouchbaseCollector {
	return &CouchbaseCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *CouchbaseCollector) Name() string { return collectorName }

func (c *CouchbaseCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *CouchbaseCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("couchbase collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("Couchbase collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *CouchbaseCollector) Stop() error {
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
func (c *CouchbaseCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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

// collectInstance scrapes a single Couchbase endpoint and returns metrics.
// A /pools/default failure (auth, transport, non-200, malformed JSON) yields a
// state=0 metric set. Bucket scrape failures are logged and skipped so the
// cluster-level metrics survive.
func (c *CouchbaseCollector) collectInstance(ctx context.Context, inst config.CouchbaseInstance) []collector.Metric {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	baseLabels := instanceLabels(inst)
	now := time.Now()
	// mk assembles a metric with the shared base labels plus any per-metric
	// extras (used for node/bucket labels). baseLabels is copied at call time,
	// so later mutations (e.g. promoting cluster name) propagate only to
	// subsequent calls.
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

	// /pools/default — required. Failure here aborts the instance.
	body, ok := c.fetchJSON(ctx, client, inst, "/pools/default")
	if !ok {
		return failureMetrics(mk)
	}
	var pools PoolsResponse
	if err := json.Unmarshal(body, &pools); err != nil {
		c.logger.Debug("Couchbase /pools/default malformed JSON",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(mk)
	}
	// Promote the cluster-reported name over the configured instance name.
	if pools.Name != "" {
		baseLabels["cb_cluster"] = pools.Name
	}

	out := BuildCouchbaseClusterMetrics(pools, mk)

	// Bucket phase is skipped entirely when no buckets are configured. This
	// keeps lightweight deployments free of per-bucket round-trips.
	if len(inst.Buckets) == 0 {
		return out
	}
	for _, bucket := range inst.Buckets {
		bucketPath := "/pools/default/buckets/" + bucket
		bucketBody, ok := c.fetchJSON(ctx, client, inst, bucketPath)
		if !ok {
			continue
		}
		var br BucketResponse
		if err := json.Unmarshal(bucketBody, &br); err != nil {
			c.logger.Debug("Couchbase bucket malformed JSON",
				zap.String("instance", inst.Name),
				zap.String("bucket", bucket), zap.Error(err))
			continue
		}
		out = append(out, BuildCouchbaseBucketMetrics(br, mk)...)
	}
	return out
}

// fetchJSON performs an HTTP GET and returns the body bytes. The boolean is
// false when the request fails or the response status is not 200.
func (c *CouchbaseCollector) fetchJSON(ctx context.Context, client *http.Client, inst config.CouchbaseInstance, path string) ([]byte, bool) {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	url := strings.TrimRight(inst.URL, "/") + path
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		c.logger.Debug("Couchbase request build failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("Couchbase scrape request failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("Couchbase scrape non-200",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Int("status", resp.StatusCode))
		return nil, false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug("Couchbase scrape read failed",
			zap.String("instance", inst.Name), zap.String("path", path), zap.Error(err))
		return nil, false
	}
	return body, true
}

// newHTTPClient builds an *http.Client honoring TLSEnabled / TLSSkipVerify.
func newHTTPClient(inst config.CouchbaseInstance, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: inst.TLSSkipVerify,
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// instanceLabels builds the standard label set for an instance. The cb_cluster
// label defaults to the configured instance name and is replaced with the
// cluster name reported by /pools/default when present.
func instanceLabels(inst config.CouchbaseInstance) map[string]string {
	name := inst.Name
	if name == "" {
		name = inst.URL
	}
	return map[string]string{
		"cb_cluster": name,
		"db_system":  "couchbase",
	}
}

// metricBuilder is the closure signature used to assemble metrics with shared
// labels and timestamp.
type metricBuilder func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric

// failureMetrics is the state=0 metric set emitted when the /pools/default
// scrape did not produce a usable body.
func failureMetrics(mk metricBuilder) []collector.Metric {
	return []collector.Metric{
		mk("db.couchbase.state", 0, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil),
	}
}

// BuildCouchbaseClusterMetrics emits the state=1 marker, the cluster-wide
// storage totals, the node count, and per-node stats. Exported for external
// test coverage.
func BuildCouchbaseClusterMetrics(pools PoolsResponse, mk metricBuilder) []collector.Metric {
	out := make([]collector.Metric, 0, 5+len(pools.Nodes)*3)
	out = append(out,
		mk("db.couchbase.state", 1, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail", nil),
		mk("db.couchbase.cluster.ram_used_bytes", float64(pools.StorageTotals.RAM.Used), collector.MetricTypeGauge, "bytes", "Cluster RAM used (bytes)", nil),
		mk("db.couchbase.cluster.ram_total_bytes", float64(pools.StorageTotals.RAM.Total), collector.MetricTypeGauge, "bytes", "Cluster RAM total (bytes)", nil),
		mk("db.couchbase.cluster.hdd_used_bytes", float64(pools.StorageTotals.HDD.Used), collector.MetricTypeGauge, "bytes", "Cluster HDD used (bytes)", nil),
		mk("db.couchbase.cluster.hdd_total_bytes", float64(pools.StorageTotals.HDD.Total), collector.MetricTypeGauge, "bytes", "Cluster HDD total (bytes)", nil),
		mk("db.couchbase.cluster.node_count", float64(len(pools.Nodes)), collector.MetricTypeGauge, "", "Number of nodes in the cluster", nil),
	)
	for _, node := range pools.Nodes {
		labels := map[string]string{"cb_node": nodeLabel(node)}
		out = append(out,
			mk("db.couchbase.node.mem_used_bytes", float64(node.SystemStats.MemUsed), collector.MetricTypeGauge, "bytes", "Node memory used (bytes)", labels),
			mk("db.couchbase.node.cpu_utilization", node.SystemStats.CPUUtilizationRate, collector.MetricTypeGauge, "%", "Node CPU utilization rate", labels),
			mk("db.couchbase.node.cmd_get_total", float64(node.InterestingStats.CmdGet), collector.MetricTypeCounter, "", "Total cmd_get served by node", labels),
		)
	}
	return out
}

// BuildCouchbaseBucketMetrics emits the per-bucket basicStats metrics. Exported
// for external test coverage.
func BuildCouchbaseBucketMetrics(br BucketResponse, mk metricBuilder) []collector.Metric {
	labels := map[string]string{"cb_bucket": br.Name}
	return []collector.Metric{
		mk("db.couchbase.bucket.ops_per_sec", br.BasicStats.OpsPerSec, collector.MetricTypeGauge, "ops/s", "Bucket operations per second", labels),
		mk("db.couchbase.bucket.disk_used_bytes", float64(br.BasicStats.DiskUsed), collector.MetricTypeGauge, "bytes", "Bucket disk used (bytes)", labels),
		mk("db.couchbase.bucket.mem_used_bytes", float64(br.BasicStats.MemUsed), collector.MetricTypeGauge, "bytes", "Bucket memory used (bytes)", labels),
		mk("db.couchbase.bucket.item_count", float64(br.BasicStats.ItemCount), collector.MetricTypeGauge, "", "Bucket item count", labels),
	}
}

// nodeLabel picks the most informative identifier for a node entry.
func nodeLabel(node NodeEntry) string {
	if node.Hostname != "" {
		return node.Hostname
	}
	if node.OTPNode != "" {
		return node.OTPNode
	}
	return ""
}

// =====================================================================
// API response types (only fields we expose as metrics).
// =====================================================================

// PoolsResponse models the /pools/default document.
type PoolsResponse struct {
	Name          string        `json:"name"`
	StorageTotals StorageTotals `json:"storageTotals"`
	Nodes         []NodeEntry   `json:"nodes"`
}

// StorageTotals carries the cluster-wide RAM and HDD usage.
type StorageTotals struct {
	RAM StorageBucket `json:"ram"`
	HDD StorageBucket `json:"hdd"`
}

// StorageBucket is the used/total pair for a storage class.
type StorageBucket struct {
	Used  int64 `json:"used"`
	Total int64 `json:"total"`
}

// NodeEntry is a single node within /pools/default.
type NodeEntry struct {
	Hostname         string           `json:"hostname"`
	OTPNode          string           `json:"otpNode"`
	SystemStats      SystemStats      `json:"systemStats"`
	InterestingStats InterestingStats `json:"interestingStats"`
}

// SystemStats carries the per-node OS-level counters.
type SystemStats struct {
	MemUsed            float64 `json:"mem_used"`
	CPUUtilizationRate float64 `json:"cpu_utilization_rate"`
}

// InterestingStats carries the per-node Couchbase-level counters.
type InterestingStats struct {
	CmdGet int64 `json:"cmd_get"`
}

// BucketResponse models the /pools/default/buckets/{bucket} document.
type BucketResponse struct {
	Name       string     `json:"name"`
	BasicStats BasicStats `json:"basicStats"`
}

// BasicStats carries the per-bucket headline counters.
type BasicStats struct {
	OpsPerSec float64 `json:"opsPerSec"`
	DiskUsed  int64   `json:"diskUsed"`
	MemUsed   int64   `json:"memUsed"`
	ItemCount int64   `json:"itemCount"`
}
