// Package aurora implements the Amazon Aurora database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aurora

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/pi"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "aurora"

// clusterState holds the per-cluster runtime state: AWS clients, discovered
// topology, and last-known instance information.
type clusterState struct {
	cfg config.AuroraClusterConfig

	// AWS SDK clients
	rdsClient *rds.Client
	cwClient  *cloudwatch.Client
	piClient  *pi.Client

	// Discovered topology (refreshed by topology sync)
	mu          sync.RWMutex
	clusterInfo *discoveredCluster
	instances   []discoveredInstance
}

// discoveredCluster holds information discovered about an Aurora cluster.
type discoveredCluster struct {
	ClusterID        string
	ClusterARN       string
	Engine           string
	EngineVersion    string
	EngineMode       string // provisioned, serverless, parallelquery, global
	DatabaseName     string
	Port             int32
	MultiAZ          bool
	GlobalClusterID  string
	Status           string
	StorageEncrypted bool
}

// discoveredInstance holds information about a single Aurora instance.
type discoveredInstance struct {
	InstanceID       string
	InstanceARN      string
	InstanceClass    string
	IsWriter         bool
	IsReader         bool
	Endpoint         string
	Port             int32
	AvailabilityZone string
	Status           string
	PIEnabled        bool
	Engine           string
	EngineVersion    string
}

// AuroraCollector monitors one or more Amazon Aurora clusters via the AWS SDK.
// It implements the collector.Collector interface.
type AuroraCollector struct {
	cfg    Config
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	states []*clusterState
}

// NewAuroraCollector creates a new AuroraCollector.
// AWS clients are initialized lazily on the first collection cycle so startup
// does not block if an AWS region is temporarily unavailable.
func NewAuroraCollector(cfg config.AuroraCollectorConfig, logger *zap.Logger) *AuroraCollector {
	c := NewConfig(cfg)

	states := make([]*clusterState, len(c.Clusters))
	for i, cluster := range c.Clusters {
		states[i] = &clusterState{
			cfg: cluster,
		}
	}

	return &AuroraCollector{
		cfg:    c,
		logger: logger.Named(collectorName),
		states: states,
	}
}

// Name returns the collector name.
func (c *AuroraCollector) Name() string {
	return collectorName
}

// IsRunning returns whether the collector is currently running.
func (c *AuroraCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start begins periodic metric collection. It runs three tickers:
//   - CloudWatch metrics ticker at cfg.CollectionInterval
//   - Topology sync ticker at cfg.TopologyInterval
//   - Performance Insights ticker at cfg.PIInterval (if enabled)
//   - Push flush ticker at cfg.PushFlushInterval
//
// Start blocks until ctx is cancelled or Stop is called.
func (c *AuroraCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("aurora collector is already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("Aurora collector starting",
		zap.Int("clusters", len(c.cfg.Clusters)),
		zap.Duration("topology_interval", c.cfg.TopologyInterval),
	)

	for _, state := range c.states {
		if err := c.initAWSClients(ctx, state); err != nil {
			c.logger.Warn("Failed to initialize AWS clients for cluster",
				zap.String("cluster", state.cfg.ClusterID),
				zap.String("region", state.cfg.Region),
				zap.Error(err),
			)
		}
	}

	for _, state := range c.states {
		if state.rdsClient != nil {
			if _, err := c.discoverTopology(ctx, state); err != nil {
				c.logger.Warn("Initial topology discovery failed",
					zap.String("cluster", state.cfg.ClusterID),
					zap.Error(err),
				)
			}
		}
	}

	topologyTicker := time.NewTicker(c.cfg.TopologyInterval)
	defer topologyTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return c.Stop()
		case <-c.stopChan:
			return nil
		case <-topologyTicker.C:
			for _, state := range c.states {
				if state.rdsClient == nil {
					continue
				}
				if changed, err := c.discoverTopology(ctx, state); err != nil {
					c.logger.Warn("Topology discovery failed",
						zap.String("cluster", state.cfg.ClusterID),
						zap.Error(err),
					)
				} else if changed {
					c.logger.Info("Topology change detected",
						zap.String("cluster", state.cfg.ClusterID),
					)
				}
			}
		}
	}
}

// Stop gracefully shuts down the collector.
func (c *AuroraCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}
	c.logger.Info("Aurora collector stopping")
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect gathers CloudWatch metrics from all configured Aurora clusters concurrently.
func (c *AuroraCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.states) == 0 {
		return nil, nil
	}

	type result struct {
		metrics []collector.Metric
		err     error
	}

	results := make([]result, len(c.states))

	if len(c.states) == 1 {
		m, err := c.collectCluster(ctx, c.states[0])
		results[0] = result{metrics: m, err: err}
	} else {
		var wg sync.WaitGroup
		for i, s := range c.states {
			wg.Add(1)
			go func(idx int, state *clusterState) {
				defer wg.Done()
				m, err := c.collectCluster(ctx, state)
				results[idx] = result{metrics: m, err: err}
			}(i, s)
		}
		wg.Wait()
	}

	var all []collector.Metric
	for i, r := range results {
		if r.err != nil {
			c.logger.Warn("Collection failed for cluster",
				zap.String("cluster", c.states[i].cfg.ClusterID),
				zap.Error(r.err),
			)
			continue
		}
		all = append(all, r.metrics...)
	}

	if c.cfg.EnablePI {
		if piMetrics, err := c.collectAllPI(ctx); err != nil {
			c.logger.Warn("Performance Insights collection failed", zap.Error(err))
		} else {
			all = append(all, piMetrics...)
		}
	}

	return all, nil
}

// -------------------------------------------------------------------
// AWS Client Initialization
// -------------------------------------------------------------------

// initAWSClients creates the RDS, CloudWatch, and PI SDK clients for a cluster.
func (c *AuroraCollector) initAWSClients(ctx context.Context, state *clusterState) error {
	region := state.cfg.Region

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}

	if state.cfg.AccessKeyID != "" && state.cfg.SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     state.cfg.AccessKeyID,
					SecretAccessKey: state.cfg.SecretAccessKey,
					SessionToken:    state.cfg.SessionToken,
				}, nil
			},
		)))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return fmt.Errorf("aws config load failed for region %s: %w", region, err)
	}

	// Assume role if specified
	if state.cfg.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, state.cfg.RoleARN)
		cfg.Credentials = aws.NewCredentialsCache(creds)
	}

	state.rdsClient = rds.NewFromConfig(cfg)
	state.cwClient = cloudwatch.NewFromConfig(cfg)
	state.piClient = pi.NewFromConfig(cfg)

	c.logger.Info("AWS clients initialized",
		zap.String("cluster", state.cfg.ClusterID),
		zap.String("region", region),
	)
	return nil
}

// -------------------------------------------------------------------
// Collect Cluster (orchestrates sub-collectors)
// -------------------------------------------------------------------

// collectCluster runs CloudWatch metric collection for a single cluster.
func (c *AuroraCollector) collectCluster(ctx context.Context, state *clusterState) ([]collector.Metric, error) {
	if state.rdsClient == nil {
		if err := c.initAWSClients(ctx, state); err != nil {
			return nil, fmt.Errorf("aws client init: %w", err)
		}
	}

	state.mu.RLock()
	instances := state.instances
	clusterInfo := state.clusterInfo
	state.mu.RUnlock()

	if clusterInfo == nil || len(instances) == 0 {
		return nil, nil
	}

	var all []collector.Metric

	// Collect CloudWatch metrics for each instance
	for _, inst := range instances {
		cwMetrics, err := c.collectCloudWatchMetrics(ctx, state, inst)
		if err != nil {
			c.logger.Warn("CloudWatch metrics collection failed",
				zap.String("cluster", state.cfg.ClusterID),
				zap.String("instance", inst.InstanceID),
				zap.Error(err),
			)
			continue
		}
		all = append(all, cwMetrics...)
	}

	c.logger.Debug("Aurora cluster collected",
		zap.String("cluster", state.cfg.ClusterID),
		zap.Int("instances", len(instances)),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

// collectAllPI collects Performance Insights data from all PI-enabled instances.
func (c *AuroraCollector) collectAllPI(ctx context.Context) ([]collector.Metric, error) {
	var all []collector.Metric

	for _, state := range c.states {
		if state.piClient == nil {
			continue
		}

		state.mu.RLock()
		instances := state.instances
		state.mu.RUnlock()

		for _, inst := range instances {
			if !inst.PIEnabled {
				continue
			}
			piMetrics, err := c.collectPerformanceInsights(ctx, state, inst)
			if err != nil {
				c.logger.Warn("PI collection failed",
					zap.String("cluster", state.cfg.ClusterID),
					zap.String("instance", inst.InstanceID),
					zap.Error(err),
				)
				continue
			}
			all = append(all, piMetrics...)
		}
	}
	return all, nil
}

// instanceLabels builds the common label set for a given Aurora instance.
func instanceLabels(state *clusterState, inst discoveredInstance) map[string]string {
	labels := map[string]string{
		"aurora_cluster":        state.cfg.ClusterID,
		"aurora_region":         state.cfg.Region,
		"aurora_instance_id":    inst.InstanceID,
		"aurora_instance_class": inst.InstanceClass,
		"aurora_engine":         inst.Engine,
		"aurora_role":           "reader",
	}
	if inst.IsWriter {
		labels["aurora_role"] = "writer"
	}
	if inst.AvailabilityZone != "" {
		labels["aurora_az"] = inst.AvailabilityZone
	}
	for k, v := range state.cfg.Tags {
		labels[k] = v
	}
	return labels
}
