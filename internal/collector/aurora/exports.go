// Package aurora exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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
//
// This file mirrors selected unexported symbols with exported names so that
// external test packages (aurora_test) can exercise them without accessing
// unexported identifiers directly. It contains no production behaviour.

package aurora

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	pitypes "github.com/aws/aws-sdk-go-v2/service/pi/types"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- Pure helper wrappers ---

// MapCloudWatchUnitExported wraps mapCloudWatchUnit.
func MapCloudWatchUnitExported(u string) string { return mapCloudWatchUnit(u) }

// IsThrottlingErrorExported wraps isThrottlingError.
func IsThrottlingErrorExported(err error) bool { return isThrottlingError(err) }

// ContainsExported wraps contains.
func ContainsExported(s, substr string) bool { return contains(s, substr) }

// ContainsSubstrExported wraps containsSubstr.
func ContainsSubstrExported(s, substr string) bool { return containsSubstr(s, substr) }

// SanitizeMetricNameExported wraps sanitizeMetricName.
func SanitizeMetricNameExported(name string) string { return sanitizeMetricName(name) }

// SanitizeLabelNameExported wraps sanitizeLabelName.
func SanitizeLabelNameExported(name string) string { return sanitizeLabelName(name) }

// PiMetricGroupsCount returns the number of PI metric groups defined.
func PiMetricGroupsCount() int { return len(piMetricGroups()) }

// PiMetricGroupsTotalMetrics returns the total number of PI metrics defined.
func PiMetricGroupsTotalMetrics() int {
	total := 0
	for _, g := range piMetricGroups() {
		total += len(g.Metrics)
	}
	return total
}

// ApplyClusterDefaultsExported wraps applyClusterDefaults.
func ApplyClusterDefaultsExported(c *config.AuroraClusterConfig) { applyClusterDefaults(c) }

// InstanceLabelsExported builds the common label set for a synthetic instance.
func InstanceLabelsExported(
	clusterID, region string,
	tags map[string]string,
	instID, instClass, engine, az string,
	isWriter bool,
) map[string]string {
	state := &clusterState{cfg: config.AuroraClusterConfig{
		ClusterID: clusterID,
		Region:    region,
		Tags:      tags,
	}}
	inst := discoveredInstance{
		InstanceID:       instID,
		InstanceClass:    instClass,
		Engine:           engine,
		AvailabilityZone: az,
		IsWriter:         isWriter,
	}
	return instanceLabels(state, inst)
}

// PiStatementFromKeyExported wraps PiStatementFromKey with a synthetic key.
func PiStatementFromKeyExported(dims map[string]string) string {
	if dims == nil {
		return PiStatementFromKey(nil)
	}
	return PiStatementFromKey(&pitypes.ResponseResourceMetricKey{Dimensions: dims})
}

// MetricNameFromQueryExported wraps metricNameFromQuery. It builds one query
// per name with ids "m_0", "m_1", ... and looks up the provided lookupID.
func (c *AuroraCollector) MetricNameFromQueryExported(lookupID *string, names []string) string {
	queries := make([]types.MetricDataQuery, 0, len(names))
	for i := range names {
		qid := fmt.Sprintf("m_%d", i)
		name := names[i]
		queries = append(queries, types.MetricDataQuery{
			Id: &qid,
			MetricStat: &types.MetricStat{
				Metric: &types.Metric{MetricName: &name},
			},
		})
	}
	return c.metricNameFromQuery(lookupID, queries)
}

// ClusterInfoChangedExported wraps clusterInfoChanged.
func (c *AuroraCollector) ClusterInfoChangedExported(oldID, newID, oldEngine, newEngine string) bool {
	old := &discoveredCluster{ClusterID: oldID, Engine: oldEngine}
	nw := &discoveredCluster{ClusterID: newID, Engine: newEngine}
	return c.clusterInfoChanged(old, nw)
}

// QanTopLimitExported wraps qanTopLimit.
func (c *AuroraCollector) QanTopLimitExported() int { return c.qanTopLimit() }

// --- Collector harness accessors and method wrappers ---

// ResolvedConfig returns the resolved Config.
func (c *AuroraCollector) ResolvedConfig() Config { return c.cfg }

// NumStates returns the number of cluster states.
func (c *AuroraCollector) NumStates() int { return len(c.states) }

// NumInstances returns the number of discovered instances for the first cluster.
func (c *AuroraCollector) NumInstances() int {
	if len(c.states) == 0 {
		return 0
	}
	c.states[0].mu.RLock()
	defer c.states[0].mu.RUnlock()
	return len(c.states[0].instances)
}

// FirstInstanceID returns the first discovered instance ID, or "".
func (c *AuroraCollector) FirstInstanceID() string {
	if len(c.states) == 0 {
		return ""
	}
	c.states[0].mu.RLock()
	defer c.states[0].mu.RUnlock()
	if len(c.states[0].instances) == 0 {
		return ""
	}
	return c.states[0].instances[0].InstanceID
}

// ClusterEngine returns the discovered engine for the first cluster, or "".
func (c *AuroraCollector) ClusterEngine() string {
	if len(c.states) == 0 {
		return ""
	}
	c.states[0].mu.RLock()
	defer c.states[0].mu.RUnlock()
	if c.states[0].clusterInfo == nil {
		return ""
	}
	return c.states[0].clusterInfo.Engine
}

// FirstInstancePIEnabled returns whether the first instance has PI enabled.
func (c *AuroraCollector) FirstInstancePIEnabled() bool {
	if len(c.states) == 0 {
		return false
	}
	c.states[0].mu.RLock()
	defer c.states[0].mu.RUnlock()
	if len(c.states[0].instances) == 0 {
		return false
	}
	return c.states[0].instances[0].PIEnabled
}

// InitAWSClientsFirst wraps initAWSClients for the first cluster state.
func (c *AuroraCollector) InitAWSClientsFirst(ctx context.Context) error {
	return c.initAWSClients(ctx, c.states[0])
}

// DiscoverTopologyFirst wraps discoverTopology for the first cluster state.
func (c *AuroraCollector) DiscoverTopologyFirst(ctx context.Context) (bool, error) {
	return c.discoverTopology(ctx, c.states[0])
}

// CollectClusterFirst wraps collectCluster for the first cluster state.
func (c *AuroraCollector) CollectClusterFirst(ctx context.Context) ([]collector.Metric, error) {
	return c.collectCluster(ctx, c.states[0])
}

// CollectCloudWatchFirst wraps collectCloudWatchMetrics for the first instance.
func (c *AuroraCollector) CollectCloudWatchFirst(ctx context.Context) ([]collector.Metric, error) {
	inst := c.firstInstance()
	return c.collectCloudWatchMetrics(ctx, c.states[0], inst)
}

// CollectPIFirst wraps collectPerformanceInsights for the first instance.
func (c *AuroraCollector) CollectPIFirst(ctx context.Context) ([]collector.Metric, error) {
	inst := c.firstInstance()
	return c.collectPerformanceInsights(ctx, c.states[0], inst)
}

// CollectAllPIExported wraps collectAllPI.
func (c *AuroraCollector) CollectAllPIExported(ctx context.Context) ([]collector.Metric, error) {
	return c.collectAllPI(ctx)
}

// CollectQANInstanceFirst wraps collectQANInstance for the first instance.
func (c *AuroraCollector) CollectQANInstanceFirst(ctx context.Context) (int, error) {
	inst := c.firstInstance()
	b, err := c.collectQANInstance(ctx, c.states[0], inst)
	return len(b), err
}

// DescribeDBClusterFirst wraps describeDBCluster.
func (c *AuroraCollector) DescribeDBClusterFirst(ctx context.Context, clusterID string) error {
	_, err := c.describeDBCluster(ctx, c.states[0], clusterID)
	return err
}

// DescribeDBInstancesFirst wraps describeDBInstances.
func (c *AuroraCollector) DescribeDBInstancesFirst(ctx context.Context, clusterID string) (int, error) {
	insts, err := c.describeDBInstances(ctx, c.states[0], clusterID)
	return len(insts), err
}

func (c *AuroraCollector) firstInstance() discoveredInstance {
	c.states[0].mu.RLock()
	defer c.states[0].mu.RUnlock()
	if len(c.states[0].instances) == 0 {
		return discoveredInstance{InstanceID: "synthetic", PIEnabled: true}
	}
	return c.states[0].instances[0]
}

// SetSyntheticInstance injects a single instance into the first cluster state
// without a topology discovery round-trip.
func (c *AuroraCollector) SetSyntheticInstance(instanceID, instanceARN string, piEnabled bool) {
	c.states[0].mu.Lock()
	defer c.states[0].mu.Unlock()
	c.states[0].instances = []discoveredInstance{
		{
			InstanceID:  instanceID,
			InstanceARN: instanceARN,
			IsWriter:    true,
			Engine:      "aurora-postgresql",
			PIEnabled:   piEnabled,
		},
	}
	c.states[0].clusterInfo = &discoveredCluster{
		ClusterID:    c.states[0].cfg.ClusterID,
		Engine:       "aurora-postgresql",
		DatabaseName: "appdb",
	}
}

// ClearFirstClients nils the AWS clients on the first state to exercise
// not-initialized guards.
func (c *AuroraCollector) ClearFirstClients() {
	c.states[0].rdsClient = nil
	c.states[0].cwClient = nil
	c.states[0].piClient = nil
}
