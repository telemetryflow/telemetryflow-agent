// Package aurora implements the Amazon Aurora database monitoring collector.
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

package aurora

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"go.uber.org/zap"
)

// discoverTopology queries the RDS API to discover the Aurora cluster topology
// including cluster info, instances, and their roles (writer/reader).
// Returns true if the topology changed since the last discovery.
func (c *AuroraCollector) discoverTopology(
	ctx context.Context,
	state *clusterState,
) (bool, error) {
	if state.rdsClient == nil {
		return false, fmt.Errorf("RDS client not initialized")
	}

	clusterID := state.cfg.ClusterID

	// 1. Describe the Aurora cluster
	cluster, err := c.describeDBCluster(ctx, state, clusterID)
	if err != nil {
		return false, fmt.Errorf("DescribeDBClusters(%s): %w", clusterID, err)
	}

	// 2. Describe instances in the cluster
	instances, err := c.describeDBInstances(ctx, state, clusterID)
	if err != nil {
		return false, fmt.Errorf("DescribeDBInstances for cluster %s: %w", clusterID, err)
	}

	// 3. Check for global cluster membership (if applicable)
	globalClusterID := ""
	if cluster.GlobalClusterIdentifier != nil {
		globalClusterID = aws.ToString(cluster.GlobalClusterIdentifier)
	}

	// 4. Compare with previous topology
	state.mu.Lock()
	defer state.mu.Unlock()

	changed := false

	// Build new cluster info
	newClusterInfo := &discoveredCluster{
		ClusterID:        aws.ToString(cluster.DBClusterIdentifier),
		ClusterARN:       aws.ToString(cluster.DBClusterArn),
		Engine:           aws.ToString(cluster.Engine),
		EngineVersion:    aws.ToString(cluster.EngineVersion),
		EngineMode:       aws.ToString(cluster.EngineMode),
		DatabaseName:     aws.ToString(cluster.DatabaseName),
		Port:             aws.ToInt32(cluster.Port),
		MultiAZ:          aws.ToBool(cluster.MultiAZ),
		GlobalClusterID:  globalClusterID,
		Status:           aws.ToString(cluster.Status),
		StorageEncrypted: aws.ToBool(cluster.StorageEncrypted),
	}

	if state.clusterInfo == nil {
		changed = true
	} else {
		changed = c.clusterInfoChanged(state.clusterInfo, newClusterInfo)
	}
	state.clusterInfo = newClusterInfo

	// Build new instance list
	newInstances := make([]discoveredInstance, 0, len(instances))
	for _, inst := range instances {
		isWriter := false
		isReader := false

		// Determine writer/reader from instance's cluster role
		for _, member := range cluster.DBClusterMembers {
			if aws.ToString(member.DBInstanceIdentifier) == aws.ToString(inst.DBInstanceIdentifier) {
				isWriter = aws.ToBool(member.IsClusterWriter)
				isReader = !isWriter
				break
			}
		}

		// Detect if PI is enabled
		piEnabled := false
		if inst.PerformanceInsightsEnabled != nil {
			piEnabled = aws.ToBool(inst.PerformanceInsightsEnabled)
		}

		endpoint := ""
		if inst.Endpoint != nil {
			endpoint = aws.ToString(inst.Endpoint.Address)
		}

		port := int32(0)
		if inst.Endpoint != nil && inst.Endpoint.Port != nil {
			port = aws.ToInt32(inst.Endpoint.Port)
		}

		az := aws.ToString(inst.AvailabilityZone)

		newInstances = append(newInstances, discoveredInstance{
			InstanceID:       aws.ToString(inst.DBInstanceIdentifier),
			InstanceARN:      aws.ToString(inst.DBInstanceArn),
			InstanceClass:    aws.ToString(inst.DBInstanceClass),
			IsWriter:         isWriter,
			IsReader:         isReader,
			Endpoint:         endpoint,
			Port:             port,
			AvailabilityZone: az,
			Status:           aws.ToString(inst.DBInstanceStatus),
			PIEnabled:        piEnabled,
			Engine:           aws.ToString(inst.Engine),
			EngineVersion:    aws.ToString(inst.EngineVersion),
		})
	}

	// Check if instances changed
	if len(newInstances) != len(state.instances) {
		changed = true
	} else {
		for i, ni := range newInstances {
			if i >= len(state.instances) {
				changed = true
				break
			}
			if ni.InstanceID != state.instances[i].InstanceID ||
				ni.IsWriter != state.instances[i].IsWriter ||
				ni.Status != state.instances[i].Status {
				changed = true
				break
			}
		}
	}
	state.instances = newInstances

	if changed {
		writerCount := 0
		readerCount := 0
		for _, inst := range newInstances {
			if inst.IsWriter {
				writerCount++
			} else {
				readerCount++
			}
		}
		c.logger.Info("Aurora topology updated",
			zap.String("cluster", clusterID),
			zap.String("engine", newClusterInfo.Engine),
			zap.String("engine_version", newClusterInfo.EngineVersion),
			zap.Int("writers", writerCount),
			zap.Int("readers", readerCount),
			zap.Bool("multiaz", newClusterInfo.MultiAZ),
		)
	}

	return changed, nil
}

// describeDBCluster fetches the DBCluster information for a given cluster identifier.
func (c *AuroraCollector) describeDBCluster(
	ctx context.Context,
	state *clusterState,
	clusterID string,
) (*types.DBCluster, error) {
	input := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(clusterID),
	}

	var resp *rds.DescribeDBClustersOutput
	var err error

	for attempt := 0; attempt <= 3; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err = state.rdsClient.DescribeDBClusters(callCtx, input)
		cancel()

		if err == nil {
			break
		}

		if isThrottlingError(err) {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			c.logger.Debug("RDS DescribeDBClusters throttled",
				zap.String("cluster", clusterID),
				zap.Int("attempt", attempt),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}
		break
	}

	if err != nil {
		return nil, err
	}

	if len(resp.DBClusters) == 0 {
		return nil, fmt.Errorf("cluster %s not found", clusterID)
	}

	return &resp.DBClusters[0], nil
}

// describeDBInstances fetches all DB instances belonging to a given cluster.
func (c *AuroraCollector) describeDBInstances(
	ctx context.Context,
	state *clusterState,
	clusterID string,
) ([]types.DBInstance, error) {
	filters := []types.Filter{
		{
			Name:   aws.String("engine-cluster-id"),
			Values: []string{clusterID},
		},
	}

	var allInstances []types.DBInstance
	var marker *string

	for {
		input := &rds.DescribeDBInstancesInput{
			Filters: filters,
			Marker:  marker,
		}

		var resp *rds.DescribeDBInstancesOutput
		var err error

		for attempt := 0; attempt <= 3; attempt++ {
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			resp, err = state.rdsClient.DescribeDBInstances(callCtx, input)
			cancel()

			if err == nil {
				break
			}

			if isThrottlingError(err) {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				if backoff > 10*time.Second {
					backoff = 10 * time.Second
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
					continue
				}
			}
			break
		}

		if err != nil {
			return nil, err
		}

		allInstances = append(allInstances, resp.DBInstances...)

		if resp.Marker == nil || *resp.Marker == "" {
			break
		}
		marker = resp.Marker
	}

	return allInstances, nil
}

// clusterInfoChanged compares two cluster info structs.
func (c *AuroraCollector) clusterInfoChanged(old, new *discoveredCluster) bool {
	return old.ClusterID != new.ClusterID ||
		old.Engine != new.Engine ||
		old.EngineVersion != new.EngineVersion ||
		old.EngineMode != new.EngineMode ||
		old.Status != new.Status ||
		old.MultiAZ != new.MultiAZ ||
		old.GlobalClusterID != new.GlobalClusterID
}
