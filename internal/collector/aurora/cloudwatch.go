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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

const cloudwatchNamespace = "AWS/RDS"

// collectCloudWatchMetrics fetches CloudWatch metrics for a single Aurora instance
// using the GetMetricData batch API.
func (c *AuroraCollector) collectCloudWatchMetrics(
	ctx context.Context,
	state *clusterState,
	inst discoveredInstance,
) ([]collector.Metric, error) {
	if state.cwClient == nil {
		return nil, fmt.Errorf("cloudwatch client not initialized")
	}

	now := time.Now().UTC()
	startTime := now.Add(-c.cfg.CollectionInterval - 30*time.Second) // 30s overlap for CloudWatch delay
	endTime := now.Add(-30 * time.Second)                            // 30s buffer for CW availability

	allMetricNames := AllCloudWatchMetricNames()
	if len(allMetricNames) == 0 {
		return nil, nil
	}

	labels := instanceLabels(state, inst)
	var all []collector.Metric

	// Batch GetMetricData requests (max 500 MetricDataQuery per request)
	batchSize := c.cfg.CloudWatchBatchSize
	for batchStart := 0; batchStart < len(allMetricNames); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(allMetricNames) {
			batchEnd = len(allMetricNames)
		}
		batch := allMetricNames[batchStart:batchEnd]

		metrics, err := c.getMetricDataBatch(ctx, state, inst, batch, startTime, endTime, labels)
		if err != nil {
			c.logger.Warn("CloudWatch GetMetricData batch failed",
				zap.String("cluster", state.cfg.ClusterID),
				zap.String("instance", inst.InstanceID),
				zap.Int("batch_start", batchStart),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}

	return all, nil
}

// getMetricDataBatch sends a single GetMetricData request for a batch of metric names.
func (c *AuroraCollector) getMetricDataBatch(
	ctx context.Context,
	state *clusterState,
	inst discoveredInstance,
	metricNames []string,
	startTime, endTime time.Time,
	labels map[string]string,
) ([]collector.Metric, error) {
	// Build MetricDataQueries
	queries := make([]types.MetricDataQuery, 0, len(metricNames))
	for i, name := range metricNames {
		id := fmt.Sprintf("m_%d", i)
		stat := "Average"
		period := int32(c.cfg.CollectionInterval.Seconds())
		if period < 60 {
			period = 60 // CloudWatch minimum period
		}

		query := types.MetricDataQuery{
			Id: aws.String(id),
			MetricStat: &types.MetricStat{
				Metric: &types.Metric{
					Namespace:  aws.String(cloudwatchNamespace),
					MetricName: aws.String(name),
					Dimensions: []types.Dimension{
						{
							Name:  aws.String("DBInstanceIdentifier"),
							Value: aws.String(inst.InstanceID),
						},
					},
				},
				Period: aws.Int32(period),
				Stat:   aws.String(stat),
			},
			ReturnData: aws.Bool(true),
		}
		queries = append(queries, query)
	}

	// Execute GetMetricData with retry
	input := &cloudwatch.GetMetricDataInput{
		MetricDataQueries: queries,
		StartTime:         aws.Time(startTime),
		EndTime:           aws.Time(endTime),
		ScanBy:            types.ScanByTimestampDescending,
	}

	var resp *cloudwatch.GetMetricDataOutput
	var err error

	for attempt := 0; attempt <= 3; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err = state.cwClient.GetMetricData(callCtx, input)
		cancel()

		if err == nil {
			break
		}

		// Rate limiting / throttling - exponential backoff
		if isThrottlingError(err) {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			c.logger.Debug("CloudWatch throttled, backing off",
				zap.String("instance", inst.InstanceID),
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}
		// Non-throttling error - do not retry
		break
	}

	if err != nil {
		return nil, fmt.Errorf("GetMetricData: %w", err)
	}

	// Parse results
	var metrics []collector.Metric
	for _, result := range resp.MetricDataResults {
		for i, val := range result.Values {
			if math.IsNaN(val) || math.IsInf(val, 0) {
				continue
			}

			timestamp := time.Now()
			if len(result.Timestamps) > i {
				timestamp = result.Timestamps[i]
			}

			actualName := c.metricNameFromQuery(result.Id, queries)

			m := collector.Metric{
				Name:        "aurora." + actualName,
				Type:        collector.MetricTypeGauge,
				Value:       val,
				Timestamp:   timestamp,
				Labels:      make(map[string]string, len(labels)),
				Unit:        mapCloudWatchUnit(MetricUnit(actualName)),
				Description: MetricDescription(actualName),
			}
			for k, v := range labels {
				m.Labels[k] = v
			}
			metrics = append(metrics, m)
		}
	}

	return metrics, nil
}

// metricNameFromQuery looks up the original CloudWatch metric name from a query ID.
func (c *AuroraCollector) metricNameFromQuery(
	queryID *string,
	queries []types.MetricDataQuery,
) string {
	if queryID == nil {
		return ""
	}
	id := *queryID
	for _, q := range queries {
		if q.Id != nil && *q.Id == id && q.MetricStat != nil && q.MetricStat.Metric != nil {
			return aws.ToString(q.MetricStat.Metric.MetricName)
		}
	}
	return ""
}

// mapCloudWatchUnit maps CloudWatch unit strings to TFO metric units.
func mapCloudWatchUnit(cwUnit string) string {
	switch cwUnit {
	case "Percent":
		return "percent"
	case "Bytes":
		return "bytes"
	case "Bytes/Second":
		return "bytes_per_second"
	case "Seconds":
		return "seconds"
	case "Milliseconds":
		return "milliseconds"
	case "Count":
		return "count"
	case "Count/Second":
		return "count_per_second"
	case "Megabytes":
		return "megabytes"
	default:
		return cwUnit
	}
}

// isThrottlingError checks if the error is a CloudWatch rate limiting error.
func isThrottlingError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "Throttling") ||
		contains(errStr, "Rate exceeded") ||
		contains(errStr, "RequestLimitExceeded") ||
		contains(errStr, "throttling") ||
		contains(errStr, "rate")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
