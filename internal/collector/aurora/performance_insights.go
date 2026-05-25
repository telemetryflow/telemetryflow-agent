// Package aurora implements the Amazon Aurora database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pi"
	"github.com/aws/aws-sdk-go-v2/service/pi/types"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// piMetricGroup defines a Performance Insights metric group to collect.
type piMetricGroup struct {
	// Group is the PI metric group identifier (e.g. "db.load", "db.sql")
	Group string
	// Metrics is the list of metric names within this group
	Metrics []piMetricDef
}

// piMetricDef defines a single PI metric.
type piMetricDef struct {
	Metric      string
	Aggregation string // avg, sum, min, max
	Unit        string
	Description string
}

// piMetricGroups returns all PI metric groups to collect.
func piMetricGroups() []piMetricGroup {
	return []piMetricGroup{
		{
			Group: "db.load",
			Metrics: []piMetricDef{
				{Metric: "db.load.avg", Aggregation: "avg", Unit: "count", Description: "Average database load (active sessions)"},
				{Metric: "db.load.sample", Aggregation: "avg", Unit: "count", Description: "Sampled database load"},
			},
		},
		{
			Group: "db.sql",
			Metrics: []piMetricDef{
				{Metric: "db.sql.avg_latency", Aggregation: "avg", Unit: "milliseconds", Description: "Average latency per SQL digest"},
				{Metric: "db.sql.executions", Aggregation: "sum", Unit: "count", Description: "Number of SQL executions"},
				{Metric: "db.sql.rows_affected", Aggregation: "sum", Unit: "count", Description: "Number of rows affected by SQL"},
				{Metric: "db.sql.rows_processed", Aggregation: "sum", Unit: "count", Description: "Number of rows processed by SQL"},
				{Metric: "db.sql.rows_returned", Aggregation: "sum", Unit: "count", Description: "Number of rows returned by SQL"},
			},
		},
		{
			Group: "db.sql_tokenized",
			Metrics: []piMetricDef{
				{Metric: "db.sql_tokenized.avg_latency", Aggregation: "avg", Unit: "milliseconds", Description: "Average latency per tokenized SQL digest"},
				{Metric: "db.sql_tokenized.executions", Aggregation: "sum", Unit: "count", Description: "Number of tokenized SQL executions"},
				{Metric: "db.sql_tokenized.rows_affected", Aggregation: "sum", Unit: "count", Description: "Rows affected by tokenized SQL"},
				{Metric: "db.sql_tokenized.rows_processed", Aggregation: "sum", Unit: "count", Description: "Rows processed by tokenized SQL"},
				{Metric: "db.sql_tokenized.rows_returned", Aggregation: "sum", Unit: "count", Description: "Rows returned by tokenized SQL"},
			},
		},
		{
			Group: "db.wait_event",
			Metrics: []piMetricDef{
				{Metric: "db.wait_event.avg_latency", Aggregation: "avg", Unit: "milliseconds", Description: "Average wait event latency"},
				{Metric: "db.wait_event.count", Aggregation: "sum", Unit: "count", Description: "Wait event count"},
			},
		},
		{
			Group: "os",
			Metrics: []piMetricDef{
				{Metric: "os.cpuUtilization", Aggregation: "avg", Unit: "percent", Description: "OS-level CPU utilization"},
				{Metric: "os.freeMemory", Aggregation: "avg", Unit: "bytes", Description: "OS-level free memory"},
				{Metric: "os.totalMemory", Aggregation: "avg", Unit: "bytes", Description: "OS-level total memory"},
				{Metric: "os.diskQueueDepth", Aggregation: "avg", Unit: "count", Description: "OS-level disk queue depth"},
				{Metric: "os.readIOPS", Aggregation: "avg", Unit: "count_per_second", Description: "OS-level read IOPS"},
				{Metric: "os.writeIOPS", Aggregation: "avg", Unit: "count_per_second", Description: "OS-level write IOPS"},
			},
		},
	}
}

// collectPerformanceInsights fetches Performance Insights data for a single instance.
func (c *AuroraCollector) collectPerformanceInsights(
	ctx context.Context,
	state *clusterState,
	inst discoveredInstance,
) ([]collector.Metric, error) {
	if state.piClient == nil {
		return nil, fmt.Errorf("PI client not initialized")
	}

	if !inst.PIEnabled {
		return nil, nil
	}

	now := time.Now().UTC()
	startTime := now.Add(-c.cfg.PIInterval)
	endTime := now

	serviceType := "RDS"
	identifier := inst.InstanceARN
	if identifier == "" {
		identifier = fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", state.cfg.Region, "account", inst.InstanceID)
	}

	labels := instanceLabels(state, inst)
	var all []collector.Metric

	groups := piMetricGroups()
	for _, group := range groups {
		for _, metric := range group.Metrics {
			metrics, err := c.getPIResourceMetrics(
				ctx, state, identifier, serviceType,
				group.Group, metric, startTime, endTime, labels,
			)
			if err != nil {
				c.logger.Debug("PI metric collection failed",
					zap.String("cluster", state.cfg.ClusterID),
					zap.String("instance", inst.InstanceID),
					zap.String("metric", metric.Metric),
					zap.Error(err),
				)
				continue
			}
			all = append(all, metrics...)
		}
	}

	c.logger.Debug("Performance Insights collected",
		zap.String("cluster", state.cfg.ClusterID),
		zap.String("instance", inst.InstanceID),
		zap.Int("metrics", len(all)),
	)
	return all, nil
}

// getPIResourceMetrics fetches a single PI metric for a resource.
func (c *AuroraCollector) getPIResourceMetrics(
	ctx context.Context,
	state *clusterState,
	identifier, serviceType string,
	group string,
	metricDef piMetricDef,
	startTime, endTime time.Time,
	labels map[string]string,
) ([]collector.Metric, error) {
	// Build metric query in PI format
	metricQuery := fmt.Sprintf("%s.%s", group, strings.TrimPrefix(metricDef.Metric, group+"."))

	input := &pi.GetResourceMetricsInput{
		ServiceType: types.ServiceType(serviceType),
		Identifier:  aws.String(identifier),
		MetricQueries: []types.MetricQuery{
			{
				Metric: aws.String(metricQuery),
			},
		},
		StartTime:       aws.Time(startTime),
		EndTime:         aws.Time(endTime),
		PeriodInSeconds: aws.Int32(int32(c.cfg.PIInterval.Seconds())),
	}

	var resp *pi.GetResourceMetricsOutput
	var err error

	// Retry with exponential backoff
	for attempt := 0; attempt <= 3; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err = state.piClient.GetResourceMetrics(callCtx, input)
		cancel()

		if err == nil {
			break
		}

		if isThrottlingError(err) {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			c.logger.Debug("PI throttled, backing off",
				zap.String("metric", metricDef.Metric),
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
		return nil, fmt.Errorf("GetResourceMetrics(%s): %w", metricDef.Metric, err)
	}

	var metrics []collector.Metric
	for _, dp := range resp.MetricList {
		for _, pt := range dp.DataPoints {
			value := float64(0)
			if pt.Value != nil {
				value = *pt.Value
			}
			if math.IsNaN(value) || math.IsInf(value, 0) {
				continue
			}

			timestamp := time.Now()
			if pt.Timestamp != nil {
				timestamp = *pt.Timestamp
			}

			m := collector.Metric{
				Name:        "aurora.pi." + sanitizeMetricName(metricDef.Metric),
				Type:        collector.MetricTypeGauge,
				Value:       value,
				Timestamp:   timestamp,
				Labels:      make(map[string]string, len(labels)),
				Unit:        metricDef.Unit,
				Description: metricDef.Description,
			}
			for k, v := range labels {
				m.Labels[k] = v
			}

			if group == "db.sql" || group == "db.sql_tokenized" || group == "db.wait_event" {
				if dp.Key != nil {
					for dimKey, dimVal := range dp.Key.Dimensions {
						m.Labels["pi_"+sanitizeLabelName(dimKey)] = dimVal
					}
				}
			}

			metrics = append(metrics, m)
		}
	}

	return metrics, nil
}

// sanitizeMetricName replaces characters not valid in metric names.
func sanitizeMetricName(name string) string {
	return strings.ReplaceAll(name, ".", "_")
}

// sanitizeLabelName replaces characters not valid in label names.
func sanitizeLabelName(name string) string {
	replacer := strings.NewReplacer(
		".", "_",
		" ", "_",
		"/", "_",
		"-", "_",
	)
	return replacer.Replace(name)
}
