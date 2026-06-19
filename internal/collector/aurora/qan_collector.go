// Package aurora implements the Amazon Aurora database monitoring collector.
//
// This file adds the qan.QANCollector interface to AuroraCollector so that
// Performance Insights per-SQL data flows into the QAN data path (alongside
// the OTLP metrics emitted by Collect). It reuses the existing AWS clients
// and topology discovery rather than duplicating them.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package aurora

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pi"
	"github.com/aws/aws-sdk-go-v2/service/pi/types"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// AgentType returns the PMM-compatible agent type for Aurora QAN.
// Satisfies qan.QANCollector.
func (c *AuroraCollector) AgentType() qan.AgentType {
	return qan.AgentTypeAuroraPI
}

// CollectQAN builds QAN buckets from Aurora Performance Insights db.sql data
// for every PI-enabled instance across all configured clusters.
//
// Unlike the pg_stat_statements / performance_schema collectors, PI returns
// data already windowed over the requested time range, so no per-instance
// delta snapshot cache is required — each call covers a fresh window.
//
// Satisfies qan.QANCollector.
func (c *AuroraCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
	if len(c.states) == 0 || !c.cfg.EnablePI {
		return nil, nil
	}

	var allBuckets []qan.QANMetricsBucket
	for _, state := range c.states {
		if state.piClient == nil {
			// AWS clients are initialized lazily on Start; if QAN is the only
			// active path, try to initialize now so QAN works standalone.
			if err := c.initAWSClients(ctx, state); err != nil {
				c.logger.Debug("Aurora QAN: PI client not initialized",
					zap.String("cluster", state.cfg.ClusterID),
					zap.Error(err),
				)
				continue
			}
		}

		state.mu.RLock()
		instances := state.instances
		state.mu.RUnlock()

		for _, inst := range instances {
			if !inst.PIEnabled {
				continue
			}
			buckets, err := c.collectQANInstance(ctx, state, inst)
			if err != nil {
				c.logger.Warn("Aurora QAN collection failed",
					zap.String("cluster", state.cfg.ClusterID),
					zap.String("instance", inst.InstanceID),
					zap.Error(err),
				)
				continue
			}
			allBuckets = append(allBuckets, buckets...)
		}
	}

	return allBuckets, nil
}

// collectQANInstance queries PI db.sql metrics for one instance and builds
// one QANMetricsBucket per SQL statement digest.
func (c *AuroraCollector) collectQANInstance(
	ctx context.Context,
	state *clusterState,
	inst discoveredInstance,
) ([]qan.QANMetricsBucket, error) {
	identifier := inst.InstanceARN
	if identifier == "" {
		identifier = fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", state.cfg.Region, "account", inst.InstanceID)
	}

	endTime := time.Now().UTC()
	startTime := endTime.Add(-c.cfg.PIInterval)
	periodSec := int32(c.cfg.PIInterval.Seconds())
	if periodSec < 1 {
		periodSec = 60
	}

	// Fetch executions (sum over window) and avg latency (avg over window),
	// keyed by the db.sql.statement dimension.
	execByStmt, err := c.piSQLByKey(ctx, state.piClient, identifier, "db.sql.executions", startTime, endTime, periodSec, true)
	if err != nil {
		return nil, fmt.Errorf("pi executions: %w", err)
	}
	latencyByStmt, err := c.piSQLByKey(ctx, state.piClient, identifier, "db.sql.avg_latency", startTime, endTime, periodSec, false)
	if err != nil {
		return nil, fmt.Errorf("pi avg_latency: %w", err)
	}

	if len(execByStmt) == 0 {
		return nil, nil
	}

	labels := instanceLabels(state, inst)
	periodStart := startTime.Unix()
	periodLen := int64(periodSec)

	dbName := ""
	state.mu.RLock()
	if state.clusterInfo != nil {
		dbName = state.clusterInfo.DatabaseName
	}
	state.mu.RUnlock()

	var buckets []qan.QANMetricsBucket
	for stmt, execs := range execByStmt {
		if execs <= 0 || stmt == "" {
			continue
		}
		avgLatencyMs, ok := latencyByStmt[stmt]
		if !ok {
			avgLatencyMs = 0
		}
		avgLatencySec := avgLatencyMs / 1000.0
		totalTimeSec := avgLatencySec * execs

		example := stmt
		const maxExampleLen = 2000
		truncated := false
		if len(example) > maxExampleLen {
			example = example[:maxExampleLen]
			truncated = true
		}

		fp := FingerprintAurora(stmt)

		buckets = append(buckets, qan.QANMetricsBucket{
			AgentType:        qan.AgentTypeAuroraPI,
			QueryID:          fp,
			Fingerprint:      fp,
			Example:          example,
			ExampleTruncated: truncated,
			PeriodStartSec:   periodStart,
			PeriodLengthSec:  periodLen,
			Database:         dbName,
			Labels:           labels,
			NumQueries:       execs,
			QueryTimeCnt:     execs,
			QueryTimeSum:     totalTimeSec,
			QueryTimeMin:     avgLatencySec,
			QueryTimeMax:     avgLatencySec,
			// PI exposes only avg latency per digest; use it as the best
			// available p99 estimate (upper-bound semantics do not apply
			// since avg < max). Field stays non-zero for ranking.
			QueryTimeP99: avgLatencySec,
		})
	}

	// Rank by total time and truncate to the configured top-queries limit.
	limit := c.qanTopLimit()
	if len(buckets) > limit {
		SortAuroraBuckets(buckets)
		buckets = buckets[:limit]
	}

	return buckets, nil
}

// piSQLByKey queries a single PI db.sql metric and returns a map from the
// SQL statement digest text to the aggregated value. When sum is true the
// data-point values are summed (count-style metrics); otherwise the last
// data point is used (gauge/avg-style metrics).
func (c *AuroraCollector) piSQLByKey(
	ctx context.Context,
	client *pi.Client,
	identifier, metric string,
	startTime, endTime time.Time,
	periodSec int32,
	sum bool,
) (map[string]float64, error) {
	input := &pi.GetResourceMetricsInput{
		ServiceType: types.ServiceTypeRds,
		Identifier:  aws.String(identifier),
		MetricQueries: []types.MetricQuery{
			{Metric: aws.String(metric)},
		},
		StartTime:       aws.Time(startTime),
		EndTime:         aws.Time(endTime),
		PeriodInSeconds: aws.Int32(periodSec),
	}

	resp, err := c.piCallWithRetry(ctx, client, input)
	if err != nil {
		return nil, err
	}

	out := make(map[string]float64)
	for _, dp := range resp.MetricList {
		stmt := PiStatementFromKey(dp.Key)
		if stmt == "" {
			continue
		}
		for _, pt := range dp.DataPoints {
			val := 0.0
			if pt.Value != nil {
				val = *pt.Value
			}
			if math.IsNaN(val) || math.IsInf(val, 0) {
				continue
			}
			if sum {
				out[stmt] += val
			} else {
				out[stmt] = val
			}
		}
	}
	return out, nil
}

// piCallWithRetry wraps GetResourceMetrics with throttling backoff.
func (c *AuroraCollector) piCallWithRetry(ctx context.Context, client *pi.Client, input *pi.GetResourceMetricsInput) (*pi.GetResourceMetricsOutput, error) {
	var (
		resp *pi.GetResourceMetricsOutput
		err  error
	)
	for attempt := 0; attempt <= 3; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err = client.GetResourceMetrics(callCtx, input)
		cancel()
		if err == nil {
			return resp, nil
		}
		if !isThrottlingError(err) {
			return nil, err
		}
		backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, err
}

// PiStatementFromKey extracts the db.sql.statement dimension from a PI key.
func PiStatementFromKey(key *types.ResponseResourceMetricKey) string {
	if key == nil {
		return ""
	}
	for k, v := range key.Dimensions {
		if k == "db.sql.statement" {
			return v
		}
	}
	return ""
}

// qanTopLimit returns the max number of per-SQL buckets per instance.
// Falls back to 200 when no explicit limit is configured.
func (c *AuroraCollector) qanTopLimit() int {
	if c.cfg.TopQueriesLimit > 0 {
		return c.cfg.TopQueriesLimit
	}
	return 200
}

// SortAuroraBuckets orders buckets by QueryTimeSum descending (in-place).
func SortAuroraBuckets(b []qan.QANMetricsBucket) {
	for i := 1; i < len(b); i++ {
		for j := i; j > 0 && b[j].QueryTimeSum > b[j-1].QueryTimeSum; j-- {
			b[j], b[j-1] = b[j-1], b[j]
		}
	}
}

// FingerprintAurora produces a stable short fingerprint for a statement digest.
func FingerprintAurora(stmt string) string {
	h := sha256.Sum256([]byte(stmt))
	return fmt.Sprintf("%x", h[:16])
}
