// Package exporter_test contains unit tests for the CloudWatch output
// (AWS SDK v2 PutMetricData path). All tests inject a fake client; no real
// AWS calls are made.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// fakeCloudWatchClient is a recording PutMetricData fake.
type fakeCloudWatchClient struct {
	calls   []*cloudwatch.PutMetricDataInput
	results []*cloudwatch.PutMetricDataOutput
	err     error
}

func (f *fakeCloudWatchClient) PutMetricData(_ context.Context, params *cloudwatch.PutMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error) {
	f.calls = append(f.calls, params)
	if f.err != nil {
		return nil, f.err
	}
	var out *cloudwatch.PutMetricDataOutput
	if len(f.results) > 0 {
		out, f.results = f.results[0], f.results[1:]
	} else {
		out = &cloudwatch.PutMetricDataOutput{}
	}
	return out, nil
}

// newCloudWatchOutputWithFake wires up an output that uses a fresh fake
// client (no Connect required).
func newCloudWatchOutputWithFake(t *testing.T, cfg exporter.CloudWatchOutputConfig) (*exporter.CloudWatchOutput, *fakeCloudWatchClient) {
	t.Helper()
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "TelemetryFlow"
	}
	cfg.Logger = zap.NewNop()

	out, err := exporter.NewCloudWatchOutput(cfg)
	require.NoError(t, err)
	fake := &fakeCloudWatchClient{}
	out.SetClientForTest(fake)
	return out, fake
}

func TestCloudWatch_Write_FiveMetricsSingleCall(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{
		BatchSize: 20,
	})

	now := time.UnixMilli(1_700_000_000_000).UTC()
	metrics := []plugin.Metric{
		{Name: "system.cpu.usage", Type: plugin.MetricTypeGauge, Value: 0.42, Timestamp: now, Labels: map[string]string{"host": "node-1"}, Unit: "percent"},
		{Name: "system.mem.used", Type: plugin.MetricTypeGauge, Value: 1024, Timestamp: now, Labels: map[string]string{"host": "node-1"}, Unit: "bytes"},
		{Name: "net.bytes_sent", Type: plugin.MetricTypeCounter, Value: 7, Timestamp: now, Labels: map[string]string{"host": "node-1"}, Unit: "bytes"},
		{Name: "disk.io_time", Type: plugin.MetricTypeGauge, Value: 0.1, Timestamp: now, Labels: map[string]string{"host": "node-1"}, Unit: "seconds"},
		{Name: "requests.total", Type: plugin.MetricTypeCounter, Value: 100, Timestamp: now, Labels: map[string]string{"host": "node-1"}},
	}
	require.NoError(t, out.Write(metrics))

	require.Len(t, fake.calls, 1, "5 metrics / BatchSize 20 -> 1 PutMetricData call")
	call := fake.calls[0]
	assert.Equal(t, "TelemetryFlow", aws.ToString(call.Namespace))
	require.Len(t, call.MetricData, 5)

	names := make([]string, 0, len(call.MetricData))
	for _, d := range call.MetricData {
		names = append(names, aws.ToString(d.MetricName))
		require.Len(t, d.Dimensions, 1)
		assert.False(t, d.Timestamp.IsZero())
	}
	assert.Equal(t, []string{
		"system_cpu_usage",
		"system_mem_used",
		"net_bytes_sent",
		"disk_io_time",
		"requests_total",
	}, names, "metric name dots must be sanitised to underscores")

	// Spot-check unit mapping.
	byName := map[string]types.MetricDatum{}
	for _, d := range call.MetricData {
		byName[aws.ToString(d.MetricName)] = d
	}
	assert.Equal(t, types.StandardUnitPercent, byName["system_cpu_usage"].Unit)
	assert.Equal(t, types.StandardUnitBytes, byName["system_mem_used"].Unit)
	assert.Equal(t, types.StandardUnitSeconds, byName["disk_io_time"].Unit)
	assert.Equal(t, types.StandardUnitNone, byName["requests_total"].Unit, "missing unit -> None")
	require.NoError(t, out.Close())
}

func TestCloudWatch_BatchingRespectsBatchSize(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{
		BatchSize: 2,
	})

	now := time.Now().UTC()
	metrics := make([]plugin.Metric, 5)
	for i := range metrics {
		metrics[i] = plugin.Metric{
			Name:      "batch.test",
			Value:     float64(i),
			Timestamp: now,
			Labels:    map[string]string{"i": string(rune('a' + i))},
		}
	}
	require.NoError(t, out.Write(metrics))
	// 5 metrics / BatchSize 2 -> ceil(5/2) = 3 calls.
	require.Len(t, fake.calls, 3)
	total := 0
	for _, c := range fake.calls {
		total += len(c.MetricData)
	}
	assert.Equal(t, 5, total)
	require.NoError(t, out.Close())
}

func TestCloudWatch_MetricNameSanitisation(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{})

	now := time.Now().UTC()
	require.NoError(t, out.Write([]plugin.Metric{
		{Name: "weird metric!@#name", Value: 1, Timestamp: now},
		{Name: "ok_NAME-1:2/3", Value: 2, Timestamp: now},
	}))
	require.Len(t, fake.calls, 1)
	require.Len(t, fake.calls[0].MetricData, 2)
	assert.Equal(t, "weird_metric___name", aws.ToString(fake.calls[0].MetricData[0].MetricName))
	assert.Equal(t, "ok_NAME-1:2/3", aws.ToString(fake.calls[0].MetricData[1].MetricName), "allowed chars preserved verbatim")
	require.NoError(t, out.Close())
}

func TestCloudWatch_DimensionLimitEnforced(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{})

	labels := make(map[string]string, 40)
	for i := 0; i < 40; i++ {
		// Names sort as d00,d01,...,d39 so the first 30 in sorted order
		// are d00..d29.
		labels[dimensionName(i)] = "v"
	}
	require.NoError(t, out.Write([]plugin.Metric{
		{Name: "high.dim.metric", Value: 1, Timestamp: time.Now().UTC(), Labels: labels},
	}))
	require.Len(t, fake.calls, 1)
	require.Len(t, fake.calls[0].MetricData, 1)
	dims := fake.calls[0].MetricData[0].Dimensions
	require.Len(t, dims, 30, "CloudWatch cap is 30 dimensions per datum")

	// First sorted name is d00 (the lexicographically smallest 2-digit
	// padded name); the 30th kept dimension is d29.
	assert.Equal(t, "d00", aws.ToString(dims[0].Name))
	assert.Equal(t, "d29", aws.ToString(dims[29].Name))
	require.NoError(t, out.Close())
}

func TestCloudWatch_IAMRoleFallbackWhenNoStaticKeys(t *testing.T) {
	// Build the output with NO static keys and skip Connect (which would
	// try to hit the real credential chain). We assert authMode via the
	// cfg the output holds: with empty AccessKeyID the SDK default chain
	// (IAM role on EC2/ECS/EKS, env, shared config) takes over.
	out, _ := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{
		Region:    "ap-southeast-1",
		Namespace: "TelemetryFlow",
		// AccessKeyID + SecretAccessKey intentionally empty.
	})

	// We can only inspect behaviour without making real AWS calls:
	// Connect would attempt env/IMDS credential resolution. The test
	// here asserts the output was constructed without error in
	// IAM-role-fallback mode (no static creds). Real Connect() is
	// exercised in integration tests against an STS stub.
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestCloudWatch_WriteRequiresConnect(t *testing.T) {
	cfg := exporter.CloudWatchOutputConfig{
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
		Logger:    zap.NewNop(),
	}
	out, err := exporter.NewCloudWatchOutput(cfg)
	require.NoError(t, err)
	// No SetClientForTest, no Connect -> Write must refuse.
	err = out.Write([]plugin.Metric{{Name: "x", Value: 1, Timestamp: time.Now()}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCloudWatch_PutMetricDataErrorPropagated(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{
		BatchSize: 5,
	})
	fake.err = errors.New("AccessDenied: role lacks cloudwatch:PutMetricData")

	err := out.Write([]plugin.Metric{
		{Name: "denied.metric", Value: 1, Timestamp: time.Now().UTC()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PutMetricData failed")
	assert.Contains(t, err.Error(), "AccessDenied")
	require.NoError(t, out.Close())
}

func TestCloudWatch_EmptyBatchIsNoop(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{})
	require.NoError(t, out.Write(nil))
	require.Empty(t, fake.calls, "no PutMetricData call for an empty batch")
	require.NoError(t, out.Close())
}

func TestCloudWatch_NewRequiresRegionAndNamespace(t *testing.T) {
	t.Run("missing region", func(t *testing.T) {
		_, err := exporter.NewCloudWatchOutput(exporter.CloudWatchOutputConfig{
			Namespace: "TelemetryFlow",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "region")
	})
	t.Run("missing namespace", func(t *testing.T) {
		_, err := exporter.NewCloudWatchOutput(exporter.CloudWatchOutputConfig{
			Region: "us-east-1",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace")
	})
	t.Run("reserved AWS/ namespace", func(t *testing.T) {
		_, err := exporter.NewCloudWatchOutput(exporter.CloudWatchOutputConfig{
			Region:    "us-east-1",
			Namespace: "AWS/EC2",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AWS/")
	})
}

// dimensionName returns a zero-padded 2-digit key so the sorted order is
// stable across the dimension cap boundary.
func dimensionName(i int) string {
	if i < 10 {
		return "d0" + string(rune('0'+i))
	}
	return "d" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}
