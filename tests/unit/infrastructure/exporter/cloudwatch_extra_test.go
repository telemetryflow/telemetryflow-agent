// Package exporter_test — additional CloudWatch output coverage: Name,
// Connect across all three auth modes (local AWS config load, no network),
// the full unit-mapping table, and name/label sanitisation + truncation.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package exporter_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func TestCloudWatch_Name(t *testing.T) {
	out, _ := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{})
	assert.Equal(t, "cloudwatch", out.Name())
}

// TestCloudWatch_Connect_AuthModes drives Connect through all three
// credential branches. Connect only loads the AWS config + builds a client;
// it performs no remote round-trip, so these run offline.
func TestCloudWatch_Connect_AuthModes(t *testing.T) {
	cases := []struct {
		name string
		cfg  exporter.CloudWatchOutputConfig
	}{
		{"static-keys", exporter.CloudWatchOutputConfig{
			Region: "us-east-1", Namespace: "TFO",
			AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret-example",
		}},
		{"assume-role", exporter.CloudWatchOutputConfig{
			Region: "us-east-1", Namespace: "TFO",
			RoleARN: "arn:aws:iam::123456789012:role/tfo-agent",
		}},
		{"iam-role-chain", exporter.CloudWatchOutputConfig{
			Region: "us-east-1", Namespace: "TFO",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Logger = zap.NewNop()
			out, err := exporter.NewCloudWatchOutput(tc.cfg)
			require.NoError(t, err)
			require.NoError(t, out.Connect(), "Connect loads AWS config locally")
			require.NoError(t, out.Close())
		})
	}
}

// TestCloudWatch_UnitMappingTable exercises every branch of the unit mapper
// by writing one metric per unit string and inspecting the fake's datums.
func TestCloudWatch_UnitMappingTable(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{BatchSize: 100})

	table := []struct {
		unit string
		want cwtypes.StandardUnit
	}{
		{"bytes", cwtypes.StandardUnitBytes},
		{"bytes_per_second", cwtypes.StandardUnitBytesSecond},
		{"seconds", cwtypes.StandardUnitSeconds},
		{"milliseconds", cwtypes.StandardUnitMilliseconds},
		{"microseconds", cwtypes.StandardUnitMicroseconds},
		{"percent", cwtypes.StandardUnitPercent},
		{"count", cwtypes.StandardUnitCount},
		{"count_per_second", cwtypes.StandardUnitCountSecond},
		{"bits", cwtypes.StandardUnitBits},
		{"bits_per_second", cwtypes.StandardUnitBitsSecond},
		{"gigabytes", cwtypes.StandardUnitGigabytes},
		{"megabytes", cwtypes.StandardUnitMegabytes},
		{"kilobytes", cwtypes.StandardUnitKilobytes},
		{"terabytes", cwtypes.StandardUnitTerabytes},
		{"gigabits", cwtypes.StandardUnitGigabits},
		{"megabits", cwtypes.StandardUnitMegabits},
		{"kilobits", cwtypes.StandardUnitKilobits},
		{"gigabytes_second", cwtypes.StandardUnitGigabytesSecond},
		{"megabytes_second", cwtypes.StandardUnitMegabytesSecond},
		{"kilobytes_second", cwtypes.StandardUnitKilobytesSecond},
		{"nonsense_unit", cwtypes.StandardUnitNone},
	}

	now := time.Now().UTC()
	metrics := make([]plugin.Metric, 0, len(table))
	for i, tc := range table {
		metrics = append(metrics, plugin.Metric{
			// Distinct names keep datums individually addressable.
			Name:      "unit_probe_" + string(rune('a'+i%26)) + "_" + tc.unit,
			Value:     float64(i),
			Timestamp: now,
			Unit:      tc.unit,
		})
	}
	require.NoError(t, out.Write(metrics))

	byName := map[string]cwtypes.StandardUnit{}
	for _, c := range fake.calls {
		for _, d := range c.MetricData {
			byName[aws.ToString(d.MetricName)] = d.Unit
		}
	}
	for i, tc := range table {
		name := "unit_probe_" + string(rune('a'+i%26)) + "_" + tc.unit
		assert.Equal(t, tc.want, byName[name], "unit %q", tc.unit)
	}
	require.NoError(t, out.Close())
}

// TestCloudWatch_NameAndLabelTruncation drives sanitizeCloudWatchName +
// truncateString via an over-length (>255 byte) metric name and label value.
func TestCloudWatch_NameAndLabelTruncation(t *testing.T) {
	out, fake := newCloudWatchOutputWithFake(t, exporter.CloudWatchOutputConfig{})

	longName := strings.Repeat("x", 300)   // > cloudwatchNameMaxLen (255)
	longLabelV := strings.Repeat("y", 400) // label value also truncated
	require.NoError(t, out.Write([]plugin.Metric{{
		Name:      longName,
		Value:     1,
		Timestamp: time.Now().UTC(),
		Labels:    map[string]string{"k": longLabelV},
	}}))

	require.Len(t, fake.calls, 1)
	require.Len(t, fake.calls[0].MetricData, 1)
	d := fake.calls[0].MetricData[0]
	assert.LessOrEqual(t, len(aws.ToString(d.MetricName)), 255, "metric name truncated to <=255 bytes")
	require.Len(t, d.Dimensions, 1)
	assert.LessOrEqual(t, len(aws.ToString(d.Dimensions[0].Value)), 255, "dimension value truncated to <=255 bytes")
	require.NoError(t, out.Close())
}
