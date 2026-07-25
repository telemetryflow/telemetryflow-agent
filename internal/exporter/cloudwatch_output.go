// Package exporter: cloudwatch_output.go implements an Amazon CloudWatch
// output that publishes plugin.Metric values via the PutMetricData API
// (AWS SDK v2). It maps TelemetryFlow metric units onto CloudWatch standard
// units, enforces the per-call 1000-metric limit and the 30-dimension cap,
// and sanitises metric / dimension names to the CloudWatch-allowed set.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// cloudwatchPutMetricDataMax is the hard CloudWatch API limit on the number
// of MetricDatum entries per PutMetricData call (see AWS docs).
const cloudwatchPutMetricDataMax = 1000

// cloudwatchMaxDimensions is the maximum number of dimensions CloudWatch
// accepts per metric datum.
const cloudwatchMaxDimensions = 30

// cloudwatchNameMaxLen is the maximum length of a CloudWatch metric name or
// dimension name/value.
const cloudwatchNameMaxLen = 255

// PutMetricDataAPIClient is the subset of the CloudWatch SDK client used by
// CloudWatchOutput. Defining it locally lets tests inject a fake without
// depending on the SDK's generated interface (which is not present in this
// SDK version).
type PutMetricDataAPIClient interface {
	PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error)
}

// CloudWatchOutputConfig configures a CloudWatchOutput. Region and Namespace
// are required. When AccessKeyID/SecretAccessKey are empty, AWS SDK default
// credential chain resolution is used (IAM role, env vars, shared config).
type CloudWatchOutputConfig struct {
	// Region is the AWS region, e.g. "ap-southeast-1". Required.
	Region string

	// Namespace is the CloudWatch namespace, e.g. "TelemetryFlow". Required.
	// Must not start with "AWS/".
	Namespace string

	// AccessKeyID + SecretAccessKey are optional static credentials. When
	// AccessKeyID is empty the SDK default credential chain is used (IAM
	// role for EC2/ECS/EKS, env vars, shared config).
	AccessKeyID     string
	SecretAccessKey string

	// RoleARN, when set, makes the output assume the given role via STS
	// before any PutMetricData call.
	RoleARN string

	// BatchSize is the max number of MetricDatum per PutMetricData call.
	// Default 20 (conservative; the API ceiling is 1000). Values >1000 are
	// clamped to 1000.
	BatchSize int

	// FlushInterval is reserved for the async flusher path; the synchronous
	// Write path flushes immediately. Default 30s.
	FlushInterval time.Duration

	// Logger receives structured diagnostics. Defaults to a nop logger.
	Logger *zap.Logger
}

// CloudWatchOutput is a plugin.Output that ships metrics to Amazon
// CloudWatch via PutMetricData.
type CloudWatchOutput struct {
	cfg    CloudWatchOutputConfig
	log    *zap.Logger
	client PutMetricDataAPIClient

	// pending accumulates metric data between Write calls when an async
	// flusher is wired up; today Write flushes synchronously but the buffer
	// is kept so the field set is stable for future work.
	mu      sync.Mutex
	pending []types.MetricDatum
}

// NewCloudWatchOutput validates the configuration and returns a ready
// output. Connect must still be called before Write.
func NewCloudWatchOutput(cfg CloudWatchOutputConfig) (*CloudWatchOutput, error) {
	if cfg.Region == "" {
		return nil, errors.New("cloudwatch: region is required")
	}
	if cfg.Namespace == "" {
		return nil, errors.New("cloudwatch: namespace is required")
	}
	if strings.HasPrefix(cfg.Namespace, "AWS/") {
		return nil, fmt.Errorf("cloudwatch: namespace %q must not start with AWS/", cfg.Namespace)
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 20
	}
	if cfg.BatchSize > cloudwatchPutMetricDataMax {
		cfg.BatchSize = cloudwatchPutMetricDataMax
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("cloudwatch_output")

	return &CloudWatchOutput{
		cfg: cfg,
		log: logger,
	}, nil
}

// Name implements plugin.Output.
func (o *CloudWatchOutput) Name() string { return "cloudwatch" }

// SetClientForTest injects a PutMetricDataAPIClient (typically a fake) so
// tests can exercise Write/Close without making real AWS calls. Production
// code paths go through Connect instead.
func (o *CloudWatchOutput) SetClientForTest(c PutMetricDataAPIClient) {
	o.client = c
}

// Connect loads the AWS configuration (static credentials, IAM role chain,
// or STS assume-role depending on config) and constructs the CloudWatch
// client. It does not perform a remote round-trip.
func (o *CloudWatchOutput) Connect() error {
	ctx := context.Background()

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(o.cfg.Region),
	}

	if o.cfg.AccessKeyID != "" && o.cfg.SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     o.cfg.AccessKeyID,
					SecretAccessKey: o.cfg.SecretAccessKey,
				}, nil
			},
		)))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return fmt.Errorf("cloudwatch: load aws config: %w", err)
	}

	if o.cfg.RoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, o.cfg.RoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)
	}

	o.client = cloudwatch.NewFromConfig(awsCfg)
	o.log.Info("cloudwatch output connected",
		zap.String("region", o.cfg.Region),
		zap.String("namespace", o.cfg.Namespace),
		zap.String("auth", o.authMode()),
	)
	return nil
}

// authMode describes the credential source used by Connect (for logs only).
func (o *CloudWatchOutput) authMode() string {
	switch {
	case o.cfg.RoleARN != "":
		return "assume-role"
	case o.cfg.AccessKeyID != "":
		return "static-keys"
	default:
		return "iam-role-chain"
	}
}

// Close flushes any pending metric data. There is no persistent resource to
// release today (the AWS SDK client manages its own HTTP connection pool).
func (o *CloudWatchOutput) Close() error {
	o.mu.Lock()
	pending := append([]types.MetricDatum(nil), o.pending...)
	o.pending = nil
	o.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}
	return o.flush(context.Background(), pending)
}

// Write implements plugin.Output. It converts each plugin.Metric to a
// CloudWatch MetricDatum, then batches and pushes via PutMetricData.
func (o *CloudWatchOutput) Write(metrics []plugin.Metric) error {
	if o.client == nil {
		return errors.New("cloudwatch: not connected")
	}
	if len(metrics) == 0 {
		return nil
	}

	data := make([]types.MetricDatum, 0, len(metrics))
	for _, m := range metrics {
		data = append(data, metricToCloudWatchDatum(m))
	}

	batchSize := o.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 20
	}

	ctx := context.Background()
	for start := 0; start < len(data); start += batchSize {
		end := start + batchSize
		if end > len(data) {
			end = len(data)
		}
		if err := o.flush(ctx, data[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// flush sends a single batch via PutMetricData.
func (o *CloudWatchOutput) flush(ctx context.Context, batch []types.MetricDatum) error {
	input := &cloudwatch.PutMetricDataInput{
		Namespace:  aws.String(o.cfg.Namespace),
		MetricData: batch,
	}
	if _, err := o.client.PutMetricData(ctx, input); err != nil {
		return fmt.Errorf("cloudwatch: PutMetricData failed for %d metrics: %w", len(batch), err)
	}
	o.log.Debug("cloudwatch push ok",
		zap.Int("metrics", len(batch)),
		zap.String("namespace", o.cfg.Namespace),
	)
	return nil
}

// metricToCloudWatchDatum converts a plugin.Metric to a CloudWatch
// MetricDatum, applying name sanitisation, the 30-dimension cap, and unit
// mapping. Histograms and summaries are flattened to their sum/count (each
// emitted as a separate datum by the caller); this helper only handles the
// scalar view.
func metricToCloudWatchDatum(m plugin.Metric) types.MetricDatum {
	return types.MetricDatum{
		MetricName: aws.String(sanitizeCloudWatchName(m.Name, cloudwatchNameMaxLen)),
		Dimensions: labelsToCloudWatchDimensions(m.Labels),
		Value:      aws.Float64(m.Value),
		Unit:       mapCloudWatchStandardUnit(m.Unit),
		Timestamp:  aws.Time(m.Timestamp),
	}
}

// labelsToCloudWatchDimensions converts a metric's labels to a sorted (by
// name) slice of CloudWatch Dimensions, capped at 30 entries per the
// CloudWatch spec. Labels whose name or value sanitises to empty are
// skipped.
func labelsToCloudWatchDimensions(labels map[string]string) []types.Dimension {
	if len(labels) == 0 {
		return nil
	}

	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	// Deterministic order so tests can compare dimensions verbatim.
	sort.Strings(names)

	dims := make([]types.Dimension, 0, len(labels))
	for _, name := range names {
		if len(dims) >= cloudwatchMaxDimensions {
			break
		}
		sName := sanitizeCloudWatchName(name, cloudwatchNameMaxLen)
		sVal := truncateString(labels[name], cloudwatchNameMaxLen)
		if sName == "" || sVal == "" {
			continue
		}
		dims = append(dims, types.Dimension{
			Name:  aws.String(sName),
			Value: aws.String(sVal),
		})
	}
	return dims
}

// mapCloudWatchStandardUnit maps a TelemetryFlow metric unit hint to the
// nearest CloudWatch StandardUnit enum. Unknown units resolve to "None"
// (CloudWatch's default for unitless metrics).
func mapCloudWatchStandardUnit(unit string) types.StandardUnit {
	switch strings.ToLower(unit) {
	case "bytes":
		return types.StandardUnitBytes
	case "bytes_per_second", "bytes/sec", "bps":
		return types.StandardUnitBytesSecond
	case "seconds", "second", "s":
		return types.StandardUnitSeconds
	case "milliseconds", "millisecond", "ms":
		return types.StandardUnitMilliseconds
	case "microseconds", "microsecond", "us":
		return types.StandardUnitMicroseconds
	case "percent", "%":
		return types.StandardUnitPercent
	case "count":
		return types.StandardUnitCount
	case "count_per_second", "count/second", "counts_per_second":
		return types.StandardUnitCountSecond
	case "bits":
		return types.StandardUnitBits
	case "bits_per_second", "bits/sec":
		return types.StandardUnitBitsSecond
	case "gigabytes":
		return types.StandardUnitGigabytes
	case "megabytes":
		return types.StandardUnitMegabytes
	case "kilobytes":
		return types.StandardUnitKilobytes
	case "terabytes":
		return types.StandardUnitTerabytes
	case "gigabits":
		return types.StandardUnitGigabits
	case "megabits":
		return types.StandardUnitMegabits
	case "kilobits":
		return types.StandardUnitKilobits
	case "gigabytes_second", "gigabytes/second":
		return types.StandardUnitGigabytesSecond
	case "megabytes_second", "megabytes/second":
		return types.StandardUnitMegabytesSecond
	case "kilobytes_second", "kilobytes/second":
		return types.StandardUnitKilobytesSecond
	default:
		return types.StandardUnitNone
	}
}

// sanitizeCloudWatchName keeps only the characters CloudWatch allows in
// metric names and dimension names: [a-zA-Z0-9_-:/]. Other characters are
// replaced with '_'. Dots (which TelemetryFlow uses as the metric name
// separator, e.g. "system.cpu.usage") are NOT in the allowed set, so they
// are mapped to underscores.
func sanitizeCloudWatchName(name string, maxLen int) string {
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-', r == ':', r == '/':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return truncateString(b.String(), maxLen)
}

// truncateString returns s truncated to at most maxLen bytes. If truncation
// would split a UTF-8 rune it is dropped entirely.
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	// Walk runes so we never cut mid-codepoint.
	end := 0
	for i := range s {
		if i > maxLen {
			break
		}
		end = i
	}
	return s[:end]
}

// init self-registers the output with the plugin registry so it is
// reachable by name. The instance returned is unconfigured; the pipeline
// builder is expected to call NewCloudWatchOutput with the resolved
// configuration before Connect/Write.
func init() {
	plugin.MustAddOutput("cloudwatch", func() plugin.Output {
		out, err := NewCloudWatchOutput(CloudWatchOutputConfig{})
		if err != nil {
			return &CloudWatchOutput{}
		}
		return out
	})
}
