// Package exporter_test contains additional unit tests for OTLP exporter
// construction covering TLS, auth, compression, and endpoint-path branches.
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
package exporter_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func fullFeaturedConfig(protocol string) exporter.OTLPExporterConfig {
	return exporter.OTLPExporterConfig{
		AgentID:             "agent-1",
		AgentName:           "tfo-agent",
		Hostname:            "host-1",
		Environment:         "prod",
		Version:             "1.2.3",
		Tags:                map[string]string{"environment": "prod", "region": "id"},
		Labels:              map[string]string{"team": "obs"},
		Endpoint:            "127.0.0.1:4317",
		Protocol:            protocol,
		APIKeyID:            "key-id",
		APIKeySecret:        "key-secret",
		TLSEnabled:          true,
		TLSSkipVerify:       true,
		Compression:         true,
		BatchSize:           10,
		FlushInterval:       time.Second,
		Timeout:             2 * time.Second,
		EndpointVersion:     "v2",
		MetricsEndpointPath: "/v2/metrics",
		TracesEndpointPath:  "/v2/traces",
		LogsEndpointPath:    "/v2/logs",
		MetricsEnabled:      true,
		TracesEnabled:       true,
		LogsEnabled:         true,
		Logger:              zap.NewNop(),
	}
}

func TestOTLPExporter_StartWithFullFeaturesHTTP(t *testing.T) {
	e := exporter.NewOTLPExporter(fullFeaturedConfig("http"))
	ctx := context.Background()
	require.NoError(t, e.Start(ctx))
	// Starting again returns an error.
	require.Error(t, e.Start(ctx))
	require.True(t, e.IsRunning())
	_ = e.Stop(ctx)
	require.False(t, e.IsRunning())
	// Stop when not running is a no-op.
	require.NoError(t, e.Stop(ctx))
}

func TestOTLPExporter_StartWithFullFeaturesGRPC(t *testing.T) {
	e := exporter.NewOTLPExporter(fullFeaturedConfig("grpc"))
	ctx := context.Background()
	require.NoError(t, e.Start(ctx))
	require.NotNil(t, e.Meter())
	require.NotNil(t, e.Tracer())
	require.NotNil(t, e.LoggerProvider())
	_ = e.Stop(ctx)
}

func TestOTLPExporter_UnsupportedProtocol(t *testing.T) {
	cfg := fullFeaturedConfig("bogus")
	cfg.TracesEnabled = false
	cfg.LogsEnabled = false
	e := exporter.NewOTLPExporter(cfg)
	require.Error(t, e.Start(context.Background()))
}

func TestOTLPExporter_UnsupportedProtocolTraces(t *testing.T) {
	cfg := fullFeaturedConfig("bogus")
	cfg.MetricsEnabled = false
	cfg.LogsEnabled = false
	e := exporter.NewOTLPExporter(cfg)
	require.Error(t, e.Start(context.Background()))
}

func TestOTLPExporter_UnsupportedProtocolLogs(t *testing.T) {
	cfg := fullFeaturedConfig("bogus")
	cfg.MetricsEnabled = false
	cfg.TracesEnabled = false
	e := exporter.NewOTLPExporter(cfg)
	require.Error(t, e.Start(context.Background()))
}
