// Package integrations_test — additional coverage for the Validate() branches
// of the integration exporters. These are pure, network-free config checks, so
// the tests exercise every disabled/missing-field/valid path deterministically.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package integrations_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func TestSNMPExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	tests := []struct {
		name    string
		config  integrations.SNMPConfig
		wantErr bool
	}{
		{"disabled", integrations.SNMPConfig{Enabled: false}, false},
		{"no targets", integrations.SNMPConfig{Enabled: true}, true},
		{"empty address", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: ""}}}, true},
		{"v3 no username", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: "1.2.3.4"}}, Version: "v3"}, true},
		{"v3 authNoPriv no auth_password", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: "1.2.3.4"}}, Version: "v3", Username: "u", SecurityLevel: "authNoPriv"}, true},
		{"v3 authPriv no priv_password", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: "1.2.3.4"}}, Version: "v3", Username: "u", SecurityLevel: "authPriv", AuthPassword: "a"}, true},
		{"v3 valid authPriv", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: "1.2.3.4"}}, Version: "v3", Username: "u", SecurityLevel: "authPriv", AuthPassword: "a", PrivPassword: "p"}, false},
		{"v2 valid", integrations.SNMPConfig{Enabled: true, Targets: []integrations.SNMPTarget{{Address: "1.2.3.4"}}, Version: "v2c"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := integrations.NewSNMPExporter(tt.config, log).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrometheusExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	tests := []struct {
		name    string
		config  integrations.PrometheusConfig
		wantErr bool
	}{
		{"disabled", integrations.PrometheusConfig{Enabled: false}, false},
		{"empty endpoint", integrations.PrometheusConfig{Enabled: true}, true},
		{"bad scheme", integrations.PrometheusConfig{Enabled: true, Endpoint: "ftp://x"}, true},
		{"valid http", integrations.PrometheusConfig{Enabled: true, Endpoint: "http://localhost:9090"}, false},
		{"valid https", integrations.PrometheusConfig{Enabled: true, Endpoint: "https://localhost:9090"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := integrations.NewPrometheusExporter(tt.config, log).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSplunkExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	tests := []struct {
		name    string
		config  integrations.SplunkConfig
		wantErr bool
	}{
		{"disabled", integrations.SplunkConfig{Enabled: false}, false},
		{"no endpoint", integrations.SplunkConfig{Enabled: true}, true},
		{"no token", integrations.SplunkConfig{Enabled: true, HECEndpoint: "http://x"}, true},
		{"valid", integrations.SplunkConfig{Enabled: true, HECEndpoint: "http://x", HECToken: "t"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := integrations.NewSplunkExporter(tt.config, log).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOpenObserveExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	tests := []struct {
		name    string
		config  integrations.OpenObserveConfig
		wantErr bool
	}{
		{"disabled", integrations.OpenObserveConfig{Enabled: false}, false},
		{"no username", integrations.OpenObserveConfig{Enabled: true}, true},
		{"no password", integrations.OpenObserveConfig{Enabled: true, Username: "u"}, true},
		{"valid", integrations.OpenObserveConfig{Enabled: true, Username: "u", Password: "p"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := integrations.NewOpenObserveExporter(tt.config, log).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDatadogExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	tests := []struct {
		name    string
		config  integrations.DatadogConfig
		wantErr bool
	}{
		{"disabled", integrations.DatadogConfig{Enabled: false}, false},
		{"no api key", integrations.DatadogConfig{Enabled: true}, true},
		{"short api key", integrations.DatadogConfig{Enabled: true, APIKey: "short"}, true},
		{"valid api key", integrations.DatadogConfig{Enabled: true, APIKey: "0123456789abcdef0123456789abcdef"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := integrations.NewDatadogExporter(tt.config, log).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInstanaExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	// disabled → nil regardless of key
	require.NoError(t, integrations.NewInstanaExporter(integrations.InstanaConfig{Enabled: false}, log).Validate())
	// enabled + missing agent key → error
	assert.Error(t, integrations.NewInstanaExporter(integrations.InstanaConfig{Enabled: true}, log).Validate())
	// enabled + agent key → nil
	assert.NoError(t, integrations.NewInstanaExporter(integrations.InstanaConfig{Enabled: true, AgentKey: "k"}, log).Validate())
}

func TestNetdataExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	// NetdataConfig.Validate always nil; exporter.Validate nil enabled or not.
	require.NoError(t, (&integrations.NetdataConfig{}).Validate())
	assert.NoError(t, integrations.NewNetdataExporter(integrations.NetdataConfig{Enabled: false}, log).Validate())
	assert.NoError(t, integrations.NewNetdataExporter(integrations.NetdataConfig{Enabled: true}, log).Validate())
}

func TestSigNozExporterValidateBranches(t *testing.T) {
	log := zap.NewNop()
	assert.NoError(t, integrations.NewSigNozExporter(integrations.SigNozConfig{Enabled: false}, log).Validate())
	assert.NoError(t, integrations.NewSigNozExporter(integrations.SigNozConfig{Enabled: true}, log).Validate())
}
