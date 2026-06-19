// Package qan_test contains unit tests for QAN config validation.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package qan_test

import (
	"strings"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// validBase returns a QANConfig that passes validation. Individual cases
// mutate one field to trigger the condition under test.
func validBase() qan.QANConfig {
	return qan.QANConfig{
		Enabled:          true,
		Endpoint:         "http://localhost:3000",
		Interval:         60 * time.Second,
		FlushInterval:    10 * time.Second,
		Timeout:          30 * time.Second,
		BatchSize:        100,
		MaxRetryAttempts: 3,
		TopQueriesLimit:  200,
	}
}

func TestQANConfig_Validate_DisabledNoOp(t *testing.T) {
	// When disabled, validation must never fail regardless of other fields.
	cfg := qan.QANConfig{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config should be a no-op, got error: %v", err)
	}
}

func TestQANConfig_Validate_HappyPath(t *testing.T) {
	if err := validBase().Validate(); err != nil {
		t.Fatalf("valid config should pass, got error: %v", err)
	}
}

func TestQANConfig_Validate_RequiresEndpointWhenEnabled(t *testing.T) {
	cfg := validBase()
	cfg.Endpoint = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when enabled and endpoint empty, got nil")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("error should mention endpoint, got: %v", err)
	}
}

func TestQANConfig_Validate_RejectsZeroInterval(t *testing.T) {
	cfg := validBase()
	cfg.Interval = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero interval, got nil")
	}
}

func TestQANConfig_Validate_RejectsSubSecondIntervals(t *testing.T) {
	cases := map[string]func(cfg *qan.QANConfig){
		"flush_interval": func(c *qan.QANConfig) { c.FlushInterval = 100 * time.Millisecond },
		"timeout":        func(c *qan.QANConfig) { c.Timeout = 0 },
		"interval":       func(c *qan.QANConfig) { c.Interval = 500 * time.Millisecond },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validBase()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", name)
			}
		})
	}
}

func TestQANConfig_Validate_RejectsBadCounts(t *testing.T) {
	cases := map[string]func(cfg *qan.QANConfig){
		"batch_size_zero":     func(c *qan.QANConfig) { c.BatchSize = 0 },
		"batch_size_negative": func(c *qan.QANConfig) { c.BatchSize = -1 },
		"top_queries_zero":    func(c *qan.QANConfig) { c.TopQueriesLimit = 0 },
		"retry_negative":      func(c *qan.QANConfig) { c.MaxRetryAttempts = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validBase()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", name)
			}
		})
	}
}

func TestDefaultQANConfig_DisabledByDefault(t *testing.T) {
	// The default must keep QAN off so the path has zero overhead until opted in.
	if qan.DefaultQANConfig().Enabled {
		t.Fatal("default QAN config must have Enabled=false for zero-overhead guarantee")
	}
}

func TestDefaultQANConfig_PassesValidation(t *testing.T) {
	// Default (disabled) config must pass validation.
	if err := qan.DefaultQANConfig().Validate(); err != nil {
		t.Fatalf("default config must validate cleanly, got: %v", err)
	}
}
