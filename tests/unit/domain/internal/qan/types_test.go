// Package qan_test contains unit tests for QAN data types.
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

package qan_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

func TestQANMetricsBucket_JSONRoundTrip(t *testing.T) {
	bucket := qan.QANMetricsBucket{
		AgentType:        qan.AgentTypePostgreSQLPgStatements,
		QueryID:          "abc123",
		Fingerprint:      "fp_hash",
		Example:          "SELECT * FROM users WHERE id = ?",
		ExampleTruncated: true,
		Tables:           []string{"users"},
		PeriodStartSec:   1700000000,
		PeriodLengthSec:  60,
		Database:         "mydb",
		Username:         "app_user",
		NumQueries:       100,
		QueryTimeCnt:     100,
		QueryTimeSum:     5.5,
		QueryTimeMin:     0.01,
		QueryTimeMax:     2.5,
		QueryTimeP99:     2.0,
		Labels:           map[string]string{"env": "prod"},
		PostgreSQL: &qan.PostgreSQLQANMetrics{
			RowsCnt:          100,
			RowsSum:          5000,
			SharedBlksHitCnt: 100,
			SharedBlksHitSum: 9000,
			CmdType:          "SELECT",
		},
	}

	data, err := json.Marshal(bucket)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded qan.QANMetricsBucket
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.QueryID != bucket.QueryID {
		t.Errorf("QueryID mismatch: got %s, want %s", decoded.QueryID, bucket.QueryID)
	}
	if decoded.AgentType != bucket.AgentType {
		t.Errorf("AgentType mismatch: got %s, want %s", decoded.AgentType, bucket.AgentType)
	}
	if decoded.NumQueries != bucket.NumQueries {
		t.Errorf("NumQueries mismatch: got %f, want %f", decoded.NumQueries, bucket.NumQueries)
	}
	if decoded.PostgreSQL == nil {
		t.Fatal("PostgreSQL should not be nil")
	}
	if decoded.PostgreSQL.CmdType != "SELECT" {
		t.Errorf("CmdType mismatch: got %s, want SELECT", decoded.PostgreSQL.CmdType)
	}
	if decoded.MySQL != nil {
		t.Error("MySQL should be nil for PostgreSQL bucket")
	}
	if decoded.MongoDB != nil {
		t.Error("MongoDB should be nil for PostgreSQL bucket")
	}
}

func TestQANMetricsBucket_MySQLOmitEmpty(t *testing.T) {
	bucket := qan.QANMetricsBucket{
		AgentType: qan.AgentTypeMySQLPerfSchema,
		QueryID:   "mysql_1",
		MySQL: &qan.MySQLQANMetrics{
			RowsSentCnt:     10,
			RowsSentSum:     100,
			RowsExaminedSum: 5000,
			LockTimeSum:     0.05,
		},
	}

	data, err := json.Marshal(bucket)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded qan.QANMetricsBucket
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.MySQL == nil {
		t.Fatal("MySQL should not be nil")
	}
	if decoded.MySQL.RowsSentCnt != 10 {
		t.Errorf("RowsSentCnt mismatch: got %f, want 10", decoded.MySQL.RowsSentCnt)
	}
	if decoded.PostgreSQL != nil {
		t.Error("PostgreSQL should be nil")
	}
}

func TestQANMetricsBucket_MongoDBOmitEmpty(t *testing.T) {
	bucket := qan.QANMetricsBucket{
		AgentType: qan.AgentTypeMongoDBProfiler,
		QueryID:   "mongo_1",
		MongoDB: &qan.MongoDBQANMetrics{
			DocsReturnedSum: 500,
			DocsScannedSum:  5000,
			KeysExaminedSum: 3000,
			PlanSummary:     "IXSCAN",
		},
	}

	data, err := json.Marshal(bucket)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded qan.QANMetricsBucket
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.MongoDB == nil {
		t.Fatal("MongoDB should not be nil")
	}
	if decoded.MongoDB.PlanSummary != "IXSCAN" {
		t.Errorf("PlanSummary mismatch: got %s, want IXSCAN", decoded.MongoDB.PlanSummary)
	}
}

func TestQANMetricsBucket_OmitEmptyFields(t *testing.T) {
	// Bucket with only required fields — optional fields should be omitted from JSON
	bucket := qan.QANMetricsBucket{
		AgentType:  qan.AgentTypePostgreSQLPgStatements,
		QueryID:    "minimal",
		NumQueries: 1,
	}

	data, err := json.Marshal(bucket)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(data)

	// Verify omitempty fields are not present (check for field keys, not just substrings)
	if contains(jsonStr, "\"example\"") {
		t.Error("example should be omitted when empty")
	}
	if contains(jsonStr, "\"schema\"") {
		t.Error("schema should be omitted when empty")
	}
	if contains(jsonStr, "\"postgresql\":") {
		t.Error("postgresql should be omitted when nil")
	}
	if contains(jsonStr, "\"mysql\":") {
		t.Error("mysql should be omitted when nil")
	}
	if contains(jsonStr, "\"mongodb\":") {
		t.Error("mongodb should be omitted when nil")
	}
}

func TestCollectRequest_JSON(t *testing.T) {
	req := qan.CollectRequest{
		AgentID: "agent-001",
		Buckets: []qan.QANMetricsBucket{
			{QueryID: "q1", AgentType: qan.AgentTypePostgreSQLPgStatements},
			{QueryID: "q2", AgentType: qan.AgentTypeMySQLPerfSchema},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded qan.CollectRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.AgentID != "agent-001" {
		t.Errorf("AgentID mismatch: got %s", decoded.AgentID)
	}
	if len(decoded.Buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(decoded.Buckets))
	}
}

func TestCollectResponse_JSON(t *testing.T) {
	resp := qan.CollectResponse{
		Accepted: 95,
		Rejected: 5,
		Errors:   []string{"invalid fingerprint for bucket 3"},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded qan.CollectResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Accepted != 95 {
		t.Errorf("Accepted mismatch: got %d", decoded.Accepted)
	}
	if decoded.Rejected != 5 {
		t.Errorf("Rejected mismatch: got %d", decoded.Rejected)
	}
	if len(decoded.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(decoded.Errors))
	}
}

func TestCollectResponse_JSONOmitErrors(t *testing.T) {
	resp := qan.CollectResponse{
		Accepted: 100,
		Rejected: 0,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "errors") {
		t.Error("errors should be omitted when nil")
	}
}

func TestDefaultQANConfig(t *testing.T) {
	cfg := qan.DefaultQANConfig()

	if cfg.Enabled {
		t.Error("default QAN should be disabled")
	}
	if cfg.Interval != 60*time.Second {
		t.Errorf("default interval should be 60s, got %v", cfg.Interval)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("default batch size should be 100, got %d", cfg.BatchSize)
	}
	if cfg.FlushInterval != 10*time.Second {
		t.Errorf("default flush interval should be 10s, got %v", cfg.FlushInterval)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("default timeout should be 30s, got %v", cfg.Timeout)
	}
	if cfg.MaxRetryAttempts != 3 {
		t.Errorf("default max retry attempts should be 3, got %d", cfg.MaxRetryAttempts)
	}
	if cfg.TopQueriesLimit != 200 {
		t.Errorf("default top queries limit should be 200, got %d", cfg.TopQueriesLimit)
	}
}

func TestQANConfig_APIKeySecretOmitJSON(t *testing.T) {
	cfg := qan.QANConfig{
		Enabled:      true,
		Endpoint:     "http://example.com",
		APIKeyID:     "tfk_test",
		APIKeySecret: "tfs_secret",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "tfs_secret") {
		t.Error("APIKeySecret should be omitted from JSON output")
	}
	if !contains(jsonStr, "tfk_test") {
		t.Error("APIKeyID should be present in JSON output")
	}
}

func TestAgentType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		agent    qan.AgentType
		expected string
	}{
		{"postgresql", qan.AgentTypePostgreSQLPgStatements, "qan-postgresql-pgstatements"},
		{"mysql_perfschema", qan.AgentTypeMySQLPerfSchema, "qan-mysql-perfschema"},
		{"mongodb_profiler", qan.AgentTypeMongoDBProfiler, "qan-mongodb-profiler"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.agent) != tt.expected {
				t.Errorf("AgentType mismatch: got %s, want %s", tt.agent, tt.expected)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
