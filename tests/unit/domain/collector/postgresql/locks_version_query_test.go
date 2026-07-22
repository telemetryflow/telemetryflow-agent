// Package postgresql_test contains unit tests for the corresponding collector module.
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

package postgresql_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestCollectLocksByType(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"locktype", "cnt"}).
			AddRow("relation", int64(5)).
			AddRow("tuple", int64(2)))
	metrics, err := postgresql.CollectLocksByTypeExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_locks").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectLocksByTypeExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectLocksByMode(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).
			AddRow("AccessShareLock", int64(8)))
	metrics, err := postgresql.CollectLocksByModeExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_locks").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectLocksByModeExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectBlockedQueryMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"blocked_count", "longest_wait_sec"}).
			AddRow(int64(3), float64(12.5)))
	metrics, err := postgresql.CollectBlockedQueryMetricsExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_locks").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectBlockedQueryMetricsExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectLockMetrics_Umbrella(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"locktype", "cnt"}).AddRow("relation", int64(1)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("ExclusiveLock", int64(1)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"blocked_count", "longest_wait_sec"}).AddRow(int64(0), float64(0)))
	metrics, err := postgresql.CollectLockMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}

func TestDetectVersion(t *testing.T) {
	tests := []struct {
		name       string
		versionStr string
		wantFlavor string
	}{
		{"plain", "15.2", "postgresql"},
		{"aws", "15.2 (aws)", "aws-rds"},
		{"azure", "13.4 azure", "azure"},
		{"gcp", "14.1 google cloudsql", "gcp-cloudsql"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockPool(t)
			inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
			mock.ExpectQuery("server_version_num").
				WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(int64(150002)))
			mock.ExpectQuery("server_version").
				WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(tc.versionStr))

			ver, verStr, flavor, err := postgresql.DetectVersionExported(context.Background(), mock, inst)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ver != 150002 {
				t.Errorf("version = %d, want 150002", ver)
			}
			if verStr != tc.versionStr {
				t.Errorf("versionStr = %q, want %q", verStr, tc.versionStr)
			}
			if flavor != tc.wantFlavor {
				t.Errorf("flavor = %q, want %q", flavor, tc.wantFlavor)
			}
		})
	}
}

func TestDetectVersion_Error(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	mock.ExpectQuery("server_version_num").WillReturnError(errors.New("boom"))
	if _, _, _, err := postgresql.DetectVersionExported(context.Background(), mock, inst); err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectVersion_ShowFails(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	mock.ExpectQuery("server_version_num").
		WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(int64(160000)))
	mock.ExpectQuery("server_version").WillReturnError(errors.New("denied"))

	ver, verStr, _, err := postgresql.DetectVersionExported(context.Background(), mock, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != 160000 {
		t.Errorf("version = %d, want 160000", ver)
	}
	if verStr != "160000" {
		t.Errorf("versionStr = %q, want fallback 160000", verStr)
	}
}
