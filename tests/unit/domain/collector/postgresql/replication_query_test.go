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
)

var replLagCols = []string{
	"pid", "usename", "application_name", "client_addr", "state",
	"sent_lsn", "write_lsn", "flush_lsn", "replay_lsn",
	"write_lag", "flush_lag", "replay_lag",
}

func TestCollectReplicationLagBytes(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("standby1", "10.0.0.2", "streaming", int64(4096)))
	metrics, err := postgresql.CollectReplicationLagBytesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_replication").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectReplicationLagBytesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectReplicationLag(t *testing.T) {
	mock := newMockPool(t)
	// primary lag query (nil lag durations -> only pid metric emitted per row)
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			int32(1234), "repl", "standby1", "10.0.0.2", "streaming",
			"0/1", "0/1", "0/1", "0/1",
			nil, nil, nil,
		))
	// byte-lag follow-up query
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("standby1", "10.0.0.2", "streaming", int64(2048)))

	metrics, err := postgresql.CollectReplicationLagExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_replication").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectReplicationLagExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectReplicationSlots(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_replication_slots").
		WillReturnRows(pgxmock.NewRows([]string{"slot_name", "slot_type", "active", "retained_bytes"}).
			AddRow("slot1", "physical", true, int64(8192)).
			AddRow("slot2", "logical", false, int64(0)))
	metrics, err := postgresql.CollectReplicationSlotsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 4 {
		t.Errorf("expected 4 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_replication_slots").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectReplicationSlotsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectReplicationMetrics_Standby(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_is_in_recovery").
		WillReturnRows(pgxmock.NewRows([]string{"r"}).AddRow(true))
	metrics, err := postgresql.CollectReplicationMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics on standby, got %d", len(metrics))
	}
}

func TestCollectReplicationMetrics_RecoveryCheckError(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_is_in_recovery").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectReplicationMetricsExported(context.Background(), mock, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectReplicationMetrics_Primary(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_is_in_recovery").
		WillReturnRows(pgxmock.NewRows([]string{"r"}).AddRow(false))
	// lag
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			int32(1), "repl", "s1", "10.0.0.2", "streaming",
			"0/1", "0/1", "0/1", "0/1", nil, nil, nil))
	// lag bytes
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("s1", "10.0.0.2", "streaming", int64(100)))
	// slots
	mock.ExpectQuery("pg_replication_slots").
		WillReturnRows(pgxmock.NewRows([]string{"slot_name", "slot_type", "active", "retained_bytes"}).
			AddRow("slot1", "physical", true, int64(10)))

	metrics, err := postgresql.CollectReplicationMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics on primary")
	}
}
