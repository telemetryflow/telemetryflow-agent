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
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestCollectVacuumWorkers(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(2)))
	metrics, err := postgresql.CollectVacuumWorkersExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_activity").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectVacuumWorkersExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectVacuumProgress(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_progress_vacuum").
		WillReturnRows(pgxmock.NewRows([]string{
			"table_name", "phase", "heap_blks_total", "heap_blks_scanned",
			"heap_blks_vacuumed", "index_vacuum_count", "max_dead_tuples", "num_dead_tuples",
		}).AddRow("public.orders", "scanning heap", int64(1000), int64(500), int64(400), int64(1), int64(10000), int64(500)))
	metrics, err := postgresql.CollectVacuumProgressExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_progress_vacuum").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectVacuumProgressExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectXIDAge(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "xid_age", "freeze_max"}).
			AddRow("mydb", int64(1000000), int64(200000000)))
	metrics, err := postgresql.CollectXIDAgeExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_database").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectXIDAgeExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectDeadTuples(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}).
			AddRow("public", "orders", int64(500), int64(9500)))
	metrics, err := postgresql.CollectDeadTuplesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 3 {
		t.Errorf("expected 3 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectDeadTuplesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectVacuumConfig(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("autovacuum", "on").
			AddRow("autovacuum_vacuum_threshold", "50"))
	metrics, err := postgresql.CollectVacuumConfigExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_settings").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectVacuumConfigExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectTableXIDAge(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_class").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "xid_age"}).
			AddRow("public", "orders", int64(500000)))
	metrics, err := postgresql.CollectTableXIDAgeExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_class").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectTableXIDAgeExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectVacuumNeeded(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("autovacuum_vacuum_threshold").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(50)))
	mock.ExpectQuery("autovacuum_vacuum_scale_factor").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(float64(0.2)))
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}).
			AddRow("public", "orders", int64(5000), int64(10000)))
	metrics, err := postgresql.CollectVacuumNeededExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}
}

func TestCollectVacuumNeeded_SettingsFallback(t *testing.T) {
	mock := newMockPool(t)
	// both settings queries error -> defaults applied
	mock.ExpectQuery("autovacuum_vacuum_threshold").WillReturnError(errors.New("denied"))
	mock.ExpectQuery("autovacuum_vacuum_scale_factor").WillReturnError(errors.New("denied"))
	mock.ExpectQuery("pg_stat_user_tables").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectVacuumNeededExported(context.Background(), mock, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error from tables query")
	}
}

func TestCollectDeadTupleRate(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.DeadTuplePrev = 1000
	inst.DeadTuplePrevTime = time.Now().Add(-10 * time.Second)

	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"sum"}).AddRow(int64(2500)))
	metrics, err := postgresql.CollectDeadTupleRateExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 rate metric, got %d", len(metrics))
	}

	// first cycle (no prev time) -> no metric
	mock2 := newMockPool(t)
	inst2 := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	mock2.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"sum"}).AddRow(int64(500)))
	metrics2, err := postgresql.CollectDeadTupleRateExported(context.Background(), mock2, inst2, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics2) != 0 {
		t.Errorf("expected no metric on first cycle, got %d", len(metrics2))
	}

	mock3 := newMockPool(t)
	mock3.ExpectQuery("pg_stat_user_tables").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectDeadTupleRateExported(context.Background(), mock3, inst, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectSubscriptionMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_subscription").
		WillReturnRows(pgxmock.NewRows([]string{"subname", "lsn", "lag_interval"}).
			AddRow("sub1", "0/1", float64(1.5)))
	metrics, err := postgresql.CollectSubscriptionMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}
}

func TestCollectSubscriptionMetrics_NoView(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
	metrics, err := postgresql.CollectSubscriptionMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics, got %d", len(metrics))
	}
}

func TestCollectSubscriptionMetrics_QueryError(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_subscription").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectSubscriptionMetricsExported(context.Background(), mock, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectVacuumMetrics_Umbrella(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery("pg_stat_progress_vacuum").
		WillReturnRows(pgxmock.NewRows([]string{
			"table_name", "phase", "heap_blks_total", "heap_blks_scanned",
			"heap_blks_vacuumed", "index_vacuum_count", "max_dead_tuples", "num_dead_tuples",
		}).AddRow("public.t", "scanning heap", int64(10), int64(5), int64(3), int64(0), int64(100), int64(5)))
	mock.ExpectQuery("pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "xid_age", "freeze_max"}).
			AddRow("mydb", int64(1000), int64(200000000)))
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}).
			AddRow("public", "t", int64(10), int64(90)))
	mock.ExpectQuery("pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).AddRow("autovacuum", "on"))
	mock.ExpectQuery("pg_class").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "xid_age"}).AddRow("public", "t", int64(100)))
	// vacuum needed: two settings + tables
	mock.ExpectQuery("autovacuum_vacuum_threshold").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(50)))
	mock.ExpectQuery("autovacuum_vacuum_scale_factor").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(float64(0.2)))
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}).
			AddRow("public", "t", int64(10), int64(90)))
	// dead tuple rate
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{"sum"}).AddRow(int64(10)))
	// subscription metrics
	mock.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	metrics, err := postgresql.CollectVacuumMetricsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}
