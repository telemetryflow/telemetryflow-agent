// Package mysql_test — rows.Err() branch coverage for the MariaDB / Percona /
// schema / replication / QAN collect* functions. A single result row with
// RowError(0) makes rows.Next() stop immediately and rows.Err() return non-nil,
// exercising each function's final `rows.Err()` path without a live DB.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package mysql_test

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// rowErr returns a one-row result set whose iteration fails at row 0, so the
// caller's `rows.Err()` check returns errBoom.
func rowErr() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"a", "b"}).AddRow("x", "y").RowError(0, errBoom)
}

func lbl() map[string]string { return map[string]string{"mysql_instance": "t"} }

// Each function issues one primary query; a lax "." matcher avoids pinning the
// exact SQL. Functions that return rows.Err() surface errBoom; functions that
// swallow it still execute the branch. We only require no panic + (where the
// function returns the error) a non-nil err.

// --- explicit per-function rows.Err() tests --------------------------------

func TestCollectMariaDBAria_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectMariaDBAriaExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectMariaDBThreadPool_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectMariaDBThreadPoolExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectMariaDBUserStats_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectMariaDBUserStatsExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectMariaDBMultiSourceReplication_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectMariaDBMultiSourceReplicationExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectMariaDBQueryCache_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectMariaDBQueryCacheExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectPerconaUserStats_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectPerconaUserStatsExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectPerconaThreadPool_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectPerconaThreadPoolExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectPerconaAudit_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectPerconaAuditExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectGalera_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectGaleraStatusExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectReplication_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectReplicationStatusExport(context.Background(), db, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestCollectSchema_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.CollectSchemaExport(context.Background(), db, config.MySQLInstanceConfig{}, lbl()); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestDetectMariaDBEngines_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.DetectMariaDBEnginesExport(context.Background(), db); err == nil {
		t.Fatal("expected rows.Err()")
	}
}

func TestDetectPerconaPlugins_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(rowErr())
	if _, err := mysql.DetectPerconaPluginsExport(context.Background(), db); err == nil {
		t.Fatal("expected rows.Err()")
	}
}
