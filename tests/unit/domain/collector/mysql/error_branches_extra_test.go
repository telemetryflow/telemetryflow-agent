// Package mysql_test — extra sqlmock-driven tests covering the scan-error
// (`continue`) and rows.Err() branches of the MySQL collect* functions that
// the happy-path tests do not reach. No live DB; deterministic go-sqlmock only.
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
)

// oneColRow returns a single-column result set. Functions that Scan into two or
// more destinations hit their `if err := rows.Scan(...); err != nil { continue }`
// branch because database/sql rejects the destination-count mismatch.
func oneColRow() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"only"}).AddRow("x")
}

// --- scan-error (continue) branches ----------------------------------------

func TestCollectGlobalStatus_ScanError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnRows(oneColRow())
	rows, _, err := mysql.CollectGlobalStatusExport(context.Background(), db)
	if err != nil {
		t.Fatalf("scan-error row must be skipped, not errored: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("scan-error row must be skipped, got %d rows", len(rows))
	}
}

func TestCollectGlobalVariables_ScanError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL VARIABLES").WillReturnRows(oneColRow())
	vars, err := mysql.CollectGlobalVariablesExport(context.Background(), db)
	if err != nil {
		t.Fatalf("scan-error row must be skipped: %v", err)
	}
	if len(vars) != 0 {
		t.Fatalf("scan-error row must be skipped, got %d vars", len(vars))
	}
}

// --- rows.Err() branches ----------------------------------------------------

func TestCollectGlobalStatus_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threads_connected", "1").RowError(0, errBoom))
	if _, _, err := mysql.CollectGlobalStatusExport(context.Background(), db); err == nil {
		t.Fatal("expected rows.Err() to surface")
	}
}

func TestCollectGlobalVariables_RowsErr(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL VARIABLES").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("version", "8.0").RowError(0, errBoom))
	if _, err := mysql.CollectGlobalVariablesExport(context.Background(), db); err == nil {
		t.Fatal("expected rows.Err() to surface")
	}
}
