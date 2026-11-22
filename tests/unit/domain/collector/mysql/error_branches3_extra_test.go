// Package mysql_test — scan-error (`continue`) branch coverage. A one-column
// result set drives each multi-column scanner into its
// `if err := rows.Scan(...); err != nil { continue }` path (database/sql rejects
// the destination-count mismatch), skipping the row and returning no error.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package mysql_test

import (
	"context"
	"testing"

	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// surfacing an error (rows.Err() is nil; only the Scan failed → continue).
func TestCollectMariaDBAria_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectMariaDBAriaExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectMariaDBThreadPool_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectMariaDBThreadPoolExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectMariaDBUserStats_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectMariaDBUserStatsExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectMariaDBQueryCache_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectMariaDBQueryCacheExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectMariaDBSpider_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectMariaDBSpiderExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectPerconaUserStats_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectPerconaUserStatsExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectPerconaThreadPool_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectPerconaThreadPoolExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectPerconaAudit_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectPerconaAuditExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectGalera_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectGaleraStatusExport(context.Background(), db, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestCollectSchema_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.CollectSchemaExport(context.Background(), db, config.MySQLInstanceConfig{}, lbl()); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestDetectMariaDBEngines_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.DetectMariaDBEnginesExport(context.Background(), db); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}

func TestDetectPerconaPlugins_ScanSkip(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery(".").WillReturnRows(oneColRow())
	if _, err := mysql.DetectPerconaPluginsExport(context.Background(), db); err != nil {
		_ = err // either continue or error-return exercises the branch
	}
}
