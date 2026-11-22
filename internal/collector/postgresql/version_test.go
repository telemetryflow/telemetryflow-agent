// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License").

package postgresql

import "testing"

// pg_stat_statements renamed blk_read_time/blk_write_time to the shared_/local_
// split only in version 1.11, which ships with PostgreSQL 17. PG16 and earlier
// still expose the original columns, so querying shared_blk_read_time there fails
// with SQLSTATE 42703. These tests pin the version boundary so the regression
// (previously gated at >= 150000, which broke QAN on postgres:16) cannot return.
func TestHasSplitBlkTimeColumns(t *testing.T) {
	cases := []struct {
		name       string
		versionNum int
		want       bool
	}{
		{"unknown/0 falls back to legacy", 0, false},
		{"PG13 legacy columns", 130000, false},
		{"PG14 legacy columns", 140000, false},
		{"PG15 legacy columns", 150000, false},
		{"PG16 legacy columns", 160000, false},
		{"PG16.4 legacy columns", 160004, false},
		{"PG17 split columns", 170000, true},
		{"PG18 split columns", 180000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasSplitBlkTimeColumns(tc.versionNum); got != tc.want {
				t.Fatalf("hasSplitBlkTimeColumns(%d) = %v, want %v", tc.versionNum, got, tc.want)
			}
		})
	}
}

func TestBlkTimeColumns(t *testing.T) {
	legacy := "blk_read_time, blk_write_time"
	split := "(shared_blk_read_time + local_blk_read_time) AS blk_read_time, " +
		"(shared_blk_write_time + local_blk_write_time) AS blk_write_time"

	cases := []struct {
		name       string
		versionNum int
		want       string
	}{
		{"PG16 uses legacy blk_read_time", 160000, legacy},
		{"PG17 uses shared_/local_ split aliased to blk_read_time", 170000, split},
		{"unknown/0 uses legacy", 0, legacy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blkTimeColumns(tc.versionNum); got != tc.want {
				t.Fatalf("blkTimeColumns(%d) = %q, want %q", tc.versionNum, got, tc.want)
			}
		})
	}
}
