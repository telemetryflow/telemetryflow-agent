// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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

package mysql

import (
	"database/sql"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type mysqlInstance struct {
	config        config.MySQLInstanceConfig
	db            *sql.DB
	flavor        string
	version       string
	prevStatus    map[string]uint64
	prevTimestamp time.Time
	prevDigests   map[string]*digestSnapshot
	backoff       time.Duration
	lastConnErr   time.Time
	mariadb       *mariaDBExtension
	percona       *perconaExtension
}

type mariaDBExtension struct {
	queryCacheEnabled       bool
	ariaStatsEnabled        bool
	columnStoreStatsEnabled bool
	spiderStatsEnabled      bool
	threadPoolStatsEnabled  bool
	userStatsEnabled        bool
	detectedEngines         map[string]bool
	detectedPlugins         map[string]bool
}

type perconaExtension struct {
	queryResponseTimeEnabled bool
	userStatsEnabled         bool
	enhancedSlowQueryEnabled bool
	pxcMetricsEnabled        bool
	auditMetricsEnabled      bool
	detectedPlugins          map[string]bool
}

type qrtBucket struct {
	timeRange string
	count     uint64
	total     float64
}

type digestSnapshot struct {
	CountStar    uint64
	SumTimerWait uint64
	SumRowsSent  uint64
	SumRowsExam  uint64
}
