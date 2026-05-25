// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

package postgresql

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type pgInstance struct {
	config          config.PostgreSQLInstanceConfig
	pool            *pgxpool.Pool
	version         int
	versionStr      string
	flavor          string
	prevCounters    map[string]uint64
	prevTimestamp   time.Time
	backoff         time.Duration
	lastConnErr     time.Time
	topQueriesLimit int
	topTablesLimit  int

	// deadTuplePrev tracks the previous sum(n_dead_tup) for rate computation.
	deadTuplePrev uint64
	// deadTuplePrevTime is the timestamp of the previous dead-tuple measurement.
	deadTuplePrevTime time.Time
}
