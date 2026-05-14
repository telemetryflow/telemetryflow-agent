package mssql

import (
	"database/sql"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type mssqlInstance struct {
	config        config.MSSQLInstanceConfig
	db            *sql.DB
	version       string
	engineEdition int
	prevCounters  map[string]float64
	prevTimestamp time.Time
	backoff       time.Duration
	lastConnErr   time.Time
}
