package mssql

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.MSSQLCollectorConfig
}

func NewConfig(cfg config.MSSQLCollectorConfig) Config {
	if cfg.MetricsInterval == 0 {
		cfg.MetricsInterval = 15 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.IndexInterval == 0 {
		cfg.IndexInterval = 300 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 3
	}
	if cfg.TopQueriesLimit == 0 {
		cfg.TopQueriesLimit = 50
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{MSSQLCollectorConfig: cfg}
}

func applyInstanceDefaults(inst *config.MSSQLInstanceConfig) {
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.Port == 0 {
		inst.Port = 1433
	}
	if inst.AuthType == "" {
		inst.AuthType = "sql_server"
	}
	if inst.Username == "" && inst.AuthType == "sql_server" {
		inst.Username = "sa"
	}
	if inst.Database == "" {
		inst.Database = "master"
	}
	if inst.Encrypt == "" {
		inst.Encrypt = "true"
	}
	if inst.CollectionIntervalSeconds == 0 {
		inst.CollectionIntervalSeconds = 15
	}
}
