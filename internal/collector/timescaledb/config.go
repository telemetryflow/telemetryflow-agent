package timescaledb

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.TimescaleDBCollectorConfig
}

func NewConfig(cfg config.TimescaleDBCollectorConfig) Config {
	if cfg.InstanceInterval == 0 {
		cfg.InstanceInterval = 10 * time.Second
	}
	if cfg.HypertableInterval == 0 {
		cfg.HypertableInterval = 60 * time.Second
	}
	if cfg.ChunkInterval == 0 {
		cfg.ChunkInterval = 120 * time.Second
	}
	if cfg.JobInterval == 0 {
		cfg.JobInterval = 60 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 3
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{TimescaleDBCollectorConfig: cfg}
}

func applyInstanceDefaults(inst *config.TimescaleDBInstanceConfig) {
	if inst.Port == 0 {
		inst.Port = 5432
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.User == "" {
		inst.User = "postgres"
	}
	if inst.DBName == "" {
		inst.DBName = "postgres"
	}
	if inst.SSLMode == "" {
		inst.SSLMode = "prefer"
	}
}
