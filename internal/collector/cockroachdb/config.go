package cockroachdb

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.CockroachDBCollectorConfig
}

func NewConfig(cfg config.CockroachDBCollectorConfig) Config {
	if cfg.InstanceInterval == 0 {
		cfg.InstanceInterval = 15 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.RangeInterval == 0 {
		cfg.RangeInterval = 30 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 3
	}
	if cfg.TopStatementsLimit == 0 {
		cfg.TopStatementsLimit = 200
	}
	for i := range cfg.Instances {
		applyInstanceDefaults(&cfg.Instances[i])
	}
	return Config{CockroachDBCollectorConfig: cfg}
}

func applyInstanceDefaults(inst *config.CockroachDBInstanceConfig) {
	if inst.SQLPort == 0 {
		inst.SQLPort = 26257
	}
	if inst.AdminPort == 0 {
		inst.AdminPort = 8080
	}
	if inst.Host == "" {
		inst.Host = "localhost"
	}
	if inst.User == "" {
		inst.User = "root"
	}
	if inst.Database == "" {
		inst.Database = "system"
	}
	if inst.SSLMode == "" {
		inst.SSLMode = "disable"
	}
}
