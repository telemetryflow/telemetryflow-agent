package mongodb

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.MongoDBCommunityCollectorConfig
}

func NewConfig(cfg config.MongoDBCommunityCollectorConfig) Config {
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.CurrentOpInterval == 0 {
		cfg.CurrentOpInterval = 30 * time.Second
	}
	if cfg.ProfileInterval == 0 {
		cfg.ProfileInterval = 60 * time.Second
	}
	if cfg.CollStatsInterval == 0 {
		cfg.CollStatsInterval = 300 * time.Second
	}
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 60 * time.Second
	}
	if cfg.ProfileLevel == 0 {
		cfg.ProfileLevel = 1
	}
	if cfg.SlowMs == 0 {
		cfg.SlowMs = 100
	}
	return Config{MongoDBCommunityCollectorConfig: cfg}
}
