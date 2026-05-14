package sqlite3

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Config struct {
	config.SQLite3CollectorConfig
}

func NewConfig(cfg config.SQLite3CollectorConfig) Config {
	if cfg.CollectionInterval == 0 {
		cfg.CollectionInterval = 60 * time.Second
	}
	if cfg.TableStatsInterval == 0 {
		cfg.TableStatsInterval = 300 * time.Second
	}
	if cfg.ProcessInterval == 0 {
		cfg.ProcessInterval = 120 * time.Second
	}
	if cfg.IntegrityInterval == 0 {
		cfg.IntegrityInterval = 0 // disabled by default
	}
	if cfg.IntegrityTimeout == 0 {
		cfg.IntegrityTimeout = 300 * time.Second
	}
	for i := range cfg.Databases {
		applyDatabaseDefaults(&cfg.Databases[i])
	}
	return Config{SQLite3CollectorConfig: cfg}
}

func applyDatabaseDefaults(db *config.SQLite3DatabaseConfig) {
	if db.Name == "" && db.Path != "" {
		db.Name = db.Path
	}
}
