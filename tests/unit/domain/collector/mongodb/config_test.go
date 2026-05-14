// Package mongodb_test contains unit tests for the corresponding collector module.
package mongodb_test

import (
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"

	mongodb "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := mongodb.NewConfig(config.MongoDBCommunityCollectorConfig{})

	if cfg.Interval != 10*time.Second {
		t.Errorf("default Interval = %v, want 10s", cfg.Interval)
	}
	if cfg.CurrentOpInterval != 30*time.Second {
		t.Errorf("default CurrentOpInterval = %v, want 30s", cfg.CurrentOpInterval)
	}
	if cfg.ProfileInterval != 60*time.Second {
		t.Errorf("default ProfileInterval = %v, want 60s", cfg.ProfileInterval)
	}
	if cfg.CollStatsInterval != 300*time.Second {
		t.Errorf("default CollStatsInterval = %v, want 300s", cfg.CollStatsInterval)
	}
}

func TestNewConfig_CustomValues(t *testing.T) {
	cfg := mongodb.NewConfig(config.MongoDBCommunityCollectorConfig{
		Interval:          15 * time.Second,
		CurrentOpInterval: 45 * time.Second,
		ProfileInterval:   120 * time.Second,
		CollStatsInterval: 600 * time.Second,
	})

	if cfg.Interval != 15*time.Second {
		t.Errorf("Interval = %v, want 15s", cfg.Interval)
	}
	if cfg.CurrentOpInterval != 45*time.Second {
		t.Errorf("CurrentOpInterval = %v, want 45s", cfg.CurrentOpInterval)
	}
	if cfg.ProfileInterval != 120*time.Second {
		t.Errorf("ProfileInterval = %v, want 120s", cfg.ProfileInterval)
	}
	if cfg.CollStatsInterval != 600*time.Second {
		t.Errorf("CollStatsInterval = %v, want 600s", cfg.CollStatsInterval)
	}
}
