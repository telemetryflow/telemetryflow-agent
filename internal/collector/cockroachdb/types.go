package cockroachdb

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type crdbInstance struct {
	config        config.CockroachDBInstanceConfig
	pool          *pgxpool.Pool
	version       string
	clusterID     string
	nodeID        int
	prevCounters  map[string]uint64
	prevTimestamp time.Time
	backoff       time.Duration
	lastConnErr   time.Time
	topStmtsLimit int
}
