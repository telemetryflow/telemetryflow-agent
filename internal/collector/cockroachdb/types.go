package cockroachdb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// PgxQuerier abstracts the query surface of a pgx connection pool. Both
// *pgxpool.Pool and pgxmock's mock pool satisfy it, enabling deterministic
// unit tests of the query-scanning paths without a live database.
type PgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PgxPool is the full connection surface ensureConnection manages: the query
// surface (PgxQuerier) plus liveness and lifecycle. Both *pgxpool.Pool and
// pgxmock's PgxPoolIface satisfy it, so the connection + per-instance
// orchestration paths can be driven by a mock pool via SetPoolFactoryExported
// (no live database required).
type PgxPool interface {
	PgxQuerier
	Ping(ctx context.Context) error
	Close()
}

type crdbInstance struct {
	config        config.CockroachDBInstanceConfig
	pool          PgxPool
	version       string
	clusterID     string
	nodeID        int
	prevCounters  map[string]uint64
	prevTimestamp time.Time
	backoff       time.Duration
	lastConnErr   time.Time
	topStmtsLimit int
}
