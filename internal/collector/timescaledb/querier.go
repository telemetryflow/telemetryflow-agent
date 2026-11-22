package timescaledb

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// PgxQuerier is the minimal query surface used by the collect* functions.
// Both *pgxpool.Pool and pgxmock's pool satisfy it, which keeps the
// collection logic testable without a live database connection.
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
