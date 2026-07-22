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
