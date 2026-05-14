package cockroachdb

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func detectVersion(ctx context.Context, pool *pgxpool.Pool, inst *crdbInstance, logger *zap.Logger) error {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var version string
	var clusterID string
	var nodeID int

	err := pool.QueryRow(ctx2, `
		SELECT
			crdb_internal.node_executable_version(),
			crdb_internal.cluster_id(),
			crdb_internal.node_id()
	`).Scan(&version, &clusterID, &nodeID)
	if err != nil {
		return fmt.Errorf("detect crdb version: %w", err)
	}

	inst.version = version
	inst.clusterID = clusterID
	inst.nodeID = nodeID

	logger.Info("Detected CockroachDB version",
		zap.String("instance", inst.config.Name),
		zap.String("version", version),
		zap.String("cluster_id", clusterID),
		zap.Int("node_id", nodeID),
	)
	return nil
}
