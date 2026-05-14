package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"
)

func detectVersion(ctx context.Context, db *sql.DB, inst *mssqlInstance, logger *zap.Logger) error {
	var version string
	var edition int
	err := db.QueryRowContext(ctx,
		`SELECT SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('EngineEdition')`,
	).Scan(&version, &edition)
	if err != nil {
		return fmt.Errorf("detect version: %w", err)
	}
	inst.version = version
	inst.engineEdition = edition
	logger.Info("MSSQL version detected",
		zap.String("instance", inst.config.Name),
		zap.String("version", version),
		zap.Int("engine_edition", edition),
	)
	return nil
}
