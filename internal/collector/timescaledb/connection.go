package timescaledb

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

var reEnvVar = regexp.MustCompile(`\$\{([^}]+)\}`)

func resolveEnvVars(s string) string {
	return reEnvVar.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-1]
		varName := inner
		var defaultVal string
		if idx := findDefaultSep(inner); idx >= 0 {
			varName = inner[:idx]
			defaultVal = inner[idx+2:]
		}
		if v := os.Getenv(varName); v != "" {
			return v
		}
		return defaultVal
	})
}

func findDefaultSep(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' && i > 0 && s[i-1] == ':' {
			return i - 1
		}
	}
	return -1
}

func buildConnString(cfg config.TimescaleDBInstanceConfig) string {
	password := resolveEnvVars(cfg.Password)
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, password, cfg.Host, cfg.Port, cfg.DBName, cfg.SSLMode,
	)
	if cfg.SSLRootCert != "" {
		dsn += fmt.Sprintf("&sslrootcert=%s", cfg.SSLRootCert)
	}
	if cfg.SSLCert != "" {
		dsn += fmt.Sprintf("&sslcert=%s", cfg.SSLCert)
	}
	if cfg.SSLKey != "" {
		dsn += fmt.Sprintf("&sslkey=%s", cfg.SSLKey)
	}
	return dsn
}

func (c *TimescaleDBCollector) ensureConnection(ctx context.Context, inst *tsdbInstance) (*pgxpool.Pool, error) {
	if inst.pool != nil {
		if err := inst.pool.Ping(ctx); err == nil {
			return inst.pool, nil
		}
		inst.pool.Close()
		inst.pool = nil
	}

	if !inst.lastConnErr.IsZero() {
		wait := inst.backoff
		if wait == 0 {
			wait = time.Second
		}
		if time.Since(inst.lastConnErr) < wait {
			return nil, fmt.Errorf("timescaledb %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	poolCfg, err := pgxpool.ParseConfig(buildConnString(inst.config))
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("timescaledb %s: parse config: %w", inst.config.Name, err)
	}
	poolCfg.MaxConns = int32(c.cfg.MaxConnections)
	poolCfg.MinConns = 1
	poolCfg.MaxConnLifetime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx2, poolCfg)
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("timescaledb %s: create pool: %w", inst.config.Name, err)
	}

	if err := pool.Ping(ctx2); err != nil {
		pool.Close()
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("timescaledb %s: ping: %w", inst.config.Name, err)
	}

	inst.pool = pool
	inst.backoff = 0
	inst.lastConnErr = time.Time{}
	c.logger.Info("Connected to TimescaleDB instance",
		zap.String("instance", inst.config.Name),
		zap.String("host", inst.config.Host),
		zap.Int("port", inst.config.Port),
	)
	return pool, nil
}

func (c *TimescaleDBCollector) closeConnection(inst *tsdbInstance) {
	if inst.pool != nil {
		inst.pool.Close()
		inst.pool = nil
	}
}

func (c *TimescaleDBCollector) advanceBackoff(inst *tsdbInstance) {
	inst.lastConnErr = time.Now()
	if inst.backoff == 0 {
		inst.backoff = time.Second
	} else {
		inst.backoff *= 2
		if inst.backoff > 60*time.Second {
			inst.backoff = 60 * time.Second
		}
	}
}
