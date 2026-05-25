// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postgresql

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

// reEnvVar matches ${ENV_VAR} or ${ENV_VAR:-default} patterns.
var reEnvVar = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveEnvVars replaces ${ENV_VAR} patterns in s with the corresponding
// environment variable value. Supports ${VAR:-default} syntax. If the
// variable is not set and no default is provided, the pattern is replaced
// with an empty string.
func resolveEnvVars(s string) string {
	return reEnvVar.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-1] // strip ${ and }
		varName := inner
		var defaultVal string
		if idx := findDefaultSep(inner); idx >= 0 {
			varName = inner[:idx]
			defaultVal = inner[idx+2:] // skip ":-"
		}
		if v := os.Getenv(varName); v != "" {
			return v
		}
		return defaultVal
	})
}

// findDefaultSep finds the index of ":-" in s, returning -1 if not found.
func findDefaultSep(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' && s[i-1] == ':' {
			return i - 1
		}
	}
	return -1
}

func buildConnString(cfg config.PostgreSQLInstanceConfig) string {
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

func (c *PostgreSQLCollector) ensureConnection(ctx context.Context, inst *pgInstance) (*pgxpool.Pool, error) {
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
			return nil, fmt.Errorf("postgresql %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	poolCfg, err := pgxpool.ParseConfig(buildConnString(inst.config))
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("postgresql %s: parse config: %w", inst.config.Name, err)
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
		return nil, fmt.Errorf("postgresql %s: create pool: %w", inst.config.Name, err)
	}

	if err := pool.Ping(ctx2); err != nil {
		pool.Close()
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("postgresql %s: ping: %w", inst.config.Name, err)
	}

	inst.pool = pool
	inst.backoff = 0
	inst.lastConnErr = time.Time{}
	c.logger.Info("Connected to PostgreSQL instance",
		zap.String("instance", inst.config.Name),
		zap.String("host", inst.config.Host),
		zap.Int("port", inst.config.Port),
	)
	return pool, nil
}

func (c *PostgreSQLCollector) closeConnection(inst *pgInstance) {
	if inst.pool != nil {
		inst.pool.Close()
		inst.pool = nil
	}
}
