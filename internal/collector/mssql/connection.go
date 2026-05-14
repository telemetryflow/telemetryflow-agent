package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"time"

	_ "github.com/microsoft/go-mssqldb"
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

func buildConnString(cfg config.MSSQLInstanceConfig) string {
	password := resolveEnvVars(cfg.Password)

	var dsn string
	if cfg.InstanceName != "" {
		dsn = fmt.Sprintf("sqlserver://%s:%s@%s?instanceName=%s&database=%s&encrypt=%s&trustServerCertificate=%t",
			cfg.Username, password, hostPort(cfg),
			cfg.InstanceName, cfg.Database,
			cfg.Encrypt, cfg.TrustServerCertificate,
		)
	} else {
		dsn = fmt.Sprintf("sqlserver://%s:%s@%s?database=%s&encrypt=%s&trustServerCertificate=%t",
			cfg.Username, password, hostPort(cfg),
			cfg.Database,
			cfg.Encrypt, cfg.TrustServerCertificate,
		)
	}
	return dsn
}

func hostPort(cfg config.MSSQLInstanceConfig) string {
	return fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
}

func (c *MSSQLCollector) ensureConnection(ctx context.Context, inst *mssqlInstance) (*sql.DB, error) {
	if inst.db != nil {
		if err := inst.db.PingContext(ctx); err == nil {
			return inst.db, nil
		}
		_ = inst.db.Close()
		inst.db = nil
	}

	if !inst.lastConnErr.IsZero() {
		wait := inst.backoff
		if wait == 0 {
			wait = time.Second
		}
		if time.Since(inst.lastConnErr) < wait {
			return nil, fmt.Errorf("mssql %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	db, err := sql.Open("sqlserver", buildConnString(inst.config))
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mssql %s: open: %w", inst.config.Name, err)
	}

	db.SetMaxOpenConns(c.cfg.MaxConnections)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx2); err != nil {
		_ = db.Close()
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mssql %s: ping: %w", inst.config.Name, err)
	}

	inst.db = db
	inst.backoff = 0
	inst.lastConnErr = time.Time{}
	c.logger.Info("Connected to MSSQL instance",
		zap.String("instance", inst.config.Name),
		zap.String("host", inst.config.Host),
		zap.Int("port", inst.config.Port),
	)
	return db, nil
}

func (c *MSSQLCollector) closeConnection(inst *mssqlInstance) {
	if inst.db != nil {
		_ = inst.db.Close()
		inst.db = nil
	}
}

func (c *MSSQLCollector) advanceBackoff(inst *mssqlInstance) {
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
