package sqlite3

import (
	"database/sql"
	"sync"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type sqliteDatabase struct {
	config     config.SQLite3DatabaseConfig
	db         *sql.DB
	prevPragma map[string]string
	prevBusy   uint64
	mu         sync.Mutex
	checking   bool
}

type pragmaValues struct {
	JournalMode       string
	Synchronous       string
	CacheSize         int64
	MmapSize          int64
	WalAutocheckpoint int64
	BusyTimeout       int64
	LockingMode       string
	PageSize          int64
	PageCount         int64
	FreelistCount     int64
	AutoVacuum        int64
	SchemaVersion     int64
	DataVersion       int64
}

var (
	_ = tableInfo{}
	_ = indexInfo{}
	_ = integrityResult{}
	_ = dbstatRow{}
)

type tableInfo struct {
	Name       string
	Type       string
	ApproxRows int64
	HasRowID   bool
}

type indexInfo struct {
	Name    string
	Table   string
	Unique  bool
	Columns []string
}

type integrityResult struct {
	CheckType string
	Status    string
	Duration  time.Duration
	Errors    []string
}

type dbstatRow struct {
	TableName  string
	PageCount  int64
	UnusedPage int64
}
