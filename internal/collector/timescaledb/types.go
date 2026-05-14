package timescaledb

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type tsdbInstance struct {
	config     config.TimescaleDBInstanceConfig
	pool       *pgxpool.Pool
	pgVersion  int
	pgVersionS string
	tsdbVer    string

	backoff     time.Duration
	lastConnErr time.Time
}

//nolint:unused
type hypertableSnapshot struct {
	schema             string
	name               string
	numDimensions      int
	numChunks          int
	compressionEnabled bool
	totalBytes         float64
	indexBytes         float64
	toastBytes         float64
	chunkInterval      string
}

//nolint:unused
type chunkSnapshot struct {
	chunkName    string
	schema       string
	hypertable   string
	rangeStart   time.Time
	rangeEnd     time.Time
	isCompressed bool
	totalBytes   float64
}

//nolint:unused
type compressionSnapshot struct {
	schema             string
	hypertable         string
	beforeBytes        float64
	afterBytes         float64
	chunksCompressed   int
	chunksUncompressed int
}

//nolint:unused
type caggSnapshot struct {
	viewName         string
	sourceSchema     string
	sourceHypertable string
	materializedOnly bool
	refreshLag       float64
	lastRefreshDur   float64
	refreshFailures  int
}

//nolint:unused
type jobSnapshot struct {
	jobID            int
	procName         string
	schema           string
	hypertable       string
	scheduleInterval string
	lastRunStatus    string
	lastRunDuration  float64
	totalFailures    int
	totalCrashes     int
	nextStart        time.Time
	stuck            bool
}

//nolint:unused
type dataNodeSnapshot struct {
	name       string
	available  bool
	chunkCount int
}
