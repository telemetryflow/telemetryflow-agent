package mongodb

import (
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type mongoInstance struct {
	config       config.MongoDBCommunityInstanceConfig
	client       *mongo.Client
	mu           sync.Mutex
	versionStr   string
	isReplicaSet bool
	isSharded    bool

	backoff     time.Duration
	lastConnErr time.Time

	prevCounters map[string]float64
	prevTime     time.Time

	// Collection discovery cache
	discoveredDBs []string
	discoveredAt  time.Time
}
