package mongodb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.uber.org/zap"
)

func (c *MongoDBCollector) ensureConnection(ctx context.Context, inst *mongoInstance) (*mongo.Client, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.client != nil {
		if err := inst.client.Ping(ctx, readpref.SecondaryPreferred()); err == nil {
			return inst.client, nil
		}
		_ = inst.client.Disconnect(ctx)
		inst.client = nil
	}

	if !inst.lastConnErr.IsZero() {
		wait := inst.backoff
		if wait == 0 {
			wait = time.Second
		}
		if time.Since(inst.lastConnErr) < wait {
			return nil, fmt.Errorf("mongodb %s: in back-off (retry in %s)",
				inst.config.Name, (wait - time.Since(inst.lastConnErr)).Round(time.Millisecond))
		}
	}

	opts := options.Client().ApplyURI(inst.config.URI).
		SetReadPreference(readpref.SecondaryPreferred()).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(10 * time.Second)

	if inst.config.Username != "" {
		opts.SetAuth(options.Credential{
			Username: inst.config.Username,
			Password: inst.config.Password,
		})
	}

	if inst.config.TLSCertFile != "" || inst.config.TLSCAFile != "" || inst.config.TLSInsecureSkipVerify {
		tlsCfg := &tls.Config{}
		if inst.config.TLSInsecureSkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		if inst.config.TLSCAFile != "" {
			ca, err := os.ReadFile(inst.config.TLSCAFile)
			if err != nil {
				c.advanceBackoff(inst)
				return nil, fmt.Errorf("mongodb %s: read CA file: %w", inst.config.Name, err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsCfg.RootCAs = pool
		}
		if inst.config.TLSCertFile != "" && inst.config.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(inst.config.TLSCertFile, inst.config.TLSKeyFile)
			if err != nil {
				c.advanceBackoff(inst)
				return nil, fmt.Errorf("mongodb %s: load cert: %w", inst.config.Name, err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		opts.SetTLSConfig(tlsCfg)
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mongodb %s: connect: %w", inst.config.Name, err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx2, readpref.SecondaryPreferred()); err != nil {
		_ = client.Disconnect(ctx)
		c.advanceBackoff(inst)
		return nil, fmt.Errorf("mongodb %s: ping: %w", inst.config.Name, err)
	}

	inst.client = client
	inst.backoff = 0
	inst.lastConnErr = time.Time{}

	// Detect version
	c.detectTopology(ctx, inst)

	c.logger.Info("Connected to MongoDB instance",
		zap.String("instance", inst.config.Name),
	)
	return client, nil
}

func (c *MongoDBCollector) closeConnection(inst *mongoInstance) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.client != nil {
		_ = inst.client.Disconnect(context.Background())
		inst.client = nil
	}
}

func (c *MongoDBCollector) advanceBackoff(inst *mongoInstance) {
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

func (c *MongoDBCollector) detectTopology(ctx context.Context, inst *mongoInstance) {
	if inst.client == nil {
		return
	}
	admin := inst.client.Database("admin")

	// Get build info for version
	var buildInfo bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&buildInfo); err == nil {
		if v, ok := buildInfo["version"].(string); ok {
			inst.versionStr = v
		}
	}

	// Check replica set
	var isMaster bson.M
	if err := admin.RunCommand(ctx, bson.D{{Key: "isMaster", Value: 1}}).Decode(&isMaster); err == nil {
		if _, ok := isMaster["setName"]; ok {
			inst.isReplicaSet = true
		}
		if msg, ok := isMaster["msg"].(string); ok && msg == "isdbgrid" {
			inst.isSharded = true
		}
	}
}
