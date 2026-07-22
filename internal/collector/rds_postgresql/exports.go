// Package rds_postgresql exposes unexported symbols for external test packages.
//
// This file only forwards to existing unexported symbols so that external test
// packages (rds_postgresql_test) can construct instances and drive the
// unexported collection helpers. It contains no production logic and mirrors
// the convention established by internal/collector/postgresql/exports.go.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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

package rds_postgresql

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// RDSPgTestInstance is a test-visible handle around the unexported
// qanRdsPgInstance so external tests can construct and manipulate instances.
type RDSPgTestInstance struct {
	inner *qanRdsPgInstance
}

// NewRDSPgTestInstance builds a test instance with an initialized snapshot map.
func NewRDSPgTestInstance(cfg config.RDSPostgreSQLInstanceConfig) *RDSPgTestInstance {
	return &RDSPgTestInstance{
		inner: &qanRdsPgInstance{
			config:       cfg,
			prevSnapshot: make(map[string]*rdsPgSnapshot),
		},
	}
}

// SetPool injects a live pool, bypassing ensureConnection's dialing.
func (t *RDSPgTestInstance) SetPool(pool *pgxpool.Pool) { t.inner.pool = pool }

// Pool returns the currently set pool.
func (t *RDSPgTestInstance) Pool() *pgxpool.Pool { return t.inner.pool }

// SetPrevTime overrides the previous collection timestamp.
func (t *RDSPgTestInstance) SetPrevTime(tm time.Time) { t.inner.prevTime = tm }

// PrevTime returns the previous collection timestamp.
func (t *RDSPgTestInstance) PrevTime() time.Time { return t.inner.prevTime }

// PrevSnapshotLen returns the number of tracked queries from the last snapshot.
func (t *RDSPgTestInstance) PrevSnapshotLen() int { return len(t.inner.prevSnapshot) }

// CollectInstanceExported drives the unexported collectInstance.
func (c *QANRDSPostgreSQLCollector) CollectInstanceExported(ctx context.Context, t *RDSPgTestInstance) ([]qan.QANMetricsBucket, error) {
	return c.collectInstance(ctx, t.inner)
}

// EnsureConnectionExported drives the unexported ensureConnection.
func (c *QANRDSPostgreSQLCollector) EnsureConnectionExported(ctx context.Context, t *RDSPgTestInstance) (*pgxpool.Pool, error) {
	return c.ensureConnection(ctx, t.inner)
}

// DatabaseNameExported drives the unexported databaseName.
func (c *QANRDSPostgreSQLCollector) DatabaseNameExported(t *RDSPgTestInstance) string {
	return c.databaseName(t.inner)
}

// InstanceLabelsExported drives the unexported instanceLabels.
func (c *QANRDSPostgreSQLCollector) InstanceLabelsExported(t *RDSPgTestInstance) map[string]string {
	return c.instanceLabels(t.inner)
}

// CollectQANBucketsExported drives the unexported collectQANBuckets scan/delta
// body against the supplied querier for the given test instance, returning the
// resulting buckets so external tests can exercise the path with a mock pool.
func (c *QANRDSPostgreSQLCollector) CollectQANBucketsExported(ctx context.Context, q PgxQuerier, t *RDSPgTestInstance) ([]qan.QANMetricsBucket, error) {
	return c.collectQANBuckets(ctx, q, t.inner)
}

// SetInstances replaces the collector's instance list with the given test instances.
func (c *QANRDSPostgreSQLCollector) SetInstances(ts ...*RDSPgTestInstance) {
	insts := make([]*qanRdsPgInstance, len(ts))
	for i, t := range ts {
		insts[i] = t.inner
	}
	c.instances = insts
}
