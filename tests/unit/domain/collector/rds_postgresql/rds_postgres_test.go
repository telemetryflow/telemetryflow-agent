// Package postgresql_test contains unit tests for the RDS PostgreSQL collector.
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
//
// The RDS PostgreSQL collector uses pgxpool (jackc/pgx), which cannot be driven
// by database/sql sqlmock. DB-facing paths are therefore exercised via
// deterministic connection failures (loopback port 1), and the HTTP reporter is
// driven with httptest. Pure helpers are covered directly through exported seams.

package rds_postgresql_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func unreachableRDSInstance(name string) config.RDSPostgreSQLInstanceConfig {
	return config.RDSPostgreSQLInstanceConfig{
		Name:       name,
		InstanceID: "db-" + name,
		Host:       "127.0.0.1",
		Port:       1,
		User:       "postgres",
		Password:   "secret",
		DBName:     "postgres",
		Region:     "us-east-1",
	}
}

func newRDSCollector(t *testing.T, insts ...config.RDSPostgreSQLInstanceConfig) *postgresql.RDSPostgreSQLCollector {
	t.Helper()
	cfg := config.RDSPostgreSQLCollectorConfig{
		Enabled:                 true,
		Instances:               insts,
		MaxConnections:          2,
		TopQueriesLimit:         10,
		CollectPgStatStatements: true,
	}
	return postgresql.NewRDSPostgreSQLCollector(cfg, zap.NewNop())
}

// --- Constructor + defaults ---

func TestRDS_NewAppliesDefaults(t *testing.T) {
	cfg := config.RDSPostgreSQLCollectorConfig{
		Instances: []config.RDSPostgreSQLInstanceConfig{{Name: "a", Host: "h"}},
	}
	c := postgresql.NewRDSPostgreSQLCollector(cfg, zap.NewNop())
	if c.Name() != "rds_postgresql" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.IsRunning() {
		t.Error("should not be running initially")
	}
}

func TestRDS_ApplyInstanceDefaults(t *testing.T) {
	inst := config.RDSPostgreSQLInstanceConfig{Name: "x"}
	postgresql.ApplyRDSInstanceDefaultsExported(&inst)
	if inst.Port != 5432 {
		t.Errorf("Port = %d, want 5432", inst.Port)
	}
	if inst.User != "postgres" {
		t.Errorf("User = %q, want postgres", inst.User)
	}
	if inst.DBName != "postgres" {
		t.Errorf("DBName = %q, want postgres", inst.DBName)
	}

	// Non-defaults are preserved.
	custom := config.RDSPostgreSQLInstanceConfig{Name: "y", Port: 6000, User: "app", DBName: "orders"}
	postgresql.ApplyRDSInstanceDefaultsExported(&custom)
	if custom.Port != 6000 || custom.User != "app" || custom.DBName != "orders" {
		t.Errorf("defaults overwrote custom values: %+v", custom)
	}
}

// --- Start / Stop lifecycle ---

func TestRDS_StartCancelsWithContext(t *testing.T) {
	c := newRDSCollector(t, unreachableRDSInstance("i1"))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := c.Start(context.Background()); err == nil {
		t.Error("double Start should error")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
}

func TestRDS_StopWhenNotRunning(t *testing.T) {
	c := newRDSCollector(t, unreachableRDSInstance("i1"))
	if err := c.Stop(); err != nil {
		t.Errorf("Stop on idle collector: %v", err)
	}
}

// --- Collect drives ensureRDSConnection failure + collectActivity + collectAll* ---

func TestRDS_CollectEmptyInstances(t *testing.T) {
	c := newRDSCollector(t)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

func TestRDS_CollectUnreachableInstances(t *testing.T) {
	c := newRDSCollector(t, unreachableRDSInstance("i1"), unreachableRDSInstance("i2"))
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics from unreachable instances, got %d", len(metrics))
	}
}

func TestRDS_ConnectFailureAndBackoff(t *testing.T) {
	c := newRDSCollector(t)
	first, second := c.RDSConnectFailurePathExported(context.Background(), unreachableRDSInstance("i1"))
	if first == nil {
		t.Error("expected connect error on first attempt")
	}
	if second == nil {
		t.Error("expected back-off error on second attempt")
	}
}

// --- buildRDSConnString ---

func TestRDS_BuildConnString(t *testing.T) {
	dsn := postgresql.BuildRDSConnStringExported(config.RDSPostgreSQLInstanceConfig{
		User:     "admin",
		Password: "pw",
		Host:     "db.rds.amazonaws.com",
		Port:     5432,
		DBName:   "prod",
	})
	want := "postgres://admin:pw@db.rds.amazonaws.com:5432/prod?sslmode=require"
	if dsn != want {
		t.Errorf("dsn = %q, want %q", dsn, want)
	}
}

func TestRDS_BuildConnStringResolvesEnv(t *testing.T) {
	t.Setenv("RDS_TEST_PW", "envsecret")
	dsn := postgresql.BuildRDSConnStringExported(config.RDSPostgreSQLInstanceConfig{
		User:     "admin",
		Password: "${RDS_TEST_PW}",
		Host:     "h",
		Port:     5432,
		DBName:   "d",
	})
	if want := "postgres://admin:envsecret@h:5432/d?sslmode=require"; dsn != want {
		t.Errorf("dsn = %q, want %q", dsn, want)
	}
}

// --- rdsTLSConfig ---

func writeCACert(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-rds-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(dir, "ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	return path
}

func TestRDS_TLSConfigSuccess(t *testing.T) {
	path := writeCACert(t, t.TempDir())
	cfg, err := postgresql.RDSTLSConfigExported(path)
	if err != nil {
		t.Fatalf("rdsTLSConfig: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected TLS config with RootCAs")
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("MinVersion = %x", cfg.MinVersion)
	}
}

func TestRDS_TLSConfigInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := postgresql.RDSTLSConfigExported(path); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestRDS_TLSConfigMissingBundle(t *testing.T) {
	// A path that does not exist; also falls through the default-locations loop.
	if _, err := postgresql.RDSTLSConfigExported(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Error("expected error when CA bundle is absent")
	}
	// Empty path triggers the default well-known locations (also absent in CI).
	if _, err := postgresql.RDSTLSConfigExported(""); err == nil {
		t.Error("expected error when no CA bundle found in default locations")
	}
}

// --- Label + helper functions ---

func TestRDS_InstanceLabels(t *testing.T) {
	inst := config.RDSPostgreSQLInstanceConfig{
		Name:       "prod",
		Host:       "prod.rds",
		InstanceID: "db-prod",
		Region:     "eu-west-1",
		Tags:       map[string]string{"team": "data"},
	}
	labels := postgresql.RDSInstanceLabelsExported(inst, "PostgreSQL 16.1")
	checks := map[string]string{
		"postgresql_instance": "prod",
		"postgresql_host":     "prod.rds",
		"rds_instance_id":     "db-prod",
		"rds_region":          "eu-west-1",
		"cloud_provider":      "aws",
		"db_system":           "rds_postgresql",
		"postgresql_version":  "PostgreSQL 16.1",
		"team":                "data",
	}
	for k, want := range checks {
		if labels[k] != want {
			t.Errorf("label %q = %q, want %q", k, labels[k], want)
		}
	}
}

func TestRDS_InstanceLabelsNoVersion(t *testing.T) {
	labels := postgresql.RDSInstanceLabelsExported(config.RDSPostgreSQLInstanceConfig{Name: "n"}, "")
	if _, ok := labels["postgresql_version"]; ok {
		t.Error("postgresql_version should be omitted when version is empty")
	}
}

func TestRDS_HasWalStats(t *testing.T) {
	if postgresql.HasRDSWalStatsExported(130000) {
		t.Error("PG 13 should not report WAL stats")
	}
	if !postgresql.HasRDSWalStatsExported(140000) {
		t.Error("PG 14 should report WAL stats")
	}
	if !postgresql.HasRDSWalStatsExported(160000) {
		t.Error("PG 16 should report WAL stats")
	}
}

func TestRDS_ContainsString(t *testing.T) {
	if !postgresql.ContainsStringExported("PostgreSQL 16.1 on x86_64 rds", "rds") {
		t.Error("expected substring match")
	}
	if postgresql.ContainsStringExported("plain postgres", "rds") {
		t.Error("unexpected substring match")
	}
	if !postgresql.ContainsStringExported("abc", "abc") {
		t.Error("equal strings should match")
	}
	if postgresql.ContainsStringExported("ab", "abc") {
		t.Error("substring longer than string should not match")
	}
}

func TestRDS_ToPgInstanceConfig(t *testing.T) {
	inst := config.RDSPostgreSQLInstanceConfig{
		Name:     "prod",
		Host:     "h",
		Port:     5432,
		User:     "u",
		Password: "p",
		DBName:   "d",
		Tags:     map[string]string{"a": "b"},
	}
	got := postgresql.RDSToPgInstanceConfigExported(inst, 160000)
	if got.Name != "prod" || got.Host != "h" || got.Port != 5432 {
		t.Errorf("unexpected conversion: %+v", got)
	}
	if got.SSLMode != "require" {
		t.Errorf("SSLMode = %q, want require", got.SSLMode)
	}
	if got.Tags["a"] != "b" {
		t.Errorf("tags not carried over: %+v", got.Tags)
	}
}
