// Package scraper_test contains unit tests for ScrapeJob and its HTTP client wiring.
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

package scraper_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

func TestBearerRoundTripper(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := &http.Client{Transport: scraper.BearerRoundTripperExported("my-token", http.DefaultTransport)}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, "Bearer my-token", gotAuth)
}

func TestBasicAuthRoundTripper(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := &http.Client{Transport: scraper.BasicAuthRoundTripperExported("alice", "secret", http.DefaultTransport)}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.True(t, ok)
	assert.Equal(t, "alice", user)
	assert.Equal(t, "secret", pass)
}

func TestBuildTLSConfig_Insecure(t *testing.T) {
	cfg, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{InsecureSkipVerify: true})
	require.NoError(t, err)
	assert.True(t, cfg.InsecureSkipVerify)
}

func TestBuildTLSConfig_ValidCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	cfg, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{CAFile: caPath})
	require.NoError(t, err)
	require.NotNil(t, cfg.RootCAs)
}

func TestBuildTLSConfig_MissingCAFile(t *testing.T) {
	_, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{CAFile: "/nonexistent/ca.pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA file")
}

func TestBuildTLSConfig_InvalidCAContents(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a certificate"), 0o600))

	_, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{CAFile: caPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

func TestBuildTLSConfig_ValidClientCert(t *testing.T) {
	// Generate a self-signed cert/key pair via httptest server's TLS config.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	leaf := srv.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyDER, err := marshalKey(leaf.PrivateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	cfg, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{CertFile: certPath, KeyFile: keyPath})
	require.NoError(t, err)
	assert.Len(t, cfg.Certificates, 1)
}

func TestBuildTLSConfig_InvalidClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte("bad"), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte("bad"), 0o600))

	_, err := scraper.BuildTLSConfigExported(scraper.TLSConfig{CertFile: certPath, KeyFile: keyPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load client cert/key")
}

func TestNewScrapeJob_Defaults(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(scraper.ScrapeJobConfig{JobName: "j"}, out, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, job)
}

func TestNewScrapeJob_BearerToken(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(
		scraper.ScrapeJobConfig{JobName: "j", BearerToken: "tok", ScrapeTimeout: 5 * time.Second},
		out, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, job)
}

func TestNewScrapeJob_BasicAuth(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(
		scraper.ScrapeJobConfig{JobName: "j", BasicAuth: &scraper.BasicAuthConfig{Username: "u", Password: "p"}},
		out, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, job)
}

func TestNewScrapeJob_BearerTokenFile(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokPath, []byte("file-token"), 0o600))

	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(
		scraper.ScrapeJobConfig{JobName: "j", BearerTokenFile: tokPath},
		out, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, job)
}

func TestNewScrapeJob_BearerTokenFileMissing(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	_, err := scraper.NewScrapeJobExported(
		scraper.ScrapeJobConfig{JobName: "j", BearerTokenFile: "/nonexistent/token"},
		out, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read bearer token file")
}

func TestNewScrapeJob_TLSError(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	_, err := scraper.NewScrapeJobExported(
		scraper.ScrapeJobConfig{JobName: "j", TLSConfig: scraper.TLSConfig{CAFile: "/nonexistent/ca.pem"}},
		out, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build TLS config")
}

func TestScrapeJob_StartStop_ProducesMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	out := make(chan []collector.Metric, 10)
	cfg := scraper.ScrapeJobConfig{
		JobName:        "loop-job",
		Targets:        []string{stripScheme(srv.URL)},
		ScrapeInterval: 20 * time.Millisecond,
	}
	job, err := scraper.NewScrapeJobExported(cfg, out, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job.Start(ctx)

	select {
	case batch := <-out:
		assert.NotEmpty(t, batch)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scrape batch")
	}

	job.Stop()
	cancel()
}

func TestScrapeJob_StartStop_NoTargets(t *testing.T) {
	// Zero interval takes the default 60s path; verify Start/Stop don't panic.
	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(scraper.ScrapeJobConfig{JobName: "empty"}, out, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	job.Start(ctx)
	cancel()
	job.Stop()
}

func TestScrapeJob_StopBeforeStart(t *testing.T) {
	out := make(chan []collector.Metric, 1)
	job, err := scraper.NewScrapeJobExported(scraper.ScrapeJobConfig{JobName: "j"}, out, zap.NewNop())
	require.NoError(t, err)
	// Stop without Start must be a no-op (nil ticker).
	job.Stop()
}

func TestScrapeJob_RunScrape_TargetError(t *testing.T) {
	// A failing target: server that errors. runScrape should log and continue,
	// producing no batch. Exercised via Start with a short interval.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	out := make(chan []collector.Metric, 10)
	cfg := scraper.ScrapeJobConfig{
		JobName:        "err-job",
		Targets:        []string{stripScheme(srv.URL)},
		ScrapeInterval: 20 * time.Millisecond,
	}
	job, err := scraper.NewScrapeJobExported(cfg, out, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	job.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	job.Stop()
	cancel()

	assert.Empty(t, out)
}

func TestScrapeJob_RunScrape_ChannelFullDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	// Unbuffered channel with no reader forces the non-blocking send default
	// branch (drop) in runScrape.
	out := make(chan []collector.Metric)
	cfg := scraper.ScrapeJobConfig{
		JobName:        "drop-job",
		Targets:        []string{stripScheme(srv.URL)},
		ScrapeInterval: 20 * time.Millisecond,
	}
	job, err := scraper.NewScrapeJobExported(cfg, out, zap.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	job.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	job.Stop()
	cancel()
	// No reader ever consumed; test passes if no deadlock/panic occurred.
}

// marshalKey marshals a private key to PKCS#8 DER for PEM encoding in tests.
func marshalKey(key any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}
