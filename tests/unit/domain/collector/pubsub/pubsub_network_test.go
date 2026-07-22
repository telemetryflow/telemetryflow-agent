// External black-box unit tests covering the Pub/Sub collector's network
// paths (OAuth2 JWT grant + Cloud Monitoring query) via httptest, credential
// loading, and error paths. No live GCP is contacted; RS256 signing uses an
// in-test key and endpoints are redirected with SetEndpointsExported.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pubsub_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/pubsub"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func float64Ptr(v float64) *float64 { return &v }

// genKey returns a fresh 2048-bit RSA key for signing test JWTs.
func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// pkcs8PEM encodes a key as a PKCS#8 PEM block.
func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// pkcs1PEM encodes a key as a PKCS#1 PEM block.
func pkcs1PEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// ecPKCS8PEM returns a PKCS#8 PEM block holding an EC (non-RSA) private key.
func ecPKCS8PEM(t *testing.T) []byte {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal ec pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// credentialsJSON builds a GCP service-account key JSON file with the given key.
func credentialsJSON(t *testing.T, email string, key *rsa.PrivateKey) []byte {
	t.Helper()
	m := map[string]string{
		"type":         "service_account",
		"client_email": email,
		"private_key":  string(pkcs8PEM(t, key)),
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal creds: %v", err)
	}
	return b
}

// oauthServer returns an httptest server that answers the JWT-bearer grant.
func oauthServer(t *testing.T, token string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer"}`))
	}))
}

// monitoringServer returns an httptest server that answers timeSeries queries.
// It emits one int64 series per metric.type query keyed off the filter.
func monitoringServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "no bearer", http.StatusUnauthorized)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return
		}
		filter := r.URL.Query().Get("filter")
		mtype := strings.TrimSuffix(strings.TrimPrefix(filter, `metric.type="`), `"`)
		resp := map[string]any{
			"timeSeries": []map[string]any{
				{
					"metric":   map[string]any{"type": mtype},
					"resource": map[string]any{"labels": map[string]any{"subscription_id": "orders-sub", "project_id": "proj-1"}},
					"points": []map[string]any{
						{
							"interval": map[string]any{"endTime": time.Now().UTC().Format(time.RFC3339Nano)},
							"value":    map[string]any{"int64Value": 7},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// TestCollect_EndToEnd exercises Collect -> collectInstance -> loadCredentials
// -> getAccessToken (httptest) -> queryMonitoring (httptest) -> BuildPubSubMetrics.
func TestCollect_EndToEnd(t *testing.T) {
	key := genKey(t)
	oauth := oauthServer(t, "test-access-token", 0)
	defer oauth.Close()
	mon := monitoringServer(t, 0)
	defer mon.Close()
	restore := pubsub.SetEndpointsExported(oauth.URL, mon.URL)
	defer restore()

	credPath := writeTempFile(t, "creds.json", credentialsJSON(t, "svc@proj.iam.gserviceaccount.com", key))

	cfg := config.PubSubCollectorConfig{
		Enabled: true,
		Tags:    map[string]string{"env": "ci"},
		Instances: []config.PubSubInstanceConfig{
			{
				Name:            "gcp-primary",
				ProjectID:       "proj-1",
				CredentialsFile: credPath,
				Tags:            map[string]string{"team": "data"},
			},
		},
	}
	c := pubsub.NewPubSubCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 5 standard metrics, one series each.
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.Value != 7 {
			t.Errorf("%s value=%v want 7", m.Name, m.Value)
		}
		if m.Labels["pubsub_instance"] != "gcp-primary" ||
			m.Labels["messaging_system"] != "pubsub" ||
			m.Labels["gcp_project"] != "proj-1" ||
			m.Labels["env"] != "ci" ||
			m.Labels["team"] != "data" ||
			m.Labels["pubsub_subscription"] != "orders-sub" {
			t.Errorf("labels wrong: %+v", m.Labels)
		}
	}
}

// TestCollect_InstanceErrorsAreSkipped verifies Collect logs and continues when
// an instance fails (here: missing project_id), returning nil metrics.
func TestCollect_InstanceErrorsAreSkipped(t *testing.T) {
	cfg := config.PubSubCollectorConfig{
		Enabled: true,
		Instances: []config.PubSubInstanceConfig{
			{Name: "broken"}, // no project_id -> collectInstance error
		},
	}
	c := pubsub.NewPubSubCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should swallow instance errors: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics, got %+v", metrics)
	}
}

// TestCollect_MonitoringHTTPError covers the queryMonitoring error branch
// bubbling up through collectInstance (Collect keeps going, returns nil).
func TestCollect_MonitoringHTTPError(t *testing.T) {
	key := genKey(t)
	oauth := oauthServer(t, "tok", 0)
	defer oauth.Close()
	mon := monitoringServer(t, http.StatusInternalServerError)
	defer mon.Close()
	restore := pubsub.SetEndpointsExported(oauth.URL, mon.URL)
	defer restore()

	credPath := writeTempFile(t, "creds.json", credentialsJSON(t, "svc@x.iam", key))
	cfg := config.PubSubCollectorConfig{
		Enabled:   true,
		Instances: []config.PubSubInstanceConfig{{Name: "i", ProjectID: "p", CredentialsFile: credPath}},
	}
	c := pubsub.NewPubSubCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil || metrics != nil {
		t.Fatalf("expected nil,nil got %+v %v", metrics, err)
	}
}

func TestGetAccessToken_Success(t *testing.T) {
	key := genKey(t)
	oauth := oauthServer(t, "abc123", 0)
	defer oauth.Close()
	restore := pubsub.SetEndpointsExported(oauth.URL, "http://unused")
	defer restore()

	tok, err := pubsub.GetAccessTokenExported(context.Background(), "svc@x", key)
	if err != nil {
		t.Fatalf("getAccessToken: %v", err)
	}
	if tok != "abc123" {
		t.Fatalf("token=%q", tok)
	}
}

func TestGetAccessToken_HTTPErrorTruncates(t *testing.T) {
	key := genKey(t)
	longBody := strings.Repeat("x", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(longBody))
	}))
	defer srv.Close()
	restore := pubsub.SetEndpointsExported(srv.URL, "http://unused")
	defer restore()

	_, err := pubsub.GetAccessTokenExported(context.Background(), "svc@x", key)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("expected HTTP 403 error, got %v", err)
	}
	if !strings.Contains(err.Error(), "...") {
		t.Fatalf("expected truncated body marker, got %v", err)
	}
}

func TestGetAccessToken_EmptyToken(t *testing.T) {
	key := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":""}`))
	}))
	defer srv.Close()
	restore := pubsub.SetEndpointsExported(srv.URL, "http://unused")
	defer restore()

	_, err := pubsub.GetAccessTokenExported(context.Background(), "svc@x", key)
	if err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("expected empty token error, got %v", err)
	}
}

func TestGetAccessToken_BadJSON(t *testing.T) {
	key := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()
	restore := pubsub.SetEndpointsExported(srv.URL, "http://unused")
	defer restore()

	_, err := pubsub.GetAccessTokenExported(context.Background(), "svc@x", key)
	if err == nil || !strings.Contains(err.Error(), "decode token response") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestGetAccessToken_RequestFails(t *testing.T) {
	key := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // closed immediately -> connection refused
	restore := pubsub.SetEndpointsExported(srv.URL, "http://unused")
	defer restore()

	_, err := pubsub.GetAccessTokenExported(context.Background(), "svc@x", key)
	if err == nil || !strings.Contains(err.Error(), "token request") {
		t.Fatalf("expected token request error, got %v", err)
	}
}

func TestLoadCredentials_FromFile(t *testing.T) {
	key := genKey(t)
	credPath := writeTempFile(t, "creds.json", credentialsJSON(t, "svc@file", key))
	email, err := pubsub.LoadCredentialsExported(config.PubSubInstanceConfig{Name: "i", CredentialsFile: credPath})
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if email != "svc@file" {
		t.Fatalf("email=%q", email)
	}
}

func TestLoadCredentials_FromEmailAndKeyFile(t *testing.T) {
	key := genKey(t)
	keyPath := writeTempFile(t, "key.pem", pkcs1PEM(key))
	email, err := pubsub.LoadCredentialsExported(config.PubSubInstanceConfig{
		Name:                "i",
		ServiceAccountEmail: "svc@pair",
		PrivateKeyFile:      keyPath,
	})
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if email != "svc@pair" {
		t.Fatalf("email=%q", email)
	}
}

func TestLoadCredentials_Errors(t *testing.T) {
	badPEM := writeTempFile(t, "bad.pem", []byte("not a pem"))
	tests := []struct {
		name string
		inst config.PubSubInstanceConfig
		want string
	}{
		{"none", config.PubSubInstanceConfig{Name: "i"}, "credentials_file or"},
		{"missing_cred_file", config.PubSubInstanceConfig{Name: "i", CredentialsFile: "/no/such/file.json"}, "read credentials"},
		{"bad_key_file", config.PubSubInstanceConfig{Name: "i", ServiceAccountEmail: "e", PrivateKeyFile: badPEM}, "private_key_file"},
		{"missing_key_file", config.PubSubInstanceConfig{Name: "i", ServiceAccountEmail: "e", PrivateKeyFile: "/no/such/key.pem"}, "private_key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pubsub.LoadCredentialsExported(tt.inst)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
}

func TestLoadCredentialsFromFile_BadJSONAndMissingFields(t *testing.T) {
	badJSON := writeTempFile(t, "bad.json", []byte("{"))
	if _, err := pubsub.LoadCredentialsExported(config.PubSubInstanceConfig{Name: "i", CredentialsFile: badJSON}); err == nil ||
		!strings.Contains(err.Error(), "parse credentials JSON") {
		t.Fatalf("expected parse error, got %v", err)
	}

	emptyFields := writeTempFile(t, "empty.json", []byte(`{"type":"service_account"}`))
	if _, err := pubsub.LoadCredentialsExported(config.PubSubInstanceConfig{Name: "i", CredentialsFile: emptyFields}); err == nil ||
		!strings.Contains(err.Error(), "missing client_email") {
		t.Fatalf("expected missing fields error, got %v", err)
	}

	badKeyInJSON := writeTempFile(t, "badkey.json", []byte(`{"client_email":"e","private_key":"nope"}`))
	if _, err := pubsub.LoadCredentialsExported(config.PubSubInstanceConfig{Name: "i", CredentialsFile: badKeyInJSON}); err == nil ||
		!strings.Contains(err.Error(), "parse private key") {
		t.Fatalf("expected parse private key error, got %v", err)
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := genKey(t)

	if _, err := pubsub.ParseRSAPrivateKeyExported(pkcs1PEM(key)); err != nil {
		t.Fatalf("pkcs1: %v", err)
	}
	if _, err := pubsub.ParseRSAPrivateKeyExported(pkcs8PEM(t, key)); err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	if _, err := pubsub.ParseRSAPrivateKeyExported([]byte("garbage")); err == nil ||
		!strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("expected no PEM block, got %v", err)
	}

	// PKCS8 block that is valid DER but not an RSA key (EC key).
	ecPEM := ecPKCS8PEM(t)
	if _, err := pubsub.ParseRSAPrivateKeyExported(ecPEM); err == nil ||
		!strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("expected not RSA error, got %v", err)
	}

	// PEM block whose bytes are neither valid PKCS1 nor PKCS8.
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junkbytes")})
	if _, err := pubsub.ParseRSAPrivateKeyExported(junk); err == nil ||
		!strings.Contains(err.Error(), "parse PKCS8") {
		t.Fatalf("expected parse PKCS8 error, got %v", err)
	}
}

func TestTruncate(t *testing.T) {
	if got := pubsub.TruncateExported("short", 10); got != "short" {
		t.Fatalf("short=%q", got)
	}
	if got := pubsub.TruncateExported("abcdef", 3); got != "abc..." {
		t.Fatalf("trunc=%q", got)
	}
}

func TestCompileFilter(t *testing.T) {
	if matched, err := pubsub.CompileFilterExported(""); err != nil || matched {
		t.Fatalf("empty: matched=%v err=%v", matched, err)
	}
	if matched, err := pubsub.CompileFilterExported("^ok-.*"); err != nil || !matched {
		t.Fatalf("valid: matched=%v err=%v", matched, err)
	}
	if _, err := pubsub.CompileFilterExported("("); err == nil {
		t.Fatal("expected compile error for bad regex")
	}
}

func TestLatestPoint(t *testing.T) {
	if _, ok := pubsub.LatestPointEndTimeExported(nil); ok {
		t.Fatal("empty points should return ok=false")
	}
	now := time.Now()
	end, ok := pubsub.LatestPointEndTimeExported([]pubsub.PubSubTestPoint{
		{EndTime: now.Add(-time.Minute), Int64Value: int64Ptr(1)},
		{EndTime: now, Int64Value: int64Ptr(2)},
	})
	if !ok || !end.Equal(now) {
		t.Fatalf("expected latest=%v ok=true, got %v %v", now, end, ok)
	}
}

// TestBuildPubSubMetrics_Branches covers double values, unknown metric types,
// empty points, and empty subscription id.
func TestBuildPubSubMetrics_Branches(t *testing.T) {
	metrics := []pubsub.PubSubTestMetric{
		{MetricType: "m/known", Suffix: "known", Typ: collector.MetricTypeGauge},
	}
	series := []pubsub.PubSubTestSeries{
		{Type: "m/unknown", SubscriptionID: "s", Points: []pubsub.PubSubTestPoint{{EndTime: time.Now(), Int64Value: int64Ptr(1)}}},
		{Type: "m/known", SubscriptionID: "s", Points: nil}, // no points -> skipped
		{Type: "m/known", SubscriptionID: "", Points: []pubsub.PubSubTestPoint{{EndTime: time.Now(), DoubleValue: float64Ptr(3.5)}}},
	}
	got, err := pubsub.BuildPubSubMetricsExported(map[string]string{"env": "ci"}, metrics, series, "")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(got))
	}
	if got[0].Value != 3.5 {
		t.Errorf("expected double 3.5, got %v", got[0].Value)
	}
	if _, ok := got[0].Labels["pubsub_subscription"]; ok {
		t.Errorf("empty subscription should not set label: %+v", got[0].Labels)
	}
}

func TestBuildPubSubMetrics_BadFilter(t *testing.T) {
	_, err := pubsub.BuildPubSubMetricsExported(nil, nil, nil, "(")
	if err == nil || !strings.Contains(err.Error(), "subscription_filter") {
		t.Fatalf("expected subscription_filter error, got %v", err)
	}
}

func TestNewPubSubCollector_DefaultStatsInterval(t *testing.T) {
	c := pubsub.NewPubSubCollector(config.PubSubCollectorConfig{}, zap.NewNop())
	if c == nil {
		t.Fatal("nil collector")
	}
	// Non-zero interval config is preserved (behavioral default only fills zero).
	c2 := pubsub.NewPubSubCollector(config.PubSubCollectorConfig{StatsInterval: 5 * time.Second}, zap.NewNop())
	if c2 == nil {
		t.Fatal("nil collector")
	}
}
