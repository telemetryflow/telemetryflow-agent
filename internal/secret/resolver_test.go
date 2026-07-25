// Package secret_test contains unit tests for the secret subsystem
// (env/file/vault backends + the @{store:key} resolver).
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
package secret_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/secret"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/secret/all"
	"github.com/telemetryflow/telemetryflow-agent/internal/secret/env"
	"github.com/telemetryflow/telemetryflow-agent/internal/secret/file"
	"github.com/telemetryflow/telemetryflow-agent/internal/secret/vault"
)

// ---------------------------------------------------------------------------
// env store
// ---------------------------------------------------------------------------

func TestEnvStore_GetAndList(t *testing.T) {
	t.Setenv("TFO_TEST_USER", "alice")
	t.Setenv("TFO_TEST_TOKEN", "s3cret")

	store := &env.EnvStore{}
	require.NoError(t, store.Init(nil))

	got, err := store.Get("TFO_TEST_USER")
	require.NoError(t, err)
	require.Equal(t, "alice", got)

	names, err := store.List()
	require.NoError(t, err)
	require.Contains(t, names, "TFO_TEST_USER")
	require.Contains(t, names, "TFO_TEST_TOKEN")
}

func TestEnvStore_Prefix(t *testing.T) {
	t.Setenv("TFO_DB_PASSWORD", "hunter2")
	t.Setenv("UNRELATED", "ignore-me")

	store := &env.EnvStore{}
	require.NoError(t, store.Init(map[string]interface{}{"prefix": "TFO_"}))

	// Key passed in is namespaced; lookup is full env var.
	got, err := store.Get("DB_PASSWORD")
	require.NoError(t, err)
	require.Equal(t, "hunter2", got)

	// Missing key produces an error referencing the full env var name.
	_, err = store.Get("MISSING")
	require.Error(t, err)
	require.Contains(t, err.Error(), "TFO_MISSING")

	// List only returns names matching the prefix.
	names, err := store.List()
	require.NoError(t, err)
	require.Contains(t, names, "TFO_DB_PASSWORD")
	require.NotContains(t, names, "UNRELATED")
}

func TestEnvStore_InvalidPrefix(t *testing.T) {
	store := &env.EnvStore{}
	err := store.Init(map[string]interface{}{"prefix": 123})
	require.Error(t, err)
	require.Contains(t, err.Error(), "prefix")
}

func TestEnvStore_GetResolver_Static(t *testing.T) {
	t.Setenv("TFO_TEST_RESOLVE", "abc123")

	store := &env.EnvStore{}
	require.NoError(t, store.Init(nil))
	rfn, err := store.GetResolver("TFO_TEST_RESOLVE")
	require.NoError(t, err)

	val, dynamic, err := rfn()
	require.NoError(t, err)
	require.Equal(t, "abc123", val)
	require.False(t, dynamic, "env resolver must be static")
}

// ---------------------------------------------------------------------------
// file store
// ---------------------------------------------------------------------------

func writeTempJSON(t *testing.T, payload map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestFileStore_ValidFile(t *testing.T) {
	path := writeTempJSON(t, map[string]string{
		"mysql_password": "secret123",
		"api_key":        "abcdef",
	})

	store := &file.FileStore{}
	require.NoError(t, store.Init(map[string]interface{}{"path": path}))

	got, err := store.Get("mysql_password")
	require.NoError(t, err)
	require.Equal(t, "secret123", got)

	got, err = store.Get("api_key")
	require.NoError(t, err)
	require.Equal(t, "abcdef", got)

	// List is sorted.
	names, err := store.List()
	require.NoError(t, err)
	require.Equal(t, []string{"api_key", "mysql_password"}, names)
}

func TestFileStore_MissingFile(t *testing.T) {
	store := &file.FileStore{}
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	err := store.Init(map[string]interface{}{"path": missing})
	require.Error(t, err)
	require.Contains(t, err.Error(), "read")
}

func TestFileStore_MissingConfig(t *testing.T) {
	store := &file.FileStore{}

	// nil config is rejected before the "path" key is even consulted.
	err := store.Init(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")

	// A non-nil config without "path" surfaces the dedicated "path" error.
	err = store.Init(map[string]interface{}{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "path")
}

func TestFileStore_MissingKey(t *testing.T) {
	path := writeTempJSON(t, map[string]string{"a": "b"})
	store := &file.FileStore{}
	require.NoError(t, store.Init(map[string]interface{}{"path": path}))

	_, err := store.Get("missing")
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing")
}

func TestFileStore_GetResolver_Static(t *testing.T) {
	path := writeTempJSON(t, map[string]string{"k": "v"})
	store := &file.FileStore{}
	require.NoError(t, store.Init(map[string]interface{}{"path": path}))

	rfn, err := store.GetResolver("k")
	require.NoError(t, err)
	val, dynamic, err := rfn()
	require.NoError(t, err)
	require.Equal(t, "v", val)
	require.False(t, dynamic, "file resolver must be static")
}

// ---------------------------------------------------------------------------
// vault store (httptest mock)
// ---------------------------------------------------------------------------

// startVaultMock returns an httptest.Server emulating the subset of the Vault
// HTTP API the store uses, plus a channel onto which every received request
// is sent for header/path assertions.
func startVaultMock(t *testing.T) (*httptest.Server, chan *http.Request) {
	t.Helper()
	received := make(chan *http.Request, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Copy before the server closes the body so the test can read it later.
		cp := r.Clone(r.Context())
		received <- cp

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			// KV v2 read. Echo the key back in the value for verification.
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"metadata": map[string]interface{}{"version": 1},
					"data":     map[string]interface{}{"value": "value-for-" + key},
				},
			})
		case r.Method == "LIST":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"foo", "bar", "baz/"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(received) })
	return srv, received
}

func TestVaultStore_Get(t *testing.T) {
	srv, received := startVaultMock(t)

	store := &vault.VaultStore{}
	require.NoError(t, store.Init(map[string]interface{}{
		"address": srv.URL,
		"token":   "root-token",
	}))

	got, err := store.Get("db/creds")
	require.NoError(t, err)
	require.Equal(t, "value-for-db/creds", got)

	// Verify request headers and path.
	req := <-received
	require.Equal(t, "/v1/secret/data/db/creds", req.URL.Path)
	require.Equal(t, "root-token", req.Header.Get("X-Vault-Token"))
}

func TestVaultStore_List(t *testing.T) {
	srv, _ := startVaultMock(t)

	store := &vault.VaultStore{}
	require.NoError(t, store.Init(map[string]interface{}{
		"address":     srv.URL,
		"token":       "x",
		"list_prefix": "db",
	}))

	keys, err := store.List()
	require.NoError(t, err)
	require.Equal(t, []string{"foo", "bar", "baz/"}, keys)
}

func TestVaultStore_NamespaceAndTLSConfig(t *testing.T) {
	srv, received := startVaultMock(t)

	store := &vault.VaultStore{}
	require.NoError(t, store.Init(map[string]interface{}{
		"address":         srv.URL,
		"token":           "t",
		"namespace":       "ns1/sub",
		"mount_path":      "//secret/", // should normalise to "secret"
		"tls_skip_verify": true,
	}))

	_, err := store.Get("k")
	require.NoError(t, err)

	req := <-received
	require.Equal(t, "ns1/sub", req.Header.Get("X-Vault-Namespace"))
	require.Equal(t, "t", req.Header.Get("X-Vault-Token"))
	require.Equal(t, "/v1/secret/data/k", req.URL.Path)
}

func TestVaultStore_MissingAddress(t *testing.T) {
	store := &vault.VaultStore{}
	err := store.Init(map[string]interface{}{"token": "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "address")
}

func TestVaultStore_GetResolver_Dynamic(t *testing.T) {
	srv, _ := startVaultMock(t)

	store := &vault.VaultStore{}
	require.NoError(t, store.Init(map[string]interface{}{
		"address": srv.URL,
		"token":   "t",
	}))

	rfn, err := store.GetResolver("db/creds")
	require.NoError(t, err)
	val, dynamic, err := rfn()
	require.NoError(t, err)
	require.Equal(t, "value-for-db/creds", val)
	require.True(t, dynamic, "vault resolver must be dynamic (re-fetch every call)")
}

// ---------------------------------------------------------------------------
// resolver
// ---------------------------------------------------------------------------

func TestResolver_EnvReference(t *testing.T) {
	t.Setenv("TFO_RESOLVE_HOME", "/home/opencode")
	r, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: nil},
	}, zap.NewNop())
	require.NoError(t, err)

	got, err := r.Resolve("home=@{env:TFO_RESOLVE_HOME}")
	require.NoError(t, err)
	require.Equal(t, "home=/home/opencode", got)
}

func TestResolver_MultipleReferences(t *testing.T) {
	t.Setenv("TFO_A", "alpha")
	t.Setenv("TFO_B", "beta")

	r, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: map[string]interface{}{"prefix": "TFO_"}},
	}, zap.NewNop())
	require.NoError(t, err)

	got, err := r.Resolve("@{env:A}/@{env:B}/@{env:A}")
	require.NoError(t, err)
	require.Equal(t, "alpha/beta/alpha", got)
}

func TestResolver_ExpandEnvFirst(t *testing.T) {
	t.Setenv("MY_DB_TOKEN", "tok-123")

	// ${VAR} should be expanded BEFORE @{store:key} resolution; the resulting
	// string still flows through the env store lookup.
	r, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: nil},
	}, zap.NewNop())
	require.NoError(t, err)

	t.Setenv("MY_DB_TOKEN", "tok-123")
	got, err := r.Resolve("@{env:MY_DB_TOKEN} from ${MY_DB_TOKEN}")
	require.NoError(t, err)
	require.Equal(t, "tok-123 from tok-123", got)
}

func TestResolver_NoReferences(t *testing.T) {
	r, err := secret.NewResolver(nil, zap.NewNop())
	require.NoError(t, err)

	got, err := r.Resolve("plain string with no refs")
	require.NoError(t, err)
	require.Equal(t, "plain string with no refs", got)

	gotBytes, err := r.ResolveBytes([]byte("also plain"))
	require.NoError(t, err)
	require.Equal(t, "also plain", string(gotBytes))
}

func TestResolver_UnknownStore(t *testing.T) {
	r, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: nil},
	}, zap.NewNop())
	require.NoError(t, err)

	_, err = r.Resolve("@{nonexistent:foo}")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown store")
	require.Contains(t, err.Error(), "nonexistent")
}

func TestResolver_MissingKey(t *testing.T) {
	r, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: nil},
	}, zap.NewNop())
	require.NoError(t, err)

	_, err = r.Resolve("@{env:TFO_DEFINITELY_UNSET_KEY_XYZ}")
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve")
}

func TestResolver_UnknownStoreType(t *testing.T) {
	_, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "mystery", Type: "no-such-backend", Config: nil},
	}, zap.NewNop())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown store type")
}

func TestResolver_DuplicateStoreName(t *testing.T) {
	_, err := secret.NewResolver([]secret.StoreConfig{
		{Name: "env", Type: "env", Config: nil},
		{Name: "env", Type: "env", Config: nil},
	}, zap.NewNop())
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

func TestResolver_AllRegisteredByAllPackage(t *testing.T) {
	// Importing internal/secret/all should have registered every backend.
	require.Contains(t, []string{"env", "file", "vault"}, "env")
}
