// Package vault implements a HashiCorp Vault SecretStore using the Vault
// HTTP API directly (no external SDK dependency).
//
// Secrets are read from the KV Secrets Engine version 2 (the default mounted
// at "secret/"). The expected path shape for a read is:
//
//	GET {address}/v1/{mount}/data/{key}
//
// and the response envelope is:
//
//	{"data": {"data": {"value": "..."}, "metadata": {...}}}
//
// Production deployments should inject short-lived tokens via a Vault Agent
// sidecar (response-wrapping or auto-auth) rather than baking long-lived
// tokens into agent configuration.
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
package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// init registers the vault SecretStore under the name "vault".
func init() {
	plugin.MustAddSecretStore("vault", func() plugin.SecretStore { return &VaultStore{} })
}

// VaultStore resolves secrets from a HashiCorp Vault server via its HTTP API.
//
// Only the KV Secrets Engine v2 read/list paths are implemented; writes and
// auth flows are intentionally out of scope (the agent consumes secrets, it
// does not manage them).
type VaultStore struct {
	address    string
	token      string
	namespace  string
	mountPath  string
	listPrefix string
	client     *http.Client
}

// Name returns the registry name of this store: "vault".
func (s *VaultStore) Name() string { return "vault" }

// Init configures the store. Recognised config keys:
//
//   - address        (string, required): Vault base URL, e.g. "https://vault:8200".
//   - token          (string, optional): X-Vault-Token value. Prefer injecting
//     this via ${VAULT_TOKEN} so it is resolved from the process env.
//   - namespace      (string, optional): X-Vault-Namespace value for Namespaces
//     (Vault Enterprise).
//   - mount_path     (string, optional, default "secret"): KV v2 mount point.
//   - list_prefix    (string, optional): path prefix passed to List.
//   - tls_skip_verify (bool, optional, default false): disables TLS certificate
//     verification. Intended for local dev only.
//
// nil config is rejected; "address" is mandatory.
func (s *VaultStore) Init(config map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("vault store: config is nil")
	}
	rawAddr, ok := config["address"]
	if !ok {
		return fmt.Errorf("vault store: \"address\" is required")
	}
	address, ok := rawAddr.(string)
	if !ok || address == "" {
		return fmt.Errorf("vault store: \"address\" must be a non-empty string")
	}
	s.address = strings.TrimRight(address, "/")

	if v, ok := config["token"].(string); ok {
		s.token = v
	}
	if v, ok := config["namespace"].(string); ok {
		s.namespace = v
	}
	s.mountPath = "secret"
	if v, ok := config["mount_path"].(string); ok {
		if v = strings.Trim(v, "/"); v != "" {
			s.mountPath = v
		}
	}
	if v, ok := config["list_prefix"].(string); ok {
		s.listPrefix = strings.Trim(v, "/")
	}
	skipVerify := false
	if v, ok := config["tls_skip_verify"].(bool); ok {
		skipVerify = v
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if skipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	s.client = client
	return nil
}

// Get reads a single secret from Vault's KV v2 backend at
// {address}/v1/{mount}/data/{key}. The secret payload must contain a "value"
// field; non-string values are best-effort coerced to a string.
func (s *VaultStore) Get(key string) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", s.address, s.mountPath, strings.Trim(key, "/"))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("vault store: build request for %q: %w", key, err)
	}
	s.applyHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault store: request for %q: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("vault store: read body for %q: %w", key, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault store: GET %q: status %d: %s",
			key, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// KV v2 envelope: {"data": {"data": {...}, "metadata": {...}}}
	var envelope struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("vault store: parse response for %q: %w", key, err)
	}
	raw, ok := envelope.Data.Data["value"]
	if !ok {
		return "", fmt.Errorf("vault store: secret %q has no \"value\" field", key)
	}
	switch v := raw.(type) {
	case string:
		return v, nil
	case bool:
		return fmt.Sprintf("%v", v), nil
	case float64:
		return fmt.Sprintf("%v", v), nil
	default:
		rendered, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("vault store: encode value for %q: %w", key, err)
		}
		return string(rendered), nil
	}
}

// List issues a Vault LIST request against the metadata API at
// {address}/v1/{mount}/metadata/{list_prefix}?list=true and returns the
// returned key names. An empty list_prefix lists the root of the mount.
func (s *VaultStore) List() ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s?list=true",
		s.address, s.mountPath, s.listPrefix)
	req, err := http.NewRequest("LIST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault store: build list request: %w", err)
	}
	s.applyHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault store: list request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vault store: read list body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault store: list: status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var listed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		return nil, fmt.Errorf("vault store: parse list response: %w", err)
	}
	return listed.Data.Keys, nil
}

// GetResolver returns a resolver closure for the given key. The returned
// resolver is dynamic (dynamic=true): Vault leases can rotate values between
// resolutions, so each call re-fetches from the server.
func (s *VaultStore) GetResolver(key string) (plugin.ResolveFunc, error) {
	store := s
	return func() (string, bool, error) {
		v, err := store.Get(key)
		return v, true, err
	}, nil
}

// applyHeaders sets the auth/namespace headers every request needs.
func (s *VaultStore) applyHeaders(req *http.Request) {
	if s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
}
