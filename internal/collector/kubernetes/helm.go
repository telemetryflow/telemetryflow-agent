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
package kubernetes

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// helmReleaseSecretType is the Secret.Type Helm v3 uses for release storage.
const helmReleaseSecretType = "helm.sh/release.v1"

// helmReleasePayload is the subset of the Helm v3 release JSON we care about.
// A release Secret's `release` field is base64(gzip(json-of-this)).
type helmReleasePayload struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"` // revision
	Info      struct {
		Status       string `json:"status"`
		LastDeployed string `json:"last_deployed"`
		Notes        string `json:"notes"`
	} `json:"info"`
	Chart struct {
		Metadata struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"metadata"`
	} `json:"chart"`
}

// collectHelmReleases discovers Helm releases from helm.sh/release.v1 Secrets,
// keeping only the newest revision per (namespace, release name).
func collectHelmReleases(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []HelmReleaseState, error) {
	secrets, err := cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm",
	})
	if err != nil {
		return nil, nil, err
	}

	// Keep the highest-revision release per key.
	latest := make(map[string]HelmReleaseState)
	for i := range secrets.Items {
		sec := &secrets.Items[i]
		if string(sec.Type) != helmReleaseSecretType {
			continue
		}
		if !cfg.shouldCollectNamespace(sec.Namespace) {
			continue
		}
		raw, ok := sec.Data["release"]
		if !ok || len(raw) == 0 {
			continue
		}
		payload, derr := decodeHelmRelease(raw)
		if derr != nil {
			continue // skip undecodable release, don't fail the whole collection
		}

		name := payload.Name
		namespace := payload.Namespace
		if namespace == "" {
			namespace = sec.Namespace
		}
		key := namespace + "/" + name

		var updated int64
		if payload.Info.LastDeployed != "" {
			if ts, perr := time.Parse(time.RFC3339, payload.Info.LastDeployed); perr == nil {
				updated = ts.UnixMilli()
			}
		}

		state := HelmReleaseState{
			Name:       name,
			Namespace:  namespace,
			Chart:      payload.Chart.Metadata.Name,
			Version:    payload.Chart.Metadata.Version,
			AppVersion: payload.Chart.Metadata.AppVersion,
			Status:     payload.Info.Status,
			Revision:   payload.Version,
			Updated:    updated,
			Notes:      payload.Info.Notes,
		}

		if prev, exists := latest[key]; !exists || state.Revision > prev.Revision {
			latest[key] = state
		}
	}

	states := make([]HelmReleaseState, 0, len(latest))
	nsCounts := make(map[string]int)
	for _, s := range latest {
		states = append(states, s)
		nsCounts[s.Namespace]++
	}

	var metrics []collector.Metric
	for ns, count := range nsCounts {
		metrics = append(metrics,
			collector.NewMetric("k8s.helm.release.count", float64(count), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ns).
				WithDescription("Helm release count per namespace"),
		)
	}

	return metrics, states, nil
}

// decodeHelmRelease decodes a Helm v3 release Secret payload: the stored value
// is base64(gzip(json)). Falls back to gzip-only, then raw JSON, for resilience.
func decodeHelmRelease(raw []byte) (*helmReleasePayload, error) {
	// Try base64 → gzip → json (the standard Helm v3 encoding).
	if decoded, err := base64.StdEncoding.DecodeString(string(raw)); err == nil {
		if p, gerr := gunzipJSON(decoded); gerr == nil {
			return p, nil
		}
	}
	// Fallback: gzip → json (already-decoded bytes).
	if p, gerr := gunzipJSON(raw); gerr == nil {
		return p, nil
	}
	// Fallback: raw json.
	var p helmReleasePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func gunzipJSON(b []byte) (*helmReleasePayload, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	var p helmReleasePayload
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
