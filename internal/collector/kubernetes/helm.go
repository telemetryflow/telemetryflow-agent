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
	"fmt"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"go.uber.org/zap"
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
//
// Root cause of stale metrics: the prior code emitted only an aggregate
// k8s.helm.release.count per namespace. If the number of releases in a namespace
// stays constant, the gauge value does not change and the platform sees no new
// data-points. Per-release metrics (revision, info) are now emitted so every
// collection cycle produces fresh time-series for each release.
//
// Listing strategy: primary pass uses LabelSelector "owner=helm" (standard for
// Helm v3). A fallback pass lists ALL secrets and filters by
// type=helm.sh/release.v1 to catch any releases whose owner label is absent
// (e.g. Helm 2 → 3 migration artifacts or manually crafted secrets).
func collectHelmReleases(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []HelmReleaseState, error) {
	// Primary: owner=helm labelled secrets (standard Helm v3 path).
	secrets, err := cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list helm secrets: %w", err)
	}

	// Keep the highest-revision release per key.
	latest := make(map[string]HelmReleaseState)
	decoded := 0
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
			logger.Debug("helm: skipping undecodable release secret",
				zap.String("secret", sec.Namespace+"/"+sec.Name),
				zap.Error(derr))
			continue
		}
		decoded++

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

	// Fallback: if the labelled list returned fewer secrets than expected (e.g.
	// owner label missing), also scan unlabelled secrets by type.
	// We only do the fallback when the primary list was non-empty but decoded
	// zero payload-bearing secrets — avoids a double full-list on healthy clusters.
	if len(secrets.Items) > 0 && decoded == 0 {
		allSecrets, ferr := cs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
		if ferr != nil {
			logger.Warn("helm: fallback all-secrets list failed", zap.Error(ferr))
		} else {
			for i := range allSecrets.Items {
				sec := &allSecrets.Items[i]
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
					continue
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
		}
	}

	states := make([]HelmReleaseState, 0, len(latest))
	nsCounts := make(map[string]int)
	for _, s := range latest {
		states = append(states, s)
		nsCounts[s.Namespace]++
	}

	var metrics []collector.Metric

	// Aggregate count per namespace (unchanged, backward-compatible).
	for ns, count := range nsCounts {
		metrics = append(metrics,
			collector.NewMetric("k8s.helm.release.count", float64(count), collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", ns).
				WithDescription("Helm release count per namespace"),
		)
	}

	// Per-release metrics: emit one data-point per release every cycle so the
	// platform receives fresh time-series even when aggregate counts are stable.
	for _, s := range states {
		releaseLabels := map[string]string{
			"cluster":     cluster,
			"namespace":   s.Namespace,
			"release":     s.Name,
			"chart":       s.Chart,
			"version":     s.Version,
			"app_version": s.AppVersion,
			"status":      s.Status,
		}
		metrics = append(metrics,
			// Current revision number — changes on every helm upgrade.
			collector.NewMetric("k8s.helm.release.revision", float64(s.Revision), collector.MetricTypeGauge).
				WithLabels(releaseLabels).
				WithDescription("Helm release current revision number"),
			// Info gauge: always 1, but label set changes with status/version so
			// the platform can build a time-series of status transitions.
			collector.NewMetric("k8s.helm.release.info", 1.0, collector.MetricTypeGauge).
				WithLabels(releaseLabels).
				WithDescription("Helm release info (labels carry status, chart, version)"),
		)
		// deployed=1/0 for quick alerting on non-deployed releases.
		deployed := 0.0
		if s.Status == "deployed" {
			deployed = 1.0
		}
		metrics = append(metrics,
			collector.NewMetric("k8s.helm.release.deployed", deployed, collector.MetricTypeGauge).
				WithLabel("cluster", cluster).
				WithLabel("namespace", s.Namespace).
				WithLabel("release", s.Name).
				WithDescription("1 if helm release status is deployed, 0 otherwise"),
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
