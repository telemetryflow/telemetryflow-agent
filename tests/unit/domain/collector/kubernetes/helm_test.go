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
package kubernetes_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// helmReleaseJSON marshals a Helm v3 release payload matching the fields the
// collector decodes from helm.sh/release.v1 secrets.
func helmReleaseJSON(t *testing.T, name, namespace string, revision int, status, lastDeployed string) []byte {
	t.Helper()
	payload := map[string]interface{}{
		"name":      name,
		"namespace": namespace,
		"version":   revision,
		"info": map[string]interface{}{
			"status":        status,
			"last_deployed": lastDeployed,
			"notes":         "test notes for " + name,
		},
		"chart": map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":       name + "-chart",
				"version":    "1.2.3",
				"appVersion": "4.5.6",
			},
		},
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return raw
}

// encodeHelmRelease produces the standard Helm v3 secret payload:
// base64(gzip(json)).
func encodeHelmRelease(t *testing.T, releaseJSON []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(releaseJSON)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes()))
}

// gzipHelmRelease produces a gzip(json) payload without base64 wrapping.
func gzipHelmRelease(t *testing.T, releaseJSON []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(releaseJSON)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// helmSecretWithPayload builds a labelled helm.sh/release.v1 Secret whose
// release field carries the given raw bytes (for alternate-encoding fixtures).
func helmSecretWithPayload(namespace, secretName string, release []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
			Labels:    map[string]string{"owner": "helm"},
		},
		Type: corev1.SecretType("helm.sh/release.v1"),
		Data: map[string][]byte{"release": release},
	}
}

// helmReleaseSecret builds a helm.sh/release.v1 Secret carrying the payload.
func helmReleaseSecret(t *testing.T, namespace, secretName, name, payloadNS string, revision int, status string) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
			Labels:    map[string]string{"owner": "helm"},
		},
		Type: corev1.SecretType("helm.sh/release.v1"),
		Data: map[string][]byte{
			"release": encodeHelmRelease(t, helmReleaseJSON(t, name, payloadNS, revision, status, "2026-09-15T01:02:03Z")),
		},
	}
}

func TestCollectHelmReleaseMetrics(t *testing.T) {
	logger := zap.NewNop()
	cs := fake.NewClientset(
		// Two revisions of the same release: only the newest revision is kept,
		// so "default" must report a count of 1, not 2.
		helmReleaseSecret(t, "default", "sh.helm.release.v1.wordpress.1", "wordpress", "default", 1, "superseded"),
		helmReleaseSecret(t, "default", "sh.helm.release.v2.wordpress.2", "wordpress", "default", 2, "deployed"),
		// A release in another namespace.
		helmReleaseSecret(t, "monitoring", "sh.helm.release.v1.grafana.1", "grafana", "monitoring", 1, "deployed"),
		// Payload with an empty namespace: falls back to the secret namespace.
		helmReleaseSecret(t, "kube-system", "sh.helm.release.v1.coredns.1", "coredns", "", 1, "deployed"),
		// Legacy gzip-only payload (no base64 layer): decodes via the fallback.
		helmSecretWithPayload("team-a", "sh.helm.release.v1.legacy.1",
			gzipHelmRelease(t, helmReleaseJSON(t, "legacy", "team-a", 1, "deployed", "2026-09-15T01:02:03Z"))),
		// Raw JSON payload (no gzip, no base64): decodes via the final fallback.
		helmSecretWithPayload("team-b", "sh.helm.release.v1.plainjson.1",
			helmReleaseJSON(t, "plainjson", "team-b", 1, "deployed", "2026-09-15T01:02:03Z")),
		// Truncated gzip stream: undecodable, skipped without failing collection.
		helmSecretWithPayload("default", "sh.helm.release.v1.truncated.1", func() []byte {
			full := gzipHelmRelease(t, helmReleaseJSON(t, "truncated", "default", 1, "deployed", ""))
			return full[:len(full)-4]
		}()),
		// gzip of invalid JSON: undecodable through every fallback, skipped.
		helmSecretWithPayload("default", "sh.helm.release.v1.badjson.1",
			gzipHelmRelease(t, []byte("{not-json"))),
		// Opaque secret carrying the owner=helm label: ignored by the type check.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "opaque-helm-labelled",
				Labels:    map[string]string{"owner": "helm"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"release": []byte("anything")},
		},
		// Helm-type secret without release data: skipped.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "sh.helm.release.v1.empty.1",
				Labels:    map[string]string{"owner": "helm"},
			},
			Type: corev1.SecretType("helm.sh/release.v1"),
		},
		// Helm-type secret with an undecodable payload: skipped, not fatal.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "sh.helm.release.v1.garbage.1",
				Labels:    map[string]string{"owner": "helm"},
			},
			Type: corev1.SecretType("helm.sh/release.v1"),
			Data: map[string][]byte{"release": []byte("%%%garbage%%%")},
		},
		// Decodable release secret without the owner=helm label: filtered out
		// by the list label selector.
		func() *corev1.Secret {
			sec := helmReleaseSecret(t, "default", "sh.helm.release.v1.unlabelled.1", "unlabelled", "default", 1, "deployed")
			sec.Labels = nil
			return sec
		}(),
	)

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	counts := map[string]float64{}
	for _, m := range metrics {
		if m.Name != "k8s.helm.release.count" {
			continue
		}
		assert.Equal(t, "test-cluster", m.Labels["cluster"])
		counts[m.Labels["namespace"]] = m.Value
	}
	assert.InDeltaMapValues(t, map[string]float64{
		"default":     1,
		"monitoring":  1,
		"kube-system": 1,
		"team-a":      1,
		"team-b":      1,
	}, counts, 0, "one latest release per namespace expected; duplicate revisions must be deduplicated")
}

func TestCollectHelmReleaseMetrics_ExcludeNamespace(t *testing.T) {
	logger := zap.NewNop()
	cs := fake.NewClientset(
		helmReleaseSecret(t, "default", "sh.helm.release.v1.app.1", "app", "default", 1, "deployed"),
		helmReleaseSecret(t, "monitoring", "sh.helm.release.v1.grafana.1", "grafana", "monitoring", 1, "deployed"),
	)

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:           true,
			ClusterName:       "test-cluster",
			ExcludeNamespaces: []string{"monitoring"},
		}, cs, nil, logger,
	)

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name != "k8s.helm.release.count" {
			continue
		}
		assert.Equal(t, "default", m.Labels["namespace"], "excluded namespace must not be reported")
		assert.Equal(t, 1.0, m.Value)
	}
}

func TestCollectHelmReleaseMetrics_EmptyCluster(t *testing.T) {
	logger := zap.NewNop()
	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			ClusterName: "test-cluster",
		}, fake.NewClientset(), nil, logger,
	)

	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)
	for _, m := range metrics {
		assert.NotEqual(t, "k8s.helm.release.count", m.Name, "no helm metrics expected on an empty cluster")
	}
}

func TestCollectHelmReleaseMetrics_ListError(t *testing.T) {
	logger := zap.NewNop()
	cs := fake.NewClientset()
	cs.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, assert.AnError
	})

	collector := k8scollector.NewKubernetesCollectorForTest(
		config.KubernetesCollectorConfig{
			Enabled:     true,
			ClusterName: "test-cluster",
		}, cs, nil, logger,
	)

	// The list failure is logged, not fatal for the collection cycle.
	metrics, err := collector.Collect(context.Background())
	require.NoError(t, err)
	for _, m := range metrics {
		assert.NotEqual(t, "k8s.helm.release.count", m.Name, "no helm metrics expected when the secret list fails")
	}
}
