// Package kubernetes_test contains httptest-backed unit tests for the Kubernetes
// collector paths that go through the API-server RESTClient proxy (apiserver
// /metrics, node logs, CoreDNS proxy), the direct kubelet HTTPS fetcher, the
// REST-config/clientset builders, cluster detection, and the metrics-server →
// kubelet fallback — all reproducibly via httptest and temp files, no live
// cluster.
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
package kubernetes_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"

	k8scollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// realMetricsClientOverHTTP builds a real metrics.k8s.io clientset pointed at an
// httptest server. The generated metrics fake clientset cannot list seeded
// objects, so httptest is the reproducible way to exercise the metrics-server
// path (fetchNodeMetrics, fetchPodMetrics, tryMetricsAPI).
func realMetricsClientOverHTTP(t *testing.T) metricsv.Interface {
	t.Helper()

	nodeMetricsList := metricsv1beta1.NodeMetricsList{
		TypeMeta: metav1.TypeMeta{Kind: "NodeMetricsList", APIVersion: "metrics.k8s.io/v1beta1"},
		Items: []metricsv1beta1.NodeMetrics{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
				Usage:      corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("1Gi")},
			},
		},
	}
	podMetricsList := metricsv1beta1.PodMetricsList{
		TypeMeta: metav1.TypeMeta{Kind: "PodMetricsList", APIVersion: "metrics.k8s.io/v1beta1"},
		Items: []metricsv1beta1.PodMetrics{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "rich-pod", Namespace: "default"},
				Containers: []metricsv1beta1.ContainerMetrics{
					{Name: "main", Usage: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			writeJSON(w, nodeMetricsList)
		case strings.HasSuffix(r.URL.Path, "/pods"):
			writeJSON(w, podMetricsList)
		default:
			writeJSON(w, &metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Success"})
		}
	}))
	t.Cleanup(srv.Close)

	mc, err := metricsv.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)
	return mc
}

const apiServerMetricsText = `# HELP apiserver_request_total requests
# TYPE apiserver_request_total counter
apiserver_request_total{verb="GET",code="200"} 42
apiserver_current_inflight_requests{request_kind="mutating"} 1
`

const corednsMetricsText = `# HELP coredns_dns_requests_total requests
# TYPE coredns_dns_requests_total counter
coredns_dns_requests_total{server="dns://:53"} 100
coredns_dns_responses_total{rcode="NOERROR"} 90
`

// realClientsetOverHTTP builds a real client-go clientset pointed at an httptest
// server that emulates the API-server endpoints the proxy-based collectors use.
func realClientsetOverHTTP(t *testing.T) kubernetes.Interface {
	t.Helper()

	nodeList := corev1.NodeList{
		TypeMeta: metav1.TypeMeta{Kind: "NodeList", APIVersion: "v1"},
		Items: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
		},
	}
	podList := corev1.PodList{
		TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"},
		Items: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "coredns-1", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/metrics":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(apiServerMetricsText))
		case strings.HasSuffix(path, "/proxy/metrics"):
			// CoreDNS via API-server service proxy fallback.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(corednsMetricsText))
		case strings.Contains(path, "/proxy/logs/"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("log line one\nlog line two\n"))
		case path == "/api/v1/nodes":
			writeJSON(w, nodeList)
		case strings.Contains(path, "/namespaces/kube-system/pods"):
			writeJSON(w, podList)
		default:
			writeJSON(w, &metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Success"})
		}
	}))
	t.Cleanup(srv.Close)

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)
	return cs
}

func writeJSON(w http.ResponseWriter, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(obj)
}

func TestCollectApiServerMetricsOverHTTP(t *testing.T) {
	cs := realClientsetOverHTTP(t)
	metrics, err := k8scollector.CollectApiServerMetricsExported(context.Background(), cs, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, metrics)
}

func TestCollectNodeLogsOverHTTP(t *testing.T) {
	cs := realClientsetOverHTTP(t)
	cfg := config.KubernetesCollectorConfig{
		NodeLogs:          true,
		NodeLogsTailLines: 50,
		NodeLogSources:    []string{"kubelet"},
	}
	entries, err := k8scollector.CollectNodeLogsExported(context.Background(), cs, cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	assert.Equal(t, "node-a", entries[0].NodeName)
	assert.NotEmpty(t, entries[0].Lines)
}

func TestCollectCoreDNSMetricsOverHTTP(t *testing.T) {
	cs := realClientsetOverHTTP(t)
	// Pod-IP scrape (127.0.0.1:9153) is refused, so the collector falls back to
	// the API-server service proxy, which the test server serves.
	metrics, err := k8scollector.CollectCoreDNSMetricsExported(context.Background(), cs, "", zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, metrics)
}

// ── Direct kubelet HTTPS fetcher ──────────────────────────────────────────

func TestKubeletHTTPFetcherFetchNodeStats(t *testing.T) {
	summaryJSON := `{"node":{"nodeName":"n","cpu":{"usageNanoCores":1000000000},"memory":{"workingSetBytes":2048}},"pods":[{"podRef":{"name":"p","namespace":"default"},"containers":[{"name":"c","cpu":{"usageNanoCores":500000000}}]}]}`

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stats/summary", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(summaryJSON))
	}))
	defer srv.Close()

	host, portStr, err := splitHostPort(srv.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(portStr)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("test-token"), 0o600))

	fetcher := k8scollector.NewKubeletHTTPFetcherForTest(srv.Client(), port, tokenFile, "")
	summary, err := fetcher.FetchNodeStats(context.Background(), host)
	require.NoError(t, err)
	require.NotNil(t, summary.Node.CPU)
	assert.Equal(t, uint64(1000000000), *summary.Node.CPU.UsageNanoCores)
	require.Len(t, summary.Pods, 1)
}

func TestKubeletHTTPFetcherErrors(t *testing.T) {
	// Missing token file -> read error.
	f := k8scollector.NewKubeletHTTPFetcherForTest(http.DefaultClient, 10250, filepath.Join(t.TempDir(), "nope"), "")
	_, err := f.FetchNodeStats(context.Background(), "127.0.0.1")
	require.Error(t, err)

	// Non-200 status -> unexpected status error.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	host, portStr, _ := splitHostPort(srv.URL)
	port, _ := strconv.Atoi(portStr)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("t"), 0o600))
	f2 := k8scollector.NewKubeletHTTPFetcherForTest(srv.Client(), port, tokenFile, "")
	_, err = f2.FetchNodeStats(context.Background(), host)
	require.Error(t, err)
}

func TestNewKubeletHTTPFetcher(t *testing.T) {
	// insecure=true skips CA reading and succeeds.
	f, err := k8scollector.NewKubeletHTTPFetcher(true)
	require.NoError(t, err)
	require.NotNil(t, f)

	// insecure=false attempts to read the in-cluster CA which is absent in tests.
	_, err = k8scollector.NewKubeletHTTPFetcher(false)
	require.Error(t, err)
}

func splitHostPort(rawURL string) (host, port string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	return u.Hostname(), u.Port(), nil
}

// ── REST config / clientset builders ──────────────────────────────────────

const kubeconfigYAML = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: abc
`

func TestClientBuilders(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(kubeconfigYAML), 0o600))

	require.NoError(t, k8scollector.BuildRESTConfigExported(kubeconfig, "test"))
	require.NoError(t, k8scollector.NewClientsetExported(kubeconfig, ""))
	require.NoError(t, k8scollector.NewMetricsClientsetExported(kubeconfig, ""))

	// KUBECONFIG env-var branch.
	t.Setenv("KUBECONFIG", kubeconfig)
	require.NoError(t, k8scollector.BuildRESTConfigExported("", ""))

	// Explicit missing path -> error (also drives the builder error paths in
	// newClientset / newMetricsClientset).
	absent := filepath.Join(t.TempDir(), "absent")
	require.Error(t, k8scollector.BuildRESTConfigExported(absent, ""))
	require.Error(t, k8scollector.NewClientsetExported(absent, ""))
	require.Error(t, k8scollector.NewMetricsClientsetExported(absent, ""))

	// No explicit path and no KUBECONFIG: exercises the in-cluster/default
	// kubeconfig fallback branch of buildRESTConfig. Result may be an error
	// (no cluster reachable) — we only care that the branch runs.
	require.NoError(t, os.Unsetenv("KUBECONFIG"))
	_ = k8scollector.BuildRESTConfigExported("", "")
}

// ── Cluster detection ─────────────────────────────────────────────────────

func TestDetectClusterName(t *testing.T) {
	t.Setenv("CLUSTER_NAME", "my-cluster")
	assert.Equal(t, "my-cluster", k8scollector.DetectClusterNameExported())

	t.Setenv("CLUSTER_NAME", "")
	t.Setenv("KUBE_CLUSTER_NAME", "kube-cluster")
	assert.Equal(t, "kube-cluster", k8scollector.DetectClusterNameExported())

	t.Setenv("KUBE_CLUSTER_NAME", "")
	t.Setenv("EKS_CLUSTER_NAME", "eks-cluster")
	assert.Equal(t, "eks-cluster", k8scollector.DetectClusterNameExported())

	t.Setenv("EKS_CLUSTER_NAME", "")
	// Falls back to hostname or "unknown"; just ensure non-empty.
	assert.NotEmpty(t, k8scollector.DetectClusterNameExported())
}

func TestDetectClusterProvider(t *testing.T) {
	cases := []struct {
		env  string
		val  string
		want string
	}{
		{"AWS_REGION", "us-east-1", "eks"},
		{"GOOGLE_CLOUD_PROJECT", "proj", "gke"},
		{"AKS_CLUSTER_NAME", "aks", "aks"},
		{"ACK_CLUSTER_ID", "ack", "ack"},
		{"CCE_CLUSTER_ID", "cce", "cce"},
		{"OPENSHIFT_BUILD_NAMESPACE", "ns", "openshift"},
		{"OKD_CLUSTER", "1", "okd"},
		{"CATTLE_SERVER", "https://x", "rancher"},
		{"MINIKUBE_HOME", "/x", "minikube"},
		{"KIND_CLUSTER_NAME", "kind", "kind"},
		{"KUBESPHERE_NAMESPACE", "ks", "kubesphere"},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			// Isolate: point host-root at an empty dir so filesystem heuristics miss.
			t.Setenv("TELEMETRYFLOW_HOST_ROOT", t.TempDir())
			t.Setenv(c.env, c.val)
			assert.Equal(t, c.want, k8scollector.DetectClusterProviderExported())
		})
	}

	t.Run("self-managed", func(t *testing.T) {
		t.Setenv("TELEMETRYFLOW_HOST_ROOT", t.TempDir())
		assert.Equal(t, "self-managed", k8scollector.DetectClusterProviderExported())
	})
}

// ── metrics-server → kubelet fallback ─────────────────────────────────────

func nodeWithLocalIP() *fake.Clientset {
	return fake.NewClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-local"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "127.0.0.1"}},
		},
	})
}

func fallbackConfig() config.KubernetesCollectorConfig {
	return config.KubernetesCollectorConfig{
		Enabled:                   true,
		Interval:                  time.Second,
		Nodes:                     true,
		MetricsAPI:                true,
		KubeletInsecureSkipVerify: true,
		ClusterName:               "test-cluster",
	}
}

func TestUsageMetricsFallbackToKubelet(t *testing.T) {
	// metricsClient nil -> skip metrics API, go straight to kubelet fallback.
	// The kubelet fetch to 127.0.0.1:10250 is refused, yielding no metrics but
	// no hard error (per-node errors are swallowed).
	coll := k8scollector.NewKubernetesCollectorForTest(fallbackConfig(), nodeWithLocalIP(), nil, zap.NewNop())
	_, err := coll.Collect(context.Background())
	require.NoError(t, err)
	// Second cycle transitions source again via lastState nodes.
	_, err = coll.Collect(context.Background())
	require.NoError(t, err)
}

func TestUsageMetricsFallbackCASource(t *testing.T) {
	// KubeletInsecureSkipVerify=false forces NewKubeletHTTPFetcher to read the
	// in-cluster CA (absent), so collectFromKubelet returns an error and the
	// source transitions to "unavailable".
	cfg := fallbackConfig()
	cfg.KubeletInsecureSkipVerify = false
	coll := k8scollector.NewKubernetesCollectorForTest(cfg, nodeWithLocalIP(), nil, zap.NewNop())
	_, err := coll.Collect(context.Background())
	require.NoError(t, err)
}

// ── NewKubernetesCollector constructor ────────────────────────────────────

func TestNewKubernetesCollector(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(kubeconfigYAML), 0o600))

	cfg := config.KubernetesCollectorConfig{
		Enabled:    true,
		Interval:   time.Second,
		Kubeconfig: kubeconfig,
		MetricsAPI: true,
		// ClusterName/Provider left empty to exercise auto-detection.
	}
	coll, err := k8scollector.NewKubernetesCollector(cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, coll)
	assert.Equal(t, "kubernetes", coll.Name())
	assert.NotEmpty(t, coll.ClusterName())
	assert.NotEmpty(t, coll.ClusterProvider())
	assert.NotNil(t, coll.Clientset())
}

// ── CoreDNS direct-scrape fallback ────────────────────────────────────────

func TestCollectCoreDNSMetricsDirectFallback(t *testing.T) {
	// Direct CoreDNS /metrics service endpoint.
	directSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(corednsMetricsText))
	}))
	defer directSrv.Close()
	directHost, directPort, _ := splitHostPort(directSrv.URL)

	// API server whose proxy/metrics path fails, forcing the direct fallback.
	podList := corev1.PodList{
		TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"},
		Items: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "coredns-1", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
		}},
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/proxy/metrics"):
			w.WriteHeader(http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/namespaces/kube-system/pods"):
			writeJSON(w, podList)
		default:
			writeJSON(w, &metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Success"})
		}
	}))
	defer apiSrv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: apiSrv.URL})
	require.NoError(t, err)

	metrics, err := k8scollector.CollectCoreDNSMetricsExported(context.Background(), cs, directHost+":"+directPort, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, metrics)
}

// erroringMetricsClientOverHTTP returns a metrics client whose API always 500s,
// exercising fetchNodeMetrics' error branch and tryMetricsAPI's failure path.
func erroringMetricsClientOverHTTP(t *testing.T) metricsv.Interface {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	mc, err := metricsv.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)
	return mc
}

func TestCollectWithFailingMetricsServer(t *testing.T) {
	cs := richClientset()
	mc := erroringMetricsClientOverHTTP(t)
	cfg := fullConfig()
	coll := k8scollector.NewKubernetesCollectorForTest(cfg, cs, mc, zap.NewNop())
	coll.SetKubeletFetcher(fakeKubeletFetcher())
	coll.SetCAdvisorFetcher(func(_ context.Context, _ string) ([]byte, error) { return nil, nil })

	_, err := coll.Collect(context.Background())
	require.NoError(t, err)
}

func TestNewKubernetesCollectorBadKubeconfig(t *testing.T) {
	cfg := config.KubernetesCollectorConfig{
		Kubeconfig: filepath.Join(t.TempDir(), "does-not-exist"),
	}
	_, err := k8scollector.NewKubernetesCollector(cfg, zap.NewNop())
	require.Error(t, err)
}

func TestStopWhenNotRunning(t *testing.T) {
	coll := k8scollector.NewKubernetesCollectorForTest(fullConfig(), fake.NewClientset(), nil, zap.NewNop())
	require.NoError(t, coll.Stop())
	assert.False(t, coll.IsRunning())
}

func TestStartStopViaStopChan(t *testing.T) {
	coll := k8scollector.NewKubernetesCollectorForTest(fullConfig(), fake.NewClientset(), nil, zap.NewNop())
	errCh := make(chan error, 1)
	go func() { errCh <- coll.Start(context.Background()) }()
	require.Eventually(t, coll.IsRunning, time.Second, 5*time.Millisecond)
	require.NoError(t, coll.Stop())
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestDetectClusterProviderFilesystem(t *testing.T) {
	cases := []struct {
		rel  string
		want string
	}{
		{"/var/lib/microshift", "microshift"},
		{"/etc/openshift", "openshift"},
		{"/etc/okd", "okd"},
		{"/var/lib/rancher/k3s", "k3s"},
		{"/var/lib/rancher/rke2", "rancher"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(root+c.rel, 0o755))
			t.Setenv("TELEMETRYFLOW_HOST_ROOT", root)
			assert.Equal(t, c.want, k8scollector.DetectClusterProviderExported())
		})
	}
}

// TestCollectFullOverHTTP drives a full Collect against a real clientset over
// httptest with the API-server-proxy collectors (node logs, apiserver, CoreDNS)
// enabled, covering both their success branches and the warn branches of the
// collectors whose list calls the stub server does not satisfy.
func TestCollectFullOverHTTP(t *testing.T) {
	cs := realClientsetOverHTTP(t)
	cfg := fullConfig()
	cfg.MetricsAPI = false
	cfg.NodeLogs = true
	cfg.NodeLogSources = []string{"kubelet"}
	cfg.ApiServerMetrics = true
	cfg.CoreDNSMetrics = true

	coll := k8scollector.NewKubernetesCollectorForTest(cfg, cs, nil, zap.NewNop())
	_, err := coll.Collect(context.Background())
	require.NoError(t, err)

	state := coll.LastClusterState()
	require.NotNil(t, state)
	assert.NotNil(t, state.ApiServerMetrics)
	assert.NotNil(t, state.CoreDNSMetrics)
	assert.NotEmpty(t, state.NodeLogs)
}

func TestCollectCoreDNSMetricsPodScrapeSuccess(t *testing.T) {
	// Bind an httptest server to the fixed CoreDNS metrics port 9153 so the
	// pod-IP scrape path (scrapeCoreDNSPod read loop) succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:9153")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:9153: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(corednsMetricsText))
	})}}
	srv.Start()
	defer srv.Close()

	cs := realClientsetOverHTTP(t) // lists a CoreDNS pod with PodIP 127.0.0.1
	metrics, err := k8scollector.CollectCoreDNSMetricsExported(context.Background(), cs, "", zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, metrics)
}

func TestCollectCoreDNSMetricsPodEdgeCases(t *testing.T) {
	// One CoreDNS pod has no IP (skipped); another returns HTTP 500 on the
	// metrics port (non-200 branch), forcing the API-server proxy fallback.
	ln, err := net.Listen("tcp", "127.0.0.1:9153")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:9153: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})}}
	srv.Start()
	defer srv.Close()

	podList := corev1.PodList{
		TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"},
		Items: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "coredns-noip", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Name: "coredns-500", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"}},
		},
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/proxy/metrics"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(corednsMetricsText))
		case strings.Contains(r.URL.Path, "/namespaces/kube-system/pods"):
			writeJSON(w, podList)
		default:
			writeJSON(w, &metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Success"})
		}
	}))
	defer apiSrv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: apiSrv.URL})
	require.NoError(t, err)
	metrics, err := k8scollector.CollectCoreDNSMetricsExported(context.Background(), cs, "", zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, metrics)
}
