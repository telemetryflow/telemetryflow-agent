// Package system_test contains unit tests for the corresponding collector module.
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

package system_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

// cloudEnvVars are cleared so filesystem-marker detection paths are reached.
var cloudEnvVars = []string{
	"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "AWS_REGION",
	"GOOGLE_CLOUD_PROJECT", "ALIBABA_CLOUD_REGION_ID", "ALICLOUD_REGION",
	"HUAWEICLOUD_REGION", "DIGITALOCEAN_TOKEN", "DO_REGION",
}

var k8sEnvVars = []string{
	"AWS_REGION", "EKS_CLUSTER_NAME", "GOOGLE_CLOUD_PROJECT", "GKE_CLUSTER_NAME",
	"AKS_CLUSTER_NAME", "AZURE_SUBSCRIPTION_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID",
	"ACK_CLUSTER_ID", "HUAWEICLOUD_SDK_TYPE", "CCE_CLUSTER_ID",
	"OPENSHIFT_BUILD_NAMESPACE", "OPENSHIFT_DEPLOYMENT_NAME", "OKD_CLUSTER",
	"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "MINIKUBE_ACTIVE_DOCKERD",
	"MINIKUBE_HOME", "KIND_CLUSTER_NAME", "KUBESPHERE_NAMESPACE",
	"KUBERNETES_SERVICE_HOST",
}

// writeHostFile creates root/relpath (with parents) containing content.
func writeHostFile(t *testing.T, root, relpath, content string) {
	t.Helper()
	full := filepath.Join(root, relpath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// mkHostDir creates root/relpath as a directory (for hostStat marker checks).
func mkHostDir(t *testing.T, root, relpath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, relpath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", relpath, err)
	}
}

// TestDetectK8sProviderHostRoot exercises the filesystem-marker (hostStat)
// branches of detectK8sProvider using TELEMETRYFLOW_HOST_ROOT fixtures — the
// exact mechanism the DaemonSet uses in production.
func TestDetectK8sProviderHostRoot(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		wantProv string
	}{
		{"microshift", "var/lib/microshift", "microshift"},
		{"openshift", "etc/openshift", "openshift"},
		{"okd", "etc/okd", "okd"},
		{"k3s", "var/lib/rancher/k3s", "k3s"},
		{"rke2", "var/lib/rancher/rke2", "rancher"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range k8sEnvVars {
				t.Setenv(v, "")
			}
			root := t.TempDir()
			mkHostDir(t, root, tc.dir)
			t.Setenv("TELEMETRYFLOW_HOST_ROOT", root)

			k8s, prov := system.DetectK8sProviderExported()
			if !k8s || prov != tc.wantProv {
				t.Errorf("got (%v, %q), want (true, %q)", k8s, prov, tc.wantProv)
			}
		})
	}
}

// TestDetectCloudMetadataHostRoot exercises the DMI-marker detection branches of
// detectCloudMetadata via TELEMETRYFLOW_HOST_ROOT fixtures, with a mock IMDS
// client so the follow-on metadata fetches stay fully offline.
func TestDetectCloudMetadataHostRoot(t *testing.T) {
	// writeNeutralDMI stubs EVERY DMI attribute detectCloudMetadata reads
	// with non-matching content. readDMI falls back to the direct path when
	// the hostRoot-prefixed file is missing, so a fixture that only stubs
	// the case-specific attribute lets the runner's real /sys leak into the
	// decision: on Azure-hosted CI runners (GitHub ubuntu = Azure VMs) the
	// real sys_vendor contains "Microsoft Corporation", the azure branch
	// fires before alibaba, and the alibaba subtest fails. Neutral defaults
	// for all attributes keep every subtest hermetic on any runner.
	writeNeutralDMI := func(t *testing.T, root string) {
		t.Helper()
		writeHostFile(t, root, "sys/hypervisor/uuid", "00000000-0000-0000-0000-000000000000\n")
		writeHostFile(t, root, "sys/class/dmi/id/product_name", "Generic Test VM\n")
		writeHostFile(t, root, "sys/class/dmi/id/sys_vendor", "Test Vendor\n")
	}

	tests := []struct {
		name     string
		relpath  string
		content  string
		wantProv string
	}{
		{"gcp", "sys/class/dmi/id/product_name", "Google Compute Engine", "gcp"},
		{"azure", "sys/class/dmi/id/sys_vendor", "Microsoft Corporation", "azure"},
		{"alibaba", "sys/class/dmi/id/product_name", "Alibaba Cloud ECS", "alibaba"},
		{"huawei", "sys/class/dmi/id/sys_vendor", "HUAWEI", "huawei"},
		{"digitalocean", "sys/class/dmi/id/sys_vendor", "DigitalOcean", "digitalocean"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restore := system.SetIMDSClientForTest(mockIMDSClient())
			defer restore()
			for _, v := range cloudEnvVars {
				t.Setenv(v, "")
			}
			root := t.TempDir()
			writeNeutralDMI(t, root)
			writeHostFile(t, root, tc.relpath, tc.content)
			t.Setenv("TELEMETRYFLOW_HOST_ROOT", root)

			prov, _, _, _, _ := system.DetectCloudMetadataExported()
			if prov != tc.wantProv {
				t.Errorf("provider = %q, want %q", prov, tc.wantProv)
			}
		})
	}

	// With only neutral markers no provider must be detected — this locks
	// in hermeticity: a failure here means the runner's real /sys (e.g.
	// Azure "Microsoft Corporation" sys_vendor on GitHub-hosted runners)
	// leaked through the direct-path fallback.
	t.Run("none", func(t *testing.T) {
		for _, v := range cloudEnvVars {
			t.Setenv(v, "")
		}
		root := t.TempDir()
		writeNeutralDMI(t, root)
		t.Setenv("TELEMETRYFLOW_HOST_ROOT", root)

		prov, _, _, _, _ := system.DetectCloudMetadataExported()
		if prov != "" {
			t.Errorf("provider = %q, want \"\" (neutral fixture must mask the host DMI)", prov)
		}
	})
}

// TestDetectCloudMetadataRancherHostRoot covers the k3s/rke2/rancher marker
// branches that return before any IMDS call.
func TestDetectCloudMetadataRancherHostRoot(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		wantProv string
	}{
		{"k3s", "var/lib/rancher/k3s", "k3s"},
		{"rke2", "var/lib/rancher/rke2", "rancher"},
		{"rancher", "var/lib/rancher", "rancher"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range cloudEnvVars {
				t.Setenv(v, "")
			}
			root := t.TempDir()
			mkHostDir(t, root, tc.dir)
			t.Setenv("TELEMETRYFLOW_HOST_ROOT", root)

			prov, _, _, _, _ := system.DetectCloudMetadataExported()
			if prov != tc.wantProv {
				t.Errorf("provider = %q, want %q", prov, tc.wantProv)
			}
		})
	}
}

// TestFetchAWSIMDSv1Fallback forces the token PUT to fail so fetchAWSIMDS falls
// back to the header-less IMDSv1 request path.
func TestFetchAWSIMDSv1Fallback(t *testing.T) {
	restore := system.SetIMDSClientForTest(v1FallbackIMDSClient())
	defer restore()
	id, typ, region, zone := system.FetchAWSIMDSExported()
	if id != "i-v1id" || typ != "m5.large" || zone != "eu-west-1b" || region != "eu-west-1" {
		t.Errorf("aws v1 = %q %q %q %q", id, typ, region, zone)
	}
}
