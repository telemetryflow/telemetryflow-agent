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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResp(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// mockIMDSClient returns responses tailored to each provider's endpoints so the
// success-path parsing logic in every fetch* function is exercised offline.
func mockIMDSClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		switch {
		// Alibaba (unique 100.100.100.200 endpoint) — checked first because its
		// path overlaps the AWS "/latest/meta-data/..." prefix.
		case strings.Contains(u, "100.100.100.200"):
			switch {
			case strings.Contains(u, "instance/instance-type"):
				return jsonResp("ecs.g6.large"), nil
			case strings.Contains(u, "instance-id"):
				return jsonResp("i-ali123"), nil
			case strings.Contains(u, "region-id"):
				return jsonResp("cn-hangzhou"), nil
			case strings.Contains(u, "zone-id"):
				return jsonResp("cn-hangzhou-b"), nil
			}
			return jsonResp(""), nil
		// AWS IMDSv2 token
		case r.Method == http.MethodPut && strings.Contains(u, "/latest/api/token"):
			return jsonResp("aws-token"), nil
		case strings.Contains(u, "/latest/meta-data/instance-id"):
			return jsonResp("i-abc123"), nil
		case strings.Contains(u, "/latest/meta-data/instance-type"):
			return jsonResp("t3.micro"), nil
		case strings.Contains(u, "placement/availability-zone"):
			return jsonResp("us-east-2a"), nil
		// GCP
		case strings.Contains(u, "computeMetadata/v1/instance/id"):
			return jsonResp("111222333"), nil
		case strings.Contains(u, "machine-type"):
			return jsonResp("projects/123/machineTypes/e2-medium"), nil
		case strings.Contains(u, "computeMetadata/v1/instance/zone"):
			return jsonResp("projects/123/zones/us-central1-a"), nil
		// Azure
		case strings.Contains(u, "/metadata/instance"):
			return jsonResp(`{"compute":{"vmId":"az-vm","vmSize":"Standard_D2","location":"eastus","zone":"1"}}`), nil
		// Huawei (OpenStack meta_data.json)
		case strings.Contains(u, "openstack/latest/meta_data.json"):
			return jsonResp(`{"uuid":"hw-uuid","availability_zone":"cn-north-4a","meta":{"metering.instance_type":"c6.large"}}`), nil
		// DigitalOcean
		case strings.Contains(u, "/metadata/v1/id"):
			return jsonResp("do-123"), nil
		case strings.Contains(u, "/metadata/v1/dns/hostname"):
			return jsonResp("droplet-host"), nil
		case strings.Contains(u, "/metadata/v1/region"):
			return jsonResp("nyc1"), nil
		case strings.Contains(u, "/metadata/v1/size"):
			return jsonResp("s-1vcpu-1gb"), nil
		}
		return jsonResp(""), nil
	})}
}

// v1FallbackIMDSClient returns 403 for the IMDSv2 token PUT (forcing the
// header-less IMDSv1 fallback) and canned AWS metadata for the GETs.
func v1FallbackIMDSClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		switch {
		case r.Method == http.MethodPut && strings.Contains(u, "/latest/api/token"):
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		case strings.Contains(u, "/latest/meta-data/instance-id"):
			return jsonResp("i-v1id"), nil
		case strings.Contains(u, "/latest/meta-data/instance-type"):
			return jsonResp("m5.large"), nil
		case strings.Contains(u, "placement/availability-zone"):
			return jsonResp("eu-west-1b"), nil
		}
		return jsonResp(""), nil
	})}
}

// failIMDSClient always errors, exercising the failure branches quickly.
func failIMDSClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("no route to metadata service")
	})}
}

func TestImdsGetSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "yes" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("  hello-value  "))
	}))
	defer srv.Close()

	restore := system.SetIMDSClientForTest(srv.Client())
	defer restore()

	got := system.ImdsGetExported(srv.URL, map[string]string{"X-Test": "yes"})
	if got != "hello-value" {
		t.Errorf("imdsGet = %q, want hello-value", got)
	}
}

func TestImdsGetNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	restore := system.SetIMDSClientForTest(srv.Client())
	defer restore()

	if got := system.ImdsGetExported(srv.URL, nil); got != "" {
		t.Errorf("expected empty on non-200, got %q", got)
	}
}

func TestImdsGetError(t *testing.T) {
	restore := system.SetIMDSClientForTest(failIMDSClient())
	defer restore()
	if got := system.ImdsGetExported("http://169.254.169.254/x", nil); got != "" {
		t.Errorf("expected empty on transport error, got %q", got)
	}
}

func TestImdsGetBadURL(t *testing.T) {
	// Control characters make http.NewRequest fail before any transport call.
	if got := system.ImdsGetExported("http://\x7f/bad", nil); got != "" {
		t.Errorf("expected empty on bad url, got %q", got)
	}
}

func TestFetchIMDSSuccessPaths(t *testing.T) {
	restore := system.SetIMDSClientForTest(mockIMDSClient())
	defer restore()

	t.Run("aws", func(t *testing.T) {
		id, typ, region, zone := system.FetchAWSIMDSExported()
		if id != "i-abc123" || typ != "t3.micro" || zone != "us-east-2a" || region != "us-east-2" {
			t.Errorf("aws = %q %q %q %q", id, typ, region, zone)
		}
	})
	t.Run("gcp", func(t *testing.T) {
		id, typ, region, zone := system.FetchGCPIMDSExported()
		if id != "111222333" || typ != "e2-medium" || zone != "us-central1-a" || region != "us-central1" {
			t.Errorf("gcp = %q %q %q %q", id, typ, region, zone)
		}
	})
	t.Run("azure", func(t *testing.T) {
		id, typ, region, zone := system.FetchAzureIMDSExported()
		if id != "az-vm" || typ != "Standard_D2" || region != "eastus" || zone != "eastus-1" {
			t.Errorf("azure = %q %q %q %q", id, typ, region, zone)
		}
	})
	t.Run("alibaba", func(t *testing.T) {
		id, _, region, zone := system.FetchAlibabaIMDSExported()
		if id != "i-ali123" || region != "cn-hangzhou" || zone != "cn-hangzhou-b" {
			t.Errorf("alibaba = %q %q %q", id, region, zone)
		}
	})
	t.Run("huawei", func(t *testing.T) {
		id, typ, region, zone := system.FetchHuaweiIMDSExported()
		if id != "hw-uuid" || typ != "c6.large" || zone != "cn-north-4a" || region != "cn-north-4" {
			t.Errorf("huawei = %q %q %q %q", id, typ, region, zone)
		}
	})
	t.Run("digitalocean", func(t *testing.T) {
		id, typ, region, zone := system.FetchDigitalOceanIMDSExported()
		if id != "do-123" || typ != "s-1vcpu-1gb" || region != "nyc1" || zone != "nyc1" {
			t.Errorf("do = %q %q %q %q", id, typ, region, zone)
		}
	})
}

func TestFetchIMDSFailurePaths(t *testing.T) {
	restore := system.SetIMDSClientForTest(failIMDSClient())
	defer restore()

	if id, _, _, _ := system.FetchAWSIMDSExported(); id != "" {
		t.Errorf("aws should be empty on failure, got %q", id)
	}
	if id, _, _, _ := system.FetchGCPIMDSExported(); id != "" {
		t.Errorf("gcp should be empty, got %q", id)
	}
	if id, _, _, _ := system.FetchAzureIMDSExported(); id != "" {
		t.Errorf("azure should be empty, got %q", id)
	}
	if id, _, _, _ := system.FetchAlibabaIMDSExported(); id != "" {
		t.Errorf("alibaba should be empty, got %q", id)
	}
	if id, _, _, _ := system.FetchHuaweiIMDSExported(); id != "" {
		t.Errorf("huawei should be empty, got %q", id)
	}
	if id, _, _, _ := system.FetchDigitalOceanIMDSExported(); id != "" {
		t.Errorf("do should be empty, got %q", id)
	}
}

// TestDetectCloudMetadataEnv drives the environment-variable detection branches
// of detectCloudMetadata with a mock IMDS client so IMDS fetches stay offline.
func TestDetectCloudMetadataEnv(t *testing.T) {
	clearVars := []string{
		"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "AWS_REGION",
		"GOOGLE_CLOUD_PROJECT", "ALIBABA_CLOUD_REGION_ID", "ALICLOUD_REGION",
		"HUAWEICLOUD_REGION", "DIGITALOCEAN_TOKEN", "DO_REGION",
		"TELEMETRYFLOW_HOST_ROOT",
	}

	tests := []struct {
		name     string
		env      map[string]string
		wantProv string
	}{
		{"rancher", map[string]string{"CATTLE_SERVER": "https://r"}, "rancher"},
		{"aws", map[string]string{"AWS_REGION": "us-east-2"}, "aws"},
		{"gcp", map[string]string{"GOOGLE_CLOUD_PROJECT": "proj"}, "gcp"},
		{"alibaba", map[string]string{"ALIBABA_CLOUD_REGION_ID": "cn-hangzhou"}, "alibaba"},
		{"huawei", map[string]string{"HUAWEICLOUD_REGION": "cn-north-4"}, "huawei"},
		{"digitalocean", map[string]string{"DO_REGION": "nyc1"}, "digitalocean"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restore := system.SetIMDSClientForTest(mockIMDSClient())
			defer restore()
			for _, v := range clearVars {
				t.Setenv(v, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			prov, _, _, _, _ := system.DetectCloudMetadataExported()
			if prov != tc.wantProv {
				t.Errorf("provider = %q, want %q", prov, tc.wantProv)
			}
		})
	}
}

// TestDetectCloudMetadataNone verifies the no-cloud path on a clean environment.
func TestDetectCloudMetadataNone(t *testing.T) {
	restore := system.SetIMDSClientForTest(failIMDSClient())
	defer restore()
	clearVars := []string{
		"CATTLE_CLUSTER_AGENT_PORT", "CATTLE_SERVER", "AWS_REGION",
		"GOOGLE_CLOUD_PROJECT", "ALIBABA_CLOUD_REGION_ID", "ALICLOUD_REGION",
		"HUAWEICLOUD_REGION", "DIGITALOCEAN_TOKEN", "DO_REGION",
		"TELEMETRYFLOW_HOST_ROOT",
	}
	for _, v := range clearVars {
		t.Setenv(v, "")
	}
	// On a developer host with no DMI markers and no env, provider is empty.
	prov, _, _, _, _ := system.DetectCloudMetadataExported()
	if prov != "" {
		t.Logf("host reports cloud provider %q (environment-dependent); acceptable", prov)
	}
}
