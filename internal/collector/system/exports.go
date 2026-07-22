// Package system exposes unexported symbols for external test packages.
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

package system

import "net/http"

// ParseUint64Exported forwards to parseUint64 for external tests.
func ParseUint64Exported(s string) uint64 { return parseUint64(s) }

// DetectK8sProviderExported forwards to detectK8sProvider.
func DetectK8sProviderExported() (bool, string) { return detectK8sProvider() }

// DetectContainerExported forwards to detectContainer.
func DetectContainerExported() bool { return detectContainer() }

// GetContainerIDExported forwards to getContainerID.
func GetContainerIDExported() string { return getContainerID() }

// DetectContainerRuntimeExported forwards to detectContainerRuntime.
func DetectContainerRuntimeExported() string { return detectContainerRuntime() }

// DetectVirtualizationExported forwards to detectVirtualization.
func DetectVirtualizationExported() (bool, string) { return detectVirtualization() }

// DetectCloudMetadataExported forwards to detectCloudMetadata.
func DetectCloudMetadataExported() (provider, instanceID, instanceType, region, zone string) {
	return detectCloudMetadata()
}

// GetContainerNameExported forwards to getContainerName.
func GetContainerNameExported() string { return getContainerName() }

// GetContainerImageExported forwards to getContainerImage.
func GetContainerImageExported() string { return getContainerImage() }

// GetHostnameFallbackExported forwards to getHostnameFallback.
func GetHostnameFallbackExported() string { return getHostnameFallback() }

// ImdsGetExported forwards to imdsGet.
func ImdsGetExported(url string, headers map[string]string) string { return imdsGet(url, headers) }

// FetchAWSIMDSExported forwards to fetchAWSIMDS.
func FetchAWSIMDSExported() (instanceID, instanceType, region, zone string) { return fetchAWSIMDS() }

// FetchGCPIMDSExported forwards to fetchGCPIMDS.
func FetchGCPIMDSExported() (instanceID, instanceType, region, zone string) { return fetchGCPIMDS() }

// FetchAzureIMDSExported forwards to fetchAzureIMDS.
func FetchAzureIMDSExported() (instanceID, instanceType, region, zone string) {
	return fetchAzureIMDS()
}

// FetchAlibabaIMDSExported forwards to fetchAlibabaIMDS.
func FetchAlibabaIMDSExported() (instanceID, instanceType, region, zone string) {
	return fetchAlibabaIMDS()
}

// FetchHuaweiIMDSExported forwards to fetchHuaweiIMDS.
func FetchHuaweiIMDSExported() (instanceID, instanceType, region, zone string) {
	return fetchHuaweiIMDS()
}

// FetchDigitalOceanIMDSExported forwards to fetchDigitalOceanIMDS.
func FetchDigitalOceanIMDSExported() (instanceID, instanceType, region, zone string) {
	return fetchDigitalOceanIMDS()
}

// SetIMDSClientForTest swaps the package IMDS HTTP client and returns a
// restore function. Enables deterministic, offline testing of the metadata
// fetch paths using a mock RoundTripper instead of live cloud endpoints.
func SetIMDSClientForTest(c *http.Client) func() {
	old := imdsClient
	imdsClient = c
	return func() { imdsClient = old }
}
