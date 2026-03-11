// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package remotewrite

// RemoteWriteReceiverConfig maps to config.RemoteWriteReceiverConfig (new section).
type RemoteWriteReceiverConfig struct {
	Enabled    bool
	Port       int // default: 9091
	BasicAuth  *BasicAuthConfig
	TLS        *TLSConfig
	BufferSize int // channel buffer size, default: 10000
}

// BasicAuthConfig holds HTTP basic authentication credentials.
type BasicAuthConfig struct {
	Username string
	Password string
}

// TLSConfig holds TLS configuration for the receiver's HTTP server.
type TLSConfig struct {
	InsecureSkipVerify bool
	CAFile             string
	CertFile           string
	KeyFile            string
}
