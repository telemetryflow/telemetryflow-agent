// Package all blank-imports every built-in SecretStore backend so that
// linking the agent binary registers them all with the global plugin
// registry. Import this package alongside internal/secret to make every
// store resolvable via NewResolver.
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
package all

import (
	_ "github.com/telemetryflow/telemetryflow-agent/internal/secret/env"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/secret/file"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/secret/vault"
)
