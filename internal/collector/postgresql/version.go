// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

package postgresql

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func detectVersion(ctx context.Context, inst *pgInstance) error {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var versionNum int
	err := inst.pool.QueryRow(ctx2, "SELECT current_setting('server_version_num')::int").Scan(&versionNum)
	if err != nil {
		return fmt.Errorf("postgresql %s: detect version: %w", inst.config.Name, err)
	}
	inst.version = versionNum

	var versionStr string
	if err := inst.pool.QueryRow(ctx2, "SHOW server_version").Scan(&versionStr); err == nil {
		inst.versionStr = strings.TrimSpace(versionStr)
	} else {
		inst.versionStr = strconv.Itoa(versionNum)
	}

	vLower := strings.ToLower(inst.versionStr)
	switch {
	case strings.Contains(vLower, "aws"):
		inst.flavor = "aws-rds"
	case strings.Contains(vLower, "azure"):
		inst.flavor = "azure"
	case strings.Contains(vLower, "google") || strings.Contains(vLower, "cloudsql"):
		inst.flavor = "gcp-cloudsql"
	default:
		inst.flavor = "postgresql"
	}
	return nil
}

func hasPgStatWal(inst *pgInstance) bool {
	return inst.version >= 140000
}

func hasExecTimeColumns(inst *pgInstance) bool {
	return inst.version >= 130000
}
