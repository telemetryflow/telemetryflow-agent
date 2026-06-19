// Package agent implements the core TelemetryFlow Agent lifecycle.
// It orchestrates all collectors, exporters, the API client, Kubernetes
// sync, heartbeat, and the optional Prometheus /metrics endpoint.
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
package agent

import (
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/host"
	"go.uber.org/zap"
)

// tfAgentNamespace is a fixed UUID namespace for deriving deterministic agent IDs.
// This ensures UUIDv5 output is unique to TelemetryFlow agents and won't collide
// with IDs from other systems using the same host fingerprint.
var tfAgentNamespace = uuid.MustParse("7f8e9d2a-b5c4-4a3f-8d2e-1f9b7c3e5a8f")

// ResolveAgentID returns a stable agent ID using this priority order:
//  1. Explicit ID from config/env (already unmarshalled into cfg.Agent.ID)
//  2. UUIDv5 derived from host fingerprint (NODE_NAME for K8s, HostID, hostname)
//  3. Random UUIDv4 as last resort (warns that ID will change on restart)
func ResolveAgentID(explicitID, hostname string, logger *zap.Logger) string {
	if explicitID != "" {
		logger.Info("Using explicit agent ID from config",
			zap.String("id", explicitID),
		)
		return explicitID
	}

	fingerprint, components := buildFingerprint(hostname, logger)
	if fingerprint != "" {
		id := uuid.NewSHA1(tfAgentNamespace, []byte(fingerprint)).String()
		logger.Info("Derived stable agent ID from host fingerprint",
			zap.String("id", id),
			zap.Strings("components", components),
		)
		return id
	}

	id := uuid.New().String()
	logger.Warn("Could not build host fingerprint — agent ID will change on every restart",
		zap.String("id", id),
		zap.String("hint", "set TELEMETRYFLOW_ID env var or agent.id in config for stable identity"),
	)
	return id
}

// buildFingerprint assembles a deterministic string from host identity components.
// Returns the fingerprint string and a slice of human-readable component labels.
//
// Priority for K8s DaemonSet:   NODE_NAME (from Downward API) takes precedence
// Priority for bare metal / VM: OS HostID (machine-id / hardware UUID)
// Hostname is always appended as a disambiguator.
func buildFingerprint(hostname string, logger *zap.Logger) (string, []string) {
	var parts []string
	var labels []string

	// Kubernetes DaemonSet: node name injected via Downward API as NODE_NAME.
	// This is the most stable identifier — it never changes as long as the node exists.
	if nodeName := os.Getenv("NODE_NAME"); nodeName != "" {
		parts = append(parts, "k8s:"+nodeName)
		labels = append(labels, "k8s_node="+nodeName)
		logger.Debug("Fingerprint: using Kubernetes node name", zap.String("node_name", nodeName))
	}

	// OS-level host ID: /etc/machine-id on Linux, hardware UUID on macOS, DMI UUID on VMs.
	// Stable across process restarts and container rebuilds on the same host.
	if info, err := host.Info(); err == nil && info.HostID != "" {
		parts = append(parts, "hostid:"+info.HostID)
		labels = append(labels, "host_id="+info.HostID[:8]+"...") // truncate for readability
		logger.Debug("Fingerprint: using OS host ID", zap.String("host_id", info.HostID))
	} else if err != nil {
		logger.Debug("Fingerprint: could not read OS host ID", zap.Error(err))
	}

	// Hostname as additional disambiguator (handles multi-tenant scenarios where
	// two hosts share a machine-id due to cloned VMs or container runtimes).
	if hostname != "" {
		parts = append(parts, "host:"+hostname)
		labels = append(labels, "hostname="+hostname)
	}

	if len(parts) == 0 {
		return "", nil
	}
	return strings.Join(parts, "|"), labels
}
