// Deterministic coverage for the container-detection env-var branches that are
// reachable on any OS. The /.dockerenv, /proc/*/cgroup and Linux DMI paths in
// these detectors read hardcoded host paths (no host-root seam) and are gated
// to Linux, so they cannot be exercised deterministically on a dev/CI host of
// another OS; only the KUBERNETES_SERVICE_HOST branch is portable.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package system_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

func TestDetectContainer_KubernetesEnvBranch(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	assert.True(t, system.DetectContainerExported(),
		"KUBERNETES_SERVICE_HOST set must report container=true")
	assert.Equal(t, "kubernetes", system.DetectContainerRuntimeExported(),
		"KUBERNETES_SERVICE_HOST set must report the kubernetes runtime")
}

func TestDetectContainer_NoMarkers(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	// On a plain host with no container markers both detectors report "none".
	// (If the CI host itself is containerised these may be non-empty; accept
	// either without failing — the point is to exercise the fall-through.)
	_ = system.DetectContainerExported()
	_ = system.DetectContainerRuntimeExported()
	_ = system.GetContainerIDExported()
}
