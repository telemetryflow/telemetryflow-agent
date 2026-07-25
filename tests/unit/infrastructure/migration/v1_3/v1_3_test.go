// Package v1_3 registers the config schema migration from version 1.2.0 to 1.3.0.
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
package v1_3_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/migration"
	v1_3 "github.com/telemetryflow/telemetryflow-agent/internal/migration/v1_3"
)

func TestRenameInsecureSkipVerify_RenamesTopLevelKey(t *testing.T) {
	in := []byte("insecure_skip_verify: true\n")
	out, err := v1_3.RenameInsecureSkipVerify(in)
	require.NoError(t, err)
	assert.Equal(t, "tls_skip_verify: true\n", string(out))
}

func TestRenameInsecureSkipVerify_PreservesNestedIndentation(t *testing.T) {
	in := []byte("telemetryflow:\n  tls:\n    insecure_skip_verify: true\n")
	out, err := v1_3.RenameInsecureSkipVerify(in)
	require.NoError(t, err)
	want := "telemetryflow:\n  tls:\n    tls_skip_verify: true\n"
	assert.Equal(t, want, string(out))
}

func TestRenameInsecureSkipVerify_NoOpWhenKeyAbsent(t *testing.T) {
	in := []byte("telemetryflow:\n  endpoint: localhost\n")
	out, err := v1_3.RenameInsecureSkipVerify(in)
	require.NoError(t, err)
	assert.Equal(t, string(in), string(out))
}

func TestRenameInsecureSkipVerify_ReplacesAllOccurrences(t *testing.T) {
	in := []byte("collectors:\n  cadvisor:\n    insecure_skip_verify: true\n  foo:\n    insecure_skip_verify: false\n")
	out, err := v1_3.RenameInsecureSkipVerify(in)
	require.NoError(t, err)
	want := "collectors:\n  cadvisor:\n    tls_skip_verify: true\n  foo:\n    tls_skip_verify: false\n"
	assert.Equal(t, want, string(out))
}

func TestRenameInsecureSkipVerify_IgnoresSubstringMatches(t *testing.T) {
	// Only keys anchored at the start of a line should be rewritten; values and
	// other keys that merely contain the substring must be left alone.
	in := []byte("note: \"foo_insecure_skip_verify: x\"\nfoo_insecure_skip_verify: bad\n")
	out, err := v1_3.RenameInsecureSkipVerify(in)
	require.NoError(t, err)
	assert.Equal(t, string(in), string(out))
}

func TestInit_RegistersAgainstDefaultRegistry(t *testing.T) {
	list := migration.List()
	var found bool
	for _, m := range list {
		if m.Name == "tls_skip_verify_rename" &&
			m.FromVersion == "1.2.0" &&
			m.ToVersion == "1.3.0" {
			found = true
			break
		}
	}
	assert.True(t, found, "v1_3 tls_skip_verify_rename not registered in DefaultRegistry")
}

func TestInit_RewriteEndToEndViaApplyLatest(t *testing.T) {
	in := []byte("agent:\n  version: \"1.2.0\"\ntelemetryflow:\n  tls:\n    insecure_skip_verify: true\n")
	out, ver, err := migration.ApplyLatest(in)
	require.NoError(t, err)
	assert.Equal(t, "1.3.0", ver)
	assert.Contains(t, string(out), "tls_skip_verify: true")
	assert.NotContains(t, string(out), "insecure_skip_verify:")
}
