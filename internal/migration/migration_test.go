// Package migration provides a versioned config schema migration framework.
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
package migration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// markerMigration returns a Migration whose Apply appends a marker line so
// tests can assert ordering and selection deterministically without depending
// on real config rewrites.
func markerMigration(from, to, name string) Migration {
	return Migration{
		FromVersion: from,
		ToVersion:   to,
		Name:        name,
		Apply: func(input []byte) ([]byte, error) {
			return append(input, []byte("\n<-"+name+"->")...), nil
		},
	}
}

func TestRegistry_RegisterRejectsDuplicateByFromVersionAndName(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "a")))

	err := r.Register(markerMigration("1.2.0", "1.3.0", "a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistry_RegisterRejectsDuplicateNameWithDifferentTarget(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "dup")))

	err := r.Register(markerMigration("1.2.0", "1.4.0", "dup"))
	require.Error(t, err)
}

func TestRegistry_RegisterAllowsSameNameAcrossDifferentFromVersions(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "x")))
	require.NoError(t, r.Register(markerMigration("1.3.0", "1.4.0", "x")))
}

func TestRegistry_RegisterValidatesRequiredFields(t *testing.T) {
	r := NewRegistry()
	noop := func([]byte) ([]byte, error) { return nil, nil }

	err := r.Register(Migration{Name: "x", FromVersion: "1.2.0", ToVersion: "1.3.0"})
	require.Error(t, err)

	err = r.Register(Migration{Name: "x", FromVersion: "", ToVersion: "1.3.0", Apply: noop})
	require.Error(t, err)

	err = r.Register(Migration{Name: "", FromVersion: "1.2.0", ToVersion: "1.3.0", Apply: noop})
	require.Error(t, err)
}

func TestRegistry_ApplyAllRunsMigrationsInSortedOrder(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.4.0", "1.5.0", "m3")))
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "m1")))
	require.NoError(t, r.Register(markerMigration("1.3.0", "1.4.0", "m2")))

	out, err := r.ApplyAll([]byte("base"), "1.2.0", "1.5.0")
	require.NoError(t, err)
	assert.Equal(t, "base\n<-m1->\n<-m2->\n<-m3->", string(out))
}

func TestRegistry_ApplyAllSkipsWhenFromVersionEqualsToVersion(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "m1")))

	out, err := r.ApplyAll([]byte("base"), "1.3.0", "1.3.0")
	require.NoError(t, err)
	assert.Equal(t, "base", string(out))
}

func TestRegistry_ApplyAllSelectsInclusiveRange(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "m1")))
	require.NoError(t, r.Register(markerMigration("1.3.0", "1.4.0", "m2")))
	require.NoError(t, r.Register(markerMigration("1.4.0", "1.5.0", "m3")))

	// Only m2 satisfies FromVersion >= 1.3.0 AND ToVersion <= 1.4.0.
	out, err := r.ApplyAll([]byte("base"), "1.3.0", "1.4.0")
	require.NoError(t, err)
	assert.Equal(t, "base\n<-m2->", string(out))
}

func TestRegistry_ApplyAllPropagatesApplyError(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Migration{
		FromVersion: "1.2.0",
		ToVersion:   "1.3.0",
		Name:        "boom",
		Apply:       func([]byte) ([]byte, error) { return nil, fmt.Errorf("nope") },
	}))

	_, err := r.ApplyAll([]byte("base"), "1.2.0", "1.3.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nope")
	assert.Contains(t, err.Error(), "boom")
}

func TestRegistry_ApplyLatestAppliesEverythingAndReturnsLastVersion(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.3.0", "1.4.0", "m2")))
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "m1")))

	out, ver, err := r.ApplyLatest([]byte("base"))
	require.NoError(t, err)
	assert.Equal(t, "base\n<-m1->\n<-m2->", string(out))
	assert.Equal(t, "1.4.0", ver)
}

func TestRegistry_ApplyLatestWithoutMigrationsReturnsDetectedVersion(t *testing.T) {
	r := NewRegistry()
	in := []byte("agent:\n  version: \"1.1.0\"\n")

	out, ver, err := r.ApplyLatest(in)
	require.NoError(t, err)
	assert.Equal(t, string(in), string(out))
	assert.Equal(t, "1.1.0", ver)
}

func TestRegistry_ListReturnsSortedCopy(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(markerMigration("1.4.0", "1.5.0", "m3")))
	require.NoError(t, r.Register(markerMigration("1.2.0", "1.3.0", "m1")))

	list := r.List()
	require.Len(t, list, 2)
	assert.Equal(t, "1.2.0", list[0].FromVersion)
	assert.Equal(t, "1.4.0", list[1].FromVersion)

	// Mutating the returned slice must not affect the registry.
	list[0] = Migration{Name: "mutated"}
	again := r.List()
	assert.Equal(t, "m1", again[0].Name)
}

func TestRegistry_MustRegisterPanicsOnDuplicate(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(markerMigration("1.2.0", "1.3.0", "a"))

	defer func() {
		require.NotNil(t, recover(), "expected panic on duplicate MustRegister")
	}()
	r.MustRegister(markerMigration("1.2.0", "1.3.0", "a"))
}

func TestDetectVersion_ReadsAgentVersionFromYAML(t *testing.T) {
	in := []byte("agent:\n  version: \"1.3.0\"\n  id: foo\n")
	assert.Equal(t, "1.3.0", DetectVersion(in))
}

func TestDetectVersion_DefaultsToLegacyWhenAbsent(t *testing.T) {
	assert.Equal(t, LegacyVersion, DetectVersion([]byte("agent:\n  id: foo\n")))
	assert.Equal(t, LegacyVersion, DetectVersion([]byte("")))
	assert.Equal(t, LegacyVersion, DetectVersion(nil))
}

func TestDetectVersion_DefaultsToLegacyOnUnparsableYAML(t *testing.T) {
	assert.Equal(t, LegacyVersion, DetectVersion([]byte(":\n  bad: yaml: [")))
}

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.2.0", 0},
		{"1.2.0", "1.3.0", -1},
		{"1.3.0", "1.2.0", 1},
		{"1.2.0", "1.2.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.2", "1.2.0", 0},
		{"1.2.0", "1.2", 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.a+"_vs_"+c.b, func(t *testing.T) {
			got := compareVersion(c.a, c.b)
			assert.Equal(t, sign(c.want), sign(got), "compareVersion(%q,%q)=%d want sign %d", c.a, c.b, got, sign(c.want))
		})
	}
}

func sign(i int) int {
	if i < 0 {
		return -1
	}
	if i > 0 {
		return 1
	}
	return 0
}
