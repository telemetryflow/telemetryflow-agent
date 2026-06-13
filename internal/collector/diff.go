// Package collector defines the Collector interface and shared metric types
// used by every data-collection subsystem in the TelemetryFlow Agent.
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
package collector

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
)

type ConfigDigest [sha256.Size]byte

func DigestConfig(v interface{}) ConfigDigest {
	b, err := json.Marshal(v)
	if err != nil {
		return ConfigDigest{}
	}
	return sha256.Sum256(b)
}

type DiffResult struct {
	ToStart   []string
	ToStop    []string
	ToRestart []string
}

type CollectorEntry struct {
	Name       string
	Collector  Collector
	ConfigHash ConfigDigest
}

func ComputeDiff(running map[string]*CollectorFSM, desired []CollectorEntry) DiffResult {
	result := DiffResult{}

	desiredMap := make(map[string]CollectorEntry, len(desired))
	for _, d := range desired {
		desiredMap[d.Name] = d
	}

	for name := range running {
		if _, exists := desiredMap[name]; !exists {
			result.ToStop = append(result.ToStop, name)
		}
	}

	for name, entry := range desiredMap {
		fsm, exists := running[name]
		if !exists {
			result.ToStart = append(result.ToStart, name)
			continue
		}
		if fsm.ConfigHash() != entry.ConfigHash {
			result.ToRestart = append(result.ToRestart, name)
		}
	}

	sort.Strings(result.ToStart)
	sort.Strings(result.ToStop)
	sort.Strings(result.ToRestart)

	return result
}
