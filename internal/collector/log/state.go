// Package log implements file-based and journald log collection for TFO-Agent.
//
// state.go defines the persisted state shape for the LogCollector so that
// file tail offsets survive agent restarts via the persister framework.
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

package log

// TailerState is the persisted state of a single FileTailer.
type TailerState struct {
	Path        string `json:"path"`
	Inode       uint64 `json:"inode"`
	Offset      int64  `json:"offset"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// CollectorState is the persisted state of the whole LogCollector.
// The map key is the configured path (or glob-expanded match) and is stable
// across restarts, which lets a freshly-created tailer look up its saved
// offset before it starts reading.
type CollectorState struct {
	Tailers map[string]TailerState `json:"tailers"`
}

// NewCollectorState returns an empty, ready-to-use CollectorState.
func NewCollectorState() *CollectorState {
	return &CollectorState{Tailers: make(map[string]TailerState)}
}
