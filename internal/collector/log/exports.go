// Package log exposes unexported symbols for external test packages.
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

import (
	"os"
	"regexp"
)

func CompilePatternsExported(patterns []string) []*regexp.Regexp {
	return compilePatterns(patterns)
}

func MatchesFilterExported(line string, include, exclude []*regexp.Regexp) bool {
	return matchesFilter(line, include, exclude)
}

// PushLineExported injects a line directly into the tailer's channel so that
// draining logic can be exercised without a live file source.
func (t *FileTailer) PushLineExported(line string) { t.lines <- line }

// DrainFileTailerExported wraps the unexported drainFileTailer for tests.
func (c *LogCollector) DrainFileTailerExported(t *FileTailer, include, exclude []*regexp.Regexp) {
	c.drainFileTailer(t, include, exclude)
}

// DrainJournaldExported wraps the unexported drainJournald for tests.
func (c *LogCollector) DrainJournaldExported(j *JournaldCollector, include, exclude []*regexp.Regexp) {
	c.drainJournald(j, include, exclude)
}

// CheckRotationExported wraps the unexported checkRotation for tests.
func (t *FileTailer) CheckRotationExported(f *os.File) bool { return t.checkRotation(f) }

// FileInodeExported wraps the unexported fileInode for tests.
func FileInodeExported(f *os.File) uint64 { return fileInode(f) }

// PushEntryExported injects a journald entry into the collector's channel so
// that the drain path can be exercised without a live journal source.
func (j *JournaldCollector) PushEntryExported(unit, priority, message string) {
	j.lines <- LogEntry{Unit: unit, Priority: priority, Message: message}
}
