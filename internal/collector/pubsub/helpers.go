// Helpers for the Pub/Sub collector. Kept separate so the main collector
// file reads as the monitoring pipeline and these remain trivial wrappers.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package pubsub

import (
	"fmt"
	"os"
	"regexp"
)

// readFile is a thin wrapper around os.ReadFile so it can be stubbed in tests.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// compileFilter compiles a subscription filter regex. Empty filter returns nil.
func compileFilter(filter string) (*regexp.Regexp, error) {
	if filter == "" {
		return nil, nil
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		return nil, fmt.Errorf("compile %q: %w", filter, err)
	}
	return re, nil
}
