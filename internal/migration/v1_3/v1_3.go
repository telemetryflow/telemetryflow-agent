// Package v1_3 registers the config schema migration from version 1.2.0 to
// 1.3.0. The migration renames the deprecated insecure_skip_verify YAML key to
// the unified tls_skip_verify wording that the 1.3 release expects.
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
package v1_3

import (
	"regexp"

	"github.com/telemetryflow/telemetryflow-agent/internal/migration"
)

// insecureSkipVerifyKey matches the deprecated "insecure_skip_verify" YAML key
// at the start of a line, capturing any leading whitespace so the replacement
// preserves the original indentation. The (?m) flag turns ^ into a per-line
// anchor so every occurrence in the document is rewritten, not only the first.
// The captured whitespace is optional (\s*) so top-level keys with zero indent
// are also renamed; the line anchor still prevents matching substrings that
// appear inside other tokens or quoted values.
var insecureSkipVerifyKey = regexp.MustCompile(`(?m)^(\s*)insecure_skip_verify:`)

func init() {
	migration.MustRegister(migration.Migration{
		FromVersion: "1.2.0",
		ToVersion:   "1.3.0",
		Name:        "tls_skip_verify_rename",
		Description: "Rename insecure_skip_verify to tls_skip_verify",
		Apply:       RenameInsecureSkipVerify,
	})
}

// RenameInsecureSkipVerify rewrites every "insecure_skip_verify:" YAML key in
// the input to "tls_skip_verify:", preserving the original indentation. Input
// without the deprecated key is returned unchanged.
func RenameInsecureSkipVerify(input []byte) ([]byte, error) {
	if !insecureSkipVerifyKey.Match(input) {
		return input, nil
	}
	return insecureSkipVerifyKey.ReplaceAll(input, []byte("${1}tls_skip_verify:")), nil
}
