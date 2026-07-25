// Package dns exposes unexported symbols for external test packages.
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

package dns

import (
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// DNSResultExported mirrors the internal dnsResult struct so external test
// packages can construct query results without touching unexported fields.
type DNSResultExported struct {
	Rcode     int
	Records   int
	ElapsedMs float64
}

func (r DNSResultExported) internal() dnsResult {
	return dnsResult{
		rcode:     r.Rcode,
		records:   r.Records,
		elapsedMs: r.ElapsedMs,
	}
}

// ResolverExported is the external-facing resolver interface. Fakes in
// external _test packages implement this; an adapter installs them.
type ResolverExported interface {
	Query(server string, port int, q config.DNSQuery, timeout time.Duration) (DNSResultExported, error)
}

type resolverExportedAdapter struct {
	ext ResolverExported
}

func (a *resolverExportedAdapter) query(server string, port int, q config.DNSQuery, timeout time.Duration) (dnsResult, error) {
	r, err := a.ext.Query(server, port, q, timeout)
	return r.internal(), err
}

// SetResolverExported injects a test fake resolver. Production code uses the
// default miekgResolver created by NewDNSCollector.
func (c *DNSCollector) SetResolverExported(r ResolverExported) {
	c.resolver = &resolverExportedAdapter{ext: r}
}

// RecordTypeExported wraps recordType for external tests.
func RecordTypeExported(s string) (uint16, error) { return recordType(s) }
