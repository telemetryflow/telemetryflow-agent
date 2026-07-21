// Package integrations exposes unexported SNMP symbols for external test packages.
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

package integrations

import (
	"time"

	"github.com/gosnmp/gosnmp"
)

// --- Exported package-level function wrappers ---

func SNMPVersionExported(v string) gosnmp.SnmpVersion { return snmpVersion(v) }

func V3MsgFlagsExported(level string) (gosnmp.SnmpV3MsgFlags, error) { return v3MsgFlags(level) }

func V3AuthProtocolExported(p string) gosnmp.SnmpV3AuthProtocol { return v3AuthProtocol(p) }

func V3PrivProtocolExported(p string) gosnmp.SnmpV3PrivProtocol { return v3PrivProtocol(p) }

func PDUValueExported(pdu gosnmp.SnmpPDU) interface{} { return pduValue(pdu) }

func ParseOIDValueExported(value interface{}, oidConfig SNMPOIDConfig) (float64, bool) {
	return parseOIDValue(value, oidConfig)
}

// --- Exported *SNMPExporter method wrappers ---

func (s *SNMPExporter) ApplyV3SecurityExported(client *gosnmp.GoSNMP) error {
	return s.applyV3Security(client)
}

func (s *SNMPExporter) SanitizeNameExported(name string) string { return s.sanitizeName(name) }

func (s *SNMPExporter) PDUToMetricExported(pdu gosnmp.SnmpPDU, oc SNMPOIDConfig, baseTags map[string]string, now time.Time, index string) (Metric, bool) {
	return s.pduToMetric(pdu, oc, baseTags, now, index)
}

func (s *SNMPExporter) BuildClientExported(target SNMPTarget) (*gosnmp.GoSNMP, error) {
	return s.buildClient(target)
}

func (s *SNMPExporter) WalkMetricNameExported(root, index string) string {
	return s.walkMetricName(root, index)
}

func (s *SNMPExporter) BuildTargetTagsExported(target SNMPTarget) map[string]string {
	return s.buildTargetTags(target)
}
