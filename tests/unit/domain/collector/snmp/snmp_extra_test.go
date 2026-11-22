// Additional external unit tests for the SNMP collector targeting the PDU
// conversion branches (octetToString coercion, numeric-string vs length
// fallback, default/typeless PDUs) and the full SNMPv3 auth/priv protocol
// matrix, all via the exported test seams. Deterministic; no live SNMP.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package snmp_test

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestSNMP_ConvertPDU_OctetAndTypeBranches(t *testing.T) {
	tests := []struct {
		name     string
		pdu      gosnmp.SnmpPDU
		wantName string
		wantVal  float64
		wantType collector.MetricType
		wantOK   bool
	}{
		{
			name:     "octet numeric []byte parses to value",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("42")},
			wantName: "m", wantVal: 42, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			name:     "octet non-numeric []byte -> length fallback",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("hello")},
			wantName: "m_len", wantVal: 5, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			name:     "octet string type non-numeric -> length",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: "world!"},
			wantName: "m_len", wantVal: 6, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			// octetToString default branch (non-[]byte/non-string) via fmt.Sprint,
			// then the numeric-parse branch of convertPDU.
			name:     "octet default-coerced int parses",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: 123},
			wantName: "m", wantVal: 123, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			name:     "counter32 -> counter",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(7)},
			wantName: "m", wantVal: 7, wantType: collector.MetricTypeCounter, wantOK: true,
		},
		{
			name:     "integer -> gauge",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 9},
			wantName: "m", wantVal: 9, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			// default type branch: ObjectIdentifier isn't numeric; bigToFloat's
			// nil path returns 0 but the PDU is still emitted as a gauge.
			name:     "unlisted type -> gauge via bigToFloat nil",
			pdu:      gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1"},
			wantName: "m", wantVal: 0, wantType: collector.MetricTypeGauge, wantOK: true,
		},
		{
			name:   "null -> dropped",
			pdu:    gosnmp.SnmpPDU{Type: gosnmp.Null, Value: 1},
			wantOK: false,
		},
		{
			name:   "no-such-object -> dropped",
			pdu:    gosnmp.SnmpPDU{Type: gosnmp.NoSuchObject, Value: 1},
			wantOK: false,
		},
		{
			name:   "nil value -> dropped",
			pdu:    gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: nil},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, val, mtype, ok := snmp.ConvertPDUExported(tt.pdu, "m")
			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			assert.Equal(t, tt.wantName, name)
			assert.InDelta(t, tt.wantVal, val, 1e-9)
			assert.Equal(t, tt.wantType, mtype)
		})
	}
}

func TestSNMP_V3Security_AuthProtocolMatrix(t *testing.T) {
	cases := []struct {
		proto string
		want  gosnmp.SnmpV3AuthProtocol
	}{
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA224", gosnmp.SHA224},
		{"SHA256", gosnmp.SHA256},
		{"SHA384", gosnmp.SHA384},
		{"SHA512", gosnmp.SHA512},
		{"bogus", gosnmp.SHA}, // default
	}
	for _, c := range cases {
		t.Run("auth_"+c.proto, func(t *testing.T) {
			_, sp := snmp.BuildV3SecurityExported(config.SNMPv3Auth{
				SecurityLevel: "authpriv", Username: "u",
				AuthProtocol: c.proto, PrivProtocol: "AES",
			})
			usm, ok := sp.(*gosnmp.UsmSecurityParameters)
			require.True(t, ok)
			assert.Equal(t, c.want, usm.AuthenticationProtocol)
		})
	}
}

func TestSNMP_V3Security_PrivProtocolMatrix(t *testing.T) {
	cases := []struct {
		proto string
		want  gosnmp.SnmpV3PrivProtocol
	}{
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES192", gosnmp.AES192},
		{"AES256", gosnmp.AES256},
		{"AES192C", gosnmp.AES192C},
		{"AES256C", gosnmp.AES256C},
		{"bogus", gosnmp.AES}, // default
	}
	for _, c := range cases {
		t.Run("priv_"+c.proto, func(t *testing.T) {
			_, sp := snmp.BuildV3SecurityExported(config.SNMPv3Auth{
				SecurityLevel: "authpriv", Username: "u",
				AuthProtocol: "SHA", PrivProtocol: c.proto,
			})
			usm, ok := sp.(*gosnmp.UsmSecurityParameters)
			require.True(t, ok)
			assert.Equal(t, c.want, usm.PrivacyProtocol)
		})
	}
}

func TestSNMP_V3Security_LevelGating(t *testing.T) {
	// noauthnopriv forces NoAuth + NoPriv regardless of configured protocols.
	flags, sp := snmp.BuildV3SecurityExported(config.SNMPv3Auth{
		SecurityLevel: "noauthnopriv", Username: "u", AuthProtocol: "SHA256", PrivProtocol: "AES256",
	})
	assert.Equal(t, gosnmp.NoAuthNoPriv, flags)
	usm := sp.(*gosnmp.UsmSecurityParameters)
	assert.Equal(t, gosnmp.NoAuth, usm.AuthenticationProtocol)
	assert.Equal(t, gosnmp.NoPriv, usm.PrivacyProtocol)

	// authnopriv keeps auth but forces NoPriv.
	flags, sp = snmp.BuildV3SecurityExported(config.SNMPv3Auth{
		SecurityLevel: "authnopriv", Username: "u", AuthProtocol: "MD5", PrivProtocol: "AES256",
	})
	assert.Equal(t, gosnmp.AuthNoPriv, flags)
	usm = sp.(*gosnmp.UsmSecurityParameters)
	assert.Equal(t, gosnmp.MD5, usm.AuthenticationProtocol)
	assert.Equal(t, gosnmp.NoPriv, usm.PrivacyProtocol)

	// empty level defaults to authpriv.
	flags, _ = snmp.BuildV3SecurityExported(config.SNMPv3Auth{Username: "u", AuthProtocol: "SHA", PrivProtocol: "AES"})
	assert.Equal(t, gosnmp.AuthPriv, flags)
}
