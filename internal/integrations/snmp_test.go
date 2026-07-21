// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package integrations

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

func newTestSNMPExporter(cfg SNMPConfig) *SNMPExporter {
	return NewSNMPExporter(cfg, zap.NewNop())
}

func TestSNMPVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want gosnmp.SnmpVersion
	}{
		{"v1 prefixed", "v1", gosnmp.Version1},
		{"1 bare", "1", gosnmp.Version1},
		{"v3 prefixed", "v3", gosnmp.Version3},
		{"3 bare", "3", gosnmp.Version3},
		{"v2c default", "v2c", gosnmp.Version2c},
		{"empty defaults to v2c", "", gosnmp.Version2c},
		{"uppercase", "V3", gosnmp.Version3},
		{"unknown defaults to v2c", "banana", gosnmp.Version2c},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snmpVersion(tt.in); got != tt.want {
				t.Errorf("snmpVersion(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestV3MsgFlags(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    gosnmp.SnmpV3MsgFlags
		wantErr bool
	}{
		{"empty is noAuthNoPriv", "", gosnmp.NoAuthNoPriv, false},
		{"noAuthNoPriv", "noAuthNoPriv", gosnmp.NoAuthNoPriv, false},
		{"authNoPriv", "authNoPriv", gosnmp.AuthNoPriv, false},
		{"authPriv", "authPriv", gosnmp.AuthPriv, false},
		{"case insensitive", "AUTHPRIV", gosnmp.AuthPriv, false},
		{"invalid errors", "bogus", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v3MsgFlags(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("v3MsgFlags(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("v3MsgFlags(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestV3AuthProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want gosnmp.SnmpV3AuthProtocol
	}{
		{"SHA", gosnmp.SHA},
		{"sha256", gosnmp.SHA256},
		{"SHA512", gosnmp.SHA512},
		{"md5", gosnmp.MD5},
		{"unknown falls back to MD5", gosnmp.MD5},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := v3AuthProtocol(tt.in); got != tt.want {
				t.Errorf("v3AuthProtocol(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestV3PrivProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want gosnmp.SnmpV3PrivProtocol
	}{
		{"AES", gosnmp.AES},
		{"aes256", gosnmp.AES256},
		{"AES192", gosnmp.AES192},
		{"des", gosnmp.DES},
		{"unknown falls back to DES", gosnmp.DES},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := v3PrivProtocol(tt.in); got != tt.want {
				t.Errorf("v3PrivProtocol(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestApplyV3SecurityPrivacy guards the fix for the SNMPv3 privacy bitmask:
// privacy parameters must be set for authPriv and left empty for authNoPriv.
func TestApplyV3SecurityPrivacy(t *testing.T) {
	tests := []struct {
		name        string
		level       string
		wantPriv    bool
		wantAuth    bool
		wantErr     bool
		privWantSet gosnmp.SnmpV3PrivProtocol
	}{
		{name: "authPriv sets privacy", level: "authPriv", wantPriv: true, wantAuth: true, privWantSet: gosnmp.AES},
		{name: "authNoPriv omits privacy", level: "authNoPriv", wantPriv: false, wantAuth: true},
		{name: "noAuthNoPriv omits both", level: "noAuthNoPriv", wantPriv: false, wantAuth: false},
		{name: "invalid level errors", level: "nope", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSNMPExporter(SNMPConfig{
				Version:       "v3",
				SecurityLevel: tt.level,
				Username:      "user",
				AuthProtocol:  "SHA",
				AuthPassword:  "authpass",
				PrivProtocol:  "AES",
				PrivPassword:  "privpass",
			})
			client := &gosnmp.GoSNMP{}
			err := s.applyV3Security(client)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyV3Security err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			usm, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
			if !ok {
				t.Fatal("SecurityParameters is not *UsmSecurityParameters")
			}
			if tt.wantAuth && usm.AuthenticationPassphrase == "" {
				t.Error("expected auth passphrase to be set")
			}
			if !tt.wantAuth && usm.AuthenticationPassphrase != "" {
				t.Error("expected auth passphrase to be empty")
			}
			if tt.wantPriv {
				if usm.PrivacyPassphrase == "" {
					t.Error("expected privacy passphrase to be set for authPriv")
				}
				if usm.PrivacyProtocol != tt.privWantSet {
					t.Errorf("PrivacyProtocol = %v, want %v", usm.PrivacyProtocol, tt.privWantSet)
				}
			} else if usm.PrivacyPassphrase != "" {
				t.Error("expected privacy passphrase to be empty when priv not requested")
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	s := newTestSNMPExporter(SNMPConfig{})
	tests := []struct {
		in   string
		want string
	}{
		{"ifInOctets", "ifinoctets"},
		{"sys-name", "sys_name"},
		{"1.3.6.1", "1_3_6_1"},
		{"Mixed-Case.OID", "mixed_case_oid"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := s.sanitizeName(tt.in); got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseOIDValue(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		cfg    SNMPOIDConfig
		want   float64
		wantOK bool
	}{
		{"int", 42, SNMPOIDConfig{}, 42, true},
		{"int64", int64(100), SNMPOIDConfig{}, 100, true},
		{"uint64", uint64(7), SNMPOIDConfig{}, 7, true},
		{"float64", 3.5, SNMPOIDConfig{}, 3.5, true},
		{"numeric string", "12.5", SNMPOIDConfig{}, 12.5, true},
		{"byte string", []byte("8"), SNMPOIDConfig{}, 8, true},
		{"scale applied", 10, SNMPOIDConfig{Scale: 0.1}, 1, true},
		{"non-numeric string", "abc", SNMPOIDConfig{}, 0, false},
		{"unsupported type", struct{}{}, SNMPOIDConfig{}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseOIDValue(tt.value, tt.cfg)
			if ok != tt.wantOK {
				t.Fatalf("parseOIDValue ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("parseOIDValue = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPDUValue(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want any
	}{
		{"octet string", gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("host")}, []byte("host")},
		{"gauge32", gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(55)}, int64(55)},
		{"counter64", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(999)}, uint64(999)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pduValue(tt.pdu)
			switch want := tt.want.(type) {
			case []byte:
				gb, ok := got.([]byte)
				if !ok || string(gb) != string(want) {
					t.Errorf("pduValue = %v, want %v", got, want)
				}
			default:
				if got != tt.want {
					t.Errorf("pduValue = %v (%T), want %v (%T)", got, got, tt.want, tt.want)
				}
			}
		})
	}
}

func TestPDUToMetric(t *testing.T) {
	s := newTestSNMPExporter(SNMPConfig{})
	now := time.Now()
	base := map[string]string{"target": "10.0.0.1"}

	t.Run("string type is skipped", func(t *testing.T) {
		pdu := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("router-1")}
		if _, ok := s.pduToMetric(pdu, SNMPOIDConfig{Type: "string", Name: "sysName"}, base, now, ""); ok {
			t.Error("expected string OID to be skipped")
		}
	})

	t.Run("counter maps to counter metric with index tag", func(t *testing.T) {
		pdu := gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(2048)}
		oc := SNMPOIDConfig{OID: "1.3.6.1.2.1.2.2.1.10", Name: "ifInOctets", Type: "counter", Unit: "bytes"}
		m, ok := s.pduToMetric(pdu, oc, base, now, "3")
		if !ok {
			t.Fatal("expected metric to be produced")
		}
		if m.Name != "snmp_ifinoctets" {
			t.Errorf("Name = %q, want snmp_ifinoctets", m.Name)
		}
		if m.Type != MetricTypeCounter {
			t.Errorf("Type = %v, want counter", m.Type)
		}
		if m.Value != 2048 {
			t.Errorf("Value = %v, want 2048", m.Value)
		}
		if m.Tags["index"] != "3" {
			t.Errorf("index tag = %q, want 3", m.Tags["index"])
		}
		if m.Tags["oid"] != oc.OID {
			t.Errorf("oid tag = %q, want %q", m.Tags["oid"], oc.OID)
		}
		if m.Tags["target"] != "10.0.0.1" {
			t.Error("base tag not copied")
		}
	})

	t.Run("does not mutate base tags", func(t *testing.T) {
		local := map[string]string{"target": "10.0.0.2"}
		pdu := gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(1)}
		_, _ = s.pduToMetric(pdu, SNMPOIDConfig{OID: "x", Name: "n", Type: "gauge"}, local, now, "9")
		if _, exists := local["index"]; exists {
			t.Error("base tags were mutated by pduToMetric")
		}
	})
}

func TestBuildClient(t *testing.T) {
	t.Run("applies defaults and per-target community override", func(t *testing.T) {
		s := newTestSNMPExporter(SNMPConfig{Version: "v2c", Community: "global", Retries: 2})
		client, err := s.buildClient(SNMPTarget{Address: "10.0.0.5", Community: "override"})
		if err != nil {
			t.Fatalf("buildClient err = %v", err)
		}
		if client.Port != 161 {
			t.Errorf("Port = %d, want 161", client.Port)
		}
		if client.Community != "override" {
			t.Errorf("Community = %q, want override", client.Community)
		}
		if client.Timeout != 10*time.Second {
			t.Errorf("Timeout = %v, want 10s", client.Timeout)
		}
		if client.Version != gosnmp.Version2c {
			t.Errorf("Version = %v, want v2c", client.Version)
		}
	})

	t.Run("per-target port wins over global", func(t *testing.T) {
		s := newTestSNMPExporter(SNMPConfig{Port: 1161})
		client, _ := s.buildClient(SNMPTarget{Address: "h", Port: 2161})
		if client.Port != 2161 {
			t.Errorf("Port = %d, want 2161", client.Port)
		}
	})

	t.Run("v3 configures USM security", func(t *testing.T) {
		s := newTestSNMPExporter(SNMPConfig{
			Version: "v3", SecurityLevel: "authPriv", Username: "u",
			AuthProtocol: "SHA", AuthPassword: "a", PrivProtocol: "AES", PrivPassword: "p",
		})
		client, err := s.buildClient(SNMPTarget{Address: "h"})
		if err != nil {
			t.Fatalf("buildClient err = %v", err)
		}
		if client.SecurityModel != gosnmp.UserSecurityModel {
			t.Error("expected UserSecurityModel for v3")
		}
	})

	t.Run("v3 invalid security level errors", func(t *testing.T) {
		s := newTestSNMPExporter(SNMPConfig{Version: "v3", SecurityLevel: "bad"})
		if _, err := s.buildClient(SNMPTarget{Address: "h"}); err == nil {
			t.Error("expected error for invalid v3 security level")
		}
	})
}

func TestWalkMetricName(t *testing.T) {
	s := newTestSNMPExporter(SNMPConfig{})
	if got := s.walkMetricName(".1.3.6.1.2.1.2.2.1.10", "3"); got != "walk_1.3.6.1.2.1.2.2.1.10" {
		t.Errorf("walkMetricName = %q", got)
	}
}

func TestBuildTargetTags(t *testing.T) {
	s := newTestSNMPExporter(SNMPConfig{
		Version: "v2c",
		Labels:  map[string]string{"env": "prod", "region": "id"},
	})
	tags := s.buildTargetTags(SNMPTarget{
		Address: "10.0.0.9",
		Name:    "core-router",
		Labels:  map[string]string{"role": "edge", "env": "override"},
	})
	if tags["target"] != "10.0.0.9" {
		t.Errorf("target = %q", tags["target"])
	}
	if tags["target_name"] != "core-router" {
		t.Errorf("target_name = %q", tags["target_name"])
	}
	if tags["snmp_version"] != "v2c" {
		t.Errorf("snmp_version = %q", tags["snmp_version"])
	}
	if tags["role"] != "edge" {
		t.Errorf("role = %q, want edge", tags["role"])
	}
	// Target label overrides global label.
	if tags["env"] != "override" {
		t.Errorf("env = %q, want override (target overrides global)", tags["env"])
	}
}
