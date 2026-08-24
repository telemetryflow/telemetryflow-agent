// Internal tests for the IF-MIB column walk + merge logic. These exercise
// walkInterfaces against a fake connection, with no live SNMP device.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// fakeConn returns canned PDUs per column OID root.
type fakeConn struct {
	byColumn map[string][]gosnmp.SnmpPDU
}

func (f *fakeConn) Connect() error { return nil }
func (f *fakeConn) Close() error   { return nil }
func (f *fakeConn) BulkWalkAll(root string) ([]gosnmp.SnmpPDU, error) {
	return f.byColumn[root], nil
}

func pdu(name string, typ gosnmp.Asn1BER, val any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: typ, Value: val}
}

func TestWalkInterfaces_MergeAndPrefer64Bit(t *testing.T) {
	conn := &fakeConn{byColumn: map[string][]gosnmp.SnmpPDU{
		oidIfName: {
			pdu(oidIfName+".1", gosnmp.OctetString, []byte("Gi0/1")),
			pdu(oidIfName+".2", gosnmp.OctetString, []byte("Gi0/2")),
		},
		oidIfHighSpeed: {
			pdu(oidIfHighSpeed+".1", gosnmp.Gauge32, uint(1000)), // 1000 Mbps -> 1e9 bps
		},
		oidIfSpeed: {
			pdu(oidIfSpeed+".2", gosnmp.Gauge32, uint(100_000_000)), // 100 Mbps (fallback for if2)
		},
		oidIfHCInOctets: {
			pdu(oidIfHCInOctets+".1", gosnmp.Counter64, uint64(5_000_000_000)),
		},
		oidIfHCOutOctets: {
			pdu(oidIfHCOutOctets+".1", gosnmp.Counter64, uint64(6_000_000_000)),
		},
		oidIfInOctets: {
			pdu(oidIfInOctets+".2", gosnmp.Counter32, uint(1234)),
		},
		oidIfOutOctets: {
			pdu(oidIfOutOctets+".2", gosnmp.Counter32, uint(5678)),
		},
		oidIfInErrors: {
			pdu(oidIfInErrors+".1", gosnmp.Counter32, uint(7)),
		},
		oidIfOutDiscards: {
			pdu(oidIfOutDiscards+".2", gosnmp.Counter32, uint(3)),
		},
		oidIfOperStatus: {
			pdu(oidIfOperStatus+".1", gosnmp.Integer, 1), // up
			pdu(oidIfOperStatus+".2", gosnmp.Integer, 2), // down
		},
	}}

	readings, err := walkInterfaces(conn)
	if err != nil {
		t.Fatalf("walkInterfaces error: %v", err)
	}
	if len(readings) != 2 {
		t.Fatalf("got %d readings, want 2", len(readings))
	}

	byIdx := map[int]InterfaceReading{}
	for _, r := range readings {
		byIdx[r.IfIndex] = r
	}

	if1 := byIdx[1]
	if if1.IfName != "Gi0/1" {
		t.Errorf("if1 name = %q, want Gi0/1", if1.IfName)
	}
	if if1.IfSpeedBps != 1_000_000_000 {
		t.Errorf("if1 speed = %d, want 1e9 (ifHighSpeed*1e6)", if1.IfSpeedBps)
	}
	if !if1.Is64Bit {
		t.Errorf("if1 should be 64-bit (HC counters present)")
	}
	if if1.InOctets != 5_000_000_000 || if1.OutOctets != 6_000_000_000 {
		t.Errorf("if1 octets = in %d/out %d, want 5e9/6e9", if1.InOctets, if1.OutOctets)
	}
	if if1.InErrors != 7 {
		t.Errorf("if1 inErrors = %d, want 7", if1.InErrors)
	}
	if if1.OperStatus != "up" {
		t.Errorf("if1 operStatus = %q, want up", if1.OperStatus)
	}

	if2 := byIdx[2]
	if if2.Is64Bit {
		t.Errorf("if2 should be 32-bit (only Counter32 octets)")
	}
	if if2.IfSpeedBps != 100_000_000 {
		t.Errorf("if2 speed = %d, want 1e8 (ifSpeed fallback)", if2.IfSpeedBps)
	}
	if if2.InOctets != 1234 || if2.OutOctets != 5678 {
		t.Errorf("if2 octets = in %d/out %d, want 1234/5678", if2.InOctets, if2.OutOctets)
	}
	if if2.OutDiscards != 3 {
		t.Errorf("if2 outDiscards = %d, want 3", if2.OutDiscards)
	}
	if if2.OperStatus != "down" {
		t.Errorf("if2 operStatus = %q, want down", if2.OperStatus)
	}
}

func TestWalkInterfaces_NoRows(t *testing.T) {
	conn := &fakeConn{byColumn: map[string][]gosnmp.SnmpPDU{}}
	if _, err := walkInterfaces(conn); err == nil {
		t.Fatal("expected error when no interfaces are returned")
	}
}

func TestIndexFromOID(t *testing.T) {
	tests := []struct {
		full, col string
		want      int
		ok        bool
	}{
		{oidIfName + ".5", oidIfName, 5, true},
		{"." + oidIfHCInOctets + ".42", oidIfHCInOctets, 42, true},
		{oidIfSpeed, oidIfSpeed, 0, false},
		{oidIfName + ".bad", oidIfName, 0, false},
	}
	for _, tt := range tests {
		got, ok := indexFromOID(tt.full, tt.col)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("indexFromOID(%q,%q) = (%d,%v), want (%d,%v)", tt.full, tt.col, got, ok, tt.want, tt.ok)
		}
	}
}

func TestOperStatusName(t *testing.T) {
	cases := map[int]string{1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown", 4: "unknown", 99: "unknown"}
	for code, want := range cases {
		if got := operStatusName(code); got != want {
			t.Errorf("operStatusName(%d) = %q, want %q", code, got, want)
		}
	}
}
