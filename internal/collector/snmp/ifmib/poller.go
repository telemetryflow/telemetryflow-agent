// IF-MIB SNMP poller: walks the RFC 2863 ifTable / ifXTable columns for a
// single device and merges them into per-interface readings keyed by ifIndex.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// IF-MIB column OIDs (RFC 2863). Each is a table column; the trailing OID
// element is the interface's ifIndex.
const (
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"     // ifTable
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5"     // Gauge32, bits/sec
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"     // INTEGER enum
	oidIfInOctets    = "1.3.6.1.2.1.2.2.1.10"    // Counter32
	oidIfInDiscards  = "1.3.6.1.2.1.2.2.1.13"    // Counter32
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"    // Counter32
	oidIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"    // Counter32
	oidIfOutDiscards = "1.3.6.1.2.1.2.2.1.19"    // Counter32
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"    // Counter32
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"  // ifXTable
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"  // Counter64
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10" // Counter64
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15" // Gauge32, Mbits/sec
)

// InterfaceReading is a single raw IF-MIB snapshot for one interface. Octet
// counters prefer the 64-bit HC variants when the device exposes them; Is64Bit
// records which counter width InOctets/OutOctets were sourced from so the
// wrap-correction math applies the right modulus.
type InterfaceReading struct {
	IfIndex     int
	IfName      string
	IfSpeedBps  uint64
	InOctets    uint64
	OutOctets   uint64
	Is64Bit     bool
	InErrors    uint64
	OutErrors   uint64
	InDiscards  uint64
	OutDiscards uint64
	OperStatus  string
}

// Poller polls one device's IF-MIB and returns a reading per interface.
// The interface exists so the collector can be exercised without a live device.
type Poller interface {
	Poll(ctx context.Context) ([]InterfaceReading, error)
}

// gosnmpConn is the subset of *gosnmp.GoSNMP used by the poller, extracted so
// the walk/merge logic can be unit-tested against a fake connection.
type gosnmpConn interface {
	Connect() error
	Close() error
	BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
}

// gosnmpPoller is the production Poller backed by gosnmp. It reuses the shared
// SNMP connection wiring (v1/v2c/v3) from the snmp package.
type gosnmpPoller struct {
	agent   config.SNMPAgent
	connect func(config.SNMPAgent) (gosnmpConn, error)
}

// NewGoSNMPPoller builds a production IF-MIB poller for a device.
func NewGoSNMPPoller(device config.SNMPInterfaceDevice) Poller {
	agent := device.ToSNMPAgent()
	snmp.ApplyAgentDefaultsExported(&agent)
	return &gosnmpPoller{
		agent:   agent,
		connect: dialGoSNMP,
	}
}

// dialGoSNMP builds and connects a gosnmp client from an agent config.
func dialGoSNMP(agent config.SNMPAgent) (gosnmpConn, error) {
	g := snmp.BuildGoSNMPExported(agent)
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

// Poll walks every IF-MIB column once, merges the columns by ifIndex, and
// returns one reading per interface. A failure to walk a single column is
// tolerated (the corresponding fields stay zero) except for the index-bearing
// walks that yield no interfaces at all.
func (p *gosnmpPoller) Poll(ctx context.Context) ([]InterfaceReading, error) {
	conn, err := p.connect(p.agent)
	if err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", p.agent.Host, err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return walkInterfaces(conn)
}

// walkInterfaces performs the column walks and merge against an established
// connection. Split out so it can be unit-tested with a fake gosnmpConn.
func walkInterfaces(conn gosnmpConn) ([]InterfaceReading, error) {
	rows := make(map[int]*InterfaceReading)

	get := func(idx int) *InterfaceReading {
		r, ok := rows[idx]
		if !ok {
			r = &InterfaceReading{IfIndex: idx, OperStatus: operStatusName(0)}
			rows[idx] = r
		}
		return r
	}

	// 64-bit HC octet counters first (preferred). Track which indices have them
	// so the 32-bit fallback does not clobber a good 64-bit value.
	has64In := map[int]bool{}
	has64Out := map[int]bool{}

	walkColumn(conn, oidIfName, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).IfName = pduString(pdu)
	})
	walkColumn(conn, oidIfDescr, func(idx int, pdu gosnmp.SnmpPDU) {
		r := get(idx)
		if r.IfName == "" { // ifName (ifXTable) preferred; ifDescr is the fallback label
			r.IfName = pduString(pdu)
		}
	})
	walkColumn(conn, oidIfHighSpeed, func(idx int, pdu gosnmp.SnmpPDU) {
		// ifHighSpeed is in Mbit/s; convert to bit/s. Preferred over ifSpeed for
		// high-speed links where ifSpeed (bit/s Gauge32) saturates at ~4.29 Gbps.
		get(idx).IfSpeedBps = pduUint(pdu) * 1_000_000
	})
	walkColumn(conn, oidIfSpeed, func(idx int, pdu gosnmp.SnmpPDU) {
		r := get(idx)
		if r.IfSpeedBps == 0 {
			r.IfSpeedBps = pduUint(pdu)
		}
	})
	walkColumn(conn, oidIfHCInOctets, func(idx int, pdu gosnmp.SnmpPDU) {
		r := get(idx)
		r.InOctets = pduUint(pdu)
		r.Is64Bit = true
		has64In[idx] = true
	})
	walkColumn(conn, oidIfHCOutOctets, func(idx int, pdu gosnmp.SnmpPDU) {
		r := get(idx)
		r.OutOctets = pduUint(pdu)
		r.Is64Bit = true
		has64Out[idx] = true
	})
	walkColumn(conn, oidIfInOctets, func(idx int, pdu gosnmp.SnmpPDU) {
		if has64In[idx] {
			return
		}
		r := get(idx)
		r.InOctets = pduUint(pdu)
		// Only downgrade to 32-bit width if neither octet direction is 64-bit.
		if !has64Out[idx] {
			r.Is64Bit = false
		}
	})
	walkColumn(conn, oidIfOutOctets, func(idx int, pdu gosnmp.SnmpPDU) {
		if has64Out[idx] {
			return
		}
		r := get(idx)
		r.OutOctets = pduUint(pdu)
		if !has64In[idx] {
			r.Is64Bit = false
		}
	})
	walkColumn(conn, oidIfInErrors, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).InErrors = pduUint(pdu)
	})
	walkColumn(conn, oidIfOutErrors, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).OutErrors = pduUint(pdu)
	})
	walkColumn(conn, oidIfInDiscards, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).InDiscards = pduUint(pdu)
	})
	walkColumn(conn, oidIfOutDiscards, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).OutDiscards = pduUint(pdu)
	})
	walkColumn(conn, oidIfOperStatus, func(idx int, pdu gosnmp.SnmpPDU) {
		get(idx).OperStatus = operStatusName(int(pduUint(pdu)))
	})

	if len(rows) == 0 {
		return nil, fmt.Errorf("no IF-MIB interfaces returned")
	}

	out := make([]InterfaceReading, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	return out, nil
}

// walkColumn BulkWalks a single IF-MIB column and invokes fn per row with the
// parsed ifIndex. Walk errors are ignored so one missing optional column does
// not abort the whole poll.
func walkColumn(conn gosnmpConn, column string, fn func(idx int, pdu gosnmp.SnmpPDU)) {
	pdus, err := conn.BulkWalkAll(column)
	if err != nil {
		return
	}
	for _, pdu := range pdus {
		idx, ok := indexFromOID(pdu.Name, column)
		if !ok {
			continue
		}
		fn(idx, pdu)
	}
}

// indexFromOID extracts the interface index — the final OID element after the
// column prefix — from a walked PDU name.
func indexFromOID(fullOID, column string) (int, bool) {
	full := strings.TrimPrefix(fullOID, ".")
	col := strings.TrimPrefix(column, ".")
	suffix := strings.TrimPrefix(full, col)
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix == "" {
		return 0, false
	}
	// The index for ifTable/ifXTable is a single sub-identifier.
	if dot := strings.IndexByte(suffix, '.'); dot >= 0 {
		suffix = suffix[:dot]
	}
	idx, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// pduUint converts any gosnmp numeric PDU value to uint64.
func pduUint(pdu gosnmp.SnmpPDU) uint64 {
	if pdu.Value == nil {
		return 0
	}
	bi := gosnmp.ToBigInt(pdu.Value)
	if bi == nil || bi.Sign() < 0 {
		return 0
	}
	return bi.Uint64()
}

// pduString coerces an OctetString PDU value to a trimmed string.
func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimSpace(string(v))
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// operStatusName maps an ifOperStatus enum (RFC 2863) to its textual value.
func operStatusName(code int) string {
	switch code {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	default:
		return "unknown"
	}
}

// Compile-time guard: *gosnmp.GoSNMP satisfies gosnmpConn.
var _ gosnmpConn = (*gosnmp.GoSNMP)(nil)
