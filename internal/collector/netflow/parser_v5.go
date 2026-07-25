// Package netflow implements a TelemetryFlow Agent network collector that
// receives NetFlow v5/v9/IPFIX datagrams from network devices and emits
// aggregate counters under the network.netflow.* namespace.
//
// This file contains a self-contained, stdlib-only NetFlow v5 parser. The
// v5 record layout is fixed (24-byte header + N x 48-byte records), so the
// parser is ~150 lines and has zero third-party dependencies.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// NetFlow version numbers carried in the first uint16 of every NetFlow /
// IPFIX packet header.
const (
	VersionNetflowV5    uint16 = 5
	VersionNetflowV9    uint16 = 9
	VersionNetflowIPFIX uint16 = 10
)

// Fixed on-wire sizes for NetFlow v5.
const (
	v5HeaderLen = 24
	v5RecordLen = 48
	v5MaxFlows  = 30
)

var (
	// errV5ShortHeader is returned when the datagram is smaller than the
	// 24-byte fixed header.
	errV5ShortHeader = errors.New("netflow v5: packet shorter than 24-byte header")
	// errV5ShortRecord is returned when the declared record count implies
	// more bytes than the datagram actually carries.
	errV5ShortRecord = errors.New("netflow v5: packet truncated mid-record")
	// errV5TooMany is returned when the declared record count exceeds the
	// NetFlow v5 maximum of 30.
	errV5TooMany = errors.New("netflow v5: count exceeds 30")
)

// V5Header is the 24-byte fixed NetFlow v5 packet header.
//
// Field semantics follow RFC 3954 ("NetFlow Version 9") predecessor, the
// Cisco NetFlow v5 specification.
type V5Header struct {
	Version          uint16 // always 5
	Count            uint16 // number of flow records in this packet (0-30)
	SysUptime        uint32 // milliseconds since the device booted
	UnixSeconds      uint32 // seconds since the Unix epoch
	UnixNanoseconds  uint32 // residual nanoseconds since UnixSeconds
	FlowSequence     uint32 // sequence counter of flows seen so far
	EngineType       uint8  // flow-switching engine type
	EngineID         uint8  // flow-switching engine ID
	SamplingInterval uint16 // sampling interval (0 when unsampled)
}

// V5Flow is a single 48-byte NetFlow v5 flow record. IP fields are copied
// into freshly-allocated 4-byte net.IP slices so callers may keep them beyond
// the lifetime of the source packet.
type V5Flow struct {
	SrcAddr  net.IP // source IP (4 bytes)
	DstAddr  net.IP // destination IP (4 bytes)
	NextHop  net.IP // next-hop router IP (4 bytes)
	Input    uint16 // SNMP ifIndex of the input interface
	Output   uint16 // SNMP ifIndex of the output interface
	Packets  uint32 // packets in the flow (dPkts)
	Octets   uint32 // bytes in the flow (dOctets)
	First    uint32 // SysUptime at flow start
	Last     uint32 // SysUptime at flow end
	SrcPort  uint16 // source transport port
	DstPort  uint16 // destination transport port
	TCPFlags uint8  // cumulative OR of TCP flags
	Protocol uint8  // IP protocol number (TCP=6, UDP=17, ...)
	TOS      uint8  // IP type-of-service
	SrcAS    uint16 // source autonomous system number
	DstAS    uint16 // destination autonomous system number
	SrcMask  uint8  // source prefix mask bits
	DstMask  uint8  // destination prefix mask bits
}

// ParseNetflowV5 parses a single NetFlow v5 packet (header + records).
//
// The packet must be at least v5HeaderLen bytes. When Count > 0 the total
// length must be exactly v5HeaderLen + Count*v5RecordLen; otherwise
// errV5ShortRecord is returned. The returned flows are heap-allocated and
// safe to retain after the input slice is reused.
func ParseNetflowV5(packet []byte) (V5Header, []V5Flow, error) {
	if len(packet) < v5HeaderLen {
		return V5Header{}, nil, errV5ShortHeader
	}
	version := binary.BigEndian.Uint16(packet[0:2])
	if version != VersionNetflowV5 {
		return V5Header{}, nil, fmt.Errorf("netflow v5: expected version 5, got %d", version)
	}
	count := binary.BigEndian.Uint16(packet[2:4])
	if count > v5MaxFlows {
		return V5Header{}, nil, fmt.Errorf("%w: got %d", errV5TooMany, count)
	}
	want := v5HeaderLen + int(count)*v5RecordLen
	if len(packet) < want {
		return V5Header{}, nil, fmt.Errorf("%w: have %d bytes, need %d", errV5ShortRecord, len(packet), want)
	}
	hdr := V5Header{
		Version:          version,
		Count:            count,
		SysUptime:        binary.BigEndian.Uint32(packet[4:8]),
		UnixSeconds:      binary.BigEndian.Uint32(packet[8:12]),
		UnixNanoseconds:  binary.BigEndian.Uint32(packet[12:16]),
		FlowSequence:     binary.BigEndian.Uint32(packet[16:20]),
		EngineType:       packet[20],
		EngineID:         packet[21],
		SamplingInterval: binary.BigEndian.Uint16(packet[22:24]),
	}
	flows := make([]V5Flow, 0, count)
	off := v5HeaderLen
	for i := 0; i < int(count); i++ {
		flows = append(flows, parseV5Record(packet[off:off+v5RecordLen]))
		off += v5RecordLen
	}
	return hdr, flows, nil
}

// parseV5Record decodes a single 48-byte record slice. The caller guarantees
// rec is exactly v5RecordLen bytes.
func parseV5Record(rec []byte) V5Flow {
	return V5Flow{
		SrcAddr:  copyIPv4(rec[0:4]),
		DstAddr:  copyIPv4(rec[4:8]),
		NextHop:  copyIPv4(rec[8:12]),
		Input:    binary.BigEndian.Uint16(rec[12:14]),
		Output:   binary.BigEndian.Uint16(rec[14:16]),
		Packets:  binary.BigEndian.Uint32(rec[16:20]),
		Octets:   binary.BigEndian.Uint32(rec[20:24]),
		First:    binary.BigEndian.Uint32(rec[24:28]),
		Last:     binary.BigEndian.Uint32(rec[28:32]),
		SrcPort:  binary.BigEndian.Uint16(rec[32:34]),
		DstPort:  binary.BigEndian.Uint16(rec[34:36]),
		TCPFlags: rec[37],
		Protocol: rec[38],
		TOS:      rec[39],
		SrcAS:    binary.BigEndian.Uint16(rec[40:42]),
		DstAS:    binary.BigEndian.Uint16(rec[42:44]),
		SrcMask:  rec[44],
		DstMask:  rec[45],
	}
}

// copyIPv4 returns a 4-byte net.IP whose backing array does not alias the
// source slice. This keeps exported V5Flow fields safe after the caller
// reuses the packet buffer.
func copyIPv4(b []byte) net.IP {
	ip := make(net.IP, 4)
	copy(ip, b)
	return ip
}
