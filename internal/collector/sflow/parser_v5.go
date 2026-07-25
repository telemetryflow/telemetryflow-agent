// Package sflow implements a TelemetryFlow Agent network collector that
// receives sFlow v5 datagrams from network devices and emits aggregate
// counters under the network.sflow.* namespace.
//
// This file contains a self-contained, stdlib-only sFlow v5 header + sample
// summary parser. Detailed sample-body decoding (raw_packet headers, counter
// data, expanded flow records) is intentionally deferred; the parser only
// decodes the datagram header and each sample's (format, length) envelope so
// the collector can emit aggregate counters per sample format.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// VersionSflowV5 is the sFlow version carried in the first uint32 of every
// sFlow v5 datagram.
const VersionSflowV5 uint32 = 5

// On-wire agent-IP version codes used in the sFlow v5 datagram header.
const (
	sflowIPVersionV4 = 1
	sflowIPVersionV6 = 2
)

var (
	errShortHeader     = errors.New("sflow v5: packet shorter than datagram header")
	errVersion         = errors.New("sflow v5: expected version 5")
	errBadIPVersion    = errors.New("sflow v5: unsupported agent IP version")
	errShortSample     = errors.New("sflow v5: packet truncated mid-sample header")
	errShortSampleBody = errors.New("sflow v5: packet truncated mid-sample body")
)

// SflowHeader is the decoded sFlow v5 datagram header.
type SflowHeader struct {
	Version        uint32 // always 5
	IPVersion      uint32 // 1=IPv4, 2=IPv6
	AgentIP        string // decoded dotted-decimal / IPv6 string
	SubAgentID     uint32
	SequenceNumber uint32
	UptimeMS       uint32
	NumSamples     uint32
}

// SampleSummary is one sample's metadata extracted from the sample envelope.
// The sample body itself is NOT decoded.
type SampleSummary struct {
	Format     uint32 // raw 32-bit format word from the wire
	Length     uint32 // declared body length in bytes
	Enterprise uint32 // extracted from the format high 20 bits (>> 12)
	// FormatType is extracted from the format low 12 bits (& 0x0FFF).
	// Standard values: 1=flow, 2=counter, 3=expanded_flow, 4=expanded_counter.
	FormatType uint32
}

// ParseSflowV5 parses an sFlow v5 datagram. Returns the decoded header and one
// SampleSummary per declared sample. Sample bodies are not decoded; only each
// sample's (format, length) envelope is consumed to advance the offset.
//
// All integer fields are big-endian (network byte order). Truncation of either
// the header or any sample envelope is reported as an error; on error the
// returned header and sample slice are zero-valued / nil.
func ParseSflowV5(packet []byte) (SflowHeader, []SampleSummary, error) {
	if len(packet) < 8 {
		return SflowHeader{}, nil, errShortHeader
	}
	version := binary.BigEndian.Uint32(packet[0:4])
	if version != VersionSflowV5 {
		return SflowHeader{}, nil, fmt.Errorf("%w: got %d", errVersion, version)
	}
	ipVersion := binary.BigEndian.Uint32(packet[4:8])
	off := 8
	var agentIP string
	switch ipVersion {
	case sflowIPVersionV4:
		if len(packet) < off+4 {
			return SflowHeader{}, nil, errShortHeader
		}
		agentIP = net.IP(packet[off : off+4]).String()
		off += 4
	case sflowIPVersionV6:
		if len(packet) < off+16 {
			return SflowHeader{}, nil, errShortHeader
		}
		agentIP = net.IP(packet[off : off+16]).String()
		off += 16
	default:
		return SflowHeader{}, nil, fmt.Errorf("%w: %d", errBadIPVersion, ipVersion)
	}
	// sub_agent_id, sequence_number, uptime_ms, num_samples (4 x uint32).
	if len(packet) < off+16 {
		return SflowHeader{}, nil, errShortHeader
	}
	subAgentID := binary.BigEndian.Uint32(packet[off : off+4])
	sequence := binary.BigEndian.Uint32(packet[off+4 : off+8])
	uptime := binary.BigEndian.Uint32(packet[off+8 : off+12])
	numSamples := binary.BigEndian.Uint32(packet[off+12 : off+16])
	off += 16

	hdr := SflowHeader{
		Version:        version,
		IPVersion:      ipVersion,
		AgentIP:        agentIP,
		SubAgentID:     subAgentID,
		SequenceNumber: sequence,
		UptimeMS:       uptime,
		NumSamples:     numSamples,
	}

	samples := make([]SampleSummary, 0, numSamples)
	for i := uint32(0); i < numSamples; i++ {
		if len(packet) < off+8 {
			return SflowHeader{}, nil, errShortSample
		}
		rawFormat := binary.BigEndian.Uint32(packet[off : off+4])
		bodyLen := binary.BigEndian.Uint32(packet[off+4 : off+8])
		off += 8
		if uint64(len(packet)-off) < uint64(bodyLen) {
			return SflowHeader{}, nil, errShortSampleBody
		}
		samples = append(samples, SampleSummary{
			Format:     rawFormat,
			Length:     bodyLen,
			Enterprise: rawFormat >> 12,
			FormatType: rawFormat & 0x0FFF,
		})
		off += int(bodyLen)
	}
	return hdr, samples, nil
}
