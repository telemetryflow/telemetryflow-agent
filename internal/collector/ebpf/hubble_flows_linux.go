//go:build linux

// Package ebpf — Hubble network-flow subscriber (Linux implementation).
//
// This file wires the Cilium Hubble Relay gRPC Observer API into the agent's
// Kubernetes network-map data path. It subscribes to the live flow stream,
// maps each *flow.Flow into an exporter.NetworkFlowRecord, and forwards batches
// through an injected callback. It is only compiled on Linux and only started
// when the Cilium flow-export feature flag is enabled.
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
package ebpf

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

const (
	// flowBatchSize is how many mapped records are buffered before a callback flush.
	flowBatchSize = 100

	// flowBatchLinger caps how long a partial batch waits before being flushed.
	flowBatchLinger = 2 * time.Second

	// reconnectInitialBackoff / reconnectMaxBackoff bound the reconnect loop.
	reconnectInitialBackoff = 2 * time.Second
	reconnectMaxBackoff     = 60 * time.Second
)

// NetworkFlowCallback receives batches of mapped network-flow records.
// It is invoked from the subscriber goroutine and must be safe for that use
// (the exporter's Record/RecordMany are).
type NetworkFlowCallback func([]exporter.NetworkFlowRecord)

// NetworkFlowSubscriber subscribes to Cilium Hubble Relay flow events and
// forwards mapped records via a callback. It owns its own gRPC connection
// (independent of the metrics-oriented hubbleClient) and handles reconnect
// with exponential backoff until the supplied context is cancelled.
type NetworkFlowSubscriber struct {
	client *hubbleClient
	cb     NetworkFlowCallback
	logger *zap.Logger
}

// NewNetworkFlowSubscriber constructs a subscriber. It does not connect until
// Run is called.
func NewNetworkFlowSubscriber(cfg config.CiliumCollectorConfig, cb NetworkFlowCallback, logger *zap.Logger) *NetworkFlowSubscriber {
	return &NetworkFlowSubscriber{
		client: newHubbleClient(cfg, logger),
		cb:     cb,
		logger: logger.With(zap.String("component", "hubble-flows")),
	}
}

// Run blocks, maintaining a Hubble flow subscription until ctx is cancelled.
// On any stream/connection error it backs off and reconnects.
func (s *NetworkFlowSubscriber) Run(ctx context.Context) {
	backoff := reconnectInitialBackoff
	for {
		if ctx.Err() != nil {
			return
		}

		err := s.subscribeOnce(ctx)
		s.client.close()

		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Warn("Hubble flow subscription ended, reconnecting",
				zap.Error(err), zap.Duration("backoff", backoff))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < reconnectMaxBackoff {
			backoff *= 2
			if backoff > reconnectMaxBackoff {
				backoff = reconnectMaxBackoff
			}
		}
	}
}

// subscribeOnce establishes a connection and reads the flow stream until it
// errors or ctx is cancelled. On a clean start it resets the caller's backoff.
func (s *NetworkFlowSubscriber) subscribeOnce(ctx context.Context) error {
	if err := s.client.connect(ctx); err != nil {
		return err
	}

	s.client.mu.RLock()
	conn := s.client.conn
	s.client.mu.RUnlock()
	if conn == nil {
		return errors.New("hubble connection not established")
	}

	observer := observerpb.NewObserverClient(conn)
	stream, err := observer.GetFlows(ctx, &observerpb.GetFlowsRequest{Follow: true})
	if err != nil {
		return err
	}

	s.logger.Info("Subscribed to Hubble flow stream",
		zap.String("address", s.client.cfg.HubbleAddress))

	buf := make([]exporter.NetworkFlowRecord, 0, flowBatchSize)
	ticker := time.NewTicker(flowBatchLinger)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		out := make([]exporter.NetworkFlowRecord, len(buf))
		copy(out, buf)
		buf = buf[:0]
		s.cb(out)
	}
	defer flush()

	// Drain the linger ticker in a helper channel so Recv (blocking) and the
	// timer can cooperate: we flush opportunistically on each received message
	// and rely on ctx cancellation to unblock Recv on shutdown.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		resp, recvErr := stream.Recv()
		if recvErr != nil {
			if errors.Is(recvErr, io.EOF) {
				return nil
			}
			return recvErr
		}

		f := resp.GetFlow()
		if f == nil {
			continue
		}

		rec, ok := mapFlow(f)
		if !ok {
			continue
		}
		buf = append(buf, rec)

		select {
		case <-ticker.C:
			flush()
		default:
			if len(buf) >= flowBatchSize {
				flush()
			}
		}
	}
}

// mapFlow converts a Hubble *flow.Flow into an exporter.NetworkFlowRecord.
// It returns ok=false for flows that carry no useful L3/L4 addressing.
// Hubble flow events do NOT carry byte/packet counters — those stay zero.
func mapFlow(f *flowpb.Flow) (exporter.NetworkFlowRecord, bool) {
	ip := f.GetIP()
	src := f.GetSource()
	dst := f.GetDestination()
	if ip == nil && src == nil && dst == nil {
		return exporter.NetworkFlowRecord{}, false
	}

	rec := exporter.NetworkFlowRecord{
		Verdict:   mapVerdict(f.GetVerdict()),
		Direction: mapDirection(f.GetTrafficDirection()),
	}

	if t := f.GetTime(); t != nil {
		rec.Timestamp = t.AsTime().UTC().Format(time.RFC3339)
	} else {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if ip != nil {
		rec.SourceIP = ip.GetSource()
		rec.TargetIP = ip.GetDestination()
	}

	if src != nil {
		rec.SourceNamespace = src.GetNamespace()
		rec.SourcePod = src.GetPodName()
		rec.SourceLabels = labelsToMap(src.GetLabels())
	}
	if dst != nil {
		rec.TargetNamespace = dst.GetNamespace()
		rec.TargetPod = dst.GetPodName()
		rec.TargetLabels = labelsToMap(dst.GetLabels())
	}

	// A destination outside the cluster has no pod/namespace identity.
	rec.IsExternal = dst == nil || (dst.GetNamespace() == "" && dst.GetPodName() == "")

	if svc := f.GetDestinationService(); svc != nil {
		if svc.GetNamespace() != "" {
			rec.TargetService = svc.GetNamespace() + "/" + svc.GetName()
		} else {
			rec.TargetService = svc.GetName()
		}
	}

	// L4: ports + protocol.
	if l4 := f.GetL4(); l4 != nil {
		switch {
		case l4.GetTCP() != nil:
			rec.Protocol = "tcp"
			rec.SourcePort = uint16(l4.GetTCP().GetSourcePort())
			rec.TargetPort = uint16(l4.GetTCP().GetDestinationPort())
		case l4.GetUDP() != nil:
			rec.Protocol = "udp"
			rec.SourcePort = uint16(l4.GetUDP().GetSourcePort())
			rec.TargetPort = uint16(l4.GetUDP().GetDestinationPort())
		case l4.GetICMPv4() != nil:
			rec.Protocol = "icmp"
		case l4.GetICMPv6() != nil:
			rec.Protocol = "icmpv6"
		case l4.GetSCTP() != nil:
			rec.Protocol = "sctp"
		}
	}

	// L7: HTTP status code / DNS query refine the protocol.
	if l7 := f.GetL7(); l7 != nil {
		if http := l7.GetHttp(); http != nil {
			rec.Protocol = "http"
			rec.HTTPStatusCode = uint16(http.GetCode())
		} else if dns := l7.GetDns(); dns != nil {
			rec.Protocol = "dns"
			rec.DNSQuery = dns.GetQuery()
		}
	}

	return rec, true
}

// mapVerdict returns the lowercase string form of a Hubble verdict.
func mapVerdict(v flowpb.Verdict) string {
	switch v {
	case flowpb.Verdict_FORWARDED:
		return "forwarded"
	case flowpb.Verdict_DROPPED:
		return "dropped"
	case flowpb.Verdict_ERROR:
		return "error"
	case flowpb.Verdict_AUDIT:
		return "audit"
	case flowpb.Verdict_REDIRECTED:
		return "redirected"
	case flowpb.Verdict_TRACED:
		return "traced"
	case flowpb.Verdict_TRANSLATED:
		return "translated"
	default:
		return "unknown"
	}
}

// mapDirection returns the lowercase string form of a Hubble traffic direction.
func mapDirection(d flowpb.TrafficDirection) string {
	switch d {
	case flowpb.TrafficDirection_INGRESS:
		return "ingress"
	case flowpb.TrafficDirection_EGRESS:
		return "egress"
	default:
		return "unknown"
	}
}

// labelsToMap converts Hubble "key=value" label strings into a map.
func labelsToMap(labels []string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for _, l := range labels {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = v
		} else {
			out[l] = ""
		}
	}
	return out
}
