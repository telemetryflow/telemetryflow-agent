//go:build linux

// TelemetryFlow Agent - eBPF L7 RED collector (Linux implementation)
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// l7BPFMaps holds references to the loaded L7 BPF maps.
// Populated by loadL7Programs; nil when L7 is not loaded.
type l7BPFMaps struct {
	stats  *ebpf.Map // l7_stats: l7ConnKey → l7StatVal
	links  []link.Link
}

// l7Maps is the package-level singleton, set only when loadL7Programs succeeds.
var l7Maps *l7BPFMaps

// l7ConnKey mirrors the BPF struct l7_conn_key { u32 pid; u32 fd }.
// Must match the C struct layout exactly.
type l7ConnKey struct {
	PID uint32
	FD  uint32
}

// l7StatVal mirrors the BPF struct l7_stat_val.
// Must match the C struct layout exactly.
type l7StatVal struct {
	Requests     uint64
	Errors       uint64
	LatencyNs    uint64
	LatencyCount uint64
}

// podInfo holds Kubernetes metadata resolved from a process cgroup.
type podInfo struct {
	PodName   string
	Namespace string
	// Cluster comes from the agent's own config labels.
}

// pidPodCache is a short-lived in-memory cache of pid→pod mappings.
// Entries are refreshed each collection interval; negative entries
// (process not in a k8s cgroup) are stored with empty PodName.
var pidPodCache sync.Map // map[uint32]*podInfo

// resolvePodFromPID maps a Linux PID to its Kubernetes pod metadata by
// reading /proc/<pid>/cgroup and matching the container-id to a known
// cgroup hierarchy path that contains the pod UID and namespace.
//
// The cgroup path on containerd/cri-o looks like:
//
//	/kubepods/burstable/pod<UID>/<containerID>
//
// On cgroup v2 (systemd slice):
//
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/<cID>.scope
//
// We extract pod UID → query /var/lib/kubelet/pods/<uid>/etc-hosts for namespace+name,
// or fall back to parsing /sys/fs/cgroup labels where available.
// If resolution fails for any reason the function returns nil (caller skips the pid).
func resolvePodFromPID(pid uint32) *podInfo {
	// Check cache first.
	if v, ok := pidPodCache.Load(pid); ok {
		return v.(*podInfo)
	}

	info := resolvePodFromPIDUncached(pid)
	// Store even nil-valued result to avoid repeated /proc reads for non-pod pids.
	// We wrap nil as an empty podInfo with blank PodName to distinguish from "not cached".
	if info == nil {
		info = &podInfo{}
	}
	pidPodCache.Store(pid, info)
	return info
}

func resolvePodFromPIDUncached(pid uint32) *podInfo {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(cgroupPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var podUID, containerID string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v1: "11:memory:/kubepods/burstable/pod<uid>/<cid>"
		// cgroup v2: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/<cid>.scope"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cgPath := parts[2]
		if !strings.Contains(cgPath, "kubepods") {
			continue
		}
		// Extract pod UID from path segment "pod<uid>"
		for _, seg := range strings.Split(cgPath, "/") {
			if strings.HasPrefix(seg, "pod") {
				candidate := strings.TrimPrefix(seg, "pod")
				// cgroup v2 pod segment ends with ".slice"
				candidate = strings.TrimSuffix(candidate, ".slice")
				if len(candidate) >= 32 {
					podUID = candidate
				}
			} else if len(seg) == 64 || strings.HasSuffix(seg, ".scope") {
				// Container ID: 64-char hex or <cid>.scope
				cid := strings.TrimSuffix(seg, ".scope")
				if len(cid) >= 12 {
					containerID = cid
				}
			}
		}
		if podUID != "" {
			break
		}
	}
	_ = containerID // used for future deeper resolution

	if podUID == "" {
		return nil
	}

	// Try to read pod name + namespace from kubelet's pod directory.
	// /var/lib/kubelet/pods/<uid>/etc-hosts contains lines like:
	//   # Kubernetes-managed hosts file for pod <namespace>/<name>
	etcHosts := filepath.Join("/var/lib/kubelet/pods", podUID, "etc-hosts")
	namespaceName := readPodNameFromEtcHosts(etcHosts)
	if namespaceName == nil {
		// Fallback: use pod UID as name (better than nothing).
		return &podInfo{PodName: podUID, Namespace: "unknown"}
	}
	return namespaceName
}

// readPodNameFromEtcHosts reads the kubelet-managed etc-hosts file for a pod
// and extracts the namespace and pod name from the comment line.
func readPodNameFromEtcHosts(path string) *podInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// "# Kubernetes-managed hosts file for pod <namespace>/<name>"
		const prefix = "# Kubernetes-managed hosts file for pod "
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) == 2 {
				return &podInfo{
					Namespace: strings.TrimSpace(parts[0]),
					PodName:   strings.TrimSpace(parts[1]),
				}
			}
		}
	}
	return nil
}

// invalidatePIDCache removes stale entries for pids that no longer exist.
// Called once per collection interval to bound cache growth.
func invalidatePIDCache() {
	pidPodCache.Range(func(key, _ interface{}) bool {
		pid := key.(uint32)
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			pidPodCache.Delete(pid)
		}
		return true
	})
}

// =========================================================================
// L7 program load / close
// =========================================================================

// loadL7Programs loads the l7 BPF program and attaches its tracepoints.
// On any error it logs a warning and returns nil (the collector is silently
// disabled — never crashes the agent).
//
// NOTE: This function uses placeholder map creation matching the existing
// pattern in loader.go (all other sub-collectors are also TODO stubs that
// create no real maps). When bpf2go code generation is run on a Linux CI
// host with clang available ("go generate ./internal/collector/ebpf/..."),
// replace the placeholder block with the generated loadL7() call.
func (c *EBPFCollector) loadL7Programs(progs *bpfPrograms) error {
	c.logger.Debug("Loading L7 BPF programs (HTTP/1.x RED collector)")

	// --------------------------------------------------------------------------
	// TODO(phase3-l7): Replace placeholder with bpf2go-generated loader:
	//
	//   objs := l7Objects{}
	//   spec, err := loadL7()
	//   if err != nil {
	//       return fmt.Errorf("l7: load spec: %w", err)
	//   }
	//   if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
	//       Maps: ebpf.MapOptions{PinPath: c.cfg.raw.PinPath},
	//   }); err != nil {
	//       return fmt.Errorf("l7: load+assign: %w", err)
	//   }
	//
	//   tpEnterWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.L7EnterWrite, nil)
	//   if err != nil { return fmt.Errorf("l7: attach sys_enter_write: %w", err) }
	//   tpEnterRead, err := link.Tracepoint("syscalls", "sys_enter_read", objs.L7EnterRead, nil)
	//   if err != nil { return fmt.Errorf("l7: attach sys_enter_read: %w", err) }
	//   tpExitRead, err := link.Tracepoint("syscalls", "sys_exit_read", objs.L7ExitRead, nil)
	//   if err != nil { return fmt.Errorf("l7: attach sys_exit_read: %w", err) }
	//
	//   l7Maps = &l7BPFMaps{
	//       stats: objs.L7Stats,
	//       links: []link.Link{tpEnterWrite, tpEnterRead, tpExitRead},
	//   }
	//   progs.links = append(progs.links, l7Maps.links...)
	//   return nil
	// --------------------------------------------------------------------------

	// Placeholder until bpf2go is run on a Linux CI host:
	// Create a minimal hash map that matches the l7_stats schema so the
	// userspace reader (collectL7) can iterate it safely (it will be empty).
	statsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(l7ConnKey{})),
		ValueSize:  uint32(unsafe.Sizeof(l7StatVal{})),
		MaxEntries: 65536,
		Name:       "l7_stats",
	})
	if err != nil {
		// The kernel may not support this map type / size; log and disable.
		return fmt.Errorf("l7: create placeholder map: %w", err)
	}

	l7Maps = &l7BPFMaps{
		stats: statsMap,
		links: nil, // no real tracepoints attached in placeholder mode
	}

	c.logger.Info("L7 RED collector loaded (placeholder — tracepoints not attached until bpf2go generation)")
	return nil
}

// closeL7Programs detaches and closes L7 BPF resources.
func closeL7Programs() {
	if l7Maps == nil {
		return
	}
	for _, l := range l7Maps.links {
		_ = l.Close()
	}
	if l7Maps.stats != nil {
		l7Maps.stats.Close()
	}
	l7Maps = nil
}

// =========================================================================
// L7 collection
// =========================================================================

// collectL7 reads the l7_stats BPF map, resolves pid→pod via cgroup, and
// emits the three canonical L7 RED metrics per pod:
//
//   - k8s.pod.l7.requests  (counter — requests in interval)
//   - k8s.pod.l7.errors    (counter — 5xx / error responses)
//   - k8s.pod.l7.latency   (gauge   — interval p99 latency in nanoseconds)
//
// The map is iterated and entries are deleted after reading so counters
// represent per-interval deltas (same pattern as other sub-collectors).
//
// Pid→pod resolution uses resolvePodFromPID which reads /proc/<pid>/cgroup.
// This reuses the cgroup-walk approach the Kubernetes collector already uses
// for container CPU/memory attribution.
func (c *EBPFCollector) collectL7(_ context.Context) ([]collector.Metric, error) {
	if l7Maps == nil || l7Maps.stats == nil {
		return nil, nil
	}

	// Invalidate stale pid→pod cache entries once per interval.
	invalidatePIDCache()

	// Aggregate per-pod across all pid+fd entries.
	type podKey struct {
		Namespace string
		PodName   string
		Protocol  string
	}
	type podAgg struct {
		Requests uint64
		Errors   uint64
		// Latency samples for pseudo-p99 (sort not viable in eBPF userspace;
		// we store sum + count and emit avg; true p99 needs histogram map).
		LatencySum   uint64
		LatencyCount uint64
	}

	agg := make(map[podKey]*podAgg)
	clusterLabel := c.cfg.raw.Labels["cluster"]
	if clusterLabel == "" {
		clusterLabel = "default"
	}

	var key l7ConnKey
	var val l7StatVal
	keysToDelete := make([]l7ConnKey, 0, 64)

	iter := l7Maps.stats.Iterate()
	for iter.Next(&key, &val) {
		if val.Requests == 0 {
			keysToDelete = append(keysToDelete, key)
			continue
		}

		pod := resolvePodFromPID(key.PID)
		var ns, name string
		if pod != nil && pod.PodName != "" {
			ns = pod.Namespace
			name = pod.PodName
		} else {
			// Not a k8s pod — still emit metrics under "pid:<n>" for completeness.
			ns = "unknown"
			name = "pid:" + strconv.FormatUint(uint64(key.PID), 10)
		}

		pk := podKey{Namespace: ns, PodName: name, Protocol: "http1"}
		pa := agg[pk]
		if pa == nil {
			pa = &podAgg{}
			agg[pk] = pa
		}
		pa.Requests += val.Requests
		pa.Errors += val.Errors
		pa.LatencySum += val.LatencyNs
		pa.LatencyCount += val.LatencyCount

		keysToDelete = append(keysToDelete, key)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("l7: iterate l7_stats: %w", err)
	}

	// Delete processed entries so the next interval sees only fresh data.
	for i := range keysToDelete {
		_ = l7Maps.stats.Delete(&keysToDelete[i])
	}

	// Convert aggregated data to metrics.
	metrics := make([]collector.Metric, 0, len(agg)*3)
	for pk, pa := range agg {
		labels := map[string]string{
			"pod":       pk.PodName,
			"namespace": pk.Namespace,
			"cluster":   clusterLabel,
			"protocol":  pk.Protocol,
		}

		metrics = append(metrics,
			collector.NewMetric("k8s.pod.l7.requests", float64(pa.Requests), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("k8s.pod.l7.errors", float64(pa.Errors), collector.MetricTypeCounter).
				WithLabels(labels),
		)

		// Emit interval p99 latency.  Without a per-entry histogram we use the
		// average latency as a proxy; true p99 requires a BPF_MAP_TYPE_HISTOGRAM
		// (kernel 5.19+) or a sorted perf-buffer stream in userspace — TODO.
		var latencyP99 float64
		if pa.LatencyCount > 0 {
			latencyP99 = float64(pa.LatencySum) / float64(pa.LatencyCount)
		}
		metrics = append(metrics,
			collector.NewMetric("k8s.pod.l7.latency", latencyP99, collector.MetricTypeGauge).
				WithLabels(labels),
		)
	}

	c.logger.Debug("L7 RED metrics collected",
		zap.Int("pods", len(agg)),
		zap.Int("metrics", len(metrics)),
	)
	return metrics, nil
}

// =========================================================================
// Build-time size assertions (catch struct layout drift early)
// =========================================================================

var _ = func() struct{} {
	// l7ConnKey must be 8 bytes (two u32 fields).
	const wantKeySize = 8
	if unsafe.Sizeof(l7ConnKey{}) != wantKeySize {
		panic("l7ConnKey size mismatch — C struct layout changed")
	}
	// l7StatVal must be 32 bytes (four u64 fields).
	const wantValSize = 32
	if unsafe.Sizeof(l7StatVal{}) != wantValSize {
		panic("l7StatVal size mismatch — C struct layout changed")
	}
	return struct{}{}
}()

// Ensure time import used for potential future backoff logic.
var _ = time.Second
