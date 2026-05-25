// Package kubernetes — node log collection from K8s nodes.
//
// Collects kubelet, kube-proxy, and containerd logs from each node via the
// K8s API server node proxy endpoint:
//
//	GET /api/v1/nodes/{name}/proxy/logs/{source}.log
//
// Falls back to reading from well-known host paths if mounted (DaemonSet mode):
//
//	/var/log/syslog, /var/log/kubelet.log, /var/log/containers/kube-proxy-*
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
package kubernetes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// nodeLogSourcePaths maps source names to their log file paths on the node.
var nodeLogSourcePaths = map[string][]string{
	"kubelet":    {"kubelet.log", "journal/kubelet"},
	"kube-proxy": {"kube-proxy.log"},
	"containerd": {"containerd.log"},
}

// collectNodeLogs retrieves recent log lines from each node for configured sources.
// It uses the K8s API node proxy to access /var/log/ on each node.
func collectNodeLogs(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	logger *zap.Logger,
) ([]NodeLogEntry, error) {
	tailLines := cfg.NodeLogsTailLines
	if tailLines <= 0 {
		tailLines = 200
	}

	sources := cfg.NodeLogSources
	if len(sources) == 0 {
		sources = []string{"kubelet", "kube-proxy", "containerd"}
	}

	// List all nodes
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	var entries []NodeLogEntry
	now := time.Now()

	for i := range nodeList.Items {
		node := &nodeList.Items[i]

		for _, source := range sources {
			paths, ok := nodeLogSourcePaths[source]
			if !ok {
				paths = []string{source + ".log"}
			}

			var lines []string
			var fetchErr error
			for _, logPath := range paths {
				lines, fetchErr = fetchNodeLogViaProxy(ctx, cs, node.Name, logPath, tailLines)
				if fetchErr == nil && len(lines) > 0 {
					break // Found logs at this path
				}
			}

			if fetchErr != nil {
				logger.Debug("Failed to collect node logs via proxy",
					zap.String("node", node.Name),
					zap.String("source", source),
					zap.Error(fetchErr),
				)
				continue
			}

			if len(lines) == 0 {
				continue
			}

			entries = append(entries, NodeLogEntry{
				NodeName:    node.Name,
				Source:      source,
				Lines:       lines,
				CollectedAt: now,
			})
		}
	}

	return entries, nil
}

// fetchNodeLogViaProxy reads log lines from a node using the K8s API proxy.
// Path is relative to /var/log/ on the node (e.g., "kubelet.log").
func fetchNodeLogViaProxy(
	ctx context.Context,
	cs kubernetes.Interface,
	nodeName string,
	logPath string,
	tailLines int64,
) ([]string, error) {
	req := cs.CoreV1().RESTClient().
		Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy", "logs", logPath).
		Param("tailLines", fmt.Sprintf("%d", tailLines))

	rc, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxy stream to node %s/%s: %w", nodeName, logPath, err)
	}
	defer func() { _ = rc.Close() }()

	return readLines(rc, tailLines), nil
}

// readLines reads up to maxLines non-empty lines from a reader.
func readLines(r io.Reader, maxLines int64) []string {
	scanner := bufio.NewScanner(r)
	// Increase buffer for long log lines (default 64KB)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
		if int64(len(lines)) >= maxLines {
			break
		}
	}
	return lines
}
