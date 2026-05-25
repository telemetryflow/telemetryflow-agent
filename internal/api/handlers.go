// Package api provides HTTP handler implementations for the agent API.
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

package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handlePodLogs streams pod container logs via SSE (Server-Sent Events).
// Query params: container, follow, tailLines, sinceSeconds, previous, timestamps
func (s *Server) handlePodLogs(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	podName := r.PathValue("pod")

	if namespace == "" || podName == "" {
		http.Error(w, `{"error":"namespace and pod are required"}`, http.StatusBadRequest)
		return
	}

	// Parse query parameters
	container := r.URL.Query().Get("container")
	follow := r.URL.Query().Get("follow") == "true"
	timestamps := r.URL.Query().Get("timestamps") != "false" // default true
	previous := r.URL.Query().Get("previous") == "true"

	var tailLines *int64
	if tl := r.URL.Query().Get("tailLines"); tl != "" {
		if n, err := strconv.ParseInt(tl, 10, 64); err == nil {
			tailLines = &n
		}
	}
	// Default to 100 tail lines if not specified and not following
	if tailLines == nil {
		defaultTail := int64(100)
		tailLines = &defaultTail
	}

	var sinceSeconds *int64
	if ss := r.URL.Query().Get("sinceSeconds"); ss != "" {
		if n, err := strconv.ParseInt(ss, 10, 64); err == nil {
			sinceSeconds = &n
		}
	}

	// Build PodLogOptions
	opts := &corev1.PodLogOptions{
		Follow:       follow,
		Timestamps:   timestamps,
		Previous:     previous,
		TailLines:    tailLines,
		SinceSeconds: sinceSeconds,
	}
	if container != "" {
		opts.Container = container
	}

	s.logger.Debug("Pod log request",
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container", container),
		zap.Bool("follow", follow),
	)

	// Get log stream from K8s API
	stream, err := s.clientset.CoreV1().Pods(namespace).GetLogs(podName, opts).Stream(r.Context())
	if err != nil {
		s.logger.Error("Failed to get pod log stream",
			zap.String("namespace", namespace),
			zap.String("pod", podName),
			zap.Error(err),
		)
		http.Error(w, fmt.Sprintf(`{"error":"failed to get pod logs: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer func() { _ = stream.Close() }()

	if follow {
		// SSE streaming mode
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
			return
		}

		scanner := bufio.NewScanner(stream)
		// Increase buffer size for long log lines (1MB)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			line := scanner.Text()
			_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}

		if err := scanner.Err(); err != nil {
			s.logger.Debug("Pod log stream ended", zap.Error(err))
		}
	} else {
		// Non-streaming mode: return all lines as JSON array
		w.Header().Set("Content-Type", "application/json")

		var lines []string
		scanner := bufio.NewScanner(stream)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"namespace": namespace,
			"pod":       podName,
			"container": container,
			"lines":     lines,
			"count":     len(lines),
		})
	}
}
