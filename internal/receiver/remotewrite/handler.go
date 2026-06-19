// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
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
package remotewrite

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

const (
	expectedContentType = "application/x-protobuf"
	expectedRWVersion   = "0.1.0"
)

// writeHandler returns an http.HandlerFunc that processes remote write requests.
// cfg is used for optional basic auth. out is the metrics channel to push to.
// flushInterval is used for the Retry-After header on 503.
func writeHandler(cfg RemoteWriteReceiverConfig, out chan<- []collector.Metric, flushInterval time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Validate Content-Type header.
		if ct := r.Header.Get("Content-Type"); ct != expectedContentType {
			RequestsTotal.WithLabelValues("error").Inc()
			http.Error(w, fmt.Sprintf("unsupported Content-Type: %q, expected %q", ct, expectedContentType), http.StatusBadRequest)
			return
		}

		// Validate X-Prometheus-Remote-Write-Version header.
		if ver := r.Header.Get("X-Prometheus-Remote-Write-Version"); ver != expectedRWVersion {
			RequestsTotal.WithLabelValues("error").Inc()
			http.Error(w, fmt.Sprintf("unsupported X-Prometheus-Remote-Write-Version: %q, expected %q", ver, expectedRWVersion), http.StatusBadRequest)
			return
		}

		// Optional basic auth check.
		if cfg.BasicAuth != nil {
			username, password, ok := r.BasicAuth()
			if !ok {
				// Try parsing Authorization header manually as a fallback.
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Basic ") {
					decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
					if err == nil {
						parts := strings.SplitN(string(decoded), ":", 2)
						if len(parts) == 2 {
							username, password, ok = parts[0], parts[1], true
						}
					}
				}
			}
			if !ok || username != cfg.BasicAuth.Username || password != cfg.BasicAuth.Password {
				RequestsTotal.WithLabelValues("error").Inc()
				w.Header().Set("WWW-Authenticate", `Basic realm="remote write"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Read request body.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			RequestsTotal.WithLabelValues("error").Inc()
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		// Decode (Snappy decompress + protobuf unmarshal).
		req, err := decodeWriteRequest(body)
		if err != nil {
			DecodeErrorsTotal.Inc()
			RequestsTotal.WithLabelValues("error").Inc()
			http.Error(w, fmt.Sprintf("decode error: %v", err), http.StatusBadRequest)
			return
		}

		// Convert all TimeSeries to collector.Metric slices.
		var allMetrics []collector.Metric
		totalSamples := 0
		for _, ts := range req.Timeseries {
			metrics, err := convertTimeSeries(ts)
			if err != nil {
				// InvalidSeriesTotal already incremented inside convertTimeSeries.
				continue
			}
			totalSamples += len(metrics)
			allMetrics = append(allMetrics, metrics...)
		}

		SamplesReceivedTotal.Add(float64(totalSamples))

		// Push to metrics channel; return 503 if full.
		if len(allMetrics) > 0 {
			select {
			case out <- allMetrics:
			default:
				RequestsTotal.WithLabelValues("error").Inc()
				retryAfter := int(flushInterval.Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				http.Error(w, "buffer full, try again later", http.StatusServiceUnavailable)
				return
			}
		}

		RequestsTotal.WithLabelValues("success").Inc()
		RequestDuration.Observe(time.Since(start).Seconds())
		w.WriteHeader(http.StatusNoContent)
	}
}
