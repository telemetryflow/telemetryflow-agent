// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package remotewrite

import "github.com/prometheus/client_golang/prometheus"

// Self-observability metric name constants.
const (
	MetricRequestsTotal          = "tfo_remote_write_requests_total"
	MetricSamplesReceivedTotal   = "tfo_remote_write_samples_received_total"
	MetricDecodeErrorsTotal      = "tfo_remote_write_decode_errors_total"
	MetricInvalidSeriesTotal     = "tfo_remote_write_invalid_series_total"
	MetricRequestDurationSeconds = "tfo_remote_write_request_duration_seconds"
)

var (
	// RequestsTotal counts remote write requests, labelled by status (success|error).
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricRequestsTotal,
			Help: "Total number of remote write requests received, labelled by status.",
		},
		[]string{"status"},
	)

	// SamplesReceivedTotal counts the total number of samples received across all requests.
	SamplesReceivedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSamplesReceivedTotal,
			Help: "Total number of samples received via remote write.",
		},
	)

	// DecodeErrorsTotal counts requests that failed Snappy decompression or protobuf unmarshalling.
	DecodeErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: MetricDecodeErrorsTotal,
			Help: "Total number of remote write requests that failed to decode.",
		},
	)

	// InvalidSeriesTotal counts individual TimeSeries rejected due to missing or empty __name__.
	InvalidSeriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: MetricInvalidSeriesTotal,
			Help: "Total number of time series rejected due to missing or empty __name__ label.",
		},
	)

	// RequestDuration tracks the end-to-end latency of remote write request handling.
	RequestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    MetricRequestDurationSeconds,
			Help:    "Duration of remote write request handling in seconds.",
			Buckets: prometheus.DefBuckets,
		},
	)
)

func init() {
	prometheus.MustRegister(
		RequestsTotal,
		SamplesReceivedTotal,
		DecodeErrorsTotal,
		InvalidSeriesTotal,
		RequestDuration,
	)
}
