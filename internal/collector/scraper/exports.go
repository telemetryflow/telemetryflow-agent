// Package scraper exports internal functions for testing.
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
package scraper

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// ParsePrometheusTextExported exposes parsePrometheusText for testing.
func ParsePrometheusTextExported(r io.Reader) ([]collector.Metric, error) {
	return parsePrometheusText(r)
}

// ConvertFamilyExported exposes convertFamily for testing.
func ConvertFamilyExported(name string, family *dto.MetricFamily) []collector.Metric {
	return convertFamily(name, family)
}

// LabelsToMapExported exposes labelsToMap for testing.
func LabelsToMapExported(pairs []*dto.LabelPair) map[string]string {
	return labelsToMap(pairs)
}

// CopyLabelsExported exposes copyLabels for testing.
func CopyLabelsExported(src map[string]string) map[string]string {
	return copyLabels(src)
}

// ApplyRelabelRulesExported exposes applyRelabelRules for testing.
func ApplyRelabelRulesExported(metrics []collector.Metric, rules []RelabelConfig) []collector.Metric {
	return applyRelabelRules(metrics, rules)
}

// BuildSourceValueExported exposes buildSourceValue for testing.
func BuildSourceValueExported(m collector.Metric, sourceLabels []string) string {
	return buildSourceValue(m, sourceLabels)
}

// BuildScrapeURLExported exposes buildScrapeURL for testing.
func BuildScrapeURLExported(target, scrapePath string) string {
	return buildScrapeURL(target, scrapePath)
}

// ScrapeTargetExported exposes scrapeTarget for testing.
func ScrapeTargetExported(ctx context.Context, client *http.Client, target string, cfg ScrapeJobConfig) ([]collector.Metric, error) {
	return scrapeTarget(ctx, client, target, cfg)
}

// BuildTLSConfigExported exposes buildTLSConfig for testing.
func BuildTLSConfigExported(cfg TLSConfig) (*tls.Config, error) {
	return buildTLSConfig(cfg)
}

// NewScrapeJobExported exposes newScrapeJob for testing.
func NewScrapeJobExported(cfg ScrapeJobConfig, out chan<- []collector.Metric, logger *zap.Logger) (*ScrapeJob, error) {
	return newScrapeJob(cfg, out, logger)
}

// BearerRoundTripperExported returns a RoundTripper that injects a bearer token,
// exposing bearerRoundTripper for testing.
func BearerRoundTripperExported(token string, next http.RoundTripper) http.RoundTripper {
	return &bearerRoundTripper{token: token, next: next}
}

// BasicAuthRoundTripperExported returns a RoundTripper that injects basic auth,
// exposing basicAuthRoundTripper for testing.
func BasicAuthRoundTripperExported(username, password string, next http.RoundTripper) http.RoundTripper {
	return &basicAuthRoundTripper{username: username, password: password, next: next}
}
