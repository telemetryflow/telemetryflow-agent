// Package fluentbit embeds Fluent Bit as a managed subprocess log collector.
//
// generator.go dynamically generates fluent-bit.conf and parsers.conf from
// the TFO-Agent YAML configuration, including INPUT, FILTER, and OUTPUT sections.
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
package fluentbit

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// GenerateConfig builds the fluent-bit.conf and parsers.conf content from agent config.
func GenerateConfig(cfg config.FluentBitCollectorConfig, tfCfg config.TelemetryFlowConfig) (conf string, parsers string, err error) {
	var b strings.Builder

	b.WriteString("# TelemetryFlow Agent — auto-generated Fluent Bit configuration\n")
	b.WriteString("# Do not edit manually. Regenerated on every agent start.\n\n")

	// ── [SERVICE] ───────────────────────────────────────────────────────
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = 5
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}

	parsersFile := filepath.Join(cfg.ConfigDir, "parsers.conf")
	multilineParsersFile := filepath.Join(cfg.ConfigDir, "multiline-parsers.conf")

	b.WriteString("[SERVICE]\n")
	fmt.Fprintf(&b, "    flush             %d\n", flush)
	b.WriteString("    daemon            off\n")
	fmt.Fprintf(&b, "    log_level         %s\n", logLevel)
	fmt.Fprintf(&b, "    parsers_file      %s\n", parsersFile)
	fmt.Fprintf(&b, "    plugins_file      %s\n", multilineParsersFile)

	if cfg.StorageEnabled {
		storagePath := cfg.StoragePath
		if storagePath == "" {
			storagePath = filepath.Join(cfg.ConfigDir, "storage")
		}
		fmt.Fprintf(&b, "    storage.path      %s\n", storagePath)
		b.WriteString("    storage.sync      normal\n")
		b.WriteString("    storage.checksum  off\n")
		b.WriteString("    storage.backlog.mem_limit 5M\n")
	}

	if cfg.HealthCheck {
		port := cfg.HealthPort
		if port <= 0 {
			port = 2020
		}
		b.WriteString("    health_check      on\n")
		b.WriteString("    hc_errors_count   5\n")
		b.WriteString("    hc_retry_failure_count 5\n")
		b.WriteString("    hc_period         5\n")
		b.WriteString("    http_server       on\n")
		b.WriteString("    http_listen       0.0.0.0\n")
		fmt.Fprintf(&b, "    http_port         %d\n", port)
	}
	b.WriteString("\n")

	// ── [INPUT] tail — file log collection ──────────────────────────────
	if cfg.Tail.Enabled && len(cfg.Tail.Paths) > 0 {
		for i, path := range cfg.Tail.Paths {
			b.WriteString("[INPUT]\n")
			b.WriteString("    name              tail\n")
			fmt.Fprintf(&b, "    tag               file.%d.*\n", i)
			fmt.Fprintf(&b, "    path              %s\n", path)
			if len(cfg.Tail.ExcludePaths) > 0 {
				fmt.Fprintf(&b, "    exclude_path      %s\n", strings.Join(cfg.Tail.ExcludePaths, ","))
			}
			if cfg.Tail.MultilineParser != "" {
				fmt.Fprintf(&b, "    multiline.parser  %s\n", cfg.Tail.MultilineParser)
			}
			if cfg.Tail.DBPath != "" {
				fmt.Fprintf(&b, "    db                %s\n", cfg.Tail.DBPath)
			} else {
				fmt.Fprintf(&b, "    db                %s\n", filepath.Join(cfg.ConfigDir, fmt.Sprintf("tail-%d.db", i)))
			}
			if cfg.Tail.ReadFromHead {
				b.WriteString("    read_from_head    on\n")
			}
			if cfg.Tail.RefreshInterval > 0 {
				fmt.Fprintf(&b, "    refresh_interval  %d\n", cfg.Tail.RefreshInterval)
			}
			if cfg.Tail.RotateWait > 0 {
				fmt.Fprintf(&b, "    rotate_wait       %d\n", cfg.Tail.RotateWait)
			}
			if cfg.StorageEnabled {
				b.WriteString("    storage.type      filesystem\n")
			}
			b.WriteString("\n")
		}
	}

	// ── [INPUT] systemd — journal log collection ────────────────────────
	if cfg.Systemd.Enabled && len(cfg.Systemd.Units) > 0 {
		b.WriteString("[INPUT]\n")
		b.WriteString("    name              systemd\n")
		b.WriteString("    tag               journald.*\n")
		for _, unit := range cfg.Systemd.Units {
			fmt.Fprintf(&b, "    systemd_filter    _SYSTEMD_UNIT=%s.service\n", unit)
		}
		if cfg.Systemd.StripUnderscores {
			b.WriteString("    strip_underscores on\n")
		}
		if cfg.StorageEnabled {
			b.WriteString("    storage.type      filesystem\n")
		}
		b.WriteString("\n")
	}

	// ── [INPUT] tail — K8s container logs ───────────────────────────────
	if cfg.Kubernetes.Enabled {
		logPath := cfg.Kubernetes.LogPath
		if logPath == "" {
			logPath = "/var/log/containers/*.log"
		}
		b.WriteString("[INPUT]\n")
		b.WriteString("    name              tail\n")
		b.WriteString("    tag               kube.*\n")
		fmt.Fprintf(&b, "    path              %s\n", logPath)
		b.WriteString("    multiline.parser  cri\n")
		fmt.Fprintf(&b, "    db                %s\n", filepath.Join(cfg.ConfigDir, "kube-containers.db"))
		b.WriteString("    mem_buf_limit     5MB\n")
		b.WriteString("    skip_long_lines   on\n")
		if cfg.StorageEnabled {
			b.WriteString("    storage.type      filesystem\n")
		}
		b.WriteString("\n")

		// ── [FILTER] kubernetes — metadata enrichment ───────────────────
		b.WriteString("[FILTER]\n")
		b.WriteString("    name              kubernetes\n")
		b.WriteString("    match             kube.*\n")
		b.WriteString("    kube_url          https://kubernetes.default.svc:443\n")
		b.WriteString("    kube_ca_file      /var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n")
		b.WriteString("    kube_token_file   /var/run/secrets/kubernetes.io/serviceaccount/token\n")
		if cfg.Kubernetes.MergeLog {
			b.WriteString("    merge_log         on\n")
		}
		if !cfg.Kubernetes.KeepLog {
			b.WriteString("    keep_log          off\n")
		}
		if cfg.Kubernetes.K8sLoggingParser {
			b.WriteString("    k8s-logging.parser on\n")
		}
		b.WriteString("    labels            on\n")
		b.WriteString("    annotations       off\n")
		b.WriteString("\n")
	}

	// ── Custom inputs ───────────────────────────────────────────────────
	for _, input := range cfg.CustomInputs {
		b.WriteString("[INPUT]\n")
		for k, v := range input.Properties {
			fmt.Fprintf(&b, "    %-18s%s\n", k, v)
		}
		b.WriteString("\n")
	}

	// ── Custom filters ──────────────────────────────────────────────────
	for _, filter := range cfg.CustomFilters {
		b.WriteString("[FILTER]\n")
		for k, v := range filter.Properties {
			fmt.Fprintf(&b, "    %-18s%s\n", k, v)
		}
		b.WriteString("\n")
	}

	// ── [OUTPUT] opentelemetry — push to TFO Platform ───────────────────
	host, port, tls, err := parseEndpoint(tfCfg.Endpoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse TelemetryFlow endpoint: %w", err)
	}

	b.WriteString("[OUTPUT]\n")
	b.WriteString("    name              opentelemetry\n")
	b.WriteString("    match             *\n")
	fmt.Fprintf(&b, "    host              %s\n", host)
	fmt.Fprintf(&b, "    port              %s\n", port)
	b.WriteString("    logs_uri          /v1/logs\n")

	if tls {
		b.WriteString("    tls               on\n")
		if tfCfg.TLS.SkipVerify {
			b.WriteString("    tls.verify        off\n")
		} else {
			b.WriteString("    tls.verify        on\n")
		}
	} else {
		b.WriteString("    tls               off\n")
	}

	if tfCfg.APIKeyID != "" {
		fmt.Fprintf(&b, "    header            X-TelemetryFlow-Key-ID %s\n", tfCfg.APIKeyID)
	}
	if tfCfg.APIKeySecret != "" {
		fmt.Fprintf(&b, "    header            X-TelemetryFlow-Key-Secret %s\n", tfCfg.APIKeySecret)
	}

	b.WriteString("    logs_body_key     $message\n")
	b.WriteString("    retry_limit       5\n")
	b.WriteString("\n")

	// ── Build parsers.conf ──────────────────────────────────────────────
	parsersContent := BuiltinParsersConf + "\n" + BuiltinMultilineParsersConf

	return b.String(), parsersContent, nil
}

// WriteConfigs writes the generated config files to disk.
func WriteConfigs(configDir, conf, parsers string) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir %s: %w", configDir, err)
	}

	storagePath := filepath.Join(configDir, "storage")
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return fmt.Errorf("create storage dir %s: %w", storagePath, err)
	}

	confPath := filepath.Join(configDir, "fluent-bit.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("write %s: %w", confPath, err)
	}

	parsersPath := filepath.Join(configDir, "parsers.conf")
	if err := os.WriteFile(parsersPath, []byte(parsers), 0600); err != nil {
		return fmt.Errorf("write %s: %w", parsersPath, err)
	}

	multilinePath := filepath.Join(configDir, "multiline-parsers.conf")
	if err := os.WriteFile(multilinePath, []byte(BuiltinMultilineParsersConf), 0600); err != nil {
		return fmt.Errorf("write %s: %w", multilinePath, err)
	}

	return nil
}

// parseEndpoint extracts host, port, and TLS flag from an endpoint string.
// Supports formats: "host:port", "https://host:port", "grpc://host:port"
func parseEndpoint(endpoint string) (host, port string, tls bool, err error) {
	if endpoint == "" {
		return "localhost", "4318", false, nil
	}

	// If no scheme, assume plain TCP
	if !strings.Contains(endpoint, "://") {
		h, p, splitErr := net.SplitHostPort(endpoint)
		if splitErr != nil {
			return endpoint, "4318", false, nil
		}
		return h, p, false, nil
	}

	u, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return "", "", false, fmt.Errorf("parse endpoint %q: %w", endpoint, parseErr)
	}

	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "4318"
		}
	}
	tls = u.Scheme == "https"

	return host, port, tls, nil
}
