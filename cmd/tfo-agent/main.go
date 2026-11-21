// Package main is the entry point for the TelemetryFlow Agent (tfo-agent).
// It wires together the Cobra CLI, configuration loading, and the core Agent
// lifecycle — start, collect, export, heartbeat, and graceful shutdown.
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
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/telemetryflow/telemetryflow-agent/internal/agent"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/deploy"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

var (
	cfgFile   string
	logLevel  string
	logFormat string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "tfo-agent",
		Short: "TelemetryFlow Agent - Enterprise Observability Platform",
		Long: fmt.Sprintf(`%s
TelemetryFlow Agent is an enterprise-grade telemetry collection agent
that collects system metrics, logs, and traces and exports them to the
TelemetryFlow platform using OTLP protocol.

Features:
  • System metrics collection (CPU, memory, disk, network)
  • Log collection and forwarding
  • Heartbeat monitoring with auto-reconnection
  • Automatic retry and disk-backed buffering
  • Graceful shutdown with signal handling
  • Cross-platform support (Linux, macOS, Windows)

Usage:
  tfo-agent [flags]              Start the agent (default behavior)
  tfo-agent start [flags]        Start the agent
  tfo-agent version [flags]      Print version information
  tfo-agent config <command>     Configuration management

  `, version.Banner()),
		// Run agent by default when no subcommand is provided
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand provided, run the agent
			return runAgent()
		},
	}

	// Add subcommands
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(deployCmd())

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: searches for tfo-agent.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "", "log format (json, text)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// startCmd returns the start command
func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the TelemetryFlow agent",
		Long:  `Start the TelemetryFlow agent and begin collecting telemetry data.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}
}

// versionCmd returns the version command
func versionCmd() *cobra.Command {
	var jsonOutput bool
	var shortOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and license information",
		Run: func(cmd *cobra.Command, args []string) {
			if jsonOutput {
				info := version.Get()
				fmt.Printf(`{"product":"%s","version":"%s","gitCommit":"%s","buildTime":"%s","goVersion":"%s","os":"%s","arch":"%s","vendor":"%s","developer":"%s","license":"%s"}`+"\n",
					info.Product, info.Version, info.GitCommit, info.BuildTime, info.GoVersion, info.OS, info.Arch, info.Vendor, info.Developer, info.License)
			} else if shortOutput {
				fmt.Println(version.OneLiner())
			} else {
				fmt.Println(version.String())
			}
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	cmd.Flags().BoolVarP(&shortOutput, "short", "s", false, "output short version")
	return cmd
}

// configCmd returns the config command
func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}

	// config validate subcommand
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			loader := config.NewLoader()
			cfg, err := loader.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("configuration validation failed: %w", err)
			}
			fmt.Printf("Configuration is valid\n")
			fmt.Printf("  Endpoint: %s\n", cfg.GetEffectiveEndpoint())
			fmt.Printf("  Hostname: %s\n", cfg.Agent.Hostname)
			fmt.Printf("  Heartbeat Interval: %s\n", cfg.Heartbeat.Interval)
			return nil
		},
	}

	// config show subcommand
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			loader := config.NewLoader()
			cfg, err := loader.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			printConfig(cfg)
			return nil
		},
	}

	cmd.AddCommand(validateCmd, showCmd)
	return cmd
}

// deployCmd returns the deploy command — report a software deployment to the
// TelemetryFlow platform (Operations → Deployments). Reuses the agent's
// ingestion key + backend endpoint (overridable by flags), so any pipeline that
// already runs tfo-agent can report deploys without a separate CLI.
func deployCmd() *cobra.Command {
	var (
		endpoint, keyID, keySecret                          string
		service, version, provider, externalID, environment string
		status, commitSHA, commitRef, actor, pipelineURL    string
		startedAt, finishedAt                               string
		insecure                                            bool
	)

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Report a software deployment to the TelemetryFlow platform",
		Long: `Report a deployment (service + version + status) to TelemetryFlow
(Operations → Deployments). Authenticated by the agent's ingestion key; the
tenant/project are resolved server-side. Endpoint + key fall back to the agent
config when the flags are omitted.

Example:
  tfo-agent deploy --service checkout --version 2.6.0 --status success \
    --provider github --commit $GIT_SHA --ref main`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Config is optional for deploy — flags can supply everything. When a
			// config loads, it fills any endpoint/key/timeout the flags omitted.
			timeout := 30 * time.Second
			if cfg, err := config.NewLoader().Load(cfgFile); err == nil && cfg != nil {
				if endpoint == "" {
					endpoint = cfg.GetBackendEndpoint()
				}
				if keyID == "" {
					keyID = cfg.GetEffectiveAPIKeyID()
				}
				if keySecret == "" {
					keySecret = cfg.GetEffectiveAPIKeySecret()
				}
				if t := cfg.GetEffectiveTimeout(); t > 0 {
					timeout = t
				}
			}

			reporter := deploy.NewReporter(endpoint, keyID, keySecret, timeout,
				deploy.WithInsecureTLS(insecure))

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			resp, err := reporter.Report(ctx, deploy.Request{
				Service:     service,
				Version:     version,
				Provider:    provider,
				ExternalID:  externalID,
				Environment: environment,
				Status:      status,
				CommitSHA:   commitSHA,
				CommitRef:   commitRef,
				Actor:       actor,
				URL:         pipelineURL,
				StartedAt:   startedAt,
				FinishedAt:  finishedAt,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Deployment recorded: id=%s status=%s created=%v\n",
				resp.Data.DeploymentID, resp.Data.Status, resp.Data.Created)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&endpoint, "endpoint", "", "platform backend base URL (default: agent config)")
	f.StringVar(&keyID, "key-id", "", "ingestion key id (tfk_…; default: agent config)")
	f.StringVar(&keySecret, "key-secret", "", "ingestion key secret (tfs_…; default: agent config)")
	f.StringVar(&service, "service", "", "service name (required)")
	f.StringVar(&version, "version", "", "deployed version (required)")
	f.StringVar(&provider, "provider", "", "source provider (github|gitlab|bitbucket|jenkins|aws|azure|argocd|cli)")
	f.StringVar(&externalID, "external-id", "", "provider run/deployment id (dedup key; generated if empty)")
	f.StringVar(&environment, "environment", "", "environment (default: production)")
	f.StringVar(&status, "status", "", "status (queued|running|success|failed|rolled_back; default: success)")
	f.StringVar(&commitSHA, "commit", "", "commit SHA")
	f.StringVar(&commitRef, "ref", "", "commit ref / branch")
	f.StringVar(&actor, "actor", "", "who triggered the deploy (hashed server-side)")
	f.StringVar(&pipelineURL, "url", "", "link to the pipeline run (display only)")
	f.StringVar(&startedAt, "started-at", "", "ISO 8601 start time")
	f.StringVar(&finishedAt, "finished-at", "", "ISO 8601 finish time")
	f.BoolVar(&insecure, "insecure", false, "skip TLS verification (self-signed platform certs)")

	return cmd
}

// runAgent starts the agent
func runAgent() error {
	// Load configuration
	loader := config.NewLoader()
	cfg, err := loader.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override log settings from flags
	if logLevel != "" {
		cfg.Logging.Level = logLevel
	}
	if logFormat != "" {
		cfg.Logging.Format = logFormat
	}

	// Initialize logger
	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	// Print startup banner
	fmt.Print(version.Banner())

	// Log startup info
	logger.Info("Starting TelemetryFlow Agent",
		zap.String("product", version.ProductName),
		zap.String("version", version.Short()),
		zap.String("vendor", version.Vendor),
		zap.String("developer", version.Developer),
		zap.String("hostname", cfg.Agent.Hostname),
		zap.String("endpoint", cfg.GetEffectiveEndpoint()),
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start agent
	ag, err := agent.NewWithConfigFile(cfg, logger, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start agent in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- ag.Run(ctx)
	}()

	// Wait for signals or error
	for {
		select {
		case sig := <-sigChan:
			agCfg := ag.Config()
			if sig == syscall.SIGHUP && agCfg.Supervisor.Enabled && agCfg.Supervisor.HotReload {
				logger.Info("SIGHUP received, reloading configuration")
				if err := ag.ReloadConfig(); err != nil {
					logger.Error("config reload failed", zap.Error(err))
				}
				continue
			}
			logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
			cancel()
			if err := <-errChan; err != nil && err != context.Canceled {
				logger.Error("Agent error during shutdown", zap.Error(err))
			}
			logger.Info("TelemetryFlow Agent stopped")
			return nil
		case err := <-errChan:
			if err != nil && err != context.Canceled {
				logger.Error("Agent error", zap.Error(err))
				return err
			}
			logger.Info("TelemetryFlow Agent stopped")
			return nil
		}
	}
}

// initLogger initializes the logger based on configuration
func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	var zapCfg zap.Config
	if cfg.Format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	zapCfg.Level = zap.NewAtomicLevelAt(level)

	if cfg.File != "" {
		zapCfg.OutputPaths = []string{cfg.File}
		zapCfg.ErrorOutputPaths = []string{cfg.File}
	}

	return zapCfg.Build()
}

// printConfig prints the configuration summary
func printConfig(cfg *config.Config) {
	fmt.Println("TelemetryFlow Agent Configuration")
	fmt.Println("==================================")
	fmt.Printf("\nAgent:\n")
	fmt.Printf("  ID:       %s\n", cfg.Agent.ID)
	fmt.Printf("  Hostname: %s\n", cfg.Agent.Hostname)

	fmt.Printf("\nTelemetryFlow:\n")
	fmt.Printf("  Endpoint:    %s\n", cfg.GetEffectiveEndpoint())
	fmt.Printf("  Workspace:   %s\n", cfg.GetEffectiveWorkspaceID())
	fmt.Printf("  TLS Enabled: %v\n", cfg.GetEffectiveTLSConfig().Enabled)

	fmt.Printf("\nHeartbeat:\n")
	fmt.Printf("  Interval: %s\n", cfg.Heartbeat.Interval)
	fmt.Printf("  Timeout:  %s\n", cfg.Heartbeat.Timeout)

	fmt.Printf("\nCollectors:\n")
	fmt.Printf("  System:  enabled=%v, interval=%s\n",
		cfg.Collector.System.Enabled, cfg.Collector.System.Interval)
	fmt.Printf("  Logs:    enabled=%v\n", cfg.Collector.Logs.Enabled)
	fmt.Printf("  Process: enabled=%v\n", cfg.Collector.Process.Enabled)

	fmt.Printf("\nExporter:\n")
	fmt.Printf("  OTLP: enabled=%v, batch_size=%d, compression=%s\n",
		cfg.Exporter.OTLP.Enabled, cfg.Exporter.OTLP.BatchSize, cfg.Exporter.OTLP.Compression)

	fmt.Printf("\nBuffer:\n")
	fmt.Printf("  Enabled: %v, max_size=%dMB, path=%s\n",
		cfg.Buffer.Enabled, cfg.Buffer.MaxSizeMB, cfg.Buffer.Path)

	fmt.Printf("\nLogging:\n")
	fmt.Printf("  Level: %s, Format: %s\n", cfg.Logging.Level, cfg.Logging.Format)
}
