// Package agent implements the core TelemetryFlow Agent lifecycle.
// It orchestrates all collectors, exporters, the API client, Kubernetes
// sync, heartbeat, and the optional Prometheus /metrics endpoint.
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
package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	agentapi "github.com/telemetryflow/telemetryflow-agent/internal/api"
	"github.com/telemetryflow/telemetryflow-agent/internal/buffer"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	auroracollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
	cadvisorcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/cadvisor"
	clickhousecollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
	cockroachdbcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	confluentkafkacollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/confluent_kafka"
	dnscollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/dns"
	dockercollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
	ebpfcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ebpf"
	fluentbitcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	httprobecollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/http_probe"
	kafkacollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/kafka"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	logcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
	memcachecollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/memcache"
	mongodbcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/mongodb"
	mssqlcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/mssql"
	mysqlcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
	natscollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/nats"
	netflowcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/netflow"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	pingcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ping"
	pgcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	pubsubcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/pubsub"
	rabbitmqcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/rabbitmq"
	rdspgcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/rds_postgresql"
	redicollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/redis"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
	snmpcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp"
	sqlite3collector "github.com/telemetryflow/telemetryflow-agent/internal/collector/sqlite3"
	sysloglistenercollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/syslog_listener"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
	tcpprobecollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/tcp_probe"
	tsdbcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	valkeycollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/valkey"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/persister"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
	"github.com/telemetryflow/telemetryflow-agent/internal/receiver/remotewrite"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
	k8s "k8s.io/client-go/kubernetes"
)

// Agent is the main telemetry agent
type Agent struct {
	id     string
	config *config.Config
	logger *zap.Logger

	// Components
	client           *api.Client
	heartbeat        *exporter.Heartbeat
	k8sSync          *exporter.KubernetesSync
	k8sCollector     *kubernetes.KubernetesCollector // kept for registration retry
	collectors       []collector.Collector
	collectorManager *collector.Manager
	prometheusServer *exporter.PrometheusServer
	agentAPIServer   *agentapi.Server
	otlpBridge       *exporter.OTLPMetricBridge
	metricForwarder  *exporter.MetricForwarder
	bufferRetry      *exporter.BufferRetrySink
	diskBuffer       *buffer.Buffer
	persister        *persister.Persister
	qanForwarder     *qan.QANForwarder
	qanExporter      *qan.QANExporter

	// State
	mu         sync.RWMutex
	running    bool
	started    time.Time
	configFile string
}

// New creates a new agent instance
func New(cfg *config.Config, logger *zap.Logger) (*Agent, error) {
	return NewWithConfigFile(cfg, logger, "")
}

// NewWithConfigFile creates a new agent instance with a known config file path for hot reload.
func NewWithConfigFile(cfg *config.Config, logger *zap.Logger, configFile string) (*Agent, error) {
	// Resolve a stable agent ID — deterministic via host fingerprint when not explicitly set.
	agentID := ResolveAgentID(cfg.Agent.ID, cfg.Agent.Hostname, logger)

	// Create API client using helper methods (prefer TelemetryFlow config over legacy API)
	tlsConfig := cfg.GetEffectiveTLSConfig()
	client := api.NewClient(api.ClientConfig{
		BaseURL:       cfg.GetBackendEndpoint(),
		APIKeyID:      cfg.GetEffectiveAPIKeyID(),
		APIKeySecret:  cfg.GetEffectiveAPIKeySecret(),
		WorkspaceID:   cfg.GetEffectiveWorkspaceID(),
		TenantID:      cfg.GetEffectiveTenantID(),
		Timeout:       cfg.GetEffectiveTimeout(),
		RetryAttempts: cfg.GetEffectiveRetryAttempts(),
		RetryDelay:    cfg.GetEffectiveRetryDelay(),
		TLSConfig: api.TLSConfig{
			Enabled:    tlsConfig.Enabled,
			SkipVerify: tlsConfig.SkipVerify,
			CertFile:   tlsConfig.CertFile,
			KeyFile:    tlsConfig.KeyFile,
			CAFile:     tlsConfig.CAFile,
		},
		Logger: logger,
	})

	// Create heartbeat exporter
	heartbeat := exporter.NewHeartbeat(exporter.HeartbeatConfig{
		AgentID:           agentID,
		Hostname:          cfg.Agent.Hostname,
		Interval:          cfg.Heartbeat.Interval,
		Timeout:           cfg.Heartbeat.Timeout,
		IncludeSystemInfo: cfg.Heartbeat.IncludeSystemInfo,
		Tags:              cfg.Agent.Tags,
		Labels:            cfg.Agent.Labels,
		Client:            client,
		Logger:            logger,
		StatusReport:      cfg.Supervisor.Enabled && cfg.Supervisor.StatusReport,
	})

	// Create collectors (alphabetical order)
	var collectors []collector.Collector

	// auroraCol is lifted to function scope so it can be registered as a QAN
	// collector when QAN.Aurora is enabled (the Aurora collector implements
	// both collector.Collector and qan.QANCollector).
	var auroraCol *auroracollector.AuroraCollector

	// Add cAdvisor collector if enabled
	if cfg.Collector.CAdvisor.Enabled {
		cadvisorCol := cadvisorcollector.NewCAdvisorCollector(cfg.Collector.CAdvisor, logger)
		collectors = append(collectors, cadvisorCol)
		logger.Info("cAdvisor collector enabled",
			zap.Duration("interval", cfg.Collector.CAdvisor.Interval),
			zap.String("endpoint", cfg.Collector.CAdvisor.Endpoint),
		)
	}

	// Add ClickHouse collector if enabled
	if cfg.Collector.ClickHouse.Enabled {
		chCol := clickhousecollector.NewClickHouseCollector(cfg.Collector.ClickHouse, logger)
		collectors = append(collectors, chCol)
		logger.Info("ClickHouse collector enabled",
			zap.Int("instances", len(cfg.Collector.ClickHouse.Instances)),
			zap.Duration("collection_interval", cfg.Collector.ClickHouse.CollectionInterval),
		)
	}

	// Add CockroachDB collector if enabled
	if cfg.Collector.CockroachDB.Enabled {
		crdbCol := cockroachdbcollector.NewCockroachDBCollector(cfg.Collector.CockroachDB, logger)
		collectors = append(collectors, crdbCol)
		logger.Info("CockroachDB collector enabled",
			zap.Int("instances", len(cfg.Collector.CockroachDB.Instances)),
			zap.Duration("instance_interval", cfg.Collector.CockroachDB.InstanceInterval),
		)
	}

	// Add Aurora collector if enabled
	if cfg.Collector.Aurora.Enabled {
		auroraCol = auroracollector.NewAuroraCollector(cfg.Collector.Aurora, logger)
		collectors = append(collectors, auroraCol)
		logger.Info("Aurora collector enabled",
			zap.Int("clusters", len(cfg.Collector.Aurora.Clusters)),
			zap.Duration("collection_interval", cfg.Collector.Aurora.CollectionInterval),
		)
	}

	// Add MySQL collector if enabled
	if cfg.Collector.MySQL.Enabled {
		mysqlCol := mysqlcollector.NewMySQLCollector(cfg.Collector.MySQL, logger)
		collectors = append(collectors, mysqlCol)
		logger.Info("MySQL collector enabled",
			zap.Int("instances", len(cfg.Collector.MySQL.Instances)),
			zap.Duration("status_interval", cfg.Collector.MySQL.StatusInterval),
		)
	}

	// Add PostgreSQL collector if enabled
	if cfg.Collector.PostgreSQL.Enabled {
		pgCol := pgcollector.NewPostgreSQLCollector(cfg.Collector.PostgreSQL, logger)
		collectors = append(collectors, pgCol)
		logger.Info("PostgreSQL collector enabled",
			zap.Int("instances", len(cfg.Collector.PostgreSQL.Instances)),
			zap.Duration("instance_interval", cfg.Collector.PostgreSQL.InstanceInterval),
		)
	}

	// Add RDS PostgreSQL collector if enabled
	if cfg.Collector.RDSPostgreSQL.Enabled {
		rdsPgCol := pgcollector.NewRDSPostgreSQLCollector(cfg.Collector.RDSPostgreSQL, logger)
		collectors = append(collectors, rdsPgCol)
		logger.Info("RDS PostgreSQL collector enabled",
			zap.Int("instances", len(cfg.Collector.RDSPostgreSQL.Instances)),
			zap.Duration("activity_interval", cfg.Collector.RDSPostgreSQL.ActivityInterval),
		)
	}

	// Add SQLite3 collector if enabled
	if cfg.Collector.SQLite3.Enabled {
		sqlite3Col := sqlite3collector.NewSQLite3Collector(cfg.Collector.SQLite3, logger)
		collectors = append(collectors, sqlite3Col)
		logger.Info("SQLite3 collector enabled",
			zap.Int("databases", len(cfg.Collector.SQLite3.Databases)),
			zap.Duration("collection_interval", cfg.Collector.SQLite3.CollectionInterval),
		)
	}

	// Add MongoDB Community collector if enabled
	if cfg.Collector.MongoDBCommunity.Enabled {
		mongoCol := mongodbcollector.NewMongoDBCollector(cfg.Collector.MongoDBCommunity, logger)
		collectors = append(collectors, mongoCol)
		logger.Info("MongoDB Community collector enabled",
			zap.Int("instances", len(cfg.Collector.MongoDBCommunity.Instances)),
			zap.Duration("interval", cfg.Collector.MongoDBCommunity.Interval),
		)
	}

	// Add MSSQL collector if enabled
	if cfg.Collector.MSSQL.Enabled {
		mssqlCol := mssqlcollector.NewMSSQLCollector(cfg.Collector.MSSQL, logger)
		collectors = append(collectors, mssqlCol)
		logger.Info("MSSQL collector enabled",
			zap.Int("instances", len(cfg.Collector.MSSQL.Instances)),
			zap.Duration("metrics_interval", cfg.Collector.MSSQL.MetricsInterval),
		)
	}

	// Add TimescaleDB collector if enabled
	if cfg.Collector.TimescaleDB.Enabled {
		tsdbCol := tsdbcollector.NewTimescaleDBCollector(cfg.Collector.TimescaleDB, logger)
		collectors = append(collectors, tsdbCol)
		logger.Info("TimescaleDB collector enabled",
			zap.Int("instances", len(cfg.Collector.TimescaleDB.Instances)),
			zap.Duration("instance_interval", cfg.Collector.TimescaleDB.InstanceInterval),
		)
	}

	// Add Redis collector if enabled
	if cfg.Collector.Redis.Enabled {
		redisCol := redicollector.NewRedisCollector(cfg.Collector.Redis, logger)
		collectors = append(collectors, redisCol)
		logger.Info("Redis collector enabled",
			zap.Int("instances", len(cfg.Collector.Redis.Instances)),
			zap.Duration("info_interval", cfg.Collector.Redis.InfoInterval),
		)
	}

	// Add Valkey collector if enabled
	if cfg.Collector.Valkey.Enabled {
		valkeyCol := valkeycollector.NewValkeyCollector(cfg.Collector.Valkey, logger)
		collectors = append(collectors, valkeyCol)
		logger.Info("Valkey collector enabled",
			zap.Int("instances", len(cfg.Collector.Valkey.Instances)),
			zap.Duration("info_interval", cfg.Collector.Valkey.InfoInterval),
		)
	}

	// Add Memcached collector if enabled
	if cfg.Collector.Memcache.Enabled {
		memcacheCol := memcachecollector.NewMemcacheCollector(cfg.Collector.Memcache, logger)
		collectors = append(collectors, memcacheCol)
		logger.Info("Memcache collector enabled",
			zap.Int("instances", len(cfg.Collector.Memcache.Instances)),
			zap.Duration("stats_interval", cfg.Collector.Memcache.StatsInterval),
		)
	}

	// Add RabbitMQ collector if enabled
	if cfg.Collector.RabbitMQ.Enabled {
		rabbitCol := rabbitmqcollector.NewRabbitMQCollector(cfg.Collector.RabbitMQ, logger)
		collectors = append(collectors, rabbitCol)
		logger.Info("RabbitMQ collector enabled",
			zap.Int("instances", len(cfg.Collector.RabbitMQ.Instances)),
			zap.Duration("queue_interval", cfg.Collector.RabbitMQ.QueueInterval),
		)
	}

	// Add Kafka collector if enabled (JMX Prometheus exporter scrape)
	if cfg.Collector.Kafka.Enabled {
		kafkaCol := kafkacollector.NewKafkaCollector(cfg.Collector.Kafka, logger)
		collectors = append(collectors, kafkaCol)
		logger.Info("Kafka collector enabled",
			zap.Int("instances", len(cfg.Collector.Kafka.Instances)),
			zap.Duration("scrape_interval", cfg.Collector.Kafka.ScrapeInterval),
		)
	}

	// Add Confluent Kafka collector if enabled (Metrics API query)
	if cfg.Collector.ConfluentKafka.Enabled {
		confluentCol := confluentkafkacollector.NewConfluentKafkaCollector(cfg.Collector.ConfluentKafka, logger)
		collectors = append(collectors, confluentCol)
		logger.Info("Confluent Kafka collector enabled",
			zap.Int("instances", len(cfg.Collector.ConfluentKafka.Instances)),
			zap.Duration("query_interval", cfg.Collector.ConfluentKafka.QueryInterval),
		)
	}

	// Add NATS collector if enabled (HTTP monitoring API)
	if cfg.Collector.NATS.Enabled {
		natsCol := natscollector.NewNATSCollector(cfg.Collector.NATS, logger)
		collectors = append(collectors, natsCol)
		logger.Info("NATS collector enabled",
			zap.Int("instances", len(cfg.Collector.NATS.Instances)),
			zap.Duration("stats_interval", cfg.Collector.NATS.StatsInterval),
		)
	}

	// === M2 Network Monitoring Collectors ===

	// Add DNS probe collector if enabled
	if cfg.Collector.DNS.Enabled {
		dnsCol := dnscollector.NewDNSCollector(cfg.Collector.DNS, logger)
		collectors = append(collectors, dnsCol)
		logger.Info("DNS collector enabled",
			zap.Int("servers", len(cfg.Collector.DNS.Servers)),
			zap.Int("queries", len(cfg.Collector.DNS.Queries)),
			zap.Duration("interval", cfg.Collector.DNS.Interval),
		)
	}

	// Add HTTP probe collector if enabled
	if cfg.Collector.HTTPProbe.Enabled {
		httpProbeCol := httprobecollector.NewHTTPProbeCollector(cfg.Collector.HTTPProbe, logger)
		collectors = append(collectors, httpProbeCol)
		logger.Info("HTTP probe collector enabled",
			zap.Int("targets", len(cfg.Collector.HTTPProbe.Targets)),
			zap.Duration("interval", cfg.Collector.HTTPProbe.Interval),
		)
	}

	// Add NetFlow listener collector if enabled
	if cfg.Collector.Netflow.Enabled {
		netflowCol := netflowcollector.NewNetflowCollector(cfg.Collector.Netflow, logger)
		collectors = append(collectors, netflowCol)
		logger.Info("Netflow collector enabled",
			zap.String("address", cfg.Collector.Netflow.Address),
			zap.Int("port", cfg.Collector.Netflow.Port),
			zap.Strings("protocols", cfg.Collector.Netflow.Protocols),
		)
	}

	// Add Ping probe collector if enabled
	if cfg.Collector.Ping.Enabled {
		pingCol := pingcollector.NewPingCollector(cfg.Collector.Ping, logger)
		collectors = append(collectors, pingCol)
		logger.Info("Ping collector enabled",
			zap.Int("targets", len(cfg.Collector.Ping.Targets)),
			zap.Duration("interval", cfg.Collector.Ping.Interval),
		)
	}

	// Add SNMP poll collector if enabled
	if cfg.Collector.SNMP.Enabled {
		snmpCol := snmpcollector.NewSNMPCollector(cfg.Collector.SNMP, logger)
		collectors = append(collectors, snmpCol)
		logger.Info("SNMP collector enabled",
			zap.Int("agents", len(cfg.Collector.SNMP.Agents)),
			zap.Int("fields", len(cfg.Collector.SNMP.Fields)),
			zap.Int("tables", len(cfg.Collector.SNMP.Tables)),
			zap.Duration("interval", cfg.Collector.SNMP.Interval),
		)
	}

	// Add Syslog listener collector if enabled
	if cfg.Collector.SyslogListener.Enabled {
		syslogCol := sysloglistenercollector.NewSyslogListenerCollector(cfg.Collector.SyslogListener, logger)
		collectors = append(collectors, syslogCol)
		logger.Info("Syslog listener collector enabled",
			zap.Int("listeners", len(cfg.Collector.SyslogListener.Listeners)),
			zap.String("default_format", cfg.Collector.SyslogListener.DefaultFormat),
		)
	}

	// Add TCP probe collector if enabled
	if cfg.Collector.TCPProbe.Enabled {
		tcpProbeCol := tcpprobecollector.NewTCPProbeCollector(cfg.Collector.TCPProbe, logger)
		collectors = append(collectors, tcpProbeCol)
		logger.Info("TCP probe collector enabled",
			zap.Int("targets", len(cfg.Collector.TCPProbe.Targets)),
			zap.Duration("interval", cfg.Collector.TCPProbe.Interval),
		)
	}

	// Add Google Cloud Pub/Sub collector if enabled (Cloud Monitoring API)
	if cfg.Collector.PubSub.Enabled {
		pubsubCol := pubsubcollector.NewPubSubCollector(cfg.Collector.PubSub, logger)
		collectors = append(collectors, pubsubCol)
		logger.Info("Pub/Sub collector enabled",
			zap.Int("instances", len(cfg.Collector.PubSub.Instances)),
			zap.Duration("stats_interval", cfg.Collector.PubSub.StatsInterval),
		)
	}

	// Add Docker collector if enabled
	if cfg.Collector.Docker.Enabled {
		dockerCol, err := dockercollector.NewDockerCollector(cfg.Collector.Docker, logger)
		if err != nil {
			logger.Warn("Failed to create Docker collector, skipping",
				zap.Error(err),
			)
		} else {
			collectors = append(collectors, dockerCol)
			logger.Info("Docker collector enabled",
				zap.Duration("interval", cfg.Collector.Docker.Interval),
				zap.String("socket", cfg.Collector.Docker.SocketPath),
			)
		}
	}

	// Add eBPF collector if enabled
	if cfg.Collector.EBPF.Enabled {
		ebpfCol, err := ebpfcollector.NewEBPFCollector(cfg.Collector.EBPF, logger)
		if err != nil {
			logger.Warn("Failed to create eBPF collector, skipping",
				zap.Error(err),
			)
		} else {
			collectors = append(collectors, ebpfCol)
			logger.Info("eBPF collector enabled",
				zap.Duration("interval", cfg.Collector.EBPF.Interval),
			)
		}
	}

	// Auto-detect Kubernetes: enable collector + sync when running inside a K8s cluster.
	// KUBERNETES_SERVICE_HOST is injected by the kubelet into every pod.
	// Skip auto-detection if K8s was explicitly disabled via TELEMETRYFLOW_K8S_ENABLED=false
	// (e.g. DaemonSet pods that only run node_exporter).
	k8sExplicitlyDisabled := strings.EqualFold(os.Getenv("TELEMETRYFLOW_K8S_ENABLED"), "false")
	if !cfg.Collector.Kubernetes.Enabled && !k8sExplicitlyDisabled && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg.Collector.Kubernetes.Enabled = true
		if !cfg.Collector.Kubernetes.SyncToBackend {
			cfg.Collector.Kubernetes.SyncToBackend = true
		}
		logger.Info("Kubernetes environment auto-detected, enabling K8s collector")
	}

	// Add Kubernetes collector if enabled
	var k8sSync *exporter.KubernetesSync
	var k8sCollector *kubernetes.KubernetesCollector
	if cfg.Collector.Kubernetes.Enabled {
		col, err := kubernetes.NewKubernetesCollector(cfg.Collector.Kubernetes, logger)
		if err != nil {
			logger.Warn("Failed to create Kubernetes collector, skipping",
				zap.Error(err),
			)
		} else {
			k8sCollector = col
			collectors = append(collectors, k8sCollector)
			logger.Info("Kubernetes collector enabled",
				zap.String("cluster", k8sCollector.ClusterName()),
				zap.String("provider", k8sCollector.ClusterProvider()),
			)

			// Auto-register cluster with backend if ClusterID is not pre-configured.
			if cfg.Collector.Kubernetes.SyncToBackend && cfg.Collector.Kubernetes.ClusterID == "" {
				regCtx, regCancel := context.WithTimeout(context.Background(), 30*time.Second)
				regResp, regErr := client.AgentRegisterCluster(regCtx, &api.AgentRegisterClusterRequest{
					Name:     k8sCollector.ClusterName(),
					Provider: k8sCollector.ClusterProvider(),
				})
				regCancel()
				if regErr != nil {
					logger.Warn("Failed to auto-register Kubernetes cluster, will retry in background",
						zap.Error(regErr),
						zap.String("cluster", k8sCollector.ClusterName()),
					)
				} else {
					cfg.Collector.Kubernetes.ClusterID = regResp.ID
					logger.Info("Kubernetes cluster auto-registered",
						zap.String("clusterID", regResp.ID),
						zap.String("name", regResp.Name),
						zap.Bool("isNew", regResp.IsNew),
					)
				}
			}

			// Create K8s state sync exporter when sync_to_backend is enabled
			if cfg.Collector.Kubernetes.SyncToBackend && cfg.Collector.Kubernetes.ClusterID != "" {
				syncInterval := cfg.Collector.Kubernetes.SyncInterval
				if syncInterval == 0 {
					syncInterval = 60 * time.Second
				}
				k8sSync = exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
					ClusterID: cfg.Collector.Kubernetes.ClusterID,
					Interval:  syncInterval,
					Timeout:   cfg.Collector.Kubernetes.SyncTimeout,
					Collector: k8sCollector,
					Client:    client,
					Logger:    logger,
				})
				logger.Info("Kubernetes state sync enabled",
					zap.String("clusterID", cfg.Collector.Kubernetes.ClusterID),
					zap.Duration("interval", syncInterval),
					zap.Duration("timeout", cfg.Collector.Kubernetes.SyncTimeout),
				)
			}
		}
	}

	// Add Node Exporter collector if enabled
	if cfg.Collector.NodeExporter.Enabled {
		neCollector := nodeexporter.NewNodeExporterCollector(cfg.Collector.NodeExporter, logger)
		collectors = append(collectors, neCollector)
		logger.Info("Node exporter collector enabled",
			zap.Duration("interval", cfg.Collector.NodeExporter.Interval),
		)
	}

	// Add system collector if enabled
	if cfg.Collector.System.Enabled {
		sysCollector := system.NewHostCollector(system.HostCollectorConfig{
			Interval:    cfg.Collector.System.Interval,
			CollectCPU:  cfg.Collector.System.CPU,
			CollectMem:  cfg.Collector.System.Memory,
			CollectDisk: cfg.Collector.System.Disk,
			CollectNet:  cfg.Collector.System.Network,
			DiskPaths:   cfg.Collector.System.DiskPaths,
			Logger:      logger,
		})
		collectors = append(collectors, sysCollector)
	}

	// Add log collector: Fluent Bit (preferred) or native (fallback).
	// Mutual exclusion — Fluent Bit replaces native when both are enabled.
	if cfg.Collector.FluentBit.Enabled {
		// Route Fluent Bit's OTLP output to the same logs endpoint the OTLP exporter
		// uses. Without this, logs would go to telemetryflow.endpoint + /v1/logs,
		// bypassing the authenticated v2 ingestion path that resolves the tenant
		// from the API key.
		fbCfg := cfg.Collector.FluentBit
		if cfg.Exporter.OTLP.Logs.Enabled {
			fbCfg.LogsEndpoint = cfg.Exporter.OTLP.Logs.Endpoint
		}

		fbCol, err := fluentbitcollector.NewFluentBitCollector(
			fbCfg,
			cfg.TelemetryFlow,
			agentID,
			logger,
		)
		if err != nil {
			logger.Warn("Failed to create Fluent Bit collector, falling back to native log collector",
				zap.Error(err),
			)
			// Fall back to native log collector
			if cfg.Collector.Logs.Enabled {
				logCol := logcollector.NewLogCollector(cfg.Collector.Logs, agentID, logger)
				collectors = append(collectors, logCol)
				logger.Info("Native log collector enabled (Fluent Bit fallback)")
			}
		} else {
			collectors = append(collectors, fbCol)
			logger.Info("Fluent Bit log collector enabled",
				zap.String("binary", cfg.Collector.FluentBit.BinaryPath),
				zap.Bool("kubernetes", cfg.Collector.FluentBit.Kubernetes.Enabled),
				zap.Bool("systemd", cfg.Collector.FluentBit.Systemd.Enabled),
				zap.Int("tail_paths", len(cfg.Collector.FluentBit.Tail.Paths)),
			)
		}
	} else if cfg.Collector.Logs.Enabled {
		logCol := logcollector.NewLogCollector(cfg.Collector.Logs, agentID, logger)
		collectors = append(collectors, logCol)
		logger.Info("Native log collector enabled",
			zap.Int("paths", len(cfg.Collector.Logs.Paths)),
			zap.Bool("journald", cfg.Collector.Logs.Journald.Enabled),
		)
	}

	// Add Prometheus Scraper collector if enabled
	if cfg.Collector.PrometheusScraper.Enabled {
		scraperCfg := scraper.ScraperConfig{
			Enabled: cfg.Collector.PrometheusScraper.Enabled,
		}
		for _, j := range cfg.Collector.PrometheusScraper.ScrapeJobs {
			job := scraper.ScrapeJobConfig{
				JobName:         j.JobName,
				Enabled:         j.Enabled,
				Targets:         j.StaticTargets,
				ScrapeInterval:  j.ScrapeInterval,
				ScrapePath:      j.ScrapePath,
				ScrapeTimeout:   j.ScrapeTimeout,
				HonorLabels:     j.HonorLabels,
				BearerToken:     j.BearerToken,
				BearerTokenFile: j.BearerTokenFile,
				TLSConfig: scraper.TLSConfig{
					InsecureSkipVerify: j.TLSConfig.SkipVerify,
					CAFile:             j.TLSConfig.CAFile,
					CertFile:           j.TLSConfig.CertFile,
					KeyFile:            j.TLSConfig.KeyFile,
				},
			}
			if j.BasicAuth != nil {
				job.BasicAuth = &scraper.BasicAuthConfig{
					Username: j.BasicAuth.Username,
					Password: j.BasicAuth.Password,
				}
			}
			for _, r := range j.RelabelConfigs {
				job.RelabelConfigs = append(job.RelabelConfigs, scraper.RelabelConfig{
					SourceLabels: r.SourceLabels,
					Regex:        r.Regex,
					TargetLabel:  r.TargetLabel,
					Replacement:  r.Replacement,
					Action:       r.Action,
				})
			}
			scraperCfg.Jobs = append(scraperCfg.Jobs, job)
		}
		scraperCollector := scraper.NewPrometheusScraperCollector(scraperCfg, logger)
		collectors = append(collectors, scraperCollector)
		logger.Info("Prometheus scraper collector enabled",
			zap.Int("jobs", len(scraperCfg.Jobs)),
		)
	}

	// Add Remote Write Receiver collector if enabled
	if cfg.Collector.RemoteWriteReceiver.Enabled {
		rwCfg := remotewrite.RemoteWriteReceiverConfig{
			Enabled:    cfg.Collector.RemoteWriteReceiver.Enabled,
			Port:       cfg.Collector.RemoteWriteReceiver.Port,
			BufferSize: cfg.Collector.RemoteWriteReceiver.BufferSize,
		}
		if cfg.Collector.RemoteWriteReceiver.BasicAuth != nil {
			rwCfg.BasicAuth = &remotewrite.BasicAuthConfig{
				Username: cfg.Collector.RemoteWriteReceiver.BasicAuth.Username,
				Password: cfg.Collector.RemoteWriteReceiver.BasicAuth.Password,
			}
		}
		if cfg.Collector.RemoteWriteReceiver.TLS != nil {
			rwCfg.TLS = &remotewrite.TLSConfig{
				InsecureSkipVerify: cfg.Collector.RemoteWriteReceiver.TLS.SkipVerify,
				CAFile:             cfg.Collector.RemoteWriteReceiver.TLS.CAFile,
				CertFile:           cfg.Collector.RemoteWriteReceiver.TLS.CertFile,
				KeyFile:            cfg.Collector.RemoteWriteReceiver.TLS.KeyFile,
			}
		}
		rwReceiver := remotewrite.NewRemoteWriteReceiver(rwCfg, logger)
		collectors = append(collectors, rwReceiver)
		logger.Info("Remote write receiver enabled",
			zap.Int("port", rwCfg.Port),
		)
	}

	// Create Prometheus metrics server if enabled
	var promServer *exporter.PrometheusServer
	if cfg.PrometheusServer.Enabled {
		promServer = exporter.NewPrometheusServer(cfg.PrometheusServer, logger)
		logger.Info("Prometheus metrics server enabled",
			zap.Int("port", cfg.PrometheusServer.Port),
			zap.String("path", cfg.PrometheusServer.Path),
		)
	}

	// Create OTLP metric bridge if metrics export is enabled.
	// This is the export pipeline that forwards collected metrics to the
	// TelemetryFlow Platform backend via OTLP HTTP.
	var otlpBridge *exporter.OTLPMetricBridge
	var otlpSink exporter.MetricSink
	if cfg.IsMetricsEnabled() {
		bridgeCtx := context.Background()
		otlpHost, otlpPath, otlpTLS := cfg.GetOTLPEndpoint("metrics")
		bridge, err := exporter.NewOTLPMetricBridge(bridgeCtx, exporter.OTLPMetricBridgeConfig{
			Endpoint:      otlpHost,
			Path:          otlpPath,
			TLSEnabled:    otlpTLS,
			TLSSkipVerify: cfg.GetEffectiveTLSConfig().SkipVerify,
			Headers: map[string]string{
				"X-TelemetryFlow-Key-ID":     cfg.GetEffectiveAPIKeyID(),
				"X-TelemetryFlow-Key-Secret": cfg.GetEffectiveAPIKeySecret(),
				"X-TelemetryFlow-Agent-ID":   agentID,
			},
			Logger: logger,
		})
		if err != nil {
			logger.Warn("Failed to create OTLP metric bridge, metrics will not be exported",
				zap.Error(err),
			)
		} else {
			otlpBridge = bridge
			otlpSink = bridge
			logger.Info("OTLP metric bridge enabled",
				zap.String("endpoint", otlpHost),
				zap.String("path", otlpPath),
			)
		}
	}

	// Wire disk-backed buffer around the OTLP sink so transient backend
	// failures do not lose metrics (M1.2 — internal/buffer existed but was
	// not instantiated; this closes that gap).
	var bufferRetry *exporter.BufferRetrySink
	if cfg.Buffer.Enabled && otlpSink != nil {
		bufPath := cfg.Buffer.Path
		if bufPath == "" {
			bufPath = "/var/lib/tfo-agent/buffer"
		}
		buf, err := buffer.New(buffer.Config{
			Enabled:       true,
			Path:          bufPath,
			MaxSizeMB:     cfg.Buffer.MaxSizeMB,
			MaxAge:        cfg.Buffer.MaxAge,
			FlushInterval: cfg.Buffer.FlushInterval,
		})
		if err != nil {
			logger.Warn("Failed to initialise disk buffer — metrics will be lost on backend outage",
				zap.String("path", bufPath),
				zap.Error(err),
			)
		} else {
			bufferRetry = exporter.NewBufferRetrySink(otlpSink, exporter.BufferRetryConfig{
				Enabled: true,
				Buffer:  buf,
				Logger:  logger,
			})
			otlpSink = bufferRetry
			logger.Info("Disk-backed retry buffer wired",
				zap.String("path", bufPath),
				zap.Int64("max_size_mb", cfg.Buffer.MaxSizeMB),
			)
		}
	}

	// Create metric forwarder — bridges collectors to export sinks.
	// Without this, collectors collect metrics but never export them.
	var forwarder *exporter.MetricForwarder
	if len(collectors) > 0 {
		fwdInterval := cfg.Collector.System.Interval
		if fwdInterval == 0 {
			fwdInterval = 30 * time.Second
		}
		fwdCfg := exporter.MetricForwarderConfig{
			Collectors: collectors,
			Interval:   fwdInterval,
			Logger:     logger,
		}
		if otlpSink != nil {
			fwdCfg.OTLPSink = otlpSink
		}
		if promServer != nil {
			fwdCfg.PromSink = promServer
		}
		forwarder = exporter.NewMetricForwarder(fwdCfg)
		logger.Info("Metric forwarder enabled",
			zap.Int("collectors", len(collectors)),
			zap.Duration("interval", fwdInterval),
		)
	}

	// Create QAN data path (separate from OTLP metrics).
	// Only active when cfg.QAN.Enabled is true — zero overhead when disabled.
	var qanFwd *qan.QANForwarder
	var qanExp *qan.QANExporter
	if cfg.QAN.Enabled {
		var qanCollectors []qan.QANCollector

		if cfg.QAN.Collectors.PostgreSQL && cfg.Collector.PostgreSQL.Enabled && len(cfg.Collector.PostgreSQL.Instances) > 0 {
			pgQAN := pgcollector.NewQANPostgreSQLCollector(pgcollector.QANConfig{
				Instances:       cfg.Collector.PostgreSQL.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.PostgreSQL.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, pgQAN)
			logger.Info("QAN PostgreSQL collector enabled",
				zap.Int("instances", len(cfg.Collector.PostgreSQL.Instances)),
			)
		}

		if cfg.QAN.Collectors.MySQL && cfg.Collector.MySQL.Enabled && len(cfg.Collector.MySQL.Instances) > 0 {
			myQAN := mysqlcollector.NewQANMySQLCollector(mysqlcollector.QANMySQLConfig{
				Instances:       cfg.Collector.MySQL.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.MySQL.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, myQAN)
			logger.Info("QAN MySQL collector enabled",
				zap.Int("instances", len(cfg.Collector.MySQL.Instances)),
			)
		}

		if cfg.QAN.Collectors.MongoDB && cfg.Collector.MongoDBCommunity.Enabled && len(cfg.Collector.MongoDBCommunity.Instances) > 0 {
			mongoQAN := mongodbcollector.NewQANMongoDBCollector(mongodbcollector.QANMongoDBConfig{
				Instances:       cfg.Collector.MongoDBCommunity.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.MongoDBCommunity.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, mongoQAN)
			logger.Info("QAN MongoDB collector enabled",
				zap.Int("instances", len(cfg.Collector.MongoDBCommunity.Instances)),
			)
		}

		if cfg.QAN.Collectors.MSSQL && cfg.Collector.MSSQL.Enabled && len(cfg.Collector.MSSQL.Instances) > 0 {
			mssqlQAN := mssqlcollector.NewQANMSSQLCollector(mssqlcollector.QANMSSQLConfig{
				Instances:       cfg.Collector.MSSQL.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.MSSQL.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, mssqlQAN)
			logger.Info("QAN MSSQL collector enabled",
				zap.Int("instances", len(cfg.Collector.MSSQL.Instances)),
			)
		}

		if cfg.QAN.Collectors.CockroachDB && cfg.Collector.CockroachDB.Enabled && len(cfg.Collector.CockroachDB.Instances) > 0 {
			crdbQAN := cockroachdbcollector.NewQANCockroachDBCollector(cockroachdbcollector.QANCockroachDBConfig{
				Instances:       cfg.Collector.CockroachDB.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.CockroachDB.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, crdbQAN)
			logger.Info("QAN CockroachDB collector enabled",
				zap.Int("instances", len(cfg.Collector.CockroachDB.Instances)),
			)
		}

		if cfg.QAN.Collectors.TimescaleDB && cfg.Collector.TimescaleDB.Enabled && len(cfg.Collector.TimescaleDB.Instances) > 0 {
			tsQAN := tsdbcollector.NewQANTimescaleDBCollector(tsdbcollector.QANTimescaleDBConfig{
				Instances:       cfg.Collector.TimescaleDB.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.TimescaleDB.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, tsQAN)
			logger.Info("QAN TimescaleDB collector enabled",
				zap.Int("instances", len(cfg.Collector.TimescaleDB.Instances)),
			)
		}

		if cfg.QAN.Collectors.RDSPostgreSQL && cfg.Collector.RDSPostgreSQL.Enabled && len(cfg.Collector.RDSPostgreSQL.Instances) > 0 {
			rdsPgQAN := rdspgcollector.NewQANRDSPostgreSQLCollector(rdspgcollector.QANRDSPostgreSQLConfig{
				Instances:       cfg.Collector.RDSPostgreSQL.Instances,
				TopQueriesLimit: cfg.QAN.TopQueriesLimit,
				Labels:          cfg.Collector.RDSPostgreSQL.Tags,
				Logger:          logger,
			}, logger)
			qanCollectors = append(qanCollectors, rdsPgQAN)
			logger.Info("QAN RDS PostgreSQL collector enabled",
				zap.Int("instances", len(cfg.Collector.RDSPostgreSQL.Instances)),
			)
		}

		// Aurora QAN reuses the Aurora collector, which derives per-query
		// buckets from Performance Insights. It requires both the Aurora
		// collector and PI to be enabled.
		if cfg.QAN.Collectors.Aurora && auroraCol != nil && cfg.Collector.Aurora.EnablePI {
			qanCollectors = append(qanCollectors, auroraCol)
			logger.Info("QAN Aurora (Performance Insights) collector enabled",
				zap.Int("clusters", len(cfg.Collector.Aurora.Clusters)),
			)
		}

		if len(qanCollectors) > 0 {
			qanExp = qan.NewQANExporter(cfg.QAN, agentID, logger)

			qanFwd = qan.NewQANForwarder(qan.QANForwarderConfig{
				Collectors: qanCollectors,
				Sink:       qanExp,
				Interval:   cfg.QAN.Interval,
				Logger:     logger,
			})
			logger.Info("QAN forwarder enabled",
				zap.Int("collectors", len(qanCollectors)),
				zap.Duration("interval", cfg.QAN.Interval),
			)
		} else {
			logger.Warn("QAN enabled but no DB collectors with instances found — QAN path inactive")
		}
	}

	// Create Agent API server if enabled (for real-time K8s queries like pod log streaming)
	var apiServer *agentapi.Server
	if cfg.AgentAPI.Enabled {
		var k8sCs k8s.Interface
		if k8sCollector != nil {
			k8sCs = k8sCollector.Clientset()
		}
		apiServer = agentapi.NewServer(
			agentapi.Config{
				Enabled: cfg.AgentAPI.Enabled,
				Port:    cfg.AgentAPI.Port,
				APIKey:  cfg.AgentAPI.APIKey,
			},
			k8sCs,
			logger,
			nil,
		)
		if k8sCollector != nil {
			logger.Info("Agent API server enabled",
				zap.Int("port", cfg.AgentAPI.Port),
			)
		} else {
			logger.Info("Agent API server enabled (no K8s, supervisor endpoints only)",
				zap.Int("port", cfg.AgentAPI.Port),
			)
		}
	}

	// Initialise persister (M1.7). When cfg.Persister.Enabled is true the agent
	// persists StatefulPlugin state to a JSON file across restarts. Plugins opt
	// in by implementing plugin.StatefulPlugin (e.g. M3 log tail offset). When
	// no plugin implements the mixin the persister is wired but inert.
	var agentPersister *persister.Persister
	if cfg.Persister.Enabled {
		statefile := cfg.Persister.Statefile
		if statefile == "" {
			statefile = "/var/lib/tfo-agent/state.json"
		}
		agentPersister = persister.New(statefile).WithLogger(logger)
		// Load previously persisted state BEFORE collectors start so they can
		// pick up their saved state during Init/Start. Errors here are non-fatal
		// — a missing or corrupt statefile just means plugins start fresh.
		if err := agentPersister.Load(); err != nil {
			logger.Warn("persister load failed — starting with empty state",
				zap.String("statefile", statefile),
				zap.Error(err))
		} else {
			logger.Info("persister loaded",
				zap.String("statefile", statefile))
		}
	}

	ag := &Agent{
		id:               agentID,
		config:           cfg,
		logger:           logger,
		client:           client,
		heartbeat:        heartbeat,
		k8sSync:          k8sSync,
		k8sCollector:     k8sCollector,
		collectors:       collectors,
		collectorManager: newCollectorManager(cfg, collectors, logger),
		prometheusServer: promServer,
		agentAPIServer:   apiServer,
		otlpBridge:       otlpBridge,
		metricForwarder:  forwarder,
		bufferRetry:      bufferRetry,
		diskBuffer:       nil, // tracked separately when needed; buffer closes itself
		persister:        agentPersister,
		qanForwarder:     qanFwd,
		qanExporter:      qanExp,
		configFile:       configFile,
	}

	if ag.collectorManager != nil && cfg.Supervisor.StatusReport {
		ag.heartbeat.SetCollectorStatesFn(ag.CollectorStates)
	}

	if ag.agentAPIServer != nil {
		ag.agentAPIServer.SetAgent(&agentProviderAdapter{agent: ag})
	}

	return ag, nil
}

func newCollectorManager(cfg *config.Config, collectors []collector.Collector, logger *zap.Logger) *collector.Manager {
	if !cfg.Supervisor.Enabled {
		return nil
	}
	mgr := collector.NewManager(&cfg.Supervisor, logger)
	for _, c := range collectors {
		mgr.Register(c.Name(), c, collector.DigestConfig(nil))
	}
	logger.Info("supervisor mode enabled", zap.Int("collectors", len(collectors)))
	return mgr
}

// ID returns the agent ID
func (a *Agent) ID() string {
	return a.id
}

// Run starts the agent and blocks until context is cancelled
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent is already running")
	}
	a.running = true
	a.started = time.Now()
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()

	a.logger.Info("Agent starting",
		zap.String("id", a.id),
		zap.String("hostname", a.config.Agent.Hostname),
		zap.Int("collectors", len(a.collectors)),
	)

	// Create error channel for component errors
	// Buffer: heartbeat + k8sSync + collectors + prometheus server
	chanSize := 2 + len(a.collectors)
	if a.k8sSync != nil {
		chanSize++
	}
	errChan := make(chan error, chanSize)

	// Start Prometheus metrics server
	if a.prometheusServer != nil {
		go func() {
			if err := a.prometheusServer.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("prometheus server error: %w", err)
			}
		}()
	}

	// Start Agent API server (pod log streaming)
	if a.agentAPIServer != nil {
		go func() {
			if err := a.agentAPIServer.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("agent API server error: %w", err)
			}
		}()
	}

	// Start heartbeat
	go func() {
		if err := a.heartbeat.Start(ctx); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("heartbeat error: %w", err)
		}
	}()

	// Start Kubernetes state sync (no-op if not configured)
	if a.k8sSync != nil {
		go func() {
			if err := a.k8sSync.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("kubernetes sync error: %w", err)
			}
		}()
	} else if a.k8sCollector != nil && a.config.Collector.Kubernetes.SyncToBackend {
		// Registration failed at startup — retry with exponential backoff in background.
		go func() {
			backoff := 15 * time.Second
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
				regResp, regErr := a.client.AgentRegisterCluster(regCtx, &api.AgentRegisterClusterRequest{
					Name:     a.k8sCollector.ClusterName(),
					Provider: a.k8sCollector.ClusterProvider(),
				})
				regCancel()
				if regErr != nil {
					if backoff < 5*time.Minute {
						backoff *= 2
					}
					a.logger.Warn("K8s cluster registration retry failed",
						zap.Error(regErr),
						zap.Duration("next_retry", backoff),
					)
					continue
				}
				a.logger.Info("Kubernetes cluster registered (retry succeeded)",
					zap.String("clusterID", regResp.ID),
					zap.String("name", regResp.Name),
				)
				syncInterval := a.config.Collector.Kubernetes.SyncInterval
				if syncInterval == 0 {
					syncInterval = 60 * time.Second
				}
				a.mu.Lock()
				a.config.Collector.Kubernetes.ClusterID = regResp.ID
				a.k8sSync = exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
					ClusterID: regResp.ID,
					Interval:  syncInterval,
					Timeout:   a.config.Collector.Kubernetes.SyncTimeout,
					Collector: a.k8sCollector,
					Client:    a.client,
					Logger:    a.logger,
				})
				sync := a.k8sSync
				a.mu.Unlock()
				if err := sync.Start(ctx); err != nil && err != context.Canceled {
					a.logger.Error("Kubernetes sync stopped", zap.Error(err))
				}
				return
			}
		}()
	}

	// Start metric forwarder (bridges collectors → OTLP + Prometheus)
	if a.metricForwarder != nil {
		if err := a.metricForwarder.Start(ctx); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("metric forwarder error: %w", err)
		}
	}

	// Start buffer retry loop (drains failed batches back into OTLP sink).
	if a.bufferRetry != nil {
		a.bufferRetry.StartRetryLoop(ctx)
	}

	// Start persister save loop (M1.7). Plugins implementing
	// plugin.StatefulPlugin are registered with the persister so their state
	// is checkpointed periodically and on shutdown.
	if a.persister != nil {
		// Register any stateful plugin via type assertion. The plugin system
		// adapter exposes the underlying legacy collector via Impl(); we
		// type-assert on that. Legacy collectors that wish to persist state
		// must implement plugin.StatefulPlugin on their concrete type.
		saveInterval := a.config.Persister.SaveInterval
		if saveInterval == 0 {
			saveInterval = 5 * time.Minute
		}
		a.persister.StartSaveLoop(ctx, saveInterval)
	}

	// Start QAN exporter and forwarder (separate data path from OTLP)
	if a.qanExporter != nil {
		if err := a.qanExporter.Start(ctx); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("qan exporter error: %w", err)
		}
	}
	if a.qanForwarder != nil {
		if err := a.qanForwarder.Start(ctx); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("qan forwarder error: %w", err)
		}
	}

	// Start collectors
	if a.collectorManager != nil {
		if err := a.collectorManager.Start(ctx); err != nil {
			errChan <- fmt.Errorf("supervisor error: %w", err)
		}
	} else {
		for _, c := range a.collectors {
			c := c // capture
			go func() {
				if err := c.Start(ctx); err != nil && err != context.Canceled {
					errChan <- fmt.Errorf("collector %s error: %w", c.Name(), err)
				}
			}()
		}
	}

	a.logger.Info("Agent started successfully")

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		a.logger.Info("Agent shutdown requested")
		return a.shutdown()
	case err := <-errChan:
		a.logger.Error("Component error, initiating shutdown", zap.Error(err))
		return err
	}
}

// shutdown gracefully stops all components
func (a *Agent) shutdown() error {
	a.logger.Info("Shutting down agent components")

	// Final persister save BEFORE components stop so StatefulPlugin state is
	// captured while plugins are still alive to serve GetState().
	if a.persister != nil {
		if err := a.persister.Store(); err != nil {
			a.logger.Warn("persister final store failed", zap.Error(err))
		} else {
			a.logger.Info("persister state saved")
		}
	}

	var wg sync.WaitGroup
	var errs []error
	var errMu sync.Mutex

	// Stop Prometheus server
	if a.prometheusServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.prometheusServer.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("prometheus server stop: %w", err))
				errMu.Unlock()
			}
		}()
	}

	// Stop Agent API server
	if a.agentAPIServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.agentAPIServer.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("agent API server stop: %w", err))
				errMu.Unlock()
			}
		}()
	}

	// Stop heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.heartbeat.Stop(); err != nil {
			errMu.Lock()
			errs = append(errs, fmt.Errorf("heartbeat stop: %w", err))
			errMu.Unlock()
		}
	}()

	// Stop Kubernetes state sync
	if a.k8sSync != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.k8sSync.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("kubernetes sync stop: %w", err))
				errMu.Unlock()
			}
		}()
	}

	// Stop collectors
	if a.collectorManager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.collectorManager.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("supervisor stop: %w", err))
				errMu.Unlock()
			}
		}()
	} else {
		for _, c := range a.collectors {
			c := c
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.Stop(); err != nil {
					errMu.Lock()
					errs = append(errs, fmt.Errorf("collector %s stop: %w", c.Name(), err))
					errMu.Unlock()
				}
			}()
		}
	}

	// Stop metric forwarder
	if a.metricForwarder != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.metricForwarder.Stop()
		}()
	}

	// Stop QAN forwarder and exporter
	if a.qanForwarder != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.qanForwarder.Stop()
		}()
	}
	if a.qanExporter != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.qanExporter.Stop()
		}()
	}

	// Shutdown OTLP metric bridge
	if a.otlpBridge != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.otlpBridge.Shutdown(shutdownCtx); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("otlp bridge shutdown: %w", err))
				errMu.Unlock()
			}
		}()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.logger.Info("All components stopped")
	case <-time.After(10 * time.Second):
		a.logger.Warn("Shutdown timeout, some components may not have stopped cleanly")
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	a.mu.RLock()
	uptime := time.Since(a.started)
	a.mu.RUnlock()
	a.logger.Info("Agent shutdown complete", zap.Duration("uptime", uptime))
	return nil
}

// IsRunning returns whether the agent is running
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// Uptime returns the agent uptime
func (a *Agent) Uptime() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.running {
		return 0
	}
	return time.Since(a.started)
}

// Stats returns agent statistics
func (a *Agent) Stats() AgentStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var uptime time.Duration
	if a.running {
		uptime = time.Since(a.started)
	}

	return AgentStats{
		ID:             a.id,
		Hostname:       a.config.Agent.Hostname,
		Running:        a.running,
		Started:        a.started,
		Uptime:         uptime,
		CollectorCount: len(a.collectors),
	}
}

// AgentStats contains agent statistics
type AgentStats struct {
	ID             string        `json:"id"`
	Hostname       string        `json:"hostname"`
	Running        bool          `json:"running"`
	Started        time.Time     `json:"started"`
	Uptime         time.Duration `json:"uptime"`
	CollectorCount int           `json:"collectorCount"`
}

// ReloadConfig reloads the configuration from disk and applies changes.
// Only works when supervisor mode is enabled.
func (a *Agent) ReloadConfig() error {
	if a.collectorManager == nil {
		return fmt.Errorf("supervisor mode is not enabled, cannot reload config")
	}
	if a.configFile == "" {
		return fmt.Errorf("no config file path known, cannot reload")
	}

	loader := config.NewLoader()
	newCfg, err := loader.LoadFromFile(a.configFile)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	newCollectors := a.rebuildCollectors(newCfg)

	entries := make([]collector.CollectorEntry, 0, len(newCollectors))
	for _, c := range newCollectors {
		entries = append(entries, collector.CollectorEntry{
			Name:       c.Name(),
			Collector:  c,
			ConfigHash: collector.DigestConfig(nil),
		})
	}

	if err := a.collectorManager.ApplyDiff(entries); err != nil {
		return fmt.Errorf("failed to apply config diff: %w", err)
	}

	a.mu.Lock()
	a.config = newCfg
	a.collectors = newCollectors
	a.mu.Unlock()

	a.logger.Info("configuration reloaded successfully",
		zap.Int("collectors", len(newCollectors)),
	)
	return nil
}

// rebuildCollectors creates a fresh collector list from the given config.
func (a *Agent) rebuildCollectors(cfg *config.Config) []collector.Collector {
	var collectors []collector.Collector

	if cfg.Collector.System.Enabled {
		collectors = append(collectors, system.NewHostCollector(system.HostCollectorConfig{
			Interval:    cfg.Collector.System.Interval,
			CollectCPU:  cfg.Collector.System.CPU,
			CollectMem:  cfg.Collector.System.Memory,
			CollectDisk: cfg.Collector.System.Disk,
			CollectNet:  cfg.Collector.System.Network,
			DiskPaths:   cfg.Collector.System.DiskPaths,
			Logger:      a.logger,
		}))
	}

	if cfg.Collector.NodeExporter.Enabled {
		collectors = append(collectors, nodeexporter.NewNodeExporterCollector(cfg.Collector.NodeExporter, a.logger))
	}
	if cfg.Collector.CAdvisor.Enabled {
		collectors = append(collectors, cadvisorcollector.NewCAdvisorCollector(cfg.Collector.CAdvisor, a.logger))
	}
	if cfg.Collector.ClickHouse.Enabled {
		collectors = append(collectors, clickhousecollector.NewClickHouseCollector(cfg.Collector.ClickHouse, a.logger))
	}
	if cfg.Collector.CockroachDB.Enabled {
		collectors = append(collectors, cockroachdbcollector.NewCockroachDBCollector(cfg.Collector.CockroachDB, a.logger))
	}
	if cfg.Collector.Aurora.Enabled {
		collectors = append(collectors, auroracollector.NewAuroraCollector(cfg.Collector.Aurora, a.logger))
	}
	if cfg.Collector.MySQL.Enabled {
		collectors = append(collectors, mysqlcollector.NewMySQLCollector(cfg.Collector.MySQL, a.logger))
	}
	if cfg.Collector.PostgreSQL.Enabled {
		collectors = append(collectors, pgcollector.NewPostgreSQLCollector(cfg.Collector.PostgreSQL, a.logger))
	}
	if cfg.Collector.RDSPostgreSQL.Enabled {
		collectors = append(collectors, pgcollector.NewRDSPostgreSQLCollector(cfg.Collector.RDSPostgreSQL, a.logger))
	}
	if cfg.Collector.SQLite3.Enabled {
		collectors = append(collectors, sqlite3collector.NewSQLite3Collector(cfg.Collector.SQLite3, a.logger))
	}
	if cfg.Collector.MongoDBCommunity.Enabled {
		collectors = append(collectors, mongodbcollector.NewMongoDBCollector(cfg.Collector.MongoDBCommunity, a.logger))
	}
	if cfg.Collector.MSSQL.Enabled {
		collectors = append(collectors, mssqlcollector.NewMSSQLCollector(cfg.Collector.MSSQL, a.logger))
	}
	if cfg.Collector.TimescaleDB.Enabled {
		collectors = append(collectors, tsdbcollector.NewTimescaleDBCollector(cfg.Collector.TimescaleDB, a.logger))
	}

	return collectors
}

// CollectorStates returns the state of all managed collectors (supervisor mode only).
func (a *Agent) CollectorStates() []collector.CollectorStatus {
	if a.collectorManager == nil {
		return nil
	}
	return a.collectorManager.CollectorStates()
}

// ConfigFile returns the path to the config file.
func (a *Agent) ConfigFile() string {
	return a.configFile
}

// Config returns a copy of the current agent configuration.
func (a *Agent) Config() *config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

// KubernetesClusterID returns the current Kubernetes cluster ID under the
// agent lock. It exists so callers can observe the value that the background
// registration-retry goroutine may mutate without racing on the field.
func (a *Agent) KubernetesClusterID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Collector.Kubernetes.ClusterID
}

type agentProviderAdapter struct {
	agent *Agent
}

func (p *agentProviderAdapter) CollectorStates() []agentapi.CollectorState {
	raw := p.agent.CollectorStates()
	if raw == nil {
		return nil
	}
	states := make([]agentapi.CollectorState, len(raw))
	for i, s := range raw {
		states[i] = agentapi.CollectorState{
			Name:         s.Name,
			State:        string(s.State),
			StartedAt:    s.StartedAt.Unix(),
			LastError:    s.LastError,
			FailureCount: s.FailureCount,
		}
	}
	return states
}

func (p *agentProviderAdapter) ReloadConfig() error {
	return p.agent.ReloadConfig()
}

func (p *agentProviderAdapter) IsRunning() bool {
	return p.agent.IsRunning()
}

func (p *agentProviderAdapter) Stats() agentapi.AgentStats {
	s := p.agent.Stats()
	return agentapi.AgentStats{
		ID:             s.ID,
		Hostname:       s.Hostname,
		Running:        s.Running,
		Started:        s.Started.Unix(),
		UptimeMs:       s.Uptime.Milliseconds(),
		CollectorCount: s.CollectorCount,
	}
}
