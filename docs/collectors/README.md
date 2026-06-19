# TelemetryFlow Agent — Collector Reference

Documentation for all metric collectors in the TelemetryFlow Agent.

## Kubernetes Collector

The Kubernetes collector uses four data sources:

| Source                                 | Used by                                                                                                  |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Kubernetes API server                  | Nodes, Pods, Deployments, Workloads, Storage, HPA, PDB, Events, Resource Counts, Pod Logs                |
| metrics-server (MetricsV1beta1)        | Node and pod/container CPU+memory usage                                                                  |
| Kubelet `/stats/summary` (proxied)     | Node CPU-ns, memory working set, filesystem, imageFs, network; Container ephemeral storage + working set |
| cAdvisor `/metrics/cadvisor` (proxied) | Container CPU throttle seconds (`container_cpu_cfs_throttled_seconds_total`)                             |

| Document                                                       | Description                                                                               |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [KUBERNETES-NODES.md](KUBERNETES-NODES.md)                     | Node capacity, allocatable, usage, filesystem, network                                    |
| [KUBERNETES-PODS.md](KUBERNETES-PODS.md)                       | Pod phase, container resources, ephemeral storage, working set, CPU throttle, termination |
| [KUBERNETES-DEPLOYMENTS.md](KUBERNETES-DEPLOYMENTS.md)         | Deployment replica counts and rollout conditions                                          |
| [KUBERNETES-WORKLOADS.md](KUBERNETES-WORKLOADS.md)             | StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs                                     |
| [KUBERNETES-STORAGE.md](KUBERNETES-STORAGE.md)                 | PersistentVolumes and PersistentVolumeClaims                                              |
| [KUBERNETES-NETWORK.md](KUBERNETES-NETWORK.md)                 | Namespace-level network I/O from Kubelet summary                                          |
| [KUBERNETES-HPA.md](KUBERNETES-HPA.md)                         | HorizontalPodAutoscaler replicas and conditions                                           |
| [KUBERNETES-PDB.md](KUBERNETES-PDB.md)                         | PodDisruptionBudget health and disruption budget                                          |
| [KUBERNETES-EVENTS.md](KUBERNETES-EVENTS.md)                   | Kubernetes events and aggregate event counts                                              |
| [KUBERNETES-RESOURCE-COUNTS.md](KUBERNETES-RESOURCE-COUNTS.md) | Secrets, ConfigMaps, Ingresses per namespace                                              |
| [KUBERNETES-POD-LOGS.md](KUBERNETES-POD-LOGS.md)               | Pod container log collection                                                              |

## Host Collectors

| Document                             | Description                                                                                        |
| ------------------------------------ | -------------------------------------------------------------------------------------------------- |
| [NODE-EXPORTER.md](NODE-EXPORTER.md) | Full node_exporter equivalent: CPU, memory, disk I/O, filesystem, network, load, thermal, textfile |
| [SYSTEM.md](SYSTEM.md)               | Lightweight host metrics + rich SystemInfo for agent heartbeat                                     |

## Container Collectors

| Document                   | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| [DOCKER.md](DOCKER.md)     | Docker Engine API: container CPU, memory, network, disk I/O, PIDs  |
| [CADVISOR.md](CADVISOR.md) | cAdvisor Prometheus scraper: `container_*` and `machine_*` metrics |

## Kernel Collector

| Document           | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| [EBPF.md](EBPF.md) | eBPF: syscalls, TCP/UDP, file I/O, scheduler, memory faults, TCP state, Cilium Hubble |

## Database Monitoring Collectors

| Collector                       | Source                                                                                                        | Description                                                                                                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Amazon Aurora**               | AWS SDK (CloudWatch GetMetricData, RDS DescribeDBClusters/Instances, Performance Insights GetResourceMetrics) | 60+ CloudWatch metrics across storage, replication, cache, latency, transactions, availability; automatic topology discovery; PI-enabled instance collection; multi-cluster with IAM role assumption; push-based export to TFO Platform |
| **MySQL/MariaDB/Percona**       | Direct database connection (Go SQL driver)                                                                    | Global status/variables, InnoDB engine parsing, replication (multi-source), Galera cluster, query analytics (performance_schema), schema metrics, MariaDB-specific (Aria, ColumnStore, Spider, query cache, thread pool, user stats)    |
| **PostgreSQL / RDS PostgreSQL** | Direct database connection (pgx)                                                                              | pg_stat_activity, pg_stat_database, pg_stat_bgwriter, pg_stat_statements, table stats, replication status; RDS variant with TLS and CA bundle support                                                                                   |
| **Microsoft SQL Server**        | Direct database connection (go-mssqldb)                                                                       | Wait stats categorization, performance counters, index usage/fragmentation, tempdb space, agent job status, query store top queries, database file I/O                                                                                  |
| **MongoDB**                     | MongoDB driver                                                                                                | Server status, replica set status, sharding detection, query profiler (system.profile), collection/document stats, connection pool metrics                                                                                              |
| **ClickHouse**                  | HTTP API (JSONEachRow)                                                                                        | System tables (queries, parts, merges, replication_queue, databases, tables), query metrics, merge performance                                                                                                                          |
| **CockroachDB**                 | Direct database connection (pgx)                                                                              | SQL stats (crdb_internal.node_statement_statistics), range stats, store metrics, replication status                                                                                                                                     |
| **TimescaleDB**                 | Direct database connection (pgx)                                                                              | Hypertable stats (dimensions, chunks, compression), chunk age bucketing, continuous aggregate refresh lag, background job health (stuck detection, failures), data node availability                                                    |
| **SQLite3**                     | File-based (database/sql)                                                                                     | Page cache hit/miss, WAL metrics, lock contention, integrity checks, table row counts and page stats                                                                                                                                    |

## Cache, Queueing & Messaging Collectors

| Collector                | Source                        | Description                                                                                                                                   |
| ------------------------ | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Redis**                | RESP (INFO, commandstats)     | Connections, memory, keyspace hits/misses, evictions, per-DB keys, per-command stats; optional TLS                                            |
| **Valkey**               | RESP (INFO, commandstats)     | Same coverage as Redis under `db.valkey.*` — Valkey speaks RESP, so the redis client is reused                                                |
| **Memcached**            | TCP (stats, stats slabs)      | Connections, cmd counts, hit/miss ratios, bytes, items, evictions, per-slab stats                                                             |
| **RabbitMQ**             | Management HTTP API           | Cluster object/queue totals, message flow counters & rates, per-node mem/disk/FD/proc, per-queue messages/consumers/rates; queue_filter regex |
| **Apache Kafka**         | JMX Prometheus exporter       | Broker/topic counters & gauges normalized from the JMX exporter exposition under `queue.kafka.*`; cluster + instance labels                   |
| **Confluent Kafka**      | Confluent Metrics API         | Per-topic received/sent bytes & records, retained bytes, partition count via the Confluent Cloud/Platform metrics query API                   |
| **NATS**                 | HTTP monitoring (/varz, /jsz) | Connections, subscriptions, sent/received msgs & bytes, routes, subscription cache hit rate, JetStream streams/consumers/messages/bytes       |
| **Google Cloud Pub/Sub** | Cloud Monitoring API          | Undelivered/outstanding messages, oldest unacked age, sent/ack counts per subscription; service-account JWT (stdlib RS256, no Google SDK)     |

> **No external client libraries**: cache/queueing/messaging collectors speak their
> native wire protocols or management APIs directly and forward metrics through the
> standard OTLP pipeline.

## Metric Naming Conventions

| Prefix                      | Collector                            |
| --------------------------- | ------------------------------------ |
| `k8s.*`                     | Kubernetes collector                 |
| `node.*`                    | Node Exporter collector              |
| `system.*`                  | System Host collector                |
| `container.*`               | Docker collector                     |
| `container_*` / `machine_*` | cAdvisor (original Prometheus names) |
| `ebpf.*`                    | eBPF collector                       |
| `aurora.*`                  | Amazon Aurora collector              |
| `db.mysql.*`                | MySQL/MariaDB collector              |
| `db.postgresql.*`           | PostgreSQL collector                 |
| `mssql.*`                   | Microsoft SQL Server collector       |
| `db.mongodb.*`              | MongoDB collector                    |
| `db.clickhouse.*`           | ClickHouse collector                 |
| `db.cockroachdb.*`          | CockroachDB collector                |
| `db.timescaledb.*`          | TimescaleDB collector                |
| `db.sqlite3.*`              | SQLite3 collector                    |
| `db.redis.*`                | Redis cache collector                |
| `db.valkey.*`               | Valkey cache collector               |
| `db.memcache.*`             | Memcached cache collector            |
| `queue.rabbitmq.*`          | RabbitMQ collector                   |
| `queue.kafka.*`             | Apache Kafka collector               |
| `queue.confluent_kafka.*`   | Confluent Kafka collector            |
| `messaging.nats.*`          | NATS collector                       |
| `messaging.pubsub.*`        | Google Cloud Pub/Sub collector       |
