// Package aurora implements the Amazon Aurora database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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

package aurora

// MetricDefinition describes a single CloudWatch metric for Aurora.
type MetricDefinition struct {
	// Name is the CloudWatch metric name (e.g. "CPUUtilization").
	Name string
	// Unit is the CloudWatch unit (e.g. "Percent", "Bytes", "Seconds").
	Unit string
	// Description is a human-readable description.
	Description string
}

// MetricGroup holds a named group of related CloudWatch metrics.
type MetricGroup struct {
	Name    string
	Metrics []MetricDefinition
}

// AllMetricGroups returns the complete set of CloudWatch metric groups
// for Amazon Aurora monitoring, organized by category.
func AllMetricGroups() []MetricGroup {
	return []MetricGroup{
		// =====================================================================
		// Storage metrics (namespace: AWS/RDS)
		// =====================================================================
		{
			Name: "storage",
			Metrics: []MetricDefinition{
				{Name: "FreeStorageSpace", Unit: "Bytes", Description: "The amount of available storage space in bytes"},
				{Name: "FreeLocalStorage", Unit: "Bytes", Description: "The amount of local storage available for temporary tables in bytes"},
				{Name: "StorageNetworkReceiveThroughput", Unit: "Bytes/Second", Description: "Network receive throughput for Aurora storage in bytes per second"},
				{Name: "StorageNetworkTransmitThroughput", Unit: "Bytes/Second", Description: "Network transmit throughput for Aurora storage in bytes per second"},
				{Name: "StorageThroughputPercentage", Unit: "Percent", Description: "Provisioned storage throughput usage as a percentage"},
				{Name: "StorageIOPSPercentage", Unit: "Percent", Description: "Provisioned IOPS usage as a percentage"},
			},
		},

		// =====================================================================
		// Replication metrics
		// =====================================================================
		{
			Name: "replication",
			Metrics: []MetricDefinition{
				{Name: "AuroraReplicaLag", Unit: "Milliseconds", Description: "Lag between the primary and Aurora replica in milliseconds"},
				{Name: "AuroraReplicaLagMaximum", Unit: "Milliseconds", Description: "Maximum replica lag across all replicas in milliseconds"},
				{Name: "AuroraReplicaLagMinimum", Unit: "Milliseconds", Description: "Minimum replica lag across all replicas in milliseconds"},
				{Name: "OldestReplicationSlotLag", Unit: "Megabytes", Description: "Lag of the oldest replication slot in megabytes (PostgreSQL)"},
				{Name: "ReplicationSlotDiskUsage", Unit: "Megabytes", Description: "Disk space used by replication slots in megabytes"},
				{Name: "BinaryLogReplicationSlotLag", Unit: "Count", Description: "Binlog replica lag (MySQL)"},
				{Name: "BinLogDiskUsage", Unit: "Bytes", Description: "Disk space used by binary logs in bytes (MySQL)"},
			},
		},

		// =====================================================================
		// Cache metrics
		// =====================================================================
		{
			Name: "cache",
			Metrics: []MetricDefinition{
				{Name: "BufferCacheHitRatio", Unit: "Percent", Description: "Buffer cache hit ratio as a percentage"},
				{Name: "ResultSetCacheHitRatio", Unit: "Percent", Description: "Result set cache hit ratio as a percentage (Aurora MySQL)"},
				{Name: "AuroraMemoryEngineHitRatio", Unit: "Percent", Description: "Aurora memory engine hit ratio as a percentage"},
				{Name: "AuroraMemoryEngineRequestCount", Unit: "Count", Description: "Total number of Aurora memory engine requests"},
			},
		},

		// =====================================================================
		// Latency metrics
		// =====================================================================
		{
			Name: "latency",
			Metrics: []MetricDefinition{
				{Name: "ReadLatency", Unit: "Seconds", Description: "Average read latency in seconds"},
				{Name: "WriteLatency", Unit: "Seconds", Description: "Average write latency in seconds"},
				{Name: "CommitLatency", Unit: "Seconds", Description: "Average commit latency in seconds"},
				{Name: "AuroraSlowQueryCountPerSec", Unit: "Count/Second", Description: "Number of slow queries per second (MySQL)"},
				{Name: "AuroraSlowQueryLatencyP99", Unit: "Milliseconds", Description: "P99 latency for slow queries in milliseconds"},
				{Name: "NetworkTransmitThroughput", Unit: "Bytes/Second", Description: "Network transmit throughput in bytes per second"},
				{Name: "NetworkReceiveThroughput", Unit: "Bytes/Second", Description: "Network receive throughput in bytes per second"},
			},
		},

		// =====================================================================
		// Transaction and throughput metrics
		// =====================================================================
		{
			Name: "transactions",
			Metrics: []MetricDefinition{
				{Name: "ActiveTransactions", Unit: "Count", Description: "Number of currently active transactions"},
				{Name: "BlockedTransactions", Unit: "Count", Description: "Number of currently blocked transactions"},
				{Name: "TransactionsPerSec", Unit: "Count/Second", Description: "Number of transactions per second"},
				{Name: "CommitThroughput", Unit: "Count/Second", Description: "Number of commits per second"},
				{Name: "RollbackSegmentWait", Unit: "Count", Description: "Number of rollback segment waits (MySQL)"},
				{Name: "SelectThroughput", Unit: "Count/Second", Description: "Number of SELECT queries per second"},
				{Name: "InsertThroughput", Unit: "Count/Second", Description: "Number of INSERT queries per second"},
				{Name: "UpdateThroughput", Unit: "Count/Second", Description: "Number of UPDATE queries per second"},
				{Name: "DeleteThroughput", Unit: "Count/Second", Description: "Number of DELETE queries per second"},
				{Name: "DDLThroughput", Unit: "Count/Second", Description: "Number of DDL operations per second"},
				{Name: "DMLThroughput", Unit: "Count/Second", Description: "Number of DML operations per second"},
			},
		},

		// =====================================================================
		// Availability and health metrics
		// =====================================================================
		{
			Name: "availability",
			Metrics: []MetricDefinition{
				{Name: "DatabaseConnections", Unit: "Count", Description: "Number of current database connections"},
				{Name: "ConnectionAttempts", Unit: "Count", Description: "Number of connection attempts per second"},
				{Name: "CPUUtilization", Unit: "Percent", Description: "CPU utilization as a percentage"},
				{Name: "FreeableMemory", Unit: "Bytes", Description: "Amount of freeable memory in bytes"},
				{Name: "SwapUsage", Unit: "Bytes", Description: "Amount of swap space used in bytes"},
				{Name: "Uptime", Unit: "Count", Description: "Instance uptime in seconds"},
				{Name: "EngineUptime", Unit: "Seconds", Description: "Database engine uptime in seconds"},
				{Name: "MaxUsedTxIDs", Unit: "Count", Description: "Maximum used transaction IDs (PostgreSQL)"},
				{Name: "LoginFailures", Unit: "Count", Description: "Number of failed login attempts"},
				{Name: "Deadlocks", Unit: "Count", Description: "Number of deadlocks per second"},
				{Name: "ClusterMemoryLimitReached", Unit: "Count", Description: "Indicates if cluster memory limit was reached"},
				{Name: "ClusterReplicaLagExceeded", Unit: "Count", Description: "Indicates if replica lag exceeded threshold"},
			},
		},

		// =====================================================================
		// Backtrack metrics (Aurora MySQL)
		// =====================================================================
		{
			Name: "backtrack",
			Metrics: []MetricDefinition{
				{Name: "BacktrackWindowActual", Unit: "Seconds", Description: "Actual backtrack window in seconds"},
				{Name: "BacktrackWindowAlert", Unit: "Count", Description: "Backtrack window alert count"},
				{Name: "BacktrackChangeRecordsCreation", Unit: "Count", Description: "Number of backtrack change records created"},
				{Name: "BacktrackChangeRecordsStored", Unit: "Count", Description: "Number of backtrack change records stored"},
				{Name: "BacktrackUsage", Unit: "Count", Description: "Number of backtrack operations"},
			},
		},

		// =====================================================================
		// Serverless metrics (Aurora Serverless v1/v2)
		// =====================================================================
		{
			Name: "serverless",
			Metrics: []MetricDefinition{
				{Name: "ServerlessDatabaseCapacity", Unit: "Count", Description: "Aurora Serverless capacity units (ACU)"},
				{Name: "Capacity", Unit: "Count", Description: "Current Aurora Serverless v2 capacity"},
				{Name: "ACUUtilization", Unit: "Percent", Description: "Aurora Capacity Unit utilization percentage"},
			},
		},

		// =====================================================================
		// Global database metrics (Aurora Global Database)
		// =====================================================================
		{
			Name: "global",
			Metrics: []MetricDefinition{
				{Name: "AuroraGlobalDBReplicationLag", Unit: "Milliseconds", Description: "Replication lag from primary to secondary region"},
				{Name: "AuroraGlobalDBDataTransferBytes", Unit: "Bytes", Description: "Bytes transferred between global database regions"},
				{Name: "AuroraGlobalDBReplicatedWriteIOs", Unit: "Count", Description: "Number of write IOs replicated to secondary regions"},
				{Name: "AuroraGlobalDBLag", Unit: "Seconds", Description: "Lag between primary and secondary global cluster"},
			},
		},

		// =====================================================================
		// Instance-level metrics
		// =====================================================================
		{
			Name: "instance",
			Metrics: []MetricDefinition{
				{Name: "DiskQueueDepth", Unit: "Count", Description: "Number of IO requests waiting in the disk queue"},
				{Name: "ReadIOPS", Unit: "Count/Second", Description: "Number of read I/O operations per second"},
				{Name: "WriteIOPS", Unit: "Count/Second", Description: "Number of write I/O operations per second"},
				{Name: "ReadThroughput", Unit: "Bytes/Second", Description: "Read throughput in bytes per second"},
				{Name: "WriteThroughput", Unit: "Bytes/Second", Description: "Write throughput in bytes per second"},
				{Name: "IOThroughputPercentage", Unit: "Percent", Description: "IO throughput as a percentage of provisioned limit"},
				{Name: "IOPSPercentage", Unit: "Percent", Description: "IOPS as a percentage of provisioned limit"},
				{Name: "TempStorageIOPS", Unit: "Count/Second", Description: "Temporary storage IOPS"},
				{Name: "TempStorageThroughput", Unit: "Bytes/Second", Description: "Temporary storage throughput"},
			},
		},

		// =====================================================================
		// Volume metrics (Aurora Storage)
		// =====================================================================
		{
			Name: "volume",
			Metrics: []MetricDefinition{
				{Name: "VolumeBytesUsed", Unit: "Bytes", Description: "Total storage volume used in bytes"},
				{Name: "VolumeReadIOPs", Unit: "Count/Second", Description: "Volume read IOPS"},
				{Name: "VolumeWriteIOPs", Unit: "Count/Second", Description: "Volume write IOPS"},
			},
		},
	}
}

// AllCloudWatchMetricNames returns a flat list of all CloudWatch metric names.
func AllCloudWatchMetricNames() []string {
	var names []string
	for _, group := range AllMetricGroups() {
		for _, m := range group.Metrics {
			names = append(names, m.Name)
		}
	}
	return names
}

// MetricDescription returns the description for a given CloudWatch metric name.
// Returns empty string if not found.
func MetricDescription(name string) string {
	for _, group := range AllMetricGroups() {
		for _, m := range group.Metrics {
			if m.Name == name {
				return m.Description
			}
		}
	}
	return ""
}

// MetricUnit returns the CloudWatch unit for a given metric name.
// Returns empty string if not found.
func MetricUnit(name string) string {
	for _, group := range AllMetricGroups() {
		for _, m := range group.Metrics {
			if m.Name == name {
				return m.Unit
			}
		}
	}
	return ""
}

// PerformanceInsightsMetricGroups returns the PI metric group definitions
// for Performance Insights data collection.
func PerformanceInsightsMetricGroups() []MetricGroup {
	return []MetricGroup{
		{
			Name: "db_load",
			Metrics: []MetricDefinition{
				{Name: "db.load.avg", Unit: "Count", Description: "Average database load (active sessions)"},
				{Name: "db.load.sample", Unit: "Count", Description: "Sampled database load"},
			},
		},
		{
			Name: "db_sql",
			Metrics: []MetricDefinition{
				{Name: "db.sql.avg_latency", Unit: "Milliseconds", Description: "Average latency per SQL digest"},
				{Name: "db.sql.avg_latency_per_call", Unit: "Milliseconds", Description: "Average latency per SQL call"},
				{Name: "db.sql.executions", Unit: "Count", Description: "Number of SQL executions"},
				{Name: "db.sql.rows_affected", Unit: "Count", Description: "Number of rows affected by SQL"},
				{Name: "db.sql.rows_processed", Unit: "Count", Description: "Number of rows processed by SQL"},
				{Name: "db.sql.rows_returned", Unit: "Count", Description: "Number of rows returned by SQL"},
			},
		},
		{
			Name: "db_sql_tokenized",
			Metrics: []MetricDefinition{
				{Name: "db.sql_tokenized.avg_latency", Unit: "Milliseconds", Description: "Average latency per tokenized SQL digest"},
				{Name: "db.sql_tokenized.executions", Unit: "Count", Description: "Number of tokenized SQL executions"},
				{Name: "db.sql_tokenized.rows_affected", Unit: "Count", Description: "Rows affected by tokenized SQL"},
				{Name: "db.sql_tokenized.rows_processed", Unit: "Count", Description: "Rows processed by tokenized SQL"},
				{Name: "db.sql_tokenized.rows_returned", Unit: "Count", Description: "Rows returned by tokenized SQL"},
			},
		},
		{
			Name: "db_wait_event",
			Metrics: []MetricDefinition{
				{Name: "db.wait_event.avg_latency", Unit: "Milliseconds", Description: "Average wait event latency"},
				{Name: "db.wait_event.count", Unit: "Count", Description: "Wait event count"},
			},
		},
		{
			Name: "os",
			Metrics: []MetricDefinition{
				{Name: "os.cpuUtilization", Unit: "Percent", Description: "OS-level CPU utilization"},
				{Name: "os.freeMemory", Unit: "Bytes", Description: "OS-level free memory"},
				{Name: "os.totalMemory", Unit: "Bytes", Description: "OS-level total memory"},
				{Name: "os.diskQueueDepth", Unit: "Count", Description: "OS-level disk queue depth"},
				{Name: "os.readIOPS", Unit: "Count/Second", Description: "OS-level read IOPS"},
				{Name: "os.writeIOPS", Unit: "Count/Second", Description: "OS-level write IOPS"},
			},
		},
	}
}
