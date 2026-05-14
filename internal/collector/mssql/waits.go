package mssql

import (
	"context"
	"database/sql"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

var benignWaits = map[string]bool{
	"REQUEST_FOR_DEADLOCK_SEARCH":                    true,
	"SQLTRACE_INCREMENTAL_FLUSH_SLEEP":               true,
	"SQLTRACE_BUFFER_FLUSH":                          true,
	"LAZYWRITER_SLEEP":                               true,
	"XE_TIMER_EVENT":                                 true,
	"XE_DISPATCHER_WAIT":                             true,
	"FT_IFTS_SCHEDULER_IDLE_WAIT":                    true,
	"LOGMGR_QUEUE":                                   true,
	"CHECKPOINT_QUEUE":                               true,
	"ONDEMAND_TASK_QUEUE":                            true,
	"DBMIRRORING_CMD":                                true,
	"DBMIRROR_DBM_EVENT":                             true,
	"DBMIRROR_DBM_MUTEX":                             true,
	"DBMIRROR_EVENTS_QUEUE":                          true,
	"DBMIRROR_WORKER_QUEUE":                          true,
	"BROKER_EVENTHANDLER":                            true,
	"BROKER_RECEIVE_WAITFOR":                         true,
	"BROKER_TASK_STOP":                               true,
	"BROKER_TO_FLUSH":                                true,
	"BROKER_TRANSMITTER":                             true,
	"CLR_AUTO_EVENT":                                 true,
	"CLR_MANUAL_EVENT":                               true,
	"DISPATCHER_QUEUE_SEMAPHORE":                     true,
	"DIRTY_PAGE_POLL":                                true,
	"HADR_FILESTREAM_IOMGR_IOCOMPLETION":             true,
	"KSOURCE_WAKE":                                   true,
	"PWAIT_ALL_COMPONENTS_INITIALIZED":               true,
	"QDS_PERSIST_TASK_MAIN_LOOP_SLEEP":               true,
	"QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP": true,
	"QDS_SHUTDOWN_QUEUE":                             true,
	"SLEEP_SYSTEMTASK":                               true,
	"SLEEP_TASK":                                     true,
	"SP_SERVER_DIAGNOSTICS_SLEEP":                    true,
	"SQLTRACE_WAIT_FOR_FILES":                        true,
	"UCS_SESSION_REGISTRATION":                       true,
	"WAIT_FOR_RESULTS":                               true,
	"WAIT_XTP_OFFLINE_CKPT_NEW_LOG":                  true,
	"WAIT_XTP_CKPT_CLOSE":                            true,
	"WAIT_XTP_RECOVERY":                              true,
	"TRACEWRITE":                                     true,
}

var waitCategoryMap = map[string]string{
	"LCK_M_%":               "Lock",
	"PAGELATCH_%":           "Latches",
	"PAGEIOLATCH_%":         "Buffer I/O",
	"IO_COMPLETION":         "Buffer I/O",
	"ASYNC_NETWORK_IO":      "Network I/O",
	"CXPACKET":              "Parallelism",
	"CXCONSUMER":            "Parallelism",
	"SOS_SCHEDULER_YIELD":   "CPU",
	"CMEMTHREAD":            "Memory",
	"RESOURCE_SEMAPHORE":    "Memory",
	"MEMORY_ALLOCATION_EXT": "Memory",
	"WRITELOG":              "Transaction Log",
	"LOGBUFFER":             "Transaction Log",
	"LOGMGR":                "Transaction Log",
	"BACKUPIO":              "Backup I/O",
	"BACKUPBUFFER":          "Backup I/O",
	"ASYNC_IO_COMPLETION":   "I/O",
	"FCB_REPLICA_WRITE":     "I/O",
	"FCB_REPLICA_READ":      "I/O",
}

func categorizeWait(waitType string) string {
	if cat, ok := waitCategoryMap[waitType]; ok {
		return cat
	}
	for pattern, cat := range waitCategoryMap {
		if len(pattern) > 0 && pattern[len(pattern)-1] == '%' {
			prefix := pattern[:len(pattern)-1]
			if len(waitType) >= len(prefix) && waitType[:len(prefix)] == prefix {
				return cat
			}
		}
	}
	return "Other"
}

func collectWaitStats(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			wait_type,
			waiting_tasks_count,
			wait_time_ms,
			signal_wait_time_ms,
			max_wait_time_ms
		FROM sys.dm_os_wait_stats
		WHERE waiting_tasks_count > 0
		ORDER BY wait_time_ms DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var waitType string
		var waitingTasks, waitTimeMs, signalWaitMs, maxWaitMs float64
		if err := rows.Scan(&waitType, &waitingTasks, &waitTimeMs, &signalWaitMs, &maxWaitMs); err != nil {
			continue
		}
		if benignWaits[waitType] {
			continue
		}
		cat := categorizeWait(waitType)
		waitLabels := copyLabels(labels)
		waitLabels["mssql_wait_type"] = waitType
		waitLabels["mssql_wait_category"] = cat

		all = append(all,
			makeMetric("mssql.wait.waiting_tasks_count", waitingTasks, collector.MetricTypeGauge, waitLabels),
			makeMetric("mssql.wait.wait_time_ms", waitTimeMs, collector.MetricTypeGauge, waitLabels),
			makeMetric("mssql.wait.signal_wait_time_ms", signalWaitMs, collector.MetricTypeGauge, waitLabels),
			makeMetric("mssql.wait.max_wait_time_ms", maxWaitMs, collector.MetricTypeGauge, waitLabels),
		)
	}
	return all, rows.Err()
}
