//go:build linux

package nodeexporter

import (
	"os"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectLinux collects Linux-specific metrics: conntrack, PSI, vmstat, sockstat,
// entropy, file descriptors, and stat (context switches, interrupts, forks).
func (c *NodeExporterCollector) collectLinux() []collector.Metric {
	var metrics []collector.Metric

	if c.cfg.raw.Conntrack {
		metrics = append(metrics, c.collectConntrack()...)
	}
	if c.cfg.raw.PSI {
		metrics = append(metrics, c.collectPSI()...)
	}
	if c.cfg.raw.VMStat {
		metrics = append(metrics, c.collectVMStat()...)
	}
	if c.cfg.raw.Sockstat {
		metrics = append(metrics, c.collectSockstat()...)
	}
	if c.cfg.raw.Entropy {
		metrics = append(metrics, c.collectEntropy()...)
	}
	if c.cfg.raw.FileDesc {
		metrics = append(metrics, c.collectFileDesc()...)
	}
	if c.cfg.raw.Stat {
		metrics = append(metrics, c.collectStat()...)
	}

	return metrics
}

// collectConntrack reads nf_conntrack metrics.
func (c *NodeExporterCollector) collectConntrack() []collector.Metric {
	var metrics []collector.Metric

	if v, err := readUint64File("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		metrics = append(metrics, collector.NewMetric(
			"node.conntrack.entries", float64(v), collector.MetricTypeGauge,
		).WithDescription("Number of currently allocated conntrack entries"))
	}

	if v, err := readUint64File("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		metrics = append(metrics, collector.NewMetric(
			"node.conntrack.entries_limit", float64(v), collector.MetricTypeGauge,
		).WithDescription("Maximum number of conntrack entries"))
	}

	return metrics
}

// collectPSI reads Pressure Stall Information from /proc/pressure/*.
func (c *NodeExporterCollector) collectPSI() []collector.Metric {
	var metrics []collector.Metric

	for _, resource := range []string{"cpu", "memory", "io"} {
		data, err := os.ReadFile("/proc/pressure/" + resource)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Format: "some avg10=0.00 avg60=0.00 avg300=0.00 total=123456"
			// or:     "full avg10=0.00 avg60=0.00 avg300=0.00 total=123456"
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			kind := parts[0] // "some" or "full"
			if kind != "some" && kind != "full" {
				continue
			}
			// Extract total=NNNN (microseconds)
			for _, field := range parts[1:] {
				if strings.HasPrefix(field, "total=") {
					totalStr := strings.TrimPrefix(field, "total=")
					total := parseFloat64(totalStr)
					// Convert microseconds to seconds
					metrics = append(metrics, collector.NewMetric(
						"node.pressure."+kind+".seconds_total",
						total/1e6,
						collector.MetricTypeCounter,
					).WithLabel("resource", resource).
						WithUnit("seconds").
						WithDescription("PSI "+kind+" pressure total"))
				}
			}
		}
	}

	return metrics
}

// collectVMStat reads selected metrics from /proc/vmstat.
func (c *NodeExporterCollector) collectVMStat() []collector.Metric {
	data, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return nil
	}

	wanted := map[string]string{
		"pgpgin":     "node.vmstat.pgpgin",
		"pgpgout":    "node.vmstat.pgpgout",
		"pswpin":     "node.vmstat.pswpin",
		"pswpout":    "node.vmstat.pswpout",
		"pgfault":    "node.vmstat.pgfault",
		"pgmajfault": "node.vmstat.pgmajfault",
		"oom_kill":   "node.vmstat.oom_kill",
	}

	var metrics []collector.Metric
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		if metricName, ok := wanted[parts[0]]; ok {
			metrics = append(metrics, collector.NewMetric(
				metricName, parseFloat64(parts[1]), collector.MetricTypeCounter,
			).WithDescription("/proc/vmstat "+parts[0]))
		}
	}

	return metrics
}

// collectSockstat reads socket statistics from /proc/net/sockstat.
func (c *NodeExporterCollector) collectSockstat() []collector.Metric {
	data, err := os.ReadFile("/proc/net/sockstat")
	if err != nil {
		return nil
	}

	var metrics []collector.Metric
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch {
		case fields[0] == "sockets:":
			// "sockets: used 123"
			if fields[1] == "used" {
				metrics = append(metrics, collector.NewMetric(
					"node.sockstat.sockets_used", parseFloat64(fields[2]), collector.MetricTypeGauge,
				).WithDescription("Total sockets in use"))
			}
		case fields[0] == "TCP:":
			// "TCP: inuse 5 orphan 0 tw 3 alloc 7 mem 2"
			for i := 1; i+1 < len(fields); i += 2 {
				switch fields[i] {
				case "inuse":
					metrics = append(metrics, collector.NewMetric(
						"node.sockstat.tcp_inuse", parseFloat64(fields[i+1]), collector.MetricTypeGauge,
					).WithDescription("TCP sockets in use"))
				case "tw":
					metrics = append(metrics, collector.NewMetric(
						"node.sockstat.tcp_tw", parseFloat64(fields[i+1]), collector.MetricTypeGauge,
					).WithDescription("TCP sockets in TIME_WAIT"))
				}
			}
		case fields[0] == "UDP:":
			for i := 1; i+1 < len(fields); i += 2 {
				if fields[i] == "inuse" {
					metrics = append(metrics, collector.NewMetric(
						"node.sockstat.udp_inuse", parseFloat64(fields[i+1]), collector.MetricTypeGauge,
					).WithDescription("UDP sockets in use"))
				}
			}
		}
	}

	return metrics
}

// collectEntropy reads entropy metrics.
func (c *NodeExporterCollector) collectEntropy() []collector.Metric {
	var metrics []collector.Metric

	if v, err := readUint64File("/proc/sys/kernel/random/entropy_avail"); err == nil {
		metrics = append(metrics, collector.NewMetric(
			"node.entropy.available_bits", float64(v), collector.MetricTypeGauge,
		).WithDescription("Available entropy bits"))
	}

	if v, err := readUint64File("/proc/sys/kernel/random/poolsize"); err == nil {
		metrics = append(metrics, collector.NewMetric(
			"node.entropy.pool_size_bits", float64(v), collector.MetricTypeGauge,
		).WithDescription("Entropy pool size in bits"))
	}

	return metrics
}

// collectFileDesc reads file descriptor metrics.
func (c *NodeExporterCollector) collectFileDesc() []collector.Metric {
	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return nil
	}

	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) < 3 {
		return nil
	}

	return []collector.Metric{
		collector.NewMetric("node.filefd.allocated", parseFloat64(parts[0]), collector.MetricTypeGauge).
			WithDescription("Allocated file descriptors"),
		collector.NewMetric("node.filefd.maximum", parseFloat64(parts[2]), collector.MetricTypeGauge).
			WithDescription("Maximum file descriptors"),
	}
}

// collectStat reads context switches, interrupts, forks, and process states from /proc/stat.
func (c *NodeExporterCollector) collectStat() []collector.Metric {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}

	var metrics []collector.Metric
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "ctxt":
			metrics = append(metrics, collector.NewMetric(
				"node.context_switches_total", parseFloat64(parts[1]), collector.MetricTypeCounter,
			).WithDescription("Total context switches"))
		case "intr":
			metrics = append(metrics, collector.NewMetric(
				"node.interrupts_total", parseFloat64(parts[1]), collector.MetricTypeCounter,
			).WithDescription("Total interrupts serviced"))
		case "softirq":
			metrics = append(metrics, collector.NewMetric(
				"node.softirq_total", parseFloat64(parts[1]), collector.MetricTypeCounter,
			).WithDescription("Total soft interrupts"))
		case "processes":
			metrics = append(metrics, collector.NewMetric(
				"node.forks_total", parseFloat64(parts[1]), collector.MetricTypeCounter,
			).WithDescription("Total forks"))
		case "procs_running":
			metrics = append(metrics, collector.NewMetric(
				"node.procs_running", parseFloat64(parts[1]), collector.MetricTypeGauge,
			).WithDescription("Processes in running state"))
		case "procs_blocked":
			metrics = append(metrics, collector.NewMetric(
				"node.procs_blocked", parseFloat64(parts[1]), collector.MetricTypeGauge,
			).WithDescription("Processes blocked on I/O"))
		}
	}

	return metrics
}

// collectARPPlatform reads ARP entries from /proc/net/arp (Linux).
func collectARPPlatform() ([]collector.Metric, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, nil
	}

	// Count ARP entries per device
	deviceCounts := make(map[string]int)
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			deviceCounts[fields[5]]++
		}
	}

	var metrics []collector.Metric
	for device, count := range deviceCounts {
		metrics = append(metrics, collector.NewMetric(
			"node.arp.entries", float64(count), collector.MetricTypeGauge,
		).WithLabel("device", device).WithDescription("ARP entries by device"))
	}

	return metrics, nil
}

// readUint64File reads a single uint64 from a /proc or /sys file.
func readUint64File(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parseUint64(strings.TrimSpace(string(data))), nil
}

// parseUint64 safely parses a string to uint64.
func parseUint64(s string) uint64 {
	var v uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + uint64(c-'0')
		}
	}
	return v
}

// parseFloat64 safely parses a string to float64.
func parseFloat64(s string) float64 {
	return float64(parseUint64(s))
}
