package nodeexporter

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/net"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectNetwork collects per-interface network metrics, TCP states, and ARP entries.
// Equivalent to node_exporter's netdev, netstat, and arp collectors.
func (c *NodeExporterCollector) collectNetwork() ([]collector.Metric, error) {
	var metrics []collector.Metric

	// Per-interface I/O counters
	counters, err := net.IOCounters(true)
	if err != nil {
		return nil, fmt.Errorf("net io counters: %w", err)
	}

	// Interface metadata for MTU and up/down
	interfaces, _ := net.Interfaces()
	ifaceMap := make(map[string]net.InterfaceStat)
	for _, iface := range interfaces {
		ifaceMap[iface.Name] = iface
	}

	for _, s := range counters {
		if c.cfg.shouldExcludeNetworkDevice(s.Name) {
			continue
		}

		lbl := map[string]string{"device": s.Name}

		metrics = append(metrics,
			collector.NewMetric("node.network.receive_bytes_total", float64(s.BytesRecv), collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Total bytes received"),
			collector.NewMetric("node.network.transmit_bytes_total", float64(s.BytesSent), collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Total bytes transmitted"),
			collector.NewMetric("node.network.receive_packets_total", float64(s.PacketsRecv), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total packets received"),
			collector.NewMetric("node.network.transmit_packets_total", float64(s.PacketsSent), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total packets transmitted"),
			collector.NewMetric("node.network.receive_errs_total", float64(s.Errin), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total receive errors"),
			collector.NewMetric("node.network.transmit_errs_total", float64(s.Errout), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total transmit errors"),
			collector.NewMetric("node.network.receive_drop_total", float64(s.Dropin), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total receive drops"),
			collector.NewMetric("node.network.transmit_drop_total", float64(s.Dropout), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total transmit drops"),
		)

		// MTU and up/down
		if iface, ok := ifaceMap[s.Name]; ok {
			metrics = append(metrics,
				collector.NewMetric("node.network.mtu", float64(iface.MTU), collector.MetricTypeGauge).
					WithLabels(lbl).WithDescription("Network device MTU"),
			)
			up := 0.0
			for _, f := range iface.Flags {
				if f == "up" {
					up = 1.0
					break
				}
			}
			metrics = append(metrics,
				collector.NewMetric("node.network.up", up, collector.MetricTypeGauge).
					WithLabels(lbl).WithDescription("Network device is up (1) or down (0)"),
			)
		}
	}

	// TCP connection states
	tcpMetrics, err := c.collectTCPStates()
	if err == nil {
		metrics = append(metrics, tcpMetrics...)
	}

	// ARP entries
	arpMetrics, err := c.collectARP()
	if err == nil {
		metrics = append(metrics, arpMetrics...)
	}

	return metrics, nil
}

// collectTCPStates collects TCP connection state counts.
func (c *NodeExporterCollector) collectTCPStates() ([]collector.Metric, error) {
	conns, err := net.Connections("tcp")
	if err != nil {
		return nil, err
	}

	states := make(map[string]int)
	for _, conn := range conns {
		if conn.Status != "" {
			states[conn.Status]++
		}
	}

	var metrics []collector.Metric
	for state, count := range states {
		metrics = append(metrics, collector.NewMetric(
			"node.tcp.connection_states", float64(count), collector.MetricTypeGauge,
		).WithLabel("state", state).WithDescription("TCP connections by state"))
	}

	return metrics, nil
}

// collectARP collects ARP entry counts per device.
func (c *NodeExporterCollector) collectARP() ([]collector.Metric, error) {
	// gopsutil doesn't provide ARP directly — use /proc/net/arp on Linux
	return collectARPPlatform()
}
