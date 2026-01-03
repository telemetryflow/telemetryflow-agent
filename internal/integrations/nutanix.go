// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// NutanixConfig contains Nutanix Prism integration configuration
type NutanixConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	PrismCentralURL   string            `mapstructure:"prism_central_url"`
	PrismElementURL   string            `mapstructure:"prism_element_url"`
	Username          string            `mapstructure:"username"`
	Password          string            `mapstructure:"password"`
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	ScrapeInterval    time.Duration     `mapstructure:"scrape_interval"`
	CollectVMs        bool              `mapstructure:"collect_vms"`
	CollectHosts      bool              `mapstructure:"collect_hosts"`
	CollectClusters   bool              `mapstructure:"collect_clusters"`
	CollectStorage    bool              `mapstructure:"collect_storage"`
	CollectContainers bool              `mapstructure:"collect_containers"`
	CollectNetworks   bool              `mapstructure:"collect_networks"`
	CollectAlerts     bool              `mapstructure:"collect_alerts"`
	APIVersion        string            `mapstructure:"api_version"`
	Headers           map[string]string `mapstructure:"headers"`
	Labels            map[string]string `mapstructure:"labels"`
}

// NutanixExporter exports telemetry data from Nutanix infrastructure
type NutanixExporter struct {
	*BaseExporter
	config     NutanixConfig
	httpClient *http.Client
}

// Nutanix API structures
type nutanixVM struct {
	UUID              string   `json:"uuid"`
	Name              string   `json:"name"`
	PowerState        string   `json:"power_state"`
	NumVCPUs          int      `json:"num_vcpus"`
	MemoryMB          int64    `json:"memory_mb"`
	DiskCapacityBytes int64    `json:"disk_capacity_bytes"`
	HostUUID          string   `json:"host_uuid"`
	ClusterUUID       string   `json:"cluster_uuid"`
	HypervisorType    string   `json:"hypervisor_type"`
	IPAddresses       []string `json:"ip_addresses"`
}

type nutanixVMStats struct {
	CPUUsagePPM          int64 `json:"hypervisor_cpu_usage_ppm"`
	MemoryUsagePPM       int64 `json:"hypervisor_memory_usage_ppm"`
	IOBandwidthKBps      int64 `json:"controller_io_bandwidth_kbps"`
	NumIOPs              int64 `json:"controller_num_iops"`
	AvgIOLatencyUsecs    int64 `json:"controller_avg_io_latency_usecs"`
	ReadIOBandwidthKBps  int64 `json:"controller_read_io_bandwidth_kbps"`
	WriteIOBandwidthKBps int64 `json:"controller_write_io_bandwidth_kbps"`
}

type nutanixHost struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	ClusterUUID      string `json:"cluster_uuid"`
	HypervisorType   string `json:"hypervisor_type"`
	NumCPUs          int    `json:"num_cpu_cores"`
	NumSockets       int    `json:"num_cpu_sockets"`
	CPUFrequencyHz   int64  `json:"cpu_frequency_hz"`
	MemoryCapacityMB int64  `json:"memory_capacity_in_bytes"`
	State            string `json:"state"`
	IPMIAddress      string `json:"ipmi_address"`
	HypervisorIP     string `json:"hypervisor_address"`
	CVMAddress       string `json:"controller_vm_backplane_address"`
}

type nutanixHostStats struct {
	CPUUsagePPM         int64 `json:"hypervisor_cpu_usage_ppm"`
	MemoryUsagePPM      int64 `json:"hypervisor_memory_usage_ppm"`
	NumVMs              int   `json:"num_vms"`
	IOBandwidthKBps     int64 `json:"controller_io_bandwidth_kbps"`
	NumIOPs             int64 `json:"controller_num_iops"`
	AvgIOLatencyUsecs   int64 `json:"controller_avg_io_latency_usecs"`
	ContentCacheHitsPPM int64 `json:"content_cache_hit_ppm"`
}

type nutanixCluster struct {
	UUID                 string   `json:"uuid"`
	Name                 string   `json:"name"`
	ClusterExternalIP    string   `json:"cluster_external_ip_address"`
	NumNodes             int      `json:"num_nodes"`
	Version              string   `json:"version"`
	HypervisorTypes      []string `json:"hypervisor_types"`
	IsAvailable          bool     `json:"is_available"`
	EncryptionStatus     string   `json:"encryption_status"`
	StorageCapacityBytes int64    `json:"storage_capacity_bytes"`
	StorageUsageBytes    int64    `json:"storage_usage_bytes"`
}

type nutanixClusterStats struct {
	CPUCapacityHz        int64 `json:"cpu_capacity_hz"`
	CPUUsagePPM          int64 `json:"hypervisor_cpu_usage_ppm"`
	MemoryCapacityBytes  int64 `json:"memory_capacity_bytes"`
	MemoryUsagePPM       int64 `json:"hypervisor_memory_usage_ppm"`
	StorageCapacityBytes int64 `json:"storage_capacity_bytes"`
	StorageUsageBytes    int64 `json:"storage_usage_bytes"`
	IOBandwidthKBps      int64 `json:"controller_io_bandwidth_kbps"`
	NumIOPs              int64 `json:"controller_num_iops"`
	AvgIOLatencyUsecs    int64 `json:"controller_avg_io_latency_usecs"`
	NumVMs               int   `json:"num_vms"`
}

type nutanixStorageContainer struct {
	UUID               string `json:"uuid"`
	Name               string `json:"name"`
	ClusterUUID        string `json:"cluster_uuid"`
	StoragePoolUUID    string `json:"storage_pool_uuid"`
	ReplicationFactor  int    `json:"replication_factor"`
	CompressionEnabled bool   `json:"compression_enabled"`
	MaxCapacityBytes   int64  `json:"max_capacity_bytes"`
	UsageBytes         int64  `json:"usage_bytes"`
}

type nutanixAlert struct {
	UUID             string `json:"uuid"`
	AlertTitle       string `json:"alert_title"`
	Severity         string `json:"severity"`
	CreatedTimeUsecs int64  `json:"created_time_stamp_in_usecs"`
	Resolved         bool   `json:"resolved"`
	EntityType       string `json:"entity_type"`
	EntityUUID       string `json:"entity_uuid"`
}

// NewNutanixExporter creates a new Nutanix exporter
func NewNutanixExporter(config NutanixConfig, logger *zap.Logger) *NutanixExporter {
	return &NutanixExporter{
		BaseExporter: NewBaseExporter(
			"nutanix",
			"infrastructure",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Nutanix exporter
func (n *NutanixExporter) Init(ctx context.Context) error {
	if !n.config.Enabled {
		return nil
	}

	if err := n.Validate(); err != nil {
		return err
	}

	// Set defaults
	if n.config.APIVersion == "" {
		n.config.APIVersion = "v2.0"
	}
	if n.config.Timeout == 0 {
		n.config.Timeout = 30 * time.Second
	}
	if n.config.ScrapeInterval == 0 {
		n.config.ScrapeInterval = 60 * time.Second
	}
	if !n.config.CollectVMs && !n.config.CollectHosts && !n.config.CollectClusters && !n.config.CollectStorage {
		n.config.CollectVMs = true
		n.config.CollectHosts = true
		n.config.CollectClusters = true
		n.config.CollectStorage = true
		n.config.CollectAlerts = true
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	if n.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Nutanix Prism deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	n.httpClient = &http.Client{
		Transport: transport,
		Timeout:   n.config.Timeout,
	}

	n.SetInitialized(true)
	n.Logger().Info("Nutanix exporter initialized",
		zap.String("prismCentralUrl", n.config.PrismCentralURL),
		zap.String("apiVersion", n.config.APIVersion),
	)

	return nil
}

// Validate validates the Nutanix configuration
func (n *NutanixExporter) Validate() error {
	if !n.config.Enabled {
		return nil
	}

	if n.config.PrismCentralURL == "" && n.config.PrismElementURL == "" {
		return NewValidationError("nutanix", "url", "prism_central_url or prism_element_url is required")
	}

	if n.config.Username == "" {
		return NewValidationError("nutanix", "username", "username is required")
	}

	if n.config.Password == "" {
		return NewValidationError("nutanix", "password", "password is required")
	}

	return nil
}

// Export exports telemetry data from Nutanix
func (n *NutanixExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	metrics, err := n.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for Nutanix (it's a data source)
func (n *NutanixExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("nutanix is a data source, not a metrics destination")
}

// ExportTraces is not supported by Nutanix
func (n *NutanixExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("nutanix does not support traces")
}

// ExportLogs is not supported by Nutanix
func (n *NutanixExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("nutanix does not support log ingestion")
}

// CollectMetrics collects metrics from Nutanix infrastructure
func (n *NutanixExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !n.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !n.IsInitialized() {
		return nil, ErrNotInitialized
	}

	var metrics []Metric
	now := time.Now()

	// Collect cluster metrics
	if n.config.CollectClusters {
		clusterMetrics, err := n.collectClusterMetrics(ctx, now)
		if err != nil {
			n.Logger().Warn("Failed to collect cluster metrics", zap.Error(err))
		} else {
			metrics = append(metrics, clusterMetrics...)
		}
	}

	// Collect host metrics
	if n.config.CollectHosts {
		hostMetrics, err := n.collectHostMetrics(ctx, now)
		if err != nil {
			n.Logger().Warn("Failed to collect host metrics", zap.Error(err))
		} else {
			metrics = append(metrics, hostMetrics...)
		}
	}

	// Collect VM metrics
	if n.config.CollectVMs {
		vmMetrics, err := n.collectVMMetrics(ctx, now)
		if err != nil {
			n.Logger().Warn("Failed to collect VM metrics", zap.Error(err))
		} else {
			metrics = append(metrics, vmMetrics...)
		}
	}

	// Collect storage metrics
	if n.config.CollectStorage {
		storageMetrics, err := n.collectStorageMetrics(ctx, now)
		if err != nil {
			n.Logger().Warn("Failed to collect storage metrics", zap.Error(err))
		} else {
			metrics = append(metrics, storageMetrics...)
		}
	}

	// Collect alert metrics
	if n.config.CollectAlerts {
		alertMetrics, err := n.collectAlertMetrics(ctx, now)
		if err != nil {
			n.Logger().Warn("Failed to collect alert metrics", zap.Error(err))
		} else {
			metrics = append(metrics, alertMetrics...)
		}
	}

	return metrics, nil
}

// collectClusterMetrics collects metrics from Nutanix clusters
func (n *NutanixExporter) collectClusterMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := n.apiRequest(ctx, "GET", "/clusters", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entities []nutanixCluster `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, cluster := range resp.Entities {
		tags := map[string]string{
			"cluster_uuid": cluster.UUID,
			"cluster_name": cluster.Name,
			"version":      cluster.Version,
		}
		for k, v := range n.config.Labels {
			tags[k] = v
		}

		available := 0.0
		if cluster.IsAvailable {
			available = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "nutanix_cluster_available", Value: available, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_cluster_nodes", Value: float64(cluster.NumNodes), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_cluster_storage_capacity_bytes", Value: float64(cluster.StorageCapacityBytes), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "nutanix_cluster_storage_usage_bytes", Value: float64(cluster.StorageUsageBytes), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
		)

		// Get cluster stats
		statsBody, err := n.apiRequest(ctx, "GET", fmt.Sprintf("/clusters/%s/stats", cluster.UUID), nil)
		if err != nil {
			continue
		}

		var stats nutanixClusterStats
		if err := json.Unmarshal(statsBody, &stats); err != nil {
			continue
		}

		cpuUsagePercent := float64(stats.CPUUsagePPM) / 10000.0
		memUsagePercent := float64(stats.MemoryUsagePPM) / 10000.0
		avgLatencyMs := float64(stats.AvgIOLatencyUsecs) / 1000.0

		metrics = append(metrics,
			Metric{Name: "nutanix_cluster_cpu_usage_percent", Value: cpuUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_cluster_memory_usage_percent", Value: memUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_cluster_io_bandwidth_kbps", Value: float64(stats.IOBandwidthKBps), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
			Metric{Name: "nutanix_cluster_iops", Value: float64(stats.NumIOPs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_cluster_io_latency_ms", Value: avgLatencyMs, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "milliseconds"},
			Metric{Name: "nutanix_cluster_vms", Value: float64(stats.NumVMs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectHostMetrics collects metrics from Nutanix hosts
func (n *NutanixExporter) collectHostMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := n.apiRequest(ctx, "GET", "/hosts", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entities []nutanixHost `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, host := range resp.Entities {
		tags := map[string]string{
			"host_uuid":       host.UUID,
			"host_name":       host.Name,
			"cluster_uuid":    host.ClusterUUID,
			"hypervisor_type": host.HypervisorType,
			"state":           host.State,
		}
		for k, v := range n.config.Labels {
			tags[k] = v
		}

		healthy := 0.0
		if host.State == "NORMAL" {
			healthy = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "nutanix_host_healthy", Value: healthy, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_cpu_cores", Value: float64(host.NumCPUs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_cpu_sockets", Value: float64(host.NumSockets), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_memory_capacity_bytes", Value: float64(host.MemoryCapacityMB), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
		)

		// Get host stats
		statsBody, err := n.apiRequest(ctx, "GET", fmt.Sprintf("/hosts/%s/stats", host.UUID), nil)
		if err != nil {
			continue
		}

		var stats nutanixHostStats
		if err := json.Unmarshal(statsBody, &stats); err != nil {
			continue
		}

		cpuUsagePercent := float64(stats.CPUUsagePPM) / 10000.0
		memUsagePercent := float64(stats.MemoryUsagePPM) / 10000.0
		cacheHitPercent := float64(stats.ContentCacheHitsPPM) / 10000.0
		avgLatencyMs := float64(stats.AvgIOLatencyUsecs) / 1000.0

		metrics = append(metrics,
			Metric{Name: "nutanix_host_cpu_usage_percent", Value: cpuUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_memory_usage_percent", Value: memUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_vms", Value: float64(stats.NumVMs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_io_bandwidth_kbps", Value: float64(stats.IOBandwidthKBps), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
			Metric{Name: "nutanix_host_iops", Value: float64(stats.NumIOPs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_host_io_latency_ms", Value: avgLatencyMs, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "milliseconds"},
			Metric{Name: "nutanix_host_cache_hit_percent", Value: cacheHitPercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectVMMetrics collects metrics from Nutanix VMs
func (n *NutanixExporter) collectVMMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := n.apiRequest(ctx, "GET", "/vms", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entities []nutanixVM `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, vm := range resp.Entities {
		tags := map[string]string{
			"vm_uuid":         vm.UUID,
			"vm_name":         vm.Name,
			"power_state":     vm.PowerState,
			"hypervisor_type": vm.HypervisorType,
			"host_uuid":       vm.HostUUID,
			"cluster_uuid":    vm.ClusterUUID,
		}
		for k, v := range n.config.Labels {
			tags[k] = v
		}

		poweredOn := 0.0
		if vm.PowerState == "on" {
			poweredOn = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "nutanix_vm_power_state", Value: poweredOn, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_vm_vcpus", Value: float64(vm.NumVCPUs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_vm_memory_mb", Value: float64(vm.MemoryMB), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "megabytes"},
			Metric{Name: "nutanix_vm_disk_capacity_bytes", Value: float64(vm.DiskCapacityBytes), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
		)

		// Get VM stats if powered on
		if vm.PowerState == "on" {
			statsBody, err := n.apiRequest(ctx, "GET", fmt.Sprintf("/vms/%s/stats", vm.UUID), nil)
			if err != nil {
				continue
			}

			var stats nutanixVMStats
			if err := json.Unmarshal(statsBody, &stats); err != nil {
				continue
			}

			cpuUsagePercent := float64(stats.CPUUsagePPM) / 10000.0
			memUsagePercent := float64(stats.MemoryUsagePPM) / 10000.0
			avgLatencyMs := float64(stats.AvgIOLatencyUsecs) / 1000.0

			metrics = append(metrics,
				Metric{Name: "nutanix_vm_cpu_usage_percent", Value: cpuUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
				Metric{Name: "nutanix_vm_memory_usage_percent", Value: memUsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
				Metric{Name: "nutanix_vm_io_bandwidth_kbps", Value: float64(stats.IOBandwidthKBps), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
				Metric{Name: "nutanix_vm_iops", Value: float64(stats.NumIOPs), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
				Metric{Name: "nutanix_vm_io_latency_ms", Value: avgLatencyMs, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "milliseconds"},
				Metric{Name: "nutanix_vm_read_bandwidth_kbps", Value: float64(stats.ReadIOBandwidthKBps), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
				Metric{Name: "nutanix_vm_write_bandwidth_kbps", Value: float64(stats.WriteIOBandwidthKBps), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
			)
		}
	}

	return metrics, nil
}

// collectStorageMetrics collects metrics from Nutanix storage containers
func (n *NutanixExporter) collectStorageMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := n.apiRequest(ctx, "GET", "/storage_containers", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entities []nutanixStorageContainer `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, container := range resp.Entities {
		tags := map[string]string{
			"container_uuid": container.UUID,
			"container_name": container.Name,
			"cluster_uuid":   container.ClusterUUID,
		}
		for k, v := range n.config.Labels {
			tags[k] = v
		}

		compressionEnabled := 0.0
		if container.CompressionEnabled {
			compressionEnabled = 1.0
		}

		usagePercent := 0.0
		if container.MaxCapacityBytes > 0 {
			usagePercent = float64(container.UsageBytes) / float64(container.MaxCapacityBytes) * 100
		}

		metrics = append(metrics,
			Metric{Name: "nutanix_storage_container_capacity_bytes", Value: float64(container.MaxCapacityBytes), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "nutanix_storage_container_usage_bytes", Value: float64(container.UsageBytes), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "nutanix_storage_container_usage_percent", Value: usagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_storage_container_replication_factor", Value: float64(container.ReplicationFactor), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "nutanix_storage_container_compression_enabled", Value: compressionEnabled, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectAlertMetrics collects alert metrics from Nutanix
func (n *NutanixExporter) collectAlertMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := n.apiRequest(ctx, "GET", "/alerts?resolved=false", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entities []nutanixAlert `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// Count alerts by severity
	severityCounts := map[string]int{
		"kCritical": 0,
		"kWarning":  0,
		"kInfo":     0,
	}

	for _, alert := range resp.Entities {
		if count, ok := severityCounts[alert.Severity]; ok {
			severityCounts[alert.Severity] = count + 1
		}
	}

	var metrics []Metric
	baseTags := make(map[string]string)
	for k, v := range n.config.Labels {
		baseTags[k] = v
	}

	for severity, count := range severityCounts {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["severity"] = severity

		metrics = append(metrics,
			Metric{Name: "nutanix_alerts_active", Value: float64(count), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	// Total active alerts
	metrics = append(metrics,
		Metric{Name: "nutanix_alerts_active_total", Value: float64(len(resp.Entities)), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags},
	)

	return metrics, nil
}

// apiRequest makes an authenticated request to the Nutanix API
func (n *NutanixExporter) apiRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	baseURL := n.config.PrismCentralURL
	if baseURL == "" {
		baseURL = n.config.PrismElementURL
	}

	endpoint := fmt.Sprintf("%s/api/nutanix/%s%s", baseURL, n.config.APIVersion, path)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(n.config.Username, n.config.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nutanix API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// Health checks the health of Nutanix connectivity
func (n *NutanixExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !n.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Try to get clusters as health check
	_, err := n.apiRequest(ctx, "GET", "/clusters", nil)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   fmt.Sprintf("connection failed: %v", err),
			LastCheck: time.Now(),
			LastError: err,
			Latency:   time.Since(startTime),
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "Nutanix connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"prism_central_url": n.config.PrismCentralURL,
			"api_version":       n.config.APIVersion,
		},
	}, nil
}

// Close closes the Nutanix exporter
func (n *NutanixExporter) Close(ctx context.Context) error {
	if n.httpClient != nil {
		n.httpClient.CloseIdleConnections()
	}
	n.SetInitialized(false)
	n.Logger().Info("Nutanix exporter closed")
	return nil
}
